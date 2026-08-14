"""Optional low-noise Impacket recon command handling."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import shutil
import subprocess
import threading
from typing import TextIO

from portweft.models import ServiceObservation
from portweft.process_runner import (
    COMMAND_TIMEOUT_EXIT_CODE,
    close_process_streams,
    wait_for_process,
)
from portweft.profiles import SERVICE_PROFILES
from portweft.utils import print_error, print_step, quote_command


DEFAULT_MAX_IMPACKET_OUTPUT_CHARS = 8192
IMPACKET_INSTALL_HINT = "Install with pip install .[impacket]"
@dataclass(frozen=True, slots=True)
class ImpacketModule:
    name: str
    executables: tuple[str, ...]
    ports: frozenset[int]
    protocols: frozenset[str] = frozenset({"tcp"})


@dataclass(slots=True)
class ImpacketResult:
    module_name: str
    exit_code: int
    output: str = ""
    skipped: bool = False
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.skipped


@dataclass(frozen=True, slots=True)
class ImpacketAvailability:
    available: bool
    version: str = ""
    reason: str = ""


@dataclass(slots=True)
class ProcessResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


IMPACKET_RECON_MODULES: dict[str, ImpacketModule] = {
    "rpcdump": ImpacketModule(
        name="rpcdump",
        executables=("impacket-rpcdump", "rpcdump.py", "rpcdump"),
        ports=frozenset({135, 139, 445, 593}),
    ),
    "samrdump": ImpacketModule(
        name="samrdump",
        executables=("impacket-samrdump", "samrdump.py", "samrdump"),
        ports=frozenset({139, 445}),
    ),
}


def import_impacket_package() -> ImpacketAvailability:
    try:
        module = importlib.import_module("impacket")
    except ImportError as error:
        return ImpacketAvailability(
            available=False,
            reason=f"Impacket Python package is not importable: {error}. "
            f"{IMPACKET_INSTALL_HINT}",
        )

    version = getattr(module, "__version__", "")
    return ImpacketAvailability(available=True, version=str(version))


def ensure_impacket_package(
    max_output_chars: int = DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
) -> ImpacketAvailability:
    _ = max_output_chars
    return import_impacket_package()


def modules_for_profile(profile_name: str) -> list[str]:
    profile = SERVICE_PROFILES.get(profile_name, {})
    modules = profile.get("impacket", [])
    if isinstance(modules, list):
        return [module for module in modules if module in IMPACKET_RECON_MODULES]
    return []


def module_supports_service(module_name: str, service: ServiceObservation) -> bool:
    module = IMPACKET_RECON_MODULES.get(module_name)
    if module is None:
        return False
    return (
        service.protocol.lower() in module.protocols
        and service.port in module.ports
    )


def resolve_impacket_tool(module_name: str) -> str | None:
    module = IMPACKET_RECON_MODULES.get(module_name)
    if module is None:
        return None
    for executable in module.executables:
        found = shutil.which(executable)
        if found:
            return found
    return None


def build_impacket_command(
    module_name: str,
    executable: str,
    service: ServiceObservation,
) -> list[str]:
    if module_name not in IMPACKET_RECON_MODULES:
        raise ValueError(f"Unknown Impacket module: {module_name}")
    return [
        executable,
        "-target-ip",
        service.host,
        "-port",
        str(service.port),
        "-no-pass",
        service.host,
    ]


def run_impacket_module(
    module_name: str,
    service: ServiceObservation,
    max_output_chars: int = DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
    timeout_seconds: float | None = None,
    stats_every: float = 0,
) -> ImpacketResult:
    if not module_supports_service(module_name, service):
        return ImpacketResult(
            module_name=module_name,
            exit_code=0,
            skipped=True,
            reason=f"unsupported service {service.host}:{service.port}/{service.protocol}",
        )

    executable = resolve_impacket_tool(module_name)
    if executable is None:
        return ImpacketResult(
            module_name=module_name,
            exit_code=127,
            skipped=True,
            reason=f"Impacket tool not found for module {module_name}",
        )

    command = build_impacket_command(module_name, executable, service)
    return run_impacket_command(
        module_name,
        command,
        max_output_chars,
        timeout_seconds,
        stats_every,
    )


def run_impacket_command(
    module_name: str,
    command: list[str],
    max_output_chars: int = DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
    timeout_seconds: float | None = None,
    stats_every: float = 0,
) -> ImpacketResult:
    print_step(quote_command(command))
    try:
        completed = run_bounded_process(
            command,
            max_output_chars,
            timeout_seconds,
            stats_every,
            f"impacket {module_name}",
        )
    except FileNotFoundError:
        return ImpacketResult(
            module_name=module_name,
            exit_code=127,
            skipped=True,
            reason=f"Impacket tool not found: {command[0]}",
        )

    output = process_output(completed, max_output_chars)
    result = ImpacketResult(
        module_name=module_name,
        exit_code=completed.exit_code,
        output=output,
    )
    if completed.exit_code == COMMAND_TIMEOUT_EXIT_CODE:
        print_error(f"Impacket {module_name} timed out.")
    if not result.ok:
        print_error(f"Impacket {module_name} returned a non-zero exit code.")
        if output:
            print_error(output)
    return result


def run_bounded_process(
    command: list[str],
    max_output_chars: int,
    timeout_seconds: float | None = None,
    stats_every: float = 0,
    stage: str = "impacket",
) -> ProcessResult:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    stdout_reader = threading.Thread(
        target=read_bounded_into,
        args=(process.stdout, max_output_chars, stdout_parts),
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=read_bounded_into,
        args=(process.stderr, max_output_chars, stderr_parts),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()
    exit_code, _timed_out = wait_for_process(
        process,
        timeout_seconds,
        stats_every,
        stage,
    )
    stdout_reader.join()
    stderr_reader.join()
    close_process_streams(process)
    return ProcessResult(
        exit_code=exit_code,
        stdout=stdout_parts[0] if stdout_parts else "",
        stderr=stderr_parts[0] if stderr_parts else "",
    )


def process_output(
    result: ProcessResult,
    max_chars: int = DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
) -> str:
    return combine_output(result.stdout, result.stderr, max_chars)


def read_bounded(stream: TextIO | None, max_chars: int) -> str:
    if stream is None or max_chars <= 0:
        if stream is not None:
            for _ in stream:
                pass
        return ""

    pieces: list[str] = []
    retained = 0
    truncated = False
    for line in stream:
        if retained < max_chars:
            remaining = max_chars - retained
            piece = line[:remaining]
            pieces.append(piece)
            retained += len(piece)
            if len(line) > remaining:
                truncated = True
        else:
            truncated = True

    output = "".join(pieces).rstrip()
    if truncated:
        output = append_truncated_marker(output, max_chars)
    return output


def read_bounded_into(
    stream: TextIO | None,
    max_chars: int,
    destination: list[str],
) -> None:
    destination.append(read_bounded(stream, max_chars))


def combine_output(stdout: str, stderr: str, max_chars: int) -> str:
    if stdout and stderr:
        return read_text_bounded(f"{stdout}\n{stderr}", max_chars)
    return read_text_bounded(stdout or stderr, max_chars)


def read_text_bounded(value: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(value) <= max_chars:
        return value
    return append_truncated_marker(value[:max_chars], max_chars)


def append_truncated_marker(value: str, max_chars: int) -> str:
    marker = "... [truncated]"
    if max_chars <= len(marker):
        return value[:max_chars]
    return f"{value[: max_chars - len(marker)]}{marker}"
