"""Nmap command construction and execution."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import TextIO

from portweft import APP_NAME
from portweft.errors import (
    NmapArgumentStringError,
    NmapNotFoundError,
    NmapOutputConflictError,
)
from portweft.models import ServiceObservation
from portweft.profiles import SERVICE_PROFILES, UDP_DEFAULT_PORTS
from portweft.utils import print_error, print_step, quote_command


OUTPUT_FLAGS = {
    "-oA",
    "-oG",
    "-oN",
    "-oS",
    "-oX",
    "--webxml",
}

UDP_INCOMPATIBLE_FLAGS = {
    "-sS",
    "-sT",
    "-sA",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "-sY",
    "-sZ",
    "-F",
}

UDP_INCOMPATIBLE_PREFIXES = (
    "-PA",
    "-PS",
)

UDP_INCOMPATIBLE_OPTIONS_WITH_VALUES = {
    "-p",
    "--top-ports",
    "--scanflags",
}

WINDOWS_NMAP_CANDIDATES = (
    Path("C:/Program Files/Nmap/nmap.exe"),
    Path("C:/Program Files (x86)/Nmap/nmap.exe"),
)


@dataclass
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def split_nmap_args(value: str) -> list[str]:
    if not value.strip():
        return []
    try:
        return shlex.split(value)
    except ValueError as error:
        raise NmapArgumentStringError(f"Could not parse --nmap-args: {error}") from error


def validate_nmap_passthrough(args: list[str]) -> None:
    conflicts = [arg for arg in args if arg in OUTPUT_FLAGS]
    if conflicts:
        joined = ", ".join(conflicts)
        raise NmapOutputConflictError(
            f"{APP_NAME} owns Nmap output flags so XML can be parsed. "
            f"Remove these passthrough flags and use --output-dir instead: {joined}"
        )


def udp_default_ports_text() -> str:
    return ",".join(str(port) for port in sorted(UDP_DEFAULT_PORTS))


def normalize_unknown_nmap_args(args: list[str]) -> list[str]:
    return [arg for arg in args if arg != "--"]


def ensure_nmap_available(nmap_path: str, dry_run: bool) -> None:
    if dry_run:
        return
    if resolve_nmap_path(nmap_path):
        return
    raise NmapNotFoundError(nmap_path)


def resolve_nmap_path(nmap_path: str) -> str | None:
    expanded = Path(os.path.expandvars(os.path.expanduser(nmap_path)))
    if expanded.exists():
        return str(expanded)

    found = shutil.which(nmap_path)
    if found:
        return found

    if nmap_path == "nmap":
        for candidate in WINDOWS_NMAP_CANDIDATES:
            if candidate.exists():
                return str(candidate)

    return None


def build_initial_command(
    parsed: argparse.Namespace,
    targets: list[str],
    xml_path: Path,
    extra: list[str],
) -> list[str]:
    command = [resolved_nmap_path(parsed.nmap_path)]
    command.extend(build_base_nmap_args(parsed, extra))
    if parsed.ports:
        command.extend(["-p", parsed.ports])
    elif parsed.top_ports:
        command.extend(["--top-ports", str(parsed.top_ports)])
    command.extend(["-oX", str(xml_path)])
    command.extend(targets)
    return command


def build_udp_command(
    parsed: argparse.Namespace,
    targets: list[str],
    xml_path: Path,
    extra: list[str],
) -> list[str]:
    command = [resolved_nmap_path(parsed.nmap_path)]
    command.extend(build_base_nmap_args(parsed, filter_udp_nmap_args(extra)))
    if "-sU" not in command:
        command.append("-sU")
    command.extend(["-p", f"U:{parsed.udp_ports}"])
    command.extend(["-oX", str(xml_path)])
    command.extend(targets)
    return command


def filter_udp_nmap_args(args: list[str]) -> list[str]:
    filtered: list[str] = []
    skip_next = False
    for index, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in UDP_INCOMPATIBLE_FLAGS or has_udp_incompatible_prefix(arg):
            if udp_option_value_is_next(arg, args, index):
                skip_next = True
            continue
        if removes_next_udp_arg(arg):
            skip_next = True
            continue
        if removes_current_udp_arg(arg):
            continue
        filtered.append(arg)
    return filtered


def has_udp_incompatible_prefix(arg: str) -> bool:
    return any(
        arg == prefix or arg.startswith(prefix)
        for prefix in UDP_INCOMPATIBLE_PREFIXES
    )


def udp_option_value_is_next(arg: str, args: list[str], index: int) -> bool:
    return arg in UDP_INCOMPATIBLE_PREFIXES and has_next_value(args, index)


def removes_next_udp_arg(arg: str) -> bool:
    return arg in UDP_INCOMPATIBLE_OPTIONS_WITH_VALUES


def removes_current_udp_arg(arg: str) -> bool:
    return (
        arg.startswith("-p")
        or arg.startswith("--top-ports=")
        or arg.startswith("--scanflags=")
    )


def has_next_value(args: list[str], index: int) -> bool:
    return index + 1 < len(args) and not args[index + 1].startswith("-")


def build_followup_command(
    parsed: argparse.Namespace,
    service: ServiceObservation,
    profile_name: str,
    xml_path: Path,
    extra: list[str],
) -> list[str]:
    return build_followup_batch_command(
        parsed,
        service.host,
        service.protocol,
        [service.port],
        profile_name,
        xml_path,
        extra,
    )


def build_followup_batch_command(
    parsed: argparse.Namespace,
    host: str,
    protocol: str,
    ports: list[int],
    profile_name: str,
    xml_path: Path,
    extra: list[str],
) -> list[str]:
    profile = SERVICE_PROFILES.get(profile_name, {})
    scripts = ",".join(profile.get("scripts", []))
    command = [resolved_nmap_path(parsed.nmap_path)]
    command.extend(build_base_nmap_args(parsed, extra))
    port_text = ",".join(str(port) for port in sorted(set(ports)))
    if protocol.lower() == "udp":
        if "-sU" not in command:
            command.append("-sU")
        command.extend(["-p", f"U:{port_text}"])
    else:
        command.extend(["-p", port_text])
    if scripts:
        command.extend(["--script", scripts])
    command.extend(["-oX", str(xml_path), host])
    return command


def build_base_nmap_args(parsed: argparse.Namespace, extra: list[str]) -> list[str]:
    args = list(extra)
    version_flags = {"-A", "-sV", "--version-all", "--version-light"}
    if not parsed.no_service_version and not has_any_flag(args, version_flags):
        args.extend(["-sV", "--version-light"])
    return args


def has_any_flag(args: list[str], flags: set[str]) -> bool:
    return any(arg in flags for arg in args)


def resolved_nmap_path(nmap_path: str) -> str:
    return resolve_nmap_path(nmap_path) or nmap_path


def run_command(
    command: list[str],
    dry_run: bool,
    max_output_lines: int = 12,
) -> CommandResult:
    print_step(quote_command(command))
    if dry_run:
        return CommandResult(exit_code=0)

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise NmapNotFoundError(command[0]) from error

    import threading

    stdout_tail: deque[str] = deque(maxlen=max_output_lines)
    stderr_tail: deque[str] = deque(maxlen=max_output_lines)
    stdout_reader = threading.Thread(
        target=read_tail,
        args=(process.stdout, stdout_tail),
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=read_tail,
        args=(process.stderr, stderr_tail),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()
    exit_code = process.wait()
    stdout_reader.join()
    stderr_reader.join()

    result = CommandResult(
        exit_code=exit_code,
        stdout="\n".join(stdout_tail),
        stderr="\n".join(stderr_tail),
    )
    if not result.ok:
        print_nmap_failure(result)
    return result


def read_tail(stream: TextIO | None, tail: deque[str]) -> None:
    if stream is None:
        return
    for line in stream:
        tail.append(line.rstrip("\r\n"))


def print_nmap_failure(result: CommandResult) -> None:
    message = extract_nmap_error(result)
    print_error("Nmap returned a non-zero exit code.")
    print_error(message)


def extract_nmap_error(result: CommandResult, max_lines: int = 12) -> str:
    combined = "\n".join(part for part in (result.stderr, result.stdout) if part.strip())
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    if not lines:
        return f"Nmap exited with code {result.exit_code}, but did not print an error."
    return "\n".join(lines[-max_lines:])
