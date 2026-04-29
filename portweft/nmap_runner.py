"""Nmap command construction and execution."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import shlex
import shutil
import subprocess
from pathlib import Path

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
    command.extend(build_base_nmap_args(parsed, extra))
    if "-sU" not in command:
        command.append("-sU")
    command.extend(["-p", f"U:{parsed.udp_ports}"])
    command.extend(["-oX", str(xml_path)])
    command.extend(targets)
    return command


def build_followup_command(
    parsed: argparse.Namespace,
    service: ServiceObservation,
    profile_name: str,
    xml_path: Path,
    extra: list[str],
) -> list[str]:
    profile = SERVICE_PROFILES.get(profile_name, {})
    scripts = ",".join(profile.get("scripts", []))
    command = [resolved_nmap_path(parsed.nmap_path)]
    command.extend(build_base_nmap_args(parsed, extra))
    if service.protocol.lower() == "udp":
        if "-sU" not in command:
            command.append("-sU")
        command.extend(["-p", f"U:{service.port}"])
    else:
        command.extend(["-p", str(service.port)])
    if scripts:
        command.extend(["--script", scripts])
    command.extend(["-oX", str(xml_path), service.host])
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


def run_command(command: list[str], dry_run: bool) -> CommandResult:
    print_step(quote_command(command))
    if dry_run:
        return CommandResult(exit_code=0)

    try:
        completed = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise NmapNotFoundError(command[0]) from error

    result = CommandResult(
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if not result.ok:
        print_nmap_failure(result)
    return result


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
