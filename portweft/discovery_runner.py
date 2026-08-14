"""Normalized TCP discovery using Nmap, RustScan, or Masscan."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
from typing import TextIO

from portweft.errors import MasscanNotFoundError, RustScanNotFoundError
from portweft.models import DiscoveryResult, HostObservation, ServiceObservation
from portweft.nmap_runner import build_discovery_command, run_command
from portweft.nmap_xml import parse_nmap_xml
from portweft.targets import normalize_ip
from portweft.process_runner import (
    attach_process_group,
    close_process_streams,
    close_process_group,
    subprocess_group_kwargs,
    wait_for_process,
)
from portweft.utils import print_error, print_step, quote_command


RUSTSCAN_LINE = re.compile(r"^\s*(.+?)\s*->\s*\[([^]]*)\]\s*$")
MASSCAN_LINE = re.compile(r"^open\s+tcp\s+(\d+)\s+(\S+)(?:\s+.*)?$")


@dataclass(slots=True)
class ExternalResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def resolve_executable(path: str) -> str | None:
    expanded = Path(os.path.expandvars(os.path.expanduser(path)))
    if expanded.is_file():
        return str(expanded)
    return shutil.which(path)


def is_single_host(targets: list[str]) -> bool:
    if len(targets) != 1:
        return False
    try:
        return ipaddress.ip_network(targets[0], strict=False).num_addresses == 1
    except ValueError:
        return True


def select_discovery_backend(
    requested: str,
    targets: list[str],
    rustscan_path: str = "rustscan",
    masscan_path: str = "masscan",
    dry_run: bool = False,
) -> str:
    if requested == "rustscan":
        if not dry_run and not resolve_executable(rustscan_path):
            raise RustScanNotFoundError(rustscan_path)
        return requested
    if requested == "masscan":
        if not dry_run and not resolve_executable(masscan_path):
            raise MasscanNotFoundError(masscan_path)
        return requested
    if requested == "nmap":
        return requested
    if is_single_host(targets) and resolve_executable(rustscan_path):
        return "rustscan"
    if not is_single_host(targets) and resolve_executable(masscan_path):
        return "masscan"
    return "nmap"


def build_rustscan_command(path: str, targets: list[str]) -> list[str]:
    return [
        resolve_executable(path) or path,
        "--addresses",
        ",".join(targets),
        "--range",
        "1-65535",
        "--greppable",
        "--scripts",
        "none",
        "--no-banner",
        "--no-config",
    ]


def build_masscan_command(
    path: str,
    targets: list[str],
    output_path: Path,
    rate: int = 1000,
) -> list[str]:
    return [
        resolve_executable(path) or path,
        "-p1-65535",
        "--rate",
        str(rate),
        "-oL",
        str(output_path),
        *targets,
    ]


def parse_rustscan_greppable(output: str) -> dict[str, set[int]]:
    discovered: dict[str, set[int]] = {}
    for line in output.splitlines():
        match = RUSTSCAN_LINE.match(line)
        if not match:
            continue
        host, ports_text = match.groups()
        host = normalize_ip(host)
        if not host:
            continue
        ports = {
            port
            for item in ports_text.split(",")
            if (port := valid_port(item.strip())) is not None
        }
        if ports:
            discovered.setdefault(host, set()).update(ports)
    return discovered


def parse_masscan_list(output: str) -> dict[str, set[int]]:
    return parse_masscan_lines(output.splitlines())


def parse_masscan_lines(lines: Iterable[str]) -> dict[str, set[int]]:
    discovered: dict[str, set[int]] = {}
    for line in lines:
        match = MASSCAN_LINE.match(line.strip())
        if not match:
            continue
        port = valid_port(match.group(1))
        host = normalize_ip(match.group(2))
        if port is None or not host:
            continue
        discovered.setdefault(host, set()).add(port)
    return discovered


def valid_port(value: str) -> int | None:
    try:
        port = int(value, 10)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def valid_host(value: str) -> bool:
    return bool(normalize_ip(value))


def discovery_ports_from_hosts(hosts: list[HostObservation]) -> dict[str, set[int]]:
    return {
        host.address: {
            service.port
            for service in host.services
            if service.protocol.lower() == "tcp"
        }
        for host in hosts
        if any(service.protocol.lower() == "tcp" for service in host.services)
    }


def hosts_from_discovery(result: DiscoveryResult) -> list[HostObservation]:
    return [
        HostObservation(
            address=host,
            status="up",
            services=[
                ServiceObservation(host, port, "tcp", "open")
                for port in sorted(ports)
            ],
        )
        for host, ports in sorted(result.open_tcp_ports.items())
    ]


def run_discovery(
    parsed,
    backend: str,
    targets: list[str],
    output_path: Path,
    extra_nmap_args: list[str],
    timeout_seconds: float | None,
    command_runner=run_command,
    xml_parser=parse_nmap_xml,
) -> DiscoveryResult:
    stats_every = parsed.stats_every
    if backend == "nmap":
        command = build_discovery_command(parsed, targets, output_path, extra_nmap_args)
        result = command_runner(
            command,
            parsed.dry_run,
            timeout_seconds=timeout_seconds,
            stats_every=stats_every,
            stage="discovery (nmap)",
        )
        if parsed.dry_run:
            return DiscoveryResult(backend=backend, status="planned")
        if not result.ok:
            return DiscoveryResult(
                backend=backend,
                status=f"failed (exit code {result.exit_code})",
                exit_code=result.exit_code,
            )
        hosts = xml_parser(output_path, parsed.max_script_output_chars)
        return DiscoveryResult(backend, discovery_ports_from_hosts(hosts))

    if backend == "rustscan":
        command = build_rustscan_command(parsed.rustscan_path, targets)
        if parsed.dry_run:
            print_step(quote_command(command))
            return DiscoveryResult(backend=backend, status="planned")
        try:
            result = run_external_command(
                command,
                timeout_seconds,
                stats_every,
                "discovery (rustscan)",
            )
        except OSError as error:
            if parsed.discovery_backend == "auto":
                print_step("RustScan became unavailable; falling back to Nmap")
                return run_discovery(
                    parsed,
                    "nmap",
                    targets,
                    output_path,
                    extra_nmap_args,
                    timeout_seconds,
                    command_runner,
                    xml_parser,
                )
            raise RustScanNotFoundError(parsed.rustscan_path) from error
        if not result.ok:
            print_external_failure("RustScan", result)
            return DiscoveryResult(
                backend=backend,
                status=f"failed (exit code {result.exit_code})",
                exit_code=result.exit_code,
            )
        return DiscoveryResult(backend, parse_rustscan_greppable(result.stdout))

    command = build_masscan_command(
        parsed.masscan_path,
        targets,
        output_path,
        parsed.masscan_rate,
    )
    if parsed.dry_run:
        print_step(quote_command(command))
        return DiscoveryResult(backend=backend, status="planned")
    try:
        result = run_external_command(
            command,
            timeout_seconds,
            stats_every,
            "discovery (masscan)",
        )
    except OSError as error:
        if parsed.discovery_backend == "auto":
            print_step("Masscan became unavailable; falling back to Nmap")
            return run_discovery(
                parsed,
                "nmap",
                targets,
                output_path,
                extra_nmap_args,
                timeout_seconds,
                command_runner,
                xml_parser,
            )
        raise MasscanNotFoundError(parsed.masscan_path) from error
    if not result.ok:
        print_external_failure("Masscan", result)
        return DiscoveryResult(
            backend=backend,
            status=f"failed (exit code {result.exit_code})",
            exit_code=result.exit_code,
        )
    try:
        with output_path.open(encoding="utf-8", errors="replace") as output:
            ports = parse_masscan_lines(output)
    except OSError as error:
        print_error(f"Could not read Masscan list output: {error}")
        return DiscoveryResult(backend, status="failed (unreadable output)", exit_code=1)
    return DiscoveryResult(backend, ports)


def run_external_command(
    command: list[str],
    timeout_seconds: float | None,
    stats_every: float,
    stage: str,
    max_output_chars: int = 4 * 1024 * 1024,
) -> ExternalResult:
    print_step(quote_command(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **subprocess_group_kwargs(),
    )
    attach_process_group(process)
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    readers = [
        threading.Thread(
            target=read_bounded,
            args=(process.stdout, max_output_chars, stdout_parts),
            daemon=True,
        ),
        threading.Thread(
            target=read_bounded,
            args=(process.stderr, max_output_chars, stderr_parts),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    try:
        exit_code, _timed_out = wait_for_process(
            process,
            timeout_seconds,
            stats_every,
            stage,
        )
    finally:
        close_process_group(process)
        for reader in readers:
            reader.join()
        close_process_streams(process)
    return ExternalResult(
        exit_code,
        stdout_parts[0] if stdout_parts else "",
        stderr_parts[0] if stderr_parts else "",
    )


def read_bounded(
    stream: TextIO | None,
    max_chars: int,
    destination: list[str],
) -> None:
    if stream is None:
        return
    parts: list[str] = []
    retained = 0
    for line in stream:
        if retained >= max_chars:
            continue
        piece = line[: max_chars - retained]
        parts.append(piece)
        retained += len(piece)
    destination.append("".join(parts).rstrip())


def print_external_failure(tool: str, result: ExternalResult) -> None:
    detail = "\n".join(
        line for line in (result.stderr, result.stdout) if line.strip()
    ).strip()
    if result.exit_code == 124:
        print_error(f"{tool} discovery timed out.")
    elif tool == "Masscan" and any(
        word in detail.lower() for word in ("permission", "pcap", "socket", "root")
    ):
        print_error(
            "Masscan could not start its raw-packet scan. Run with the required "
            "capture/raw-socket privileges or select --discovery-backend nmap."
        )
    else:
        print_error(f"{tool} returned a non-zero exit code ({result.exit_code}).")
    if detail:
        print_error(detail)
