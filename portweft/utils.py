"""Shared helpers for output, names, and command display."""

from __future__ import annotations

import datetime as dt
import os
import shlex
import subprocess
import sys

from portweft.models import HostObservation, ServiceObservation


def now_slug() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ")


def print_step(message: str) -> None:
    timestamp = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def print_error(message: str) -> None:
    timestamp = dt.datetime.now().strftime("%H:%M:%S")
    for line in message.splitlines():
        print(f"[{timestamp}] Error: {line}", file=sys.stderr, flush=True)


def print_section_done(section: str, detail: str = "") -> None:
    message = f"{section} complete"
    if detail:
        message = f"{message}: {detail}"
    print_step(message)


def print_host_os(host: HostObservation) -> None:
    label = host.os_label()
    if label == "unknown":
        print_step(f"OS not identified: {host.display_name()}")
        return
    print_step(f"OS identified: {host.display_name()} -> {label}")


def print_open_services(host: HostObservation) -> None:
    if not host.services:
        print_step(f"Open ports: {host.display_name()} -> none observed")
        return

    services = sorted(host.services, key=lambda item: (item.port, item.protocol))
    print_step(f"Open ports for {host.display_name()}:")
    for service in services:
        print_step(f"  {format_service_line(service)}")


def print_followup_findings(profile_name: str, hosts: list[HostObservation]) -> None:
    for host in hosts:
        for service in sorted(host.services, key=lambda item: (item.port, item.protocol)):
            if service.scripts:
                for script_id, output in sorted(service.scripts.items()):
                    print_step(
                        f"{profile_name} detail: "
                        f"{host.address}:{service.port}/{service.protocol} "
                        f"{service.label()} | {script_id} -> {first_output_line(output)}"
                    )
            else:
                print_step(
                    f"{profile_name} detail: "
                    f"{host.address}:{service.port}/{service.protocol} "
                    f"{service.label()}"
                )


def format_service_line(service: ServiceObservation) -> str:
    return f"{service.port}/{service.protocol} {service.label()}"


def first_output_line(output: str, limit: int = 140) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return truncate(stripped, limit)
    return "no script output"


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def split_targets(targets: str) -> list[str]:
    return [target.strip() for target in targets.split(",") if target.strip()]


def quote_command(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-_" else "_" for char in value)
