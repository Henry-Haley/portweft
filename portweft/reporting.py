"""Text report generation."""

from __future__ import annotations

from collections.abc import Iterator
import datetime as dt
import platform
from pathlib import Path

from portweft import APP_NAME
from portweft.errors import ReportWriteError
from portweft.matcher import match_profiles
from portweft.models import HostObservation
from portweft.utils import safe_name


IMPACKET_SCRIPT_PREFIX = "impacket-"
CUMULATIVE_REPORT_NAME = "CUMULATIVE-report.txt"


def write_reports(
    report_dir: Path,
    targets: list[str],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
) -> list[Path]:
    """Write one cumulative report and one report for each responding host."""
    report_hosts = reportable_hosts(hosts)
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ReportWriteError(str(report_dir), str(error)) from error

    written: list[Path] = []
    cumulative_path = report_dir / CUMULATIVE_REPORT_NAME
    write_lines(
        cumulative_path,
        report_lines(targets, scan_started_at, report_hosts),
    )
    written.append(cumulative_path)

    for host in report_hosts:
        host_path = report_dir / host_report_filename(host)
        write_lines(
            host_path,
            report_lines(targets, scan_started_at, [host]),
        )
        written.append(host_path)

    return written


def write_report(
    report_path: Path,
    targets: list[str],
    initial_xml: Path,
    hosts: list[HostObservation],
    scan_started_at: dt.datetime | None = None,
) -> None:
    """Write a single report file.

    Kept for callers that want an explicit report path; the CLI uses
    write_reports() so each responding host gets its own consolidated file.
    """
    _ = initial_xml
    started_at = scan_started_at or dt.datetime.now(dt.timezone.utc)
    write_lines(
        report_path,
        report_lines(targets, started_at, reportable_hosts(hosts)),
    )


def write_lines(report_path: Path, lines: Iterator[str]) -> None:
    try:
        with report_path.open("w", encoding="utf-8") as report:
            for line in lines:
                report.write(f"{line}\n")
    except OSError as error:
        raise ReportWriteError(str(report_path), str(error)) from error


def report_lines(
    targets: list[str],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
) -> Iterator[str]:
    yield f"{APP_NAME} Report"
    yield f"Scan started (GMT): {format_gmt(scan_started_at)}"
    yield f"Generated (GMT): {format_gmt(dt.datetime.now(dt.timezone.utc))}"
    yield f"Operator OS: {platform.system()} {platform.release()}"
    yield f"Targets: {', '.join(targets)}"
    yield "Temporary XML: removed after parsing and report generation"
    yield ""
    yield "NMAP OUTPUT:"
    if not hosts:
        yield "  no responding hosts observed"
    for host in hosts:
        yield from nmap_host_lines(host)
    yield ""
    yield "IMPACKET RESULTS:"
    if not hosts:
        yield "  no responding hosts observed"
        return
    found_impacket = False
    for host in hosts:
        host_lines = list(impacket_host_lines(host))
        if not host_lines:
            continue
        found_impacket = True
        yield from host_lines
    if not found_impacket:
        yield "  none observed"


def nmap_host_lines(host: HostObservation) -> Iterator[str]:
    yield f"  Host: {host.display_name()}"
    yield f"    Status: {host.status or 'unknown'}"
    yield f"    OS: {host.os_label()}"
    yield "    Open ports:"
    services = sorted(host.services, key=lambda item: (item.port, item.protocol))
    if not services:
        yield "      none observed"
    for service in services:
        profiles = match_profiles(service)
        profile_text = ", ".join(profiles) if profiles else "none"
        yield (
            f"      - {service.port}/{service.protocol} "
            f"{service.label()} [profiles: {profile_text}]"
        )

    yield "    NSE SCRIPT RESULTS:"
    found_nse = False
    for service in services:
        scripts = nse_scripts(service.scripts)
        if not scripts:
            continue
        found_nse = True
        yield f"      {service.port}/{service.protocol} {service.label()}:"
        for script_id, output in scripts:
            yield f"        {script_id}:"
            for output_line in output.splitlines() or [""]:
                yield f"          {output_line}"
    if not found_nse:
        yield "      none observed"


def impacket_host_lines(host: HostObservation) -> Iterator[str]:
    services = sorted(host.services, key=lambda item: (item.port, item.protocol))
    service_lines: list[str] = []
    for service in services:
        scripts = impacket_scripts(service.scripts)
        if not scripts:
            continue
        service_lines.append(f"    {service.port}/{service.protocol} {service.label()}:")
        for script_id, output in scripts:
            service_lines.append(f"      {script_id}:")
            for output_line in output.splitlines() or [""]:
                service_lines.append(f"        {output_line}")

    if not service_lines:
        return
    yield f"  Host: {host.display_name()}"
    yield from service_lines


def nse_scripts(scripts: dict[str, str]) -> list[tuple[str, str]]:
    return [
        (script_id, output)
        for script_id, output in sorted(scripts.items())
        if not script_id.startswith(IMPACKET_SCRIPT_PREFIX)
    ]


def impacket_scripts(scripts: dict[str, str]) -> list[tuple[str, str]]:
    return [
        (script_id, output)
        for script_id, output in sorted(scripts.items())
        if script_id.startswith(IMPACKET_SCRIPT_PREFIX)
    ]


def reportable_hosts(hosts: list[HostObservation]) -> list[HostObservation]:
    return [host for host in hosts if host_has_scan_response(host)]


def host_has_scan_response(host: HostObservation) -> bool:
    status = (host.status or "").lower()
    return bool(host.services) or status not in ("", "down", "unknown")


def host_report_filename(host: HostObservation) -> str:
    return f"{safe_name(host.address)}-report.txt"


def format_gmt(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S GMT")
