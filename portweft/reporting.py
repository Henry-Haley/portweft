"""Text report generation."""

from __future__ import annotations

from collections.abc import Iterator
import datetime as dt
import json
import platform
from pathlib import Path

from portweft import APP_NAME
from portweft.errors import ReportWriteError
from portweft.matcher import match_profiles
from portweft.models import HostObservation, ServiceObservation
from portweft.targets import TargetResolution, successful_resolutions
from portweft.utils import safe_name, sanitize_text


IMPACKET_SCRIPT_PREFIX = "impacket-"
CUMULATIVE_REPORT_NAME = "CUMULATIVE-report.txt"
CUMULATIVE_JSON_REPORT_NAME = "CUMULATIVE-report.json"


def write_reports(
    report_dir: Path,
    targets: list[str],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
    impacket_status: str = "not requested (--impacket not used)",
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
        report_lines(targets, scan_started_at, report_hosts, impacket_status),
    )
    written.append(cumulative_path)

    for host in report_hosts:
        host_path = report_dir / host_report_filename(host)
        write_lines(
            host_path,
            report_lines(targets, scan_started_at, [host], impacket_status),
        )
        written.append(host_path)

    return written


def write_json_reports(
    report_dir: Path,
    resolutions: list[TargetResolution],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
    impacket_status: str = "not requested (--impacket not used)",
) -> list[Path]:
    """Write parseable JSON reports instead of formatted text reports."""
    report_hosts = reportable_hosts(hosts)
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ReportWriteError(str(report_dir), str(error)) from error

    written: list[Path] = []
    cumulative_path = report_dir / CUMULATIVE_JSON_REPORT_NAME
    resolved_reports = successful_resolutions(resolutions)
    write_json(
        cumulative_path,
        json_report_document(
            target=", ".join(resolution.original for resolution in resolved_reports),
            resolved_ip=", ".join(
                address
                for resolution in resolved_reports
                for address in resolution.addresses
            ),
            resolutions=resolutions,
            scan_started_at=scan_started_at,
            hosts=report_hosts,
            impacket_status=impacket_status,
        ),
    )
    written.append(cumulative_path)

    for host in report_hosts:
        host_path = report_dir / f"{safe_name(host.address)}-report.json"
        write_json(
            host_path,
            json_report_document(
                target=host.original_target or host.address,
                resolved_ip=host.resolved_ip or host.address,
                resolutions=resolutions,
                scan_started_at=scan_started_at,
                hosts=[host],
                impacket_status=impacket_status,
            ),
        )
        written.append(host_path)

    return written


def write_report(
    report_path: Path,
    targets: list[str],
    initial_xml: Path,
    hosts: list[HostObservation],
    scan_started_at: dt.datetime | None = None,
    impacket_status: str = "not requested (--impacket not used)",
) -> None:
    """Write a single report file.

    Kept for callers that want an explicit report path; the CLI uses
    write_reports() so each responding host gets its own consolidated file.
    """
    _ = initial_xml
    started_at = scan_started_at or dt.datetime.now(dt.timezone.utc)
    write_lines(
        report_path,
        report_lines(targets, started_at, reportable_hosts(hosts), impacket_status),
    )


def write_lines(report_path: Path, lines: Iterator[str]) -> None:
    try:
        with report_path.open("w", encoding="utf-8") as report:
            for line in lines:
                report.write(f"{sanitize_text(line)}\n")
    except OSError as error:
        raise ReportWriteError(str(report_path), str(error)) from error


def write_json(report_path: Path, document: dict) -> None:
    try:
        with report_path.open("w", encoding="utf-8") as report:
            json.dump(document, report, indent=2, sort_keys=True)
            report.write("\n")
    except OSError as error:
        raise ReportWriteError(str(report_path), str(error)) from error


def report_lines(
    targets: list[str],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
    impacket_status: str,
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
    yield f"  Status: {impacket_status}"
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


def json_report_document(
    target: str,
    resolved_ip: str,
    resolutions: list[TargetResolution],
    scan_started_at: dt.datetime,
    hosts: list[HostObservation],
    impacket_status: str,
) -> dict:
    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "targets": [target_resolution_json(resolution) for resolution in resolutions],
        "scan_started_gmt": format_gmt(scan_started_at),
        "generated_gmt": format_gmt(dt.datetime.now(dt.timezone.utc)),
        "impacket_status": impacket_status,
        "hosts": [host_json(host) for host in hosts],
    }


def target_resolution_json(resolution: TargetResolution) -> dict:
    return {
        "target": resolution.original,
        "resolved_ips": list(resolution.addresses),
        "error": resolution.error,
    }


def host_json(host: HostObservation) -> dict:
    return {
        "target": host.original_target or host.address,
        "resolved_ip": host.resolved_ip or host.address,
        "address": host.address,
        "hostname": host.hostname,
        "status": host.status or "unknown",
        "os": host.os_label(),
        "os_family": host.os_family,
        "services": [service_json(service) for service in sorted(
            host.services,
            key=lambda item: (item.port, item.protocol),
        )],
    }


def service_json(service: ServiceObservation) -> dict:
    return {
        "port": service.port,
        "protocol": service.protocol,
        "state": service.state,
        "name": service.service_name,
        "product": service.product,
        "version": service.version,
        "extrainfo": service.extrainfo,
        "tunnel": service.tunnel,
        "label": service.label(),
        "matched_profiles": match_profiles(service),
        "nse_results": dict(nse_scripts(service.scripts)),
        "impacket_results": dict(impacket_scripts(service.scripts)),
    }


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
