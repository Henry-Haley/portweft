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


def write_report(
    report_path: Path,
    targets: list[str],
    initial_xml: Path,
    hosts: list[HostObservation],
) -> None:
    try:
        with report_path.open("w", encoding="utf-8") as report:
            for line in report_lines(targets, initial_xml, hosts):
                report.write(f"{line}\n")
    except OSError as error:
        raise ReportWriteError(str(report_path), str(error)) from error


def report_lines(
    targets: list[str],
    initial_xml: Path,
    hosts: list[HostObservation],
) -> Iterator[str]:
    yield f"{APP_NAME} Report"
    yield f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}"
    yield f"Operator OS: {platform.system()} {platform.release()}"
    yield f"Targets: {', '.join(targets)}"
    yield f"Initial XML: {initial_xml}"
    yield ""

    for host in hosts:
        yield f"Host: {host.display_name()}"
        yield f"  Status: {host.status or 'unknown'}"
        yield f"  OS: {host.os_label()}"
        yield "  Open services:"
        if not host.services:
            yield "    none observed"
            yield ""
            continue

        for service in sorted(host.services, key=lambda item: (item.port, item.protocol)):
            profiles = match_profiles(service)
            profile_text = ", ".join(profiles) if profiles else "none"
            yield (
                f"    - {service.port}/{service.protocol} "
                f"{service.label()} [profiles: {profile_text}]"
            )
            for script_id, output in sorted(service.scripts.items()):
                yield f"      {script_id}:"
                for output_line in output.splitlines() or [""]:
                    yield f"        {output_line}"
        yield ""
