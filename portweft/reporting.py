"""Text report generation."""

from __future__ import annotations

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
    lines: list[str] = [
        f"{APP_NAME} Report",
        f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Operator OS: {platform.system()} {platform.release()}",
        f"Targets: {', '.join(targets)}",
        f"Initial XML: {initial_xml}",
        "",
    ]

    for host in hosts:
        lines.extend(
            [
                f"Host: {host.display_name()}",
                f"  Status: {host.status or 'unknown'}",
                f"  OS: {host.os_label()}",
                "  Open services:",
            ]
        )
        if not host.services:
            lines.append("    none observed")
            lines.append("")
            continue

        for service in sorted(host.services, key=lambda item: (item.port, item.protocol)):
            profiles = match_profiles(service)
            profile_text = ", ".join(profiles) if profiles else "none"
            lines.append(
                f"    - {service.port}/{service.protocol} "
                f"{service.label()} [profiles: {profile_text}]"
            )
            for script_id, output in sorted(service.scripts.items()):
                lines.append(f"      {script_id}:")
                for output_line in output.splitlines() or [""]:
                    lines.append(f"        {output_line}")
        lines.append("")

    try:
        report_path.write_text("\n".join(lines), encoding="utf-8")
    except OSError as error:
        raise ReportWriteError(str(report_path), str(error)) from error
