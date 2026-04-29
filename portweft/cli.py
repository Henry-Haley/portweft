"""Command-line interface and top-level PortWeft workflow."""

from __future__ import annotations

import argparse
from collections import defaultdict
import shutil
import sys
from pathlib import Path

from portweft import APP_NAME
from portweft.errors import OutputDirectoryError, PortWeftError
from portweft.matcher import evidence_summary, has_observable_evidence, match_profiles
from portweft.models import HostObservation, ServiceObservation
from portweft.nmap_runner import (
    build_followup_batch_command,
    build_initial_command,
    build_udp_command,
    ensure_nmap_available,
    normalize_unknown_nmap_args,
    run_command,
    split_nmap_args,
    udp_default_ports_text,
    validate_nmap_passthrough,
)
from portweft.nmap_xml import (
    DEFAULT_MAX_SCRIPT_OUTPUT_CHARS,
    merge_hosts,
    parse_nmap_xml,
)
from portweft.reporting import write_report
from portweft.utils import (
    now_slug,
    print_followup_findings,
    print_host_os,
    print_open_services,
    print_section_done,
    print_step,
    safe_name,
    split_targets,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portweft",
        description="Run Nmap, parse XML, and gather facts for open services.",
        allow_abbrev=False,
    )
    parser.add_argument("targets", help="IP, comma-separated IPs, or CIDR range")
    parser.add_argument("-p", "--ports", help="Ports for the initial scan")
    parser.add_argument("--top-ports", type=int, help="Nmap --top-ports value")
    parser.add_argument(
        "--nmap-args",
        default="",
        help="Quoted Nmap arguments to pass to initial and follow-up scans",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory for XML scan output and reports",
    )
    parser.add_argument(
        "--keep-runs",
        type=int,
        default=0,
        help="Keep only the newest N output runs after a successful scan; 0 keeps all",
    )
    parser.add_argument(
        "--max-script-output-chars",
        type=int,
        default=DEFAULT_MAX_SCRIPT_OUTPUT_CHARS,
        help="Maximum NSE script output characters retained per script",
    )
    parser.add_argument(
        "--nmap-path",
        default="nmap",
        help="Nmap executable path or name on PATH",
    )
    parser.add_argument(
        "--no-follow-up",
        action="store_true",
        help="Only run the initial scan and report parsed services",
    )
    parser.add_argument(
        "--no-udp",
        action="store_true",
        help="Do not run the small UDP companion scan",
    )
    parser.add_argument(
        "--udp-ports",
        default=udp_default_ports_text(),
        help="UDP ports for the companion UDP scan",
    )
    parser.add_argument(
        "--no-service-version",
        action="store_true",
        help="Do not add default -sV --version-light flags",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned Nmap commands without executing them",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except PortWeftError as error:
        from portweft.utils import print_error

        print_error(str(error))
        return error.exit_code


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if not effective_argv:
        parser.print_help()
        return 0

    parsed, unknown_nmap_args = parser.parse_known_args(effective_argv)
    if parsed.keep_runs < 0:
        parser.error("--keep-runs must be zero or greater.")
    if parsed.max_script_output_chars < 0:
        parser.error("--max-script-output-chars must be zero or greater.")
    ensure_nmap_available(parsed.nmap_path, parsed.dry_run)
    extra_nmap_args = split_nmap_args(parsed.nmap_args) + normalize_unknown_nmap_args(
        unknown_nmap_args
    )
    validate_nmap_passthrough(extra_nmap_args)

    targets = split_targets(parsed.targets)
    if not targets:
        parser.error("At least one target is required.")

    run_id = now_slug()
    output_root = Path(parsed.output_dir)
    scan_dir = output_root / "scans" / run_id
    report_dir = output_root / "reports"

    initial_xml = scan_dir / "initial.xml"
    udp_xml = scan_dir / "udp.xml"
    report_path = report_dir / f"{run_id}.txt"

    print_step(f"{APP_NAME} run {run_id} starting")
    print_step(f"Targets: {', '.join(targets)}")

    if not parsed.dry_run:
        prepare_output_dirs(scan_dir, report_dir)

    initial_command = build_initial_command(parsed, targets, initial_xml, extra_nmap_args)
    print_step("Initial Nmap scan starting")
    initial_result = run_command(initial_command, parsed.dry_run)
    if not initial_result.ok:
        return initial_result.exit_code
    print_section_done("Initial Nmap scan", f"XML saved to {initial_xml}")

    udp_result = None
    if parsed.no_udp:
        print_section_done("UDP companion scan", "skipped by --no-udp")
    else:
        udp_command = build_udp_command(parsed, targets, udp_xml, extra_nmap_args)
        print_step("UDP companion scan starting")
        udp_result = run_command(udp_command, parsed.dry_run)
        if udp_result.ok:
            print_section_done("UDP companion scan", f"XML saved to {udp_xml}")
        else:
            print_step("UDP companion scan failed; continuing with available TCP results")

    if parsed.dry_run:
        print_section_done("Dry run", "no files written")
        return 0

    print_step(f"Parsing initial XML: {initial_xml}")
    hosts = parse_nmap_xml(initial_xml, parsed.max_script_output_chars)
    print_section_done("Initial XML parse")

    if udp_result is not None and udp_result.ok:
        print_step(f"Parsing UDP XML: {udp_xml}")
        try:
            merge_hosts(hosts, parse_nmap_xml(udp_xml, parsed.max_script_output_chars))
        except PortWeftError as error:
            from portweft.utils import print_error

            print_error(str(error))
            print_step("UDP XML parse failed; continuing with TCP results")
        else:
            print_section_done("UDP XML parse")

    announce_host_findings(hosts)

    open_services = [service for host in hosts for service in host.services]
    print_step(f"Observed {len(hosts)} host(s) and {len(open_services)} open service(s)")

    if parsed.no_follow_up:
        print_section_done("Follow-up scans", "skipped by --no-follow-up")
    else:
        run_followups(parsed, extra_nmap_args, scan_dir, hosts, open_services)

    print_step(f"Writing report: {report_path}")
    write_report(report_path, targets, initial_xml, hosts)
    print_section_done("Report writing", str(report_path))
    prune_old_runs(output_root, parsed.keep_runs)
    print_section_done(f"{APP_NAME} run")
    return 0


def prepare_output_dirs(scan_dir: Path, report_dir: Path) -> None:
    try:
        scan_dir.mkdir(parents=True, exist_ok=True)
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OutputDirectoryError(str(scan_dir.parent.parent), str(error)) from error


def announce_host_findings(hosts: list[HostObservation]) -> None:
    for host in hosts:
        print_host_os(host)
        print_open_services(host)


def run_followups(
    parsed: argparse.Namespace,
    extra_nmap_args: list[str],
    scan_dir: Path,
    hosts: list[HostObservation],
    open_services: list[ServiceObservation],
) -> None:
    groups: dict[tuple[str, str, str], list[ServiceObservation]] = defaultdict(list)
    for service in open_services:
        profiles = match_profiles(service)
        if not profiles:
            print_unmatched_service(service)
            continue
        for profile in profiles:
            groups[(service.host, service.protocol.lower(), profile)].append(service)

    for host, protocol, profile in sorted(groups):
        services = groups[(host, protocol, profile)]
        ports = sorted({service.port for service in services})
        port_text = ",".join(str(port) for port in ports)
        followup_xml = scan_dir / f"{safe_name(host)}_{protocol}_{profile}.xml"
        print_step(f"Follow-up profile {profile} starting for {host}:{port_text}/{protocol}")
        command = build_followup_batch_command(
            parsed,
            host,
            protocol,
            ports,
            profile,
            followup_xml,
            extra_nmap_args,
        )
        followup_result = run_command(command, parsed.dry_run)
        if not followup_result.ok:
            print_step(f"Follow-up profile failed: {profile} {host}:{port_text}/{protocol}")
            continue
        try:
            update_hosts = parse_nmap_xml(followup_xml, parsed.max_script_output_chars)
        except PortWeftError as error:
            from portweft.utils import print_error

            print_error(str(error))
            print_step(
                f"Follow-up profile parse failed: {profile} "
                f"{host}:{port_text}/{protocol}"
            )
            continue
        print_followup_findings(profile, update_hosts)
        announce_new_os_findings(hosts, update_hosts)
        merge_hosts(hosts, update_hosts)
        print_section_done(
            f"Follow-up profile {profile}",
            f"{host}:{port_text}/{protocol}",
        )
    print_section_done("Follow-up scans")


def print_unmatched_service(service: ServiceObservation) -> None:
    if has_observable_evidence(service):
        print_step(
            "Service evidence observed but no follow-up profile matched: "
            f"{service.host}:{service.port}/{service.protocol} -> "
            f"{evidence_summary(service)}"
        )
        return
    print_step(f"No follow-up profile for {service.host}:{service.port}")


def announce_new_os_findings(
    existing_hosts: list[HostObservation],
    update_hosts: list[HostObservation],
) -> None:
    existing_by_address = {host.address: host for host in existing_hosts}
    for update_host in update_hosts:
        existing_host = existing_by_address.get(update_host.address)
        existing_unknown = existing_host is None or existing_host.os_label() == "unknown"
        if update_host.os_label() != "unknown" and existing_unknown:
            print_host_os(update_host)


def prune_old_runs(output_root: Path, keep_runs: int) -> None:
    if keep_runs <= 0:
        return

    scan_root = output_root / "scans"
    report_root = output_root / "reports"
    run_ids = set()
    if scan_root.exists():
        run_ids.update(path.name for path in scan_root.iterdir() if path.is_dir())
    if report_root.exists():
        run_ids.update(path.stem for path in report_root.glob("*.txt"))

    stale_run_ids = sorted(run_ids, reverse=True)[keep_runs:]
    removed = 0
    for run_id in stale_run_ids:
        scan_path = scan_root / run_id
        report_path = report_root / f"{run_id}.txt"
        try:
            if scan_path.exists():
                shutil.rmtree(scan_path)
                removed += 1
            if report_path.exists():
                report_path.unlink()
                removed += 1
        except OSError as error:
            raise OutputDirectoryError(str(output_root), str(error)) from error

    if removed:
        print_section_done("Output retention", f"removed {removed} old item(s)")
