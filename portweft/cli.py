"""Command-line interface and top-level PortWeft workflow."""

from __future__ import annotations

import argparse
from collections import defaultdict
import datetime as dt
import ipaddress
import shlex
import shutil
import sys
from pathlib import Path

from portweft import APP_NAME
from portweft.errors import (
    ImpacketUnavailableError,
    NmapArgumentStringError,
    OutputDirectoryError,
    PortSpecError,
    PortWeftError,
    TargetResolutionError,
)
from portweft.discovery_runner import (
    hosts_from_discovery,
    is_single_host,
    run_discovery,
    select_discovery_backend,
)
from portweft.impacket_runner import (
    DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
    ImpacketAvailability,
    ensure_impacket_package,
    module_supports_service,
    modules_for_profile,
    run_impacket_module,
)
from portweft.matcher import evidence_summary, has_observable_evidence, match_profiles
from portweft.models import HostObservation, ServiceObservation
from portweft.nmap_runner import (
    build_detailed_command,
    build_followup_batch_command,
    build_initial_command,
    build_udp_command,
    default_udp_ports_for_tcp_ports,
    ensure_nmap_available,
    normalize_unknown_nmap_args,
    parse_port_spec,
    run_command,
    split_nmap_args,
    udp_default_ports_text,
    validate_nmap_passthrough,
)
from portweft.nuclei_runner import ensure_nuclei_available, run_nuclei
from portweft.nmap_xml import (
    DEFAULT_MAX_SCRIPT_OUTPUT_CHARS,
    merge_hosts,
    parse_nmap_xml,
)
from portweft.reporting import write_json_reports, write_reports
from portweft.targets import (
    TargetResolution,
    annotate_hosts_with_targets,
    has_ipv6_target,
    original_targets,
    resolve_targets,
    scan_targets,
)
from portweft.utils import (
    print_error,
    print_followup_findings,
    print_host_os,
    print_open_services,
    print_section_done,
    print_step,
    safe_name,
    split_targets,
)


DEFAULT_TOP_PORTS = 1000
DEFAULT_SCAN_TIMEOUT_SECONDS = 1800.0
DEFAULT_MAX_SCAN_TARGETS = 4096
PORTWEFT_BANNER = r"""
   ____             __ _       __     ______
  / __ \____  _____/ /| |     / /__  / __/ /_
 / /_/ / __ \/ ___/ __/ | /| / / _ \/ /_/ __/
/ ____/ /_/ / /  / /_ | |/ |/ /  __/ __/ /_
/_/    \____/_/   \__/ |__/|__/\___/_/  \__/

+--------------------------------+
|        P O R T W E F T         |
|     weaving connections...      |
+--------------------------------+
""".strip("\n")
PORTWEFT_OPTIONS = {
    "-h",
    "--help",
    "-p",
    "--ports",
    "--top-ports",
    "--nmap-args",
    "--output-dir",
    "--json",
    "--resolve-mode",
    "--keep-runs",
    "--max-script-output-chars",
    "--impacket",
    "--nuclei",
    "--full",
    "--max-impacket-output-chars",
    "--nmap-path",
    "--no-follow-up",
    "--no-udp",
    "--udp-ports",
    "--no-service-version",
    "--dry-run",
    "--discovery",
    "--discovery-backend",
    "--rustscan-path",
    "--masscan-path",
    "--masscan-rate",
    "--nuclei-path",
    "--stats-every",
    "--scan-timeout",
    "--max-scan-targets",
    "--allow-large-scan",
}
PORTWEFT_OPTIONS_WITH_VALUES = {
    "-p",
    "--ports",
    "--top-ports",
    "--output-dir",
    "--resolve-mode",
    "--keep-runs",
    "--max-script-output-chars",
    "--max-impacket-output-chars",
    "--nmap-path",
    "--udp-ports",
    "--nmap-args",
    "--scan-timeout",
    "--max-scan-targets",
    "--discovery-backend",
    "--rustscan-path",
    "--masscan-path",
    "--masscan-rate",
    "--nuclei-path",
    "--stats-every",
}
NMAP_OPTIONS_WITH_VALUES = {
    "-D",
    "-S",
    "-e",
    "-g",
    "-iL",
    "-oA",
    "-oG",
    "-oN",
    "-oS",
    "-oX",
    "-p",
    "-T",
    "--data-length",
    "--dns-servers",
    "--exclude",
    "--excludefile",
    "--host-timeout",
    "--initial-rtt-timeout",
    "--max-hostgroup",
    "--max-parallelism",
    "--max-rate",
    "--max-retries",
    "--max-rtt-timeout",
    "--max-scan-delay",
    "--min-hostgroup",
    "--min-parallelism",
    "--min-rate",
    "--min-rtt-timeout",
    "--scan-delay",
    "--scanflags",
    "--script",
    "--script-args",
    "--source-port",
    "--spoof-mac",
    "--top-ports",
    "--ttl",
    "--version-intensity",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portweft",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"{PORTWEFT_BANNER}\n\n"
            "Run focused opening recon, consolidate observed facts, and stop "
            "before exploitation. Authorized use only."
        ),
        epilog=(
            "Use PortWeft only on systems you own, administer, or have explicit "
            "permission to test."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("targets", help="IP, domain, comma-separated targets, or CIDR range")
    parser.add_argument("-p", "--ports", help="Ports for the initial scan")
    parser.add_argument(
        "--top-ports",
        nargs="?",
        const=DEFAULT_TOP_PORTS,
        type=positive_int,
        help=f"Nmap --top-ports value; default is {DEFAULT_TOP_PORTS} when omitted",
    )
    parser.add_argument(
        "--nmap-args",
        default="",
        help=(
            "Quoted Nmap argument string to pass through; raw Nmap flags can also "
            "be placed directly in the command"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory for temporary scanner output and saved reports",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the STDOUT and saved reports as JSON",
    )
    parser.add_argument(
        "--resolve-mode",
        choices=("first", "all"),
        default="first",
        help="For domains with multiple DNS answers, scan the first IP or all IPs",
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
        "--impacket",
        action="store_true",
        help="Run optional low-noise Impacket recon modules for matched services",
    )
    parser.add_argument(
        "--max-impacket-output-chars",
        type=int,
        default=DEFAULT_MAX_IMPACKET_OUTPUT_CHARS,
        help="Maximum Impacket output characters retained per module",
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
        help="Print planned stages to STDERR without scanning or writing files",
    )
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help="Run CVE-tagged Nuclei validation against observed TCP services",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enable --discovery, --impacket, and --nuclei",
    )
    parser.add_argument(
        "--discovery",
        action="store_true",
        help="Discover all open TCP ports before per-host service enumeration",
    )
    parser.add_argument(
        "--discovery-backend",
        choices=("auto", "nmap", "rustscan", "masscan"),
        default="auto",
        help="TCP discovery backend (default: auto)",
    )
    parser.add_argument(
        "--rustscan-path",
        default="rustscan",
        help="RustScan executable path or name on PATH",
    )
    parser.add_argument(
        "--masscan-path",
        default="masscan",
        help="Masscan executable path or name on PATH",
    )
    parser.add_argument(
        "--masscan-rate",
        type=positive_int,
        default=1000,
        help="Masscan packets per second (default: 1000)",
    )
    parser.add_argument(
        "--nuclei-path",
        default="nuclei",
        help="Nuclei executable path or name on PATH",
    )
    parser.add_argument(
        "--stats-every",
        type=nonnegative_float,
        default=5.0,
        help="Heartbeat interval in seconds; 0 disables it (default: 5)",
    )
    parser.add_argument(
        "--scan-timeout",
        type=nonnegative_float,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=(
            "Maximum seconds per external scanner command; 0 disables the PortWeft "
            f"timeout (default: {int(DEFAULT_SCAN_TIMEOUT_SECONDS)})"
        ),
    )
    parser.add_argument(
        "--max-scan-targets",
        type=positive_int,
        default=DEFAULT_MAX_SCAN_TARGETS,
        help=(
            "Maximum estimated targets allowed without --allow-large-scan "
            f"(default: {DEFAULT_MAX_SCAN_TARGETS})"
        ),
    )
    parser.add_argument(
        "--allow-large-scan",
        action="store_true",
        help="Allow target lists or CIDR ranges above --max-scan-targets",
    )
    return parser


def positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def nonnegative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        print_error("Interrupted by user; stopping active scan.")
        return 130
    except PortWeftError as error:
        print_error(str(error))
        return error.exit_code


def extract_raw_nmap_args(argv: list[str]) -> tuple[list[str], list[str]]:
    """Move known raw Nmap flags out before target parsing."""
    cleaned: list[str] = []
    extracted: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            extracted.extend(argv[index + 1 :])
            break
        if token == "--nmap-args":
            nmap_args, next_index = consume_nmap_args(argv, index + 1)
            if nmap_args:
                cleaned.append(f"--nmap-args={shlex.join(nmap_args)}")
                index = next_index
                continue
            if index + 1 < len(argv):
                cleaned.append(f"--nmap-args={argv[index + 1]}")
                index += 2
                continue
            cleaned.append(token)
            index += 1
            continue
        if is_portweft_option(token) or is_portweft_attached_option(token):
            cleaned.append(token)
            if (
                portweft_option_expects_value(token)
                and index + 1 < len(argv)
                and not is_portweft_option(argv[index + 1])
            ):
                cleaned.append(argv[index + 1])
                index += 2
                continue
            index += 1
            continue
        if token.startswith("-"):
            extracted.append(token)
            if nmap_option_expects_value(token) and index + 1 < len(argv):
                extracted.append(argv[index + 1])
                index += 2
                continue
            index += 1
            continue
        cleaned.append(token)
        index += 1
    return cleaned, extracted


def consume_nmap_args(argv: list[str], start_index: int) -> tuple[list[str], int]:
    consumed: list[str] = []
    index = start_index
    expecting_value = False
    while index < len(argv):
        token = argv[index]
        if is_portweft_option(token):
            break
        if not token.startswith("-") and not expecting_value:
            break
        consumed.append(token)
        expecting_value = nmap_option_expects_value(token)
        index += 1
    return consumed, index


def is_portweft_option(token: str) -> bool:
    option = token.split("=", 1)[0]
    return option in PORTWEFT_OPTIONS


def is_portweft_attached_option(token: str) -> bool:
    return token.startswith("-p") and token != "-p"


def portweft_option_expects_value(token: str) -> bool:
    if "=" in token or is_portweft_attached_option(token):
        return False
    return token in PORTWEFT_OPTIONS_WITH_VALUES


def nmap_option_expects_value(token: str) -> bool:
    if "=" in token:
        return False
    return token in NMAP_OPTIONS_WITH_VALUES


def normalize_top_ports_flag(argv: list[str]) -> list[str]:
    normalized: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        normalized.append(token)
        if token == "--top-ports":
            next_token = argv[index + 1] if index + 1 < len(argv) else None
            if next_token is None or not is_int(next_token):
                normalized.append(str(DEFAULT_TOP_PORTS))
        index += 1
    return normalized


def is_int(value: str) -> bool:
    try:
        int(value, 10)
    except ValueError:
        return False
    return True


def option_was_supplied(argv: list[str], option: str) -> bool:
    return any(token == option or token.startswith(f"{option}=") for token in argv)


def validate_managed_port_specs(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
) -> None:
    for option, value in (
        ("-p/--ports", parsed.ports),
        ("--udp-ports", parsed.udp_ports),
    ):
        if not value:
            continue
        try:
            parse_port_spec(value)
        except PortSpecError as error:
            parser.error(f"{option}: {error}")


def configure_udp_companion(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
    udp_ports_explicit: bool,
) -> str:
    if parsed.no_udp:
        return "skipped by --no-udp"
    if udp_ports_explicit or not parsed.ports:
        return ""

    try:
        udp_ports = default_udp_ports_for_tcp_ports(parsed.ports)
    except PortSpecError as error:
        parser.error(f"-p/--ports: {error}")
    if not udp_ports:
        return "skipped because -p/--ports did not include default UDP companion ports"
    parsed.udp_ports = udp_ports
    return ""


def validate_flag_conflicts(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
    argv: list[str],
) -> None:
    if parsed.full and parsed.no_follow_up:
        parser.error(
            "--full requires service-aware follow-ups; remove --no-follow-up or "
            "use explicit stage flags instead."
        )
    if parsed.ports and parsed.top_ports:
        parser.error("Use either -p/--ports or --top-ports, not both.")
    if parsed.discovery and (parsed.ports or parsed.top_ports):
        parser.error("Use --discovery without -p/--ports or --top-ports.")
    if parsed.no_udp and option_was_supplied(argv, "--udp-ports"):
        parser.error("Use either --no-udp or --udp-ports, not both.")


def apply_full_profile(parsed: argparse.Namespace) -> None:
    if not parsed.full:
        return
    parsed.discovery = True
    parsed.impacket = True
    parsed.nuclei = True


def validate_nmap_args_do_not_contain_portweft_options(args: list[str]) -> None:
    conflicts = [arg for arg in args if is_portweft_option(arg)]
    if not conflicts:
        return
    joined = ", ".join(conflicts)
    raise NmapArgumentStringError(
        "PortWeft options cannot be embedded inside --nmap-args: "
        f"{joined}. Put PortWeft options outside --nmap-args or pass raw Nmap "
        "flags directly."
    )


def enforce_target_limit(
    parser: argparse.ArgumentParser,
    targets: list[str],
    max_scan_targets: int,
    allow_large_scan: bool,
) -> None:
    estimated = estimate_target_count(targets)
    if allow_large_scan or estimated <= max_scan_targets:
        return
    parser.error(
        f"Target selection expands to about {estimated} target(s), above "
        f"--max-scan-targets {max_scan_targets}. Use --allow-large-scan to proceed."
    )


def estimate_target_count(targets: list[str]) -> int:
    total = 0
    for target in targets:
        try:
            total += ipaddress.ip_network(target, strict=False).num_addresses
        except ValueError:
            total += 1
    return total


def command_timeout(parsed: argparse.Namespace) -> float | None:
    if parsed.scan_timeout <= 0:
        return None
    return parsed.scan_timeout


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if not effective_argv:
        parser.print_help(sys.stderr)
        return 2

    effective_argv = normalize_top_ports_flag(effective_argv)
    effective_argv, raw_nmap_args = extract_raw_nmap_args(effective_argv)
    parsed, unknown_nmap_args = parser.parse_known_args(effective_argv)
    apply_full_profile(parsed)
    validate_flag_conflicts(parser, parsed, effective_argv)
    if parsed.keep_runs < 0:
        parser.error("--keep-runs must be zero or greater.")
    if parsed.max_script_output_chars < 0:
        parser.error("--max-script-output-chars must be zero or greater.")
    if parsed.max_impacket_output_chars < 0:
        parser.error("--max-impacket-output-chars must be zero or greater.")
    validate_managed_port_specs(parser, parsed)
    udp_skip_detail = configure_udp_companion(
        parser,
        parsed,
        option_was_supplied(effective_argv, "--udp-ports"),
    )
    parsed_nmap_args = split_nmap_args(parsed.nmap_args)
    validate_nmap_args_do_not_contain_portweft_options(parsed_nmap_args)
    ensure_nmap_available(parsed.nmap_path, parsed.dry_run)
    extra_nmap_args = normalize_unknown_nmap_args(
        parsed_nmap_args
        + raw_nmap_args
        + normalize_unknown_nmap_args(unknown_nmap_args)
    )
    if parsed.discovery and any(
        arg.startswith(("-p", "--top-ports")) for arg in extra_nmap_args
    ):
        parser.error("Use --discovery without -p/--ports or --top-ports.")
    validate_nmap_passthrough(extra_nmap_args)

    targets = split_targets(parsed.targets)
    if not targets:
        parser.error("At least one target is required.")
    resolutions = resolve_targets(targets, parsed.resolve_mode)
    log_resolution_failures(resolutions)
    nmap_targets = scan_targets(resolutions)
    if not nmap_targets:
        raise TargetResolutionError("No valid targets to scan after DNS resolution.")
    enforce_target_limit(
        parser,
        nmap_targets,
        parsed.max_scan_targets,
        parsed.allow_large_scan,
    )
    if has_ipv6_target(nmap_targets) and "-6" not in extra_nmap_args:
        extra_nmap_args = ["-6", *extra_nmap_args]
    report_targets = original_targets(resolutions)
    if parsed.nuclei:
        ensure_nuclei_available(parsed.nuclei_path, parsed.dry_run)
    if parsed.impacket and not parsed.no_follow_up and not parsed.dry_run:
        parsed.impacket_availability = require_impacket_package(
            parsed.max_impacket_output_chars
        )

    discovery_backend = "not requested"
    discovery_fallback = ""
    if parsed.discovery:
        discovery_backend = select_discovery_backend(
            parsed.discovery_backend,
            nmap_targets,
            parsed.rustscan_path,
            parsed.masscan_path,
            parsed.dry_run,
        )
        if parsed.discovery_backend == "auto" and discovery_backend == "nmap":
            preferred = "RustScan" if is_single_host(nmap_targets) else "Masscan"
            discovery_fallback = (
                f"{preferred} is unavailable; auto discovery falling back to Nmap"
            )

    scan_started_at = dt.datetime.now(dt.timezone.utc)
    output_root = Path(parsed.output_dir)
    run_id = unique_run_id(output_root, scan_started_at)
    scan_dir = output_root / "scans" / run_id
    report_dir = output_root / "reports" / run_id

    initial_xml = scan_dir / f"{run_id}-initial.xml"
    udp_xml = scan_dir / f"{run_id}-udp.xml"

    print(PORTWEFT_BANNER, file=sys.stderr, flush=True)
    print_step(f"{APP_NAME} run {run_id} starting")
    print_step(f"Scan started (GMT): {scan_started_at.strftime('%Y-%m-%d %H:%M:%S GMT')}")
    print_step(f"Targets: {', '.join(report_targets)}")
    print_step(f"Resolved scan targets: {', '.join(nmap_targets)}")
    if parsed.discovery:
        if discovery_fallback:
            print_step(discovery_fallback)
        print_step(f"Discovery backend: {discovery_backend}")

    if not parsed.dry_run:
        prepare_output_dirs(scan_dir, report_dir)
    timeout_seconds = command_timeout(parsed)

    discovery_result = None
    if parsed.discovery:
        discovery_output = (
            initial_xml
            if discovery_backend == "nmap"
            else scan_dir / f"{run_id}-discovery.list"
        )
        print_step(f"TCP discovery scan starting ({discovery_backend})")
        discovery_result = run_discovery(
            parsed,
            discovery_backend,
            nmap_targets,
            discovery_output,
            extra_nmap_args,
            timeout_seconds,
            run_command,
            parse_nmap_xml,
        )
        if discovery_result.exit_code:
            return discovery_result.exit_code
        if discovery_result.backend != discovery_backend:
            discovery_backend = discovery_result.backend
            print_step(f"Discovery backend changed to: {discovery_backend}")
        port_count = sum(len(ports) for ports in discovery_result.open_tcp_ports.values())
        detail = "planned" if parsed.dry_run else f"{port_count} TCP port(s)"
        print_section_done("TCP discovery scan", detail)
    else:
        initial_label = "Initial Nmap scan"
        initial_command = build_initial_command(
            parsed,
            nmap_targets,
            initial_xml,
            extra_nmap_args,
        )
        print_step(f"{initial_label} starting")
        initial_result = run_command(
            initial_command,
            parsed.dry_run,
            timeout_seconds=timeout_seconds,
            stats_every=parsed.stats_every,
            stage="initial nmap scan",
        )
        if not initial_result.ok:
            return initial_result.exit_code
        print_section_done(initial_label, f"XML saved to {initial_xml}")

    udp_result = None
    if udp_skip_detail:
        print_section_done("UDP companion scan", udp_skip_detail)
    else:
        udp_command = build_udp_command(parsed, nmap_targets, udp_xml, extra_nmap_args)
        print_step("UDP companion scan starting")
        udp_result = run_command(
            udp_command,
            parsed.dry_run,
            timeout_seconds=timeout_seconds,
            stats_every=parsed.stats_every,
            stage="UDP companion nmap scan",
        )
        if udp_result.ok:
            print_section_done("UDP companion scan", f"XML saved to {udp_xml}")
        else:
            print_step("UDP companion scan failed; continuing with available TCP results")

    if parsed.dry_run:
        if parsed.discovery:
            print_section_done(
                "Detailed service enumeration",
                "planned per host after discovery results are available",
            )
        if parsed.no_follow_up:
            print_section_done("Follow-up scans", "skipped by --no-follow-up")
        else:
            print_section_done(
                "Follow-up scans",
                "planned after service identification",
            )
        if parsed.impacket:
            print_section_done("Impacket recon", "planned after service identification")
        if parsed.nuclei:
            print_section_done("Nuclei CVE-only validation", "planned")
        print_section_done("Dry run", "no files written")
        return 0

    if discovery_result is not None:
        hosts = hosts_from_discovery(discovery_result)
    else:
        print_step(f"Parsing initial XML: {initial_xml}")
        hosts = parse_nmap_xml(initial_xml, parsed.max_script_output_chars)
    annotate_hosts_with_targets(hosts, resolutions)
    if discovery_result is None:
        print_section_done("Initial XML parse")

    if parsed.discovery:
        run_discovery_enumeration(
            parsed,
            extra_nmap_args,
            scan_dir,
            hosts,
            resolutions,
            timeout_seconds,
        )

    if udp_result is not None and udp_result.ok:
        print_step(f"Parsing UDP XML: {udp_xml}")
        try:
            udp_hosts = parse_nmap_xml(udp_xml, parsed.max_script_output_chars)
            annotate_hosts_with_targets(udp_hosts, resolutions)
            merge_hosts(hosts, udp_hosts)
        except PortWeftError as error:
            print_error(str(error))
            print_step("UDP XML parse failed; continuing with TCP results")
        else:
            print_section_done("UDP XML parse")

    announce_host_findings(hosts)

    open_services = [service for host in hosts for service in host.services]
    print_step(f"Observed {len(hosts)} host(s) and {len(open_services)} open service(s)")

    impacket_status = "not requested (--impacket not used)"
    if parsed.no_follow_up:
        print_section_done("Follow-up scans", "skipped by --no-follow-up")
        if parsed.impacket:
            print_section_done("Impacket recon", "skipped by --no-follow-up")
            impacket_status = "skipped by --no-follow-up"
    else:
        run_followups(
            parsed,
            extra_nmap_args,
            scan_dir,
            hosts,
            open_services,
            resolutions,
            timeout_seconds,
        )
        if parsed.impacket:
            impacket_status = run_impacket_recon(parsed, hosts, timeout_seconds)

    nuclei_status = "not requested (--nuclei not used)"
    if parsed.nuclei:
        print_step("Nuclei CVE-only validation starting")
        nuclei_status, finding_count = run_nuclei(
            parsed.nuclei_path,
            hosts,
            scan_dir,
            timeout_seconds,
            parsed.stats_every,
        )
        print_section_done(
            "Nuclei CVE-only validation",
            f"{finding_count} finding(s); {nuclei_status}",
        )

    discovery_status = (
        discovery_result.status if discovery_result is not None else "not requested"
    )

    print_step(f"Writing reports: {report_dir}")
    if parsed.json:
        written_reports = write_json_reports(
            report_dir,
            resolutions,
            scan_started_at,
            hosts,
            impacket_status,
            discovery_mode=parsed.discovery,
            discovery_backend=discovery_backend,
            discovery_status=discovery_status,
            nuclei_status=nuclei_status,
        )
    else:
        written_reports = write_reports(
            report_dir,
            report_targets,
            scan_started_at,
            hosts,
            impacket_status,
            discovery_mode=parsed.discovery,
            discovery_backend=discovery_backend,
            discovery_status=discovery_status,
            nuclei_status=nuclei_status,
        )
    print_section_done("Report writing", f"{len(written_reports)} file(s) in {report_dir}")
    try:
        cumulative_output = written_reports[0].read_text(encoding="utf-8")
    except OSError as error:
        raise OutputDirectoryError(str(written_reports[0]), str(error)) from error
    try:
        cleanup_scan_outputs(scan_dir)
    except OutputDirectoryError as error:
        print_error(str(error))
        print_step("Temporary XML cleanup failed; reports were kept")
    prune_old_runs(output_root, parsed.keep_runs)
    print_section_done(f"{APP_NAME} run")
    sys.stdout.write(cumulative_output)
    sys.stdout.flush()
    return 0


def prepare_output_dirs(scan_dir: Path, report_dir: Path) -> None:
    try:
        scan_dir.mkdir(parents=True, exist_ok=True)
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OutputDirectoryError(str(scan_dir.parent.parent), str(error)) from error


def unique_run_id(output_root: Path, scan_started_at: dt.datetime) -> str:
    base_run_id = scan_started_at.strftime("%Y%m%d-%H%M%S-%fZ")
    run_id = base_run_id
    suffix = 2
    while (
        (output_root / "scans" / run_id).exists()
        or (output_root / "reports" / run_id).exists()
    ):
        run_id = f"{base_run_id}-{suffix}"
        suffix += 1
    return run_id


def cleanup_scan_outputs(scan_dir: Path) -> None:
    """Remove temporary XML working files after consolidated reports are written."""
    try:
        if scan_dir.exists():
            shutil.rmtree(scan_dir)
        scan_root = scan_dir.parent
        if scan_root.exists() and not any(scan_root.iterdir()):
            scan_root.rmdir()
    except OSError as error:
        raise OutputDirectoryError(str(scan_dir), str(error)) from error


def require_impacket_package(max_output_chars: int) -> ImpacketAvailability:
    availability = ensure_impacket_package(max_output_chars)
    if availability.available:
        return availability
    raise ImpacketUnavailableError(availability.reason)


def log_resolution_failures(resolutions: list[TargetResolution]) -> None:
    for resolution in resolutions:
        if resolution.ok:
            continue
        print_error(f"DNS resolution failed for {resolution.original}: {resolution.error}")
        print_error(f"Skipping target: {resolution.original}")


def announce_host_findings(hosts: list[HostObservation]) -> None:
    for host in hosts:
        print_host_os(host)
        print_open_services(host)


def run_discovery_enumeration(
    parsed: argparse.Namespace,
    extra_nmap_args: list[str],
    scan_dir: Path,
    hosts: list[HostObservation],
    resolutions: list[TargetResolution],
    timeout_seconds: float | None = None,
) -> None:
    for host in list(hosts):
        ports = sorted(
            {
                service.port
                for service in host.services
                if service.protocol.lower() == "tcp"
            }
        )
        if not ports:
            print_section_done(
                "Detailed service enumeration",
                f"skipped for {host.address}; no open TCP ports",
            )
            continue

        port_text = ",".join(str(port) for port in ports)
        xml_path = scan_dir / f"{scan_dir.name}-{safe_name(host.address)}-detailed.xml"
        print_step(f"Detailed service enumeration starting for {host.address}:{port_text}/tcp")
        result = run_command(
            build_detailed_command(
                parsed,
                host.address,
                ports,
                xml_path,
                extra_nmap_args,
            ),
            parsed.dry_run,
            timeout_seconds=timeout_seconds,
            stats_every=parsed.stats_every,
            stage=f"nmap enumeration {host.address}:{port_text}",
        )
        if not result.ok:
            print_step(
                f"Detailed service enumeration failed for {host.address}; "
                "continuing with other hosts"
            )
            continue
        try:
            update_hosts = parse_nmap_xml(xml_path, parsed.max_script_output_chars)
            annotate_hosts_with_targets(update_hosts, resolutions)
        except PortWeftError as error:
            print_error(str(error))
            print_step(
                f"Detailed service enumeration parse failed for {host.address}; "
                "continuing with other hosts"
            )
            continue
        merge_hosts(hosts, update_hosts)
        print_section_done(
            "Detailed service enumeration",
            f"{host.address}:{port_text}/tcp",
        )
    print_section_done("Detailed service enumeration")


def run_followups(
    parsed: argparse.Namespace,
    extra_nmap_args: list[str],
    scan_dir: Path,
    hosts: list[HostObservation],
    open_services: list[ServiceObservation],
    resolutions: list[TargetResolution],
    timeout_seconds: float | None = None,
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
        run_id = scan_dir.name
        followup_xml = scan_dir / f"{run_id}-{safe_name(host)}-{protocol}-{profile}.xml"
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
        followup_result = run_command(
            command,
            parsed.dry_run,
            timeout_seconds=timeout_seconds,
            stats_every=parsed.stats_every,
            stage=f"nmap follow-up {profile} {host}:{port_text}/{protocol}",
        )
        if not followup_result.ok:
            print_step(f"Follow-up profile failed: {profile} {host}:{port_text}/{protocol}")
            continue
        try:
            update_hosts = parse_nmap_xml(followup_xml, parsed.max_script_output_chars)
            annotate_hosts_with_targets(update_hosts, resolutions)
        except PortWeftError as error:
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


def run_impacket_recon(
    parsed: argparse.Namespace,
    hosts: list[HostObservation],
    timeout_seconds: float | None = None,
) -> str:
    availability = getattr(parsed, "impacket_availability", None)
    if availability is None:
        availability = require_impacket_package(parsed.max_impacket_output_chars)
    if availability.version:
        print_step(f"Impacket package imported: {availability.version}")
    else:
        print_step("Impacket package imported")

    planned: list[tuple[ServiceObservation, str]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for host in hosts:
        for service in host.services:
            for profile in match_profiles(service):
                for module_name in modules_for_profile(profile):
                    key = (
                        service.host,
                        service.protocol.lower(),
                        service.port,
                        module_name,
                    )
                    if key in seen or not module_supports_service(module_name, service):
                        continue
                    seen.add(key)
                    planned.append((service, module_name))

    if not planned:
        print_section_done("Impacket recon", "no matching recon modules")
        return "completed: no matching recon modules"

    print_step(f"Impacket recon starting ({len(planned)} module run(s))")
    for service, module_name in planned:
        target = f"{service.host}:{service.port}/{service.protocol}"
        print_step(f"Impacket {module_name} starting for {target}")
        runner_options = {}
        if stats_every := getattr(parsed, "stats_every", 0):
            runner_options["stats_every"] = stats_every
        result = run_impacket_module(
            module_name,
            service,
            parsed.max_impacket_output_chars,
            timeout_seconds,
            **runner_options,
        )
        if result.skipped:
            print_step(f"Impacket {module_name} skipped for {target}: {result.reason}")
            continue
        if not result.ok:
            print_step(f"Impacket {module_name} failed for {target}; continuing")
            continue
        if result.output:
            service.scripts[f"impacket-{module_name}"] = result.output
        print_section_done(f"Impacket {module_name}", target)

    print_section_done("Impacket recon")
    return "completed"


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
        for path in report_root.iterdir():
            if path.is_dir():
                run_ids.add(path.name)
            elif path.suffix == ".txt":
                run_ids.add(path.stem)

    stale_run_ids = sorted(run_ids, reverse=True)[keep_runs:]
    removed = 0
    for run_id in stale_run_ids:
        scan_path = scan_root / run_id
        report_dir = report_root / run_id
        report_path = report_root / f"{run_id}.txt"
        try:
            if scan_path.exists():
                shutil.rmtree(scan_path)
                removed += 1
            if report_dir.exists():
                shutil.rmtree(report_dir)
                removed += 1
            if report_path.exists():
                report_path.unlink()
                removed += 1
        except OSError as error:
            raise OutputDirectoryError(str(output_root), str(error)) from error

    if removed:
        print_section_done("Output retention", f"removed {removed} old item(s)")
