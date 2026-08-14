"""Optional CVE-only Nuclei target construction, execution, and parsing."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from portweft.discovery_runner import (
    ExternalResult,
    resolve_executable,
    run_external_command,
)
from portweft.errors import NucleiNotFoundError
from portweft.matcher import match_profiles
from portweft.models import HostObservation, NucleiFinding, ServiceObservation
from portweft.profiles import SERVICE_PROFILES
from portweft.utils import print_error


def ensure_nuclei_available(path: str, dry_run: bool = False) -> None:
    if dry_run or resolve_executable(path):
        return
    raise NucleiNotFoundError(path)


def build_nuclei_targets(hosts: list[HostObservation]) -> list[str]:
    targets = {
        target
        for host in hosts
        for service in host.services
        if (target := target_for_service(service))
    }
    return sorted(targets)


def target_for_service(service: ServiceObservation) -> str:
    if service.protocol.lower() != "tcp":
        return ""
    host = bracket_ipv6(service.host)
    profiles = set(match_profiles(service))
    name = service.service_name.lower()
    is_web = bool(
        profiles & {"web", "winrm", "elasticsearch", "docker", "kubernetes"}
    ) or "http" in name
    if is_web:
        secure = (
            service.tunnel.lower() == "ssl"
            or name in {"https", "ssl/http"}
            or name.startswith("https-")
            or "tls" in profiles
            or service.port in SERVICE_PROFILES["tls"]["ports"]
        )
        scheme = "https" if secure else "http"
        return f"{scheme}://{host}:{service.port}"
    return f"{host}:{service.port}"


def bracket_ipv6(host: str) -> str:
    candidate = host.strip("[]")
    try:
        if ipaddress.ip_address(candidate).version == 6:
            return f"[{candidate}]"
    except ValueError:
        pass
    return host


def build_nuclei_command(
    path: str,
    target_path: Path,
    output_path: Path,
) -> list[str]:
    return [
        resolve_executable(path) or path,
        "-l",
        str(target_path),
        "-tags",
        "cve",
        "-jsonl",
        "-silent",
        "-nc",
        "-omit-raw",
        "-omit-template",
        "-o",
        str(output_path),
    ]


def parse_nuclei_jsonl(output: str) -> list[NucleiFinding]:
    return parse_nuclei_lines(output.splitlines())


def parse_nuclei_lines(lines: Iterable[str]) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    seen: set[tuple[str, int | None, str, str]] = set()
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        finding = finding_from_json(item)
        key = (
            finding.host,
            finding.port,
            finding.template_id,
            finding.matched_at,
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings


def finding_from_json(item: dict) -> NucleiFinding:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    matched_at = text_value(item.get("matched-at") or item.get("matched_at"))
    reported_host = text_value(item.get("host") or item.get("ip"))
    endpoint_host, endpoint_port = extract_endpoint(reported_host or matched_at)
    port = parse_port(item.get("port")) or endpoint_port
    references = info.get("reference", [])
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        references = []
    return NucleiFinding(
        template_id=text_value(item.get("template-id") or item.get("template_id")),
        name=text_value(info.get("name")),
        severity=text_value(info.get("severity") or "unknown").lower(),
        matched_at=matched_at,
        matcher_name=text_value(item.get("matcher-name") or item.get("matcher_name")),
        protocol=text_value(item.get("type") or item.get("protocol")),
        host=endpoint_host,
        port=port,
        reference=[text_value(reference) for reference in references if reference],
    )


def text_value(value: object) -> str:
    return "" if value is None else str(value)


def parse_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def extract_endpoint(value: str) -> tuple[str, int | None]:
    if not value:
        return "", None
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return value.strip("[]"), None
    if port is None and "://" in value:
        if parsed.scheme == "http":
            port = 80
        elif parsed.scheme == "https":
            port = 443
    return host, port


def attach_nuclei_findings(
    hosts: list[HostObservation],
    findings: list[NucleiFinding],
) -> None:
    for finding in findings:
        matched_host = matching_host(hosts, finding)
        if matched_host is not None:
            matched_host.nuclei_findings.append(finding)


def matching_host(
    hosts: list[HostObservation],
    finding: NucleiFinding,
) -> HostObservation | None:
    for host in hosts:
        identities = {
            host.address.strip("[]").lower(),
            host.resolved_ip.strip("[]").lower(),
            host.hostname.lower(),
        }
        identities.discard("")
        if finding.host.strip("[]").lower() in identities:
            return host
    if len(hosts) == 1:
        return hosts[0]
    return None


def run_nuclei(
    path: str,
    hosts: list[HostObservation],
    scan_dir: Path,
    timeout_seconds: float | None,
    stats_every: float,
) -> tuple[str, int]:
    targets = build_nuclei_targets(hosts)
    if not targets:
        return "completed: no eligible TCP service targets", 0

    target_path = scan_dir / f"{scan_dir.name}-nuclei-targets.txt"
    output_path = scan_dir / f"{scan_dir.name}-nuclei.jsonl"
    try:
        target_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    except OSError as error:
        print_error(f"Could not prepare Nuclei targets: {error}")
        return "partial failure: target file could not be written", 0

    interrupted = False
    try:
        result = run_external_command(
            build_nuclei_command(path, target_path, output_path),
            timeout_seconds,
            stats_every,
            "nuclei CVE validation",
        )
    except OSError as error:
        raise NucleiNotFoundError(path) from error
    except KeyboardInterrupt:
        interrupted = True
        result = ExternalResult(exit_code=130)
    output_missing = False
    try:
        with output_path.open(encoding="utf-8", errors="replace") as output:
            findings = parse_nuclei_lines(output)
    except FileNotFoundError:
        findings = []
        output_missing = True
    except OSError as error:
        print_error(f"Could not read Nuclei JSONL output: {error}")
        findings = []
    attach_nuclei_findings(hosts, findings)
    if result.ok:
        if output_missing:
            print_error("Nuclei completed without producing a JSONL output file.")
            return "partial failure: output unavailable", len(findings)
        return "completed", len(findings)

    if interrupted:
        print_error("Nuclei was interrupted; continuing with completed scan results.")
        return "partial failure: interrupted", len(findings)
    detail = (result.stderr or result.stdout).strip()
    print_error(f"Nuclei returned a non-zero exit code ({result.exit_code}); continuing.")
    if detail:
        print_error(detail)
    if result.exit_code == 124:
        return "partial failure: timed out", len(findings)
    return f"partial failure: exit code {result.exit_code}", len(findings)
