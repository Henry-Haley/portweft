"""Service-to-profile matching."""

from __future__ import annotations

from portweft.models import ServiceObservation
from portweft.profiles import SERVICE_PROFILES


LOW_VALUE_EVIDENCE = {"", "unknown", "unknown service"}


def match_profiles(service: ServiceObservation) -> list[str]:
    banner_matches: list[str] = []
    port_matches: list[str] = []
    service_name = service.service_name.lower()
    tunnel = service.tunnel.lower()
    evidence = service_evidence(service)

    for profile_name, profile in SERVICE_PROFILES.items():
        ports = profile_set(profile, "ports")
        udp_ports = profile_set(profile, "udp_ports")
        services = profile_set(profile, "services")
        banner_terms = profile_set(profile, "banner_terms")

        if (
            service_name in services
            or has_banner_term(evidence, banner_terms)
            or (tunnel == "ssl" and profile_name == "tls")
        ):
            banner_matches.append(profile_name)
        elif service.port in ports or (
            service.protocol.lower() == "udp" and service.port in udp_ports
        ):
            port_matches.append(profile_name)

    if banner_matches:
        return banner_matches
    return port_matches


def profile_set(profile: dict[str, object], key: str) -> set:
    value = profile.get(key, set())
    if isinstance(value, set):
        return value
    if isinstance(value, (list, tuple)):
        return set(value)
    return set()


def service_evidence(service: ServiceObservation) -> str:
    pieces = [
        service.service_name,
        service.product,
        service.version,
        service.extrainfo,
        service.tunnel,
        *service.scripts.keys(),
        *service.scripts.values(),
    ]
    return " ".join(piece for piece in pieces if piece).lower()


def has_observable_evidence(service: ServiceObservation) -> bool:
    return bool(evidence_parts(service))


def evidence_summary(service: ServiceObservation, limit: int = 140) -> str:
    summary = " | ".join(evidence_parts(service))
    if len(summary) <= limit:
        return summary
    return f"{summary[: limit - 3]}..."


def evidence_parts(service: ServiceObservation) -> list[str]:
    pieces = [
        service.service_name,
        service.product,
        service.version,
        service.extrainfo,
        service.tunnel,
        *service.scripts.keys(),
        *service.scripts.values(),
    ]
    return [
        piece.strip()
        for piece in pieces
        if piece and piece.strip().lower() not in LOW_VALUE_EVIDENCE
    ]


def has_banner_term(evidence: str, banner_terms: set[str]) -> bool:
    return any(term in evidence for term in banner_terms)
