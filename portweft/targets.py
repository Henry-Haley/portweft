"""Target parsing and DNS resolution."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket

from portweft.models import HostObservation


ResolveMode = str


@dataclass(frozen=True, slots=True)
class TargetResolution:
    original: str
    addresses: tuple[str, ...] = ()
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.addresses)


def resolve_targets(
    targets: list[str],
    mode: ResolveMode = "first",
) -> list[TargetResolution]:
    return [resolve_target(target, mode) for target in targets]


def resolve_target(target: str, mode: ResolveMode = "first") -> TargetResolution:
    if is_ip_or_network(target):
        return TargetResolution(original=target, addresses=(target,))
    if looks_like_invalid_ip_or_network(target):
        return TargetResolution(original=target, error="invalid IP address or network")

    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as error:
        return TargetResolution(original=target, error=str(error))

    addresses = unique_addresses(infos)
    if mode == "first":
        addresses = addresses[:1]
    if not addresses:
        return TargetResolution(original=target, error="no addresses returned")
    return TargetResolution(original=target, addresses=tuple(addresses))


def is_ip_or_network(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def looks_like_invalid_ip_or_network(value: str) -> bool:
    candidate = value.split("/", 1)[0]
    if ":" in candidate:
        return True
    if "." not in candidate:
        return False
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() for part in parts if part)


def unique_addresses(infos: list[tuple]) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    for family, _type, _proto, _canonname, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        if address in seen:
            continue
        seen.add(address)
        addresses.append(address)
    return addresses


def successful_resolutions(
    resolutions: list[TargetResolution],
) -> list[TargetResolution]:
    return [resolution for resolution in resolutions if resolution.ok]


def scan_targets(resolutions: list[TargetResolution]) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for resolution in successful_resolutions(resolutions):
        for address in resolution.addresses:
            if address in seen:
                continue
            seen.add(address)
            targets.append(address)
    return targets


def has_ipv6_target(targets: list[str]) -> bool:
    for target in targets:
        try:
            if ipaddress.ip_address(target).version == 6:
                return True
        except ValueError:
            pass
        try:
            if ipaddress.ip_network(target, strict=False).version == 6:
                return True
        except ValueError:
            continue
    return False


def original_targets(resolutions: list[TargetResolution]) -> list[str]:
    return [resolution.original for resolution in successful_resolutions(resolutions)]


def address_target_map(resolutions: list[TargetResolution]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for resolution in successful_resolutions(resolutions):
        for address in resolution.addresses:
            mapping.setdefault(address, resolution.original)
    return mapping


def annotate_hosts_with_targets(
    hosts: list[HostObservation],
    resolutions: list[TargetResolution],
) -> None:
    mapping = address_target_map(resolutions)
    for host in hosts:
        original = mapping.get(host.address) or containing_original_target(
            host.address, resolutions
        )
        if not original:
            continue
        host.original_target = original
        host.resolved_ip = host.address


def containing_original_target(
    address: str,
    resolutions: list[TargetResolution],
) -> str:
    """Find the original CIDR containing an observed address without expanding it."""
    try:
        observed_ip = ipaddress.ip_address(address)
    except ValueError:
        return ""

    for resolution in successful_resolutions(resolutions):
        for candidate in resolution.addresses:
            if "/" not in candidate:
                continue
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            if observed_ip.version == network.version and observed_ip in network:
                return resolution.original
    return ""
