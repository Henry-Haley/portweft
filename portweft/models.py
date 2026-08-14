"""Data models for normalized scan observations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DiscoveryResult:
    backend: str
    open_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    status: str = "completed"
    exit_code: int = 0


@dataclass(slots=True)
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    matcher_name: str = ""
    protocol: str = ""
    host: str = ""
    port: int | None = None
    reference: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ServiceObservation:
    host: str
    port: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    def label(self) -> str:
        pieces = [self.service_name, self.product, self.version, self.extrainfo]
        return " ".join(piece for piece in pieces if piece).strip() or "unknown"


@dataclass(slots=True)
class HostObservation:
    address: str
    hostname: str = ""
    original_target: str = ""
    resolved_ip: str = ""
    status: str = ""
    os_family: str = "unknown"
    os_name: str = ""
    os_accuracy: str = ""
    os_source: str = "unknown"
    services: list[ServiceObservation] = field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = field(default_factory=list)

    def display_name(self) -> str:
        address_label = self.address
        if self.original_target and self.original_target != self.address:
            address_label = f"{self.original_target} -> {self.address}"
        if self.hostname:
            return f"{address_label} ({self.hostname})"
        return address_label

    def os_label(self) -> str:
        if self.os_name:
            label = self.os_name
            if self.os_accuracy:
                label = f"{label} ({self.os_accuracy}% accuracy)"
            return label
        if self.os_family != "unknown":
            if self.os_source == "service-inference":
                return f"{self.os_family} (inferred from open ports)"
            return self.os_family
        return "unknown"
