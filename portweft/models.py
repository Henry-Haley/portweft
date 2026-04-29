"""Data models for parsed Nmap observations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
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


@dataclass
class HostObservation:
    address: str
    hostname: str = ""
    status: str = ""
    os_family: str = "unknown"
    os_name: str = ""
    os_accuracy: str = ""
    os_source: str = "unknown"
    services: list[ServiceObservation] = field(default_factory=list)

    def display_name(self) -> str:
        if self.hostname:
            return f"{self.address} ({self.hostname})"
        return self.address

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
