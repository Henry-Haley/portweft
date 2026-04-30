"""Nmap XML parsing."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from portweft.errors import NmapXmlParseError
from portweft.models import HostObservation, ServiceObservation
from portweft.profiles import WEB_PORTS


DEFAULT_MAX_SCRIPT_OUTPUT_CHARS = 8192


def parse_nmap_xml(
    path: Path,
    max_script_output_chars: int = DEFAULT_MAX_SCRIPT_OUTPUT_CHARS,
) -> list[HostObservation]:
    hosts: list[HostObservation] = []
    try:
        events = ET.iterparse(path, events=("start", "end"))
        _, root = next(events)
        for event, elem in events:
            if event != "end" or elem.tag != "host":
                continue
            host = parse_host_element(elem, max_script_output_chars)
            if host is not None:
                hosts.append(host)
            elem.clear()
            root.clear()
    except StopIteration:
        return hosts
    except (ET.ParseError, OSError) as error:
        raise NmapXmlParseError(str(path), str(error)) from error

    return hosts


def parse_host_element(
    host_elem: ET.Element,
    max_script_output_chars: int,
) -> HostObservation | None:
    address = first_address(host_elem)
    if not address:
        return None

    os_family, os_name, os_accuracy, os_source = parse_os_identity(host_elem)
    host = HostObservation(
        address=address,
        hostname=first_hostname(host_elem),
        status=host_status(host_elem),
        os_family=os_family,
        os_name=os_name,
        os_accuracy=os_accuracy,
        os_source=os_source,
    )

    for port_elem in host_elem.findall("ports/port"):
        state_elem = port_elem.find("state")
        state = state_elem.attrib.get("state", "") if state_elem is not None else ""
        if state != "open":
            continue

        service_elem = port_elem.find("service")
        service = ServiceObservation(
            host=address,
            port=int(port_elem.attrib["portid"]),
            protocol=port_elem.attrib.get("protocol", "tcp"),
            state=state,
            service_name=service_attribute(service_elem, "name"),
            product=service_attribute(service_elem, "product"),
            version=service_attribute(service_elem, "version"),
            extrainfo=service_attribute(service_elem, "extrainfo"),
            tunnel=service_attribute(service_elem, "tunnel"),
            scripts=parse_script_output(port_elem, max_script_output_chars),
        )
        host.services.append(service)

    if host.os_family == "unknown":
        host.os_family = infer_os_from_services(host.services)
        if host.os_family != "unknown":
            host.os_source = "service-inference"

    return host


def service_attribute(service_elem: ET.Element | None, name: str) -> str:
    if service_elem is None:
        return ""
    return service_elem.attrib.get(name, "")


def first_address(host_elem: ET.Element) -> str:
    addresses = host_elem.findall("address")
    for addr_type in ("ipv4", "ipv6"):
        for address in addresses:
            if address.attrib.get("addrtype") == addr_type:
                return address.attrib.get("addr", "")
    return addresses[0].attrib.get("addr", "") if addresses else ""


def first_hostname(host_elem: ET.Element) -> str:
    hostname = host_elem.find("hostnames/hostname")
    return hostname.attrib.get("name", "") if hostname is not None else ""


def host_status(host_elem: ET.Element) -> str:
    status = host_elem.find("status")
    return status.attrib.get("state", "") if status is not None else ""


def parse_os_identity(host_elem: ET.Element) -> tuple[str, str, str, str]:
    osmatch = host_elem.find("os/osmatch")
    if osmatch is None:
        return "unknown", "", "", "unknown"

    os_name = osmatch.attrib.get("name", "")
    os_accuracy = osmatch.attrib.get("accuracy", "")
    os_family = infer_os_family_from_match(osmatch)
    if os_family == "unknown":
        os_family = infer_os_family_from_text(os_name)
    return os_family, os_name, os_accuracy, "nmap-osmatch"


def infer_os_family_from_match(osmatch: ET.Element) -> str:
    for osclass in osmatch.findall("osclass"):
        family = osclass.attrib.get("osfamily", "")
        vendor = osclass.attrib.get("vendor", "")
        family_guess = infer_os_family_from_text(f"{family} {vendor}")
        if family_guess != "unknown":
            return family_guess
    return "unknown"


def infer_os_family_from_text(value: str) -> str:
    text = value.lower()
    if "windows" in text or "microsoft" in text:
        return "windows"
    if any(name in text for name in ("linux", "unix", "bsd", "solaris")):
        return "unix"
    return "unknown"


def infer_os_from_services(services: list[ServiceObservation]) -> str:
    windows_ports = {135, 139, 445, 3389, 5985, 5986}
    unix_ports = {22, 111, 2049}
    if any(service.port in windows_ports for service in services):
        return "windows-like"
    if any(service.port in unix_ports for service in services):
        return "unix-like"
    if any(service.port in WEB_PORTS for service in services):
        return "web-exposed"
    return "unknown"


def parse_script_output(
    port_elem: ET.Element,
    max_script_output_chars: int = DEFAULT_MAX_SCRIPT_OUTPUT_CHARS,
) -> dict[str, str]:
    scripts: dict[str, str] = {}
    for script in port_elem.findall("script"):
        script_id = script.attrib.get("id", "unknown")
        scripts[script_id] = truncate_script_output(
            script.attrib.get("output", "").strip(),
            max_script_output_chars,
        )
    return scripts


def truncate_script_output(output: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(output) <= max_chars:
        return output
    marker = "... [truncated]"
    if max_chars <= len(marker):
        return output[:max_chars]
    return f"{output[: max_chars - len(marker)]}{marker}"


def merge_hosts(base_hosts: list[HostObservation], update_hosts: list[HostObservation]) -> None:
    by_host = {host.address: host for host in base_hosts}
    for update_host in update_hosts:
        base_host = by_host.get(update_host.address)
        if base_host is None:
            base_hosts.append(update_host)
            by_host[update_host.address] = update_host
            continue

        merge_host_identity(base_host, update_host)
        by_service = {
            (service.protocol, service.port): service for service in base_host.services
        }
        for update_service in update_host.services:
            base_service = by_service.get((update_service.protocol, update_service.port))
            if base_service is None:
                base_host.services.append(update_service)
                continue
            merge_service(base_service, update_service)


def merge_host_identity(base_host: HostObservation, update_host: HostObservation) -> None:
    if update_host.original_target and not base_host.original_target:
        base_host.original_target = update_host.original_target
    if update_host.resolved_ip and not base_host.resolved_ip:
        base_host.resolved_ip = update_host.resolved_ip
    if update_host.hostname and not base_host.hostname:
        base_host.hostname = update_host.hostname
    if update_host.os_family != "unknown" and base_host.os_family == "unknown":
        base_host.os_family = update_host.os_family
        base_host.os_source = update_host.os_source
    if update_host.os_name and not base_host.os_name:
        base_host.os_name = update_host.os_name
        base_host.os_accuracy = update_host.os_accuracy
        base_host.os_source = update_host.os_source


def merge_service(
    base_service: ServiceObservation,
    update_service: ServiceObservation,
) -> None:
    if update_service.product:
        base_service.product = update_service.product
    if update_service.version:
        base_service.version = update_service.version
    if update_service.extrainfo:
        base_service.extrainfo = update_service.extrainfo
    if update_service.service_name:
        base_service.service_name = update_service.service_name
    if update_service.tunnel:
        base_service.tunnel = update_service.tunnel
    base_service.scripts.update(update_service.scripts)
