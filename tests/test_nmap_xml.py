from __future__ import annotations

import unittest
from pathlib import Path

from portweft.errors import NmapXmlParseError
from portweft.models import HostObservation, ServiceObservation
from portweft.nmap_xml import merge_hosts, parse_nmap_xml
from tests.helpers import temporary_directory


FIXTURES = Path(__file__).parent / "fixtures"


class NmapXmlTests(unittest.TestCase):
    def test_parse_linux_host(self) -> None:
        hosts = parse_nmap_xml(FIXTURES / "linux_host.xml")

        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.address, "192.0.2.10")
        self.assertEqual(host.hostname, "linux-web.example")
        self.assertEqual(host.os_family, "unix")
        self.assertEqual(host.os_name, "Linux 5.4 - 5.15")
        self.assertEqual(host.os_accuracy, "93")
        self.assertEqual(len(host.services), 2)
        self.assertEqual([service.port for service in host.services], [22, 9000])
        self.assertEqual(host.services[0].product, "OpenSSH")
        self.assertEqual(host.services[1].scripts["http-title"], "Example title")

    def test_parse_windows_host(self) -> None:
        hosts = parse_nmap_xml(FIXTURES / "windows_host.xml")

        host = hosts[0]
        self.assertEqual(host.os_family, "windows")
        self.assertEqual(host.os_label(), "Microsoft Windows Server 2019 (96% accuracy)")
        self.assertEqual([service.port for service in host.services], [445, 3389, 389])
        self.assertIn("smb2-security-mode", host.services[0].scripts)

    def test_parse_nonstandard_ports_keeps_banner_fields(self) -> None:
        hosts = parse_nmap_xml(FIXTURES / "nonstandard_ports.xml")

        services = {service.port: service for service in hosts[0].services}
        self.assertEqual(services[2222].product, "OpenSSH")
        self.assertEqual(services[9000].product, "nginx")
        self.assertEqual(services[9445].product, "Samba smbd")

    def test_empty_xml_returns_no_hosts(self) -> None:
        self.assertEqual(parse_nmap_xml(FIXTURES / "empty.xml"), [])

    def test_script_output_can_be_capped(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "script.xml"
            path.write_text(
                """
                <nmaprun>
                  <host>
                    <address addr="192.0.2.10" addrtype="ipv4"/>
                    <ports>
                      <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <script id="big" output="abcdefghijklmnopqrstuvwxyz"/>
                      </port>
                    </ports>
                  </host>
                </nmaprun>
                """,
                encoding="utf-8",
            )

            hosts = parse_nmap_xml(path, max_script_output_chars=10)

        self.assertEqual(hosts[0].services[0].scripts["big"], "abcdefghij")

    def test_open_tcp_ports_remain_separate_for_each_host(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "discovery.xml"
            path.write_text(
                """
                <nmaprun>
                  <host>
                    <status state="up"/>
                    <address addr="192.0.2.10" addrtype="ipv4"/>
                    <ports>
                      <port protocol="tcp" portid="22"><state state="open"/></port>
                      <port protocol="tcp" portid="80"><state state="closed"/></port>
                    </ports>
                  </host>
                  <host>
                    <status state="up"/>
                    <address addr="192.0.2.11" addrtype="ipv4"/>
                    <ports>
                      <port protocol="tcp" portid="443"><state state="open"/></port>
                    </ports>
                  </host>
                </nmaprun>
                """,
                encoding="utf-8",
            )

            hosts = parse_nmap_xml(path)

        self.assertEqual(
            {host.address: [service.port for service in host.services] for host in hosts},
            {"192.0.2.10": [22], "192.0.2.11": [443]},
        )

    def test_malformed_xml_raises_parse_error(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "bad.xml"
            path.write_text("<nmaprun><host>", encoding="utf-8")

            with self.assertRaises(NmapXmlParseError):
                parse_nmap_xml(path)

    def test_invalid_open_port_records_are_ignored(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "invalid-port.xml"
            path.write_text(
                """
                <nmaprun>
                  <host>
                    <address addr="192.0.2.10" addrtype="ipv4"/>
                    <ports>
                      <port protocol="tcp" portid="nope"><state state="open"/></port>
                      <port protocol="tcp" portid="0"><state state="open"/></port>
                      <port protocol="tcp" portid="70000"><state state="open"/></port>
                      <port protocol="" portid="80"><state state="open"/></port>
                      <port protocol="bogus" portid="81"><state state="open"/></port>
                      <port protocol="sctp" portid="82"><state state="open"/></port>
                      <port protocol="tcp" portid="443"><state state="open"/></port>
                    </ports>
                  </host>
                </nmaprun>
                """,
                encoding="utf-8",
            )

            hosts = parse_nmap_xml(path)

        self.assertEqual([service.port for service in hosts[0].services], [443])

    def test_non_ip_addresses_do_not_become_host_observations(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "mac-only.xml"
            path.write_text(
                """
                <nmaprun>
                  <host>
                    <address addr="00:11:22:33:44:55" addrtype="mac"/>
                    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
                  </host>
                </nmaprun>
                """,
                encoding="utf-8",
            )

            hosts = parse_nmap_xml(path)

        self.assertEqual(hosts, [])

    def test_repeated_xml_services_are_merged_during_parsing(self) -> None:
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "duplicate-service.xml"
            path.write_text(
                """
                <nmaprun><host>
                  <address addr="192.0.2.10" addrtype="ipv4"/>
                  <ports>
                    <port protocol="tcp" portid="80"><state state="open"/></port>
                    <port protocol="tcp" portid="80">
                      <state state="open"/>
                      <service name="http" product="nginx"/>
                    </port>
                  </ports>
                </host></nmaprun>
                """,
                encoding="utf-8",
            )

            hosts = parse_nmap_xml(path)

        self.assertEqual(len(hosts[0].services), 1)
        self.assertEqual(hosts[0].services[0].product, "nginx")

    def test_merge_hosts_updates_identity_and_services(self) -> None:
        base_host = HostObservation(
            address="192.0.2.10",
            services=[
                ServiceObservation(
                    host="192.0.2.10",
                    port=22,
                    protocol="tcp",
                    state="open",
                    service_name="ssh",
                )
            ],
        )
        update_host = HostObservation(
            address="192.0.2.10",
            hostname="linux.example",
            os_family="unix",
            os_name="Linux 5.x",
            os_accuracy="95",
            os_source="nmap-osmatch",
            services=[
                ServiceObservation(
                    host="192.0.2.10",
                    port=22,
                    protocol="tcp",
                    state="open",
                    service_name="ssh",
                    product="OpenSSH",
                    version="9.6",
                    scripts={"ssh-hostkey": "fingerprint"},
                ),
                ServiceObservation(
                    host="192.0.2.10",
                    port=443,
                    protocol="tcp",
                    state="open",
                    service_name="https",
                ),
            ],
        )

        merge_hosts([base_host], [update_host])

        self.assertEqual(base_host.hostname, "linux.example")
        self.assertEqual(base_host.os_name, "Linux 5.x")
        self.assertEqual(len(base_host.services), 2)
        self.assertEqual(base_host.services[0].product, "OpenSSH")
        self.assertEqual(base_host.services[0].scripts["ssh-hostkey"], "fingerprint")

    def test_merge_hosts_deduplicates_repeated_update_services(self) -> None:
        base_host = HostObservation(address="192.0.2.10")
        update_host = HostObservation(
            address="192.0.2.10",
            services=[
                ServiceObservation("192.0.2.10", 80, "tcp", "open"),
                ServiceObservation(
                    "192.0.2.10", 80, "tcp", "open", product="nginx"
                ),
            ],
        )

        merge_hosts([base_host], [update_host])

        self.assertEqual(len(base_host.services), 1)
        self.assertEqual(base_host.services[0].product, "nginx")

    def test_merge_hosts_matches_equivalent_ipv6_spellings(self) -> None:
        base_hosts = [
            HostObservation(
                address="2001:0db8:0:0:0:0:0:1",
                services=[ServiceObservation("2001:db8::1", 80, "tcp", "open")],
            )
        ]
        update_hosts = [
            HostObservation(
                address="2001:db8::1",
                services=[
                    ServiceObservation(
                        "2001:db8::1", 80, "tcp", "open", product="nginx"
                    )
                ],
            )
        ]

        merge_hosts(base_hosts, update_hosts)

        self.assertEqual(len(base_hosts), 1)
        self.assertEqual(base_hosts[0].services[0].product, "nginx")


if __name__ == "__main__":
    unittest.main()
