from __future__ import annotations

import unittest

from portweft.matcher import (
    evidence_summary,
    has_observable_evidence,
    match_profiles,
    service_evidence,
)
from portweft.models import ServiceObservation


def service(
    port: int,
    protocol: str = "tcp",
    service_name: str = "unknown",
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    tunnel: str = "",
    scripts: dict[str, str] | None = None,
) -> ServiceObservation:
    return ServiceObservation(
        host="192.0.2.10",
        port=port,
        protocol=protocol,
        state="open",
        service_name=service_name,
        product=product,
        version=version,
        extrainfo=extrainfo,
        tunnel=tunnel,
        scripts=scripts or {},
    )


class MatcherTests(unittest.TestCase):
    def test_banner_matches_nonstandard_ssh_port(self) -> None:
        self.assertEqual(match_profiles(service(2222, product="OpenSSH")), ["ssh"])

    def test_banner_matches_nonstandard_web_port(self) -> None:
        self.assertEqual(match_profiles(service(9000, product="Apache httpd")), ["web"])

    def test_banner_matches_nonstandard_smb_port(self) -> None:
        self.assertEqual(match_profiles(service(9445, product="Samba smbd")), ["smb"])

    def test_banner_match_wins_over_port_fallback(self) -> None:
        self.assertEqual(match_profiles(service(80, product="OpenSSH")), ["ssh"])

    def test_port_fallback_when_banner_is_unknown(self) -> None:
        self.assertEqual(match_profiles(service(445)), ["smb"])

    def test_tls_tunnel_matches_tls_profile(self) -> None:
        self.assertIn("tls", match_profiles(service(9443, tunnel="ssl")))

    def test_script_output_is_match_evidence(self) -> None:
        profiles = match_profiles(
            service(9999, scripts={"http-title": "Welcome to nginx"})
        )
        self.assertEqual(profiles, ["web"])

    def test_common_service_banners_match_expected_profiles(self) -> None:
        cases = [
            (service(2121, product="vsftpd"), "ftp"),
            (service(5353, product="dnsmasq"), "dns"),
            (service(2525, product="Postfix smtpd"), "smtp"),
            (service(1993, product="Dovecot imapd"), "imap"),
            (service(1995, product="Dovecot pop3d"), "pop3"),
            (service(8888, product="kube-apiserver"), "kubernetes"),
            (service(9999, product="Microsoft SQL Server"), "mssql"),
            (service(33306, product="MariaDB"), "mysql"),
            (service(15432, product="PostgreSQL"), "postgres"),
            (service(16379, product="Redis"), "redis"),
            (service(37017, product="MongoDB"), "mongodb"),
            (service(19200, product="Elasticsearch"), "elasticsearch"),
            (service(21211, product="memcached"), "memcached"),
            (service(5905, product="RealVNC"), "vnc"),
            (service(1873, product="rsync"), "rsync"),
            (service(12375, product="Docker Engine"), "docker"),
        ]
        for observed_service, expected_profile in cases:
            with self.subTest(expected_profile=expected_profile):
                self.assertEqual(match_profiles(observed_service), [expected_profile])

    def test_common_alt_ports_fallback_to_expected_profiles(self) -> None:
        cases = [
            (8080, "web"),
            (8443, "web"),
            (2222, "ssh"),
            (2121, "ftp"),
            (2323, "telnet"),
            (5353, "dns"),
            (587, "smtp"),
            (993, "tls"),
            (5985, "winrm"),
            (33060, "mysql"),
            (27018, "mongodb"),
            (5901, "vnc"),
        ]
        for port, expected_profile in cases:
            with self.subTest(port=port):
                self.assertIn(expected_profile, match_profiles(service(port)))

    def test_udp_first_ports_match_udp_profiles_when_protocol_is_udp(self) -> None:
        cases = [
            (69, "tftp"),
            (123, "ntp"),
            (161, "snmp"),
            (500, "ike"),
            (514, "syslog"),
            (1900, "ssdp"),
        ]
        for port, expected_profile in cases:
            with self.subTest(port=port):
                self.assertIn(
                    expected_profile,
                    match_profiles(service(port, protocol="udp")),
                )

    def test_unmatched_banner_is_detectable_without_crashing(self) -> None:
        observed_service = service(7777, product="MysteryThing", version="1.0")

        self.assertEqual(match_profiles(observed_service), [])
        self.assertTrue(has_observable_evidence(observed_service))
        self.assertIn("MysteryThing", evidence_summary(observed_service))

    def test_unknown_only_service_has_no_observable_evidence(self) -> None:
        observed_service = service(7777)

        self.assertEqual(match_profiles(observed_service), [])
        self.assertFalse(has_observable_evidence(observed_service))

    def test_service_evidence_contains_all_observed_fields(self) -> None:
        evidence = service_evidence(
            service(
                1234,
                service_name="mystery",
                product="OpenSSH",
                version="9.6",
                extrainfo="Ubuntu",
                tunnel="ssl",
                scripts={"ssh-hostkey": "fingerprint"},
            )
        )
        for expected in ("mystery", "openssh", "9.6", "ubuntu", "ssl", "ssh-hostkey"):
            self.assertIn(expected, evidence)


if __name__ == "__main__":
    unittest.main()
