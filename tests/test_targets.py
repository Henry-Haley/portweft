from __future__ import annotations

import contextlib
import io
import socket
import unittest
from unittest.mock import patch

from portweft.cli import main
from portweft.models import HostObservation
from portweft.targets import (
    TargetResolution,
    annotate_hosts_with_targets,
    resolve_targets,
    scan_targets,
)


class TargetResolutionTests(unittest.TestCase):
    def test_discovered_ip_is_annotated_with_original_cidr(self) -> None:
        hosts = [HostObservation(address="10.10.10.37")]
        resolutions = [
            TargetResolution(
                original="10.10.10.0/24",
                addresses=("10.10.10.0/24",),
            )
        ]

        annotate_hosts_with_targets(hosts, resolutions)

        self.assertEqual(hosts[0].original_target, "10.10.10.0/24")
        self.assertEqual(hosts[0].resolved_ip, "10.10.10.37")

    def test_cidr_annotation_does_not_iterate_network_members(self) -> None:
        hosts = [HostObservation(address="10.200.1.2")]
        resolutions = [
            TargetResolution(original="10.0.0.0/8", addresses=("10.0.0.0/8",))
        ]

        annotate_hosts_with_targets(hosts, resolutions)

        self.assertEqual(hosts[0].original_target, "10.0.0.0/8")
    def test_valid_domain_resolves_with_getaddrinfo(self) -> None:
        with patch(
            "portweft.targets.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("198.51.100.10", 0),
                )
            ],
        ):
            resolutions = resolve_targets(["example.test"])

        self.assertEqual(resolutions[0].original, "example.test")
        self.assertEqual(resolutions[0].addresses, ("198.51.100.10",))
        self.assertEqual(scan_targets(resolutions), ["198.51.100.10"])

    def test_invalid_domain_reports_error(self) -> None:
        with patch(
            "portweft.targets.socket.getaddrinfo",
            side_effect=socket.gaierror("name not known"),
        ):
            resolutions = resolve_targets(["missing.example"])

        self.assertFalse(resolutions[0].ok)
        self.assertIn("name not known", resolutions[0].error)
        self.assertEqual(scan_targets(resolutions), [])

    def test_invalid_unicode_domain_reports_error(self) -> None:
        resolutions = resolve_targets(["\ud800"])

        self.assertFalse(resolutions[0].ok)
        self.assertTrue(resolutions[0].error)

    def test_direct_ipv6_target_is_normalized_for_scanner_identity(self) -> None:
        resolutions = resolve_targets(["2001:0db8:0:0:0:0:0:1"])

        self.assertEqual(scan_targets(resolutions), ["2001:db8::1"])

    def test_invalid_ip_like_target_does_not_query_dns(self) -> None:
        with patch("portweft.targets.socket.getaddrinfo") as getaddrinfo:
            resolutions = resolve_targets(["999.999.999.999"])

        getaddrinfo.assert_not_called()
        self.assertFalse(resolutions[0].ok)
        self.assertIn("invalid IP address", resolutions[0].error)

    def test_mix_of_ip_and_domain_preserves_original_target(self) -> None:
        with patch(
            "portweft.targets.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("198.51.100.20", 0),
                )
            ],
        ) as getaddrinfo:
            resolutions = resolve_targets(["192.0.2.10", "example.test"])

        getaddrinfo.assert_called_once_with(
            "example.test",
            None,
            type=socket.SOCK_STREAM,
        )
        self.assertEqual(scan_targets(resolutions), ["192.0.2.10", "198.51.100.20"])

        hosts = [
            HostObservation(address="192.0.2.10"),
            HostObservation(address="198.51.100.20"),
        ]
        annotate_hosts_with_targets(hosts, resolutions)

        self.assertEqual(hosts[0].display_name(), "192.0.2.10")
        self.assertEqual(hosts[1].display_name(), "example.test -> 198.51.100.20")

    def test_getaddrinfo_all_mode_keeps_multiple_ipv4_and_ipv6_addresses(self) -> None:
        with patch(
            "portweft.targets.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("2001:db8::10", 0, 0, 0),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("198.51.100.30", 0),
                ),
            ],
        ):
            first_resolution = resolve_targets(["multi.example"], mode="first")[0]
            all_resolution = resolve_targets(["multi.example"], mode="all")[0]

        self.assertEqual(first_resolution.addresses, ("2001:db8::10",))
        self.assertEqual(
            all_resolution.addresses,
            ("2001:db8::10", "198.51.100.30"),
        )

    def test_ipv6_domain_adds_ipv6_nmap_flag_in_dry_run(self) -> None:
        stderr = io.StringIO()
        with patch(
            "portweft.targets.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("2001:db8::10", 0, 0, 0),
                )
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["ipv6.example", "--dry-run", "--no-udp"])

        self.assertEqual(exit_code, 0)
        self.assertIn("-6", stderr.getvalue())
        self.assertIn("2001:db8::10", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
