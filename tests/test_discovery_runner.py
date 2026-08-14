from __future__ import annotations

import argparse
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from portweft.discovery_runner import (
    build_masscan_command,
    build_rustscan_command,
    hosts_from_discovery,
    parse_masscan_list,
    parse_rustscan_greppable,
    run_discovery,
    select_discovery_backend,
)
from portweft.errors import MasscanNotFoundError, RustScanNotFoundError
from portweft.models import DiscoveryResult, HostObservation, ServiceObservation
from portweft.nmap_runner import build_detailed_command
from tests.helpers import temporary_directory


def parsed_args(**overrides) -> argparse.Namespace:
    values = {
        "nmap_path": "nmap",
        "rustscan_path": "rustscan",
        "masscan_path": "masscan",
        "masscan_rate": 1000,
        "dry_run": False,
        "stats_every": 0,
        "max_script_output_chars": 8192,
        "no_service_version": False,
        "ports": None,
        "top_ports": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class DiscoveryRunnerTests(unittest.TestCase):
    def test_auto_selects_rustscan_for_one_host_when_available(self) -> None:
        with patch(
            "portweft.discovery_runner.resolve_executable",
            side_effect=lambda path: path if path == "rustscan" else None,
        ):
            backend = select_discovery_backend("auto", ["192.0.2.10"])
        self.assertEqual(backend, "rustscan")

    def test_auto_selects_masscan_for_multiple_hosts_when_available(self) -> None:
        with patch(
            "portweft.discovery_runner.resolve_executable",
            side_effect=lambda path: path if path == "masscan" else None,
        ):
            backend = select_discovery_backend(
                "auto", ["192.0.2.10", "192.0.2.11"]
            )
        self.assertEqual(backend, "masscan")

    def test_auto_selects_masscan_for_cidr_when_available(self) -> None:
        with patch(
            "portweft.discovery_runner.resolve_executable",
            side_effect=lambda path: path if path == "masscan" else None,
        ):
            backend = select_discovery_backend("auto", ["192.0.2.0/24"])
        self.assertEqual(backend, "masscan")

    def test_auto_falls_back_to_nmap(self) -> None:
        with patch("portweft.discovery_runner.resolve_executable", return_value=None):
            self.assertEqual(
                select_discovery_backend("auto", ["192.0.2.10"]),
                "nmap",
            )

    def test_explicit_missing_optional_backends_raise_controlled_errors(self) -> None:
        with patch("portweft.discovery_runner.resolve_executable", return_value=None):
            with self.assertRaises(RustScanNotFoundError):
                select_discovery_backend("rustscan", ["192.0.2.10"])
            with self.assertRaises(MasscanNotFoundError):
                select_discovery_backend("masscan", ["192.0.2.10"])

    def test_rustscan_parser_ignores_malformed_lines_and_deduplicates(self) -> None:
        output = """
        192.0.2.10 -> [22,80,80,bad,70000]
        noise
        192.0.2.11 -> [443]
        192.0.2.12 -> []
        """
        self.assertEqual(
            parse_rustscan_greppable(output),
            {"192.0.2.10": {22, 80}, "192.0.2.11": {443}},
        )
        self.assertEqual(parse_rustscan_greppable(""), {})

    def test_masscan_parser_keeps_hosts_separate_and_deduplicates(self) -> None:
        output = """
        #masscan
        open tcp 80 192.0.2.10 1234
        open tcp 80 192.0.2.10 1235
        open tcp 445 192.0.2.11 1236
        open udp 53 192.0.2.10 1237
        open tcp nope 192.0.2.12 1238
        """
        self.assertEqual(
            parse_masscan_list(output),
            {"192.0.2.10": {80}, "192.0.2.11": {445}},
        )
        self.assertEqual(parse_masscan_list(""), {})

    def test_commands_are_discovery_only_and_masscan_rate_is_explicit(self) -> None:
        rustscan = build_rustscan_command("rustscan", ["192.0.2.10"])
        self.assertIn("--greppable", rustscan)
        self.assertIn("none", rustscan)
        self.assertNotIn("nmap", rustscan)

        masscan = build_masscan_command(
            "masscan", ["192.0.2.0/24"], Path("out.list"), 2500
        )
        self.assertIn("-p1-65535", masscan)
        self.assertEqual(masscan[masscan.index("--rate") + 1], "2500")
        self.assertEqual(masscan[masscan.index("-oL") + 1], "out.list")

    def test_nmap_discovery_normalizes_then_targets_only_discovered_ports(self) -> None:
        discovery_host = HostObservation(
            address="192.0.2.10",
            status="up",
            services=[
                ServiceObservation("192.0.2.10", 443, "tcp", "open"),
                ServiceObservation("192.0.2.10", 22, "tcp", "open"),
                ServiceObservation("192.0.2.10", 53, "udp", "open"),
            ],
        )
        command_result = SimpleNamespace(ok=True, exit_code=0)
        result = run_discovery(
            parsed_args(),
            "nmap",
            ["192.0.2.10"],
            Path("discovery.xml"),
            [],
            10,
            command_runner=lambda *_args, **_kwargs: command_result,
            xml_parser=lambda *_args, **_kwargs: [discovery_host],
        )
        hosts = hosts_from_discovery(result)
        command = build_detailed_command(
            parsed_args(),
            hosts[0].address,
            [service.port for service in hosts[0].services],
            Path("detailed.xml"),
            [],
        )
        self.assertEqual(result.open_tcp_ports, {"192.0.2.10": {22, 443}})
        self.assertEqual(command[command.index("-p") + 1], "22,443")


if __name__ == "__main__":
    unittest.main()
