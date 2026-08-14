from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from portweft.discovery_runner import ExternalResult
from portweft.errors import NucleiNotFoundError
from portweft.models import HostObservation, ServiceObservation
from portweft.nuclei_runner import (
    build_nuclei_command,
    build_nuclei_targets,
    ensure_nuclei_available,
    parse_nuclei_jsonl,
    run_nuclei,
)
from tests.helpers import temporary_directory


def service(
    host: str,
    port: int,
    name: str,
    protocol: str = "tcp",
    tunnel: str = "",
) -> ServiceObservation:
    return ServiceObservation(
        host=host,
        port=port,
        protocol=protocol,
        state="open",
        service_name=name,
        tunnel=tunnel,
    )


class NucleiRunnerTests(unittest.TestCase):
    def test_missing_executable_preflight_is_controlled(self) -> None:
        with patch("portweft.nuclei_runner.resolve_executable", return_value=None):
            with self.assertRaises(NucleiNotFoundError):
                ensure_nuclei_available("missing-nuclei")

    def test_targets_cover_web_https_nonstandard_ipv6_and_network_tcp(self) -> None:
        hosts = [
            HostObservation(
                address="192.0.2.10",
                services=[
                    service("192.0.2.10", 80, "http"),
                    service("192.0.2.10", 8443, "https-alt"),
                    service("192.0.2.10", 22, "ssh"),
                    service("192.0.2.10", 53, "domain", protocol="udp"),
                    service("192.0.2.10", 80, "http"),
                ],
            ),
            HostObservation(
                address="2001:db8::10",
                services=[service("2001:db8::10", 9443, "http", tunnel="ssl")],
            ),
        ]
        self.assertEqual(
            build_nuclei_targets(hosts),
            [
                "192.0.2.10:22",
                "http://192.0.2.10:80",
                "https://192.0.2.10:8443",
                "https://[2001:db8::10]:9443",
            ],
        )

    def test_command_is_always_cve_filtered_jsonl_without_raw_or_template(self) -> None:
        command = build_nuclei_command(
            "nuclei", Path("targets.txt"), Path("findings.jsonl")
        )
        self.assertEqual(command[command.index("-tags") + 1], "cve")
        for flag in ("-jsonl", "-silent", "-nc", "-omit-raw", "-omit-template"):
            self.assertIn(flag, command)
        for forbidden in ("-as", "-headless", "-code", "-fuzz"):
            self.assertNotIn(forbidden, command)

    def test_jsonl_parser_tolerates_empty_malformed_unknown_fields_and_dedupes(self) -> None:
        finding = {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache path traversal",
                "severity": "high",
                "reference": ["https://example.test/advisory"],
            },
            "matched-at": "http://192.0.2.10:8080/a",
            "matcher-name": "path",
            "type": "http",
            "host": "http://192.0.2.10:8080",
            "unknown": {"future": True},
        }
        output = "\n".join(("not json", json.dumps(finding), json.dumps(finding), ""))
        parsed = parse_nuclei_jsonl(output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].host, "192.0.2.10")
        self.assertEqual(parsed[0].port, 8080)
        self.assertEqual(parsed[0].severity, "high")
        self.assertEqual(parse_nuclei_jsonl(""), [])

    def test_nonzero_exit_keeps_jsonl_findings_as_partial_results(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            services=[service("192.0.2.10", 80, "http")],
        )

        def failed_run(command, *_args):
            output_path = Path(command[command.index("-o") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "template-id": "CVE-2021-41773",
                        "info": {"name": "Apache", "severity": "high"},
                        "matched-at": "http://192.0.2.10:80/a",
                        "host": "http://192.0.2.10:80",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return ExternalResult(exit_code=2, stderr="template error")

        with temporary_directory() as temp_dir:
            scan_dir = Path(temp_dir) / "run"
            scan_dir.mkdir()
            with patch("portweft.nuclei_runner.run_external_command", failed_run):
                status, count = run_nuclei("nuclei", [host], scan_dir, 10, 0)

        self.assertIn("partial failure", status)
        self.assertEqual(count, 1)
        self.assertEqual(host.nuclei_findings[0].template_id, "CVE-2021-41773")

    def test_timeout_status_is_partial_and_does_not_require_findings(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            services=[service("192.0.2.10", 22, "ssh")],
        )
        with temporary_directory() as temp_dir:
            scan_dir = Path(temp_dir) / "run"
            scan_dir.mkdir()
            with patch(
                "portweft.nuclei_runner.run_external_command",
                return_value=ExternalResult(exit_code=124),
            ):
                status, count = run_nuclei("nuclei", [host], scan_dir, 1, 0)
        self.assertEqual(status, "partial failure: timed out")
        self.assertEqual(count, 0)

    def test_success_without_output_file_is_partial_failure(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            services=[service("192.0.2.10", 80, "http")],
        )
        with temporary_directory() as temp_dir:
            scan_dir = Path(temp_dir) / "run"
            scan_dir.mkdir()
            with patch(
                "portweft.nuclei_runner.run_external_command",
                return_value=ExternalResult(exit_code=0),
            ):
                status, count = run_nuclei("nuclei", [host], scan_dir, 10, 0)

        self.assertEqual(status, "partial failure: output unavailable")
        self.assertEqual(count, 0)

    def test_interrupt_is_a_partial_nuclei_failure(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            services=[service("192.0.2.10", 22, "ssh")],
        )
        with temporary_directory() as temp_dir:
            scan_dir = Path(temp_dir) / "run"
            scan_dir.mkdir()
            with patch(
                "portweft.nuclei_runner.run_external_command",
                side_effect=KeyboardInterrupt,
            ):
                status, count = run_nuclei("nuclei", [host], scan_dir, 1, 0)
        self.assertEqual(status, "partial failure: interrupted")
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
