from __future__ import annotations

import argparse
import contextlib
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from portweft.errors import (
    NmapArgumentStringError,
    NmapNotFoundError,
    NmapOutputConflictError,
)
from portweft.models import ServiceObservation
from portweft.nmap_runner import (
    build_followup_command,
    build_initial_command,
    build_udp_command,
    extract_nmap_error,
    run_command,
    split_nmap_args,
    udp_default_ports_text,
    validate_nmap_passthrough,
)


def parsed_args(**overrides) -> argparse.Namespace:
    values = {
        "nmap_path": "nmap-test",
        "no_service_version": False,
        "ports": None,
        "top_ports": None,
        "udp_ports": udp_default_ports_text(),
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class NmapRunnerTests(unittest.TestCase):
    def test_split_nmap_args_respects_quotes(self) -> None:
        self.assertEqual(
            split_nmap_args('-T4 -Pn --script "http-title,ssl-cert"'),
            ["-T4", "-Pn", "--script", "http-title,ssl-cert"],
        )

    def test_split_nmap_args_reports_bad_quotes(self) -> None:
        with self.assertRaises(NmapArgumentStringError):
            split_nmap_args('--script "unterminated')

    def test_validate_nmap_passthrough_rejects_output_flags(self) -> None:
        with self.assertRaises(NmapOutputConflictError):
            validate_nmap_passthrough(["-T4", "-oX", "scan.xml"])

    def test_build_initial_command_defaults_to_light_version_detection(self) -> None:
        command = build_initial_command(
            parsed_args(ports="22,80"),
            ["192.0.2.10"],
            Path("out.xml"),
            ["-T4", "-Pn"],
        )
        self.assertEqual(
            command,
            [
                "nmap-test",
                "-T4",
                "-Pn",
                "-sV",
                "--version-light",
                "-p",
                "22,80",
                "-oX",
                "out.xml",
                "192.0.2.10",
            ],
        )

    def test_build_initial_command_does_not_duplicate_service_version_flag(self) -> None:
        command = build_initial_command(
            parsed_args(top_ports=100),
            ["192.0.2.10"],
            Path("out.xml"),
            ["-sV"],
        )
        self.assertEqual(command.count("-sV"), 1)
        self.assertNotIn("--version-light", command)

    def test_build_followup_command_uses_profile_scripts(self) -> None:
        service = ServiceObservation(
            host="192.0.2.10",
            port=445,
            protocol="tcp",
            state="open",
        )
        command = build_followup_command(parsed_args(), service, "smb", Path("smb.xml"), [])
        self.assertIn("--script", command)
        self.assertIn("smb-protocols,smb2-security-mode,smb2-time", command)
        self.assertIn("445", command)

    def test_build_followup_command_omits_empty_script_argument(self) -> None:
        service = ServiceObservation(
            host="192.0.2.10",
            port=5432,
            protocol="tcp",
            state="open",
        )
        command = build_followup_command(
            parsed_args(),
            service,
            "postgres",
            Path("postgres.xml"),
            [],
        )
        self.assertNotIn("--script", command)
        self.assertIn("5432", command)

    def test_build_udp_command_uses_udp_scan_type_and_udp_port_prefix(self) -> None:
        command = build_udp_command(
            parsed_args(udp_ports="53,123,161"),
            ["192.0.2.10"],
            Path("udp.xml"),
            ["-T4", "-Pn"],
        )
        self.assertIn("-sU", command)
        self.assertIn("U:53,123,161", command)
        self.assertIn("udp.xml", command)

    def test_build_udp_followup_command_uses_udp_prefix(self) -> None:
        service = ServiceObservation(
            host="192.0.2.10",
            port=161,
            protocol="udp",
            state="open",
        )
        command = build_followup_command(parsed_args(), service, "snmp", Path("snmp.xml"), [])
        self.assertIn("-sU", command)
        self.assertIn("U:161", command)
        self.assertIn("snmp-info", command)

    def test_run_command_converts_file_not_found_to_portweft_error(self) -> None:
        with patch("portweft.nmap_runner.subprocess.run", side_effect=FileNotFoundError):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(NmapNotFoundError):
                    run_command(["missing-nmap"], dry_run=False)

    def test_run_command_returns_nmap_error_text(self) -> None:
        completed = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="nmap: unrecognized option '--bad-flag'\nsee nmap -h\n",
        )
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch("portweft.nmap_runner.subprocess.run", return_value=completed):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = run_command(["nmap", "--bad-flag"], dry_run=False)

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unrecognized option", stderr.getvalue())

    def test_extract_nmap_error_uses_stdout_when_stderr_is_empty(self) -> None:
        result = SimpleNamespace(exit_code=2, stdout="bad target\n", stderr="")
        self.assertEqual(extract_nmap_error(result), "bad target")


if __name__ == "__main__":
    unittest.main()
