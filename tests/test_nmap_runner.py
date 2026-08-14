from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from portweft.errors import (
    NmapArgumentStringError,
    NmapNotFoundError,
    NmapOutputConflictError,
    NmapPassthroughError,
    PortSpecError,
)
from portweft.models import ServiceObservation
from portweft.nmap_runner import (
    build_detailed_command,
    build_discovery_command,
    build_followup_batch_command,
    build_followup_command,
    build_initial_command,
    build_udp_command,
    default_udp_ports_for_tcp_ports,
    extract_nmap_error,
    ensure_nmap_available,
    parse_port_spec,
    resolve_nmap_path,
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


class FakeProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)

    def wait(self, timeout=None) -> int:
        _ = timeout
        return self.returncode

    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None


class TimeoutProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__(returncode=-15)
        self.wait_calls = 0
        self.terminated = False

    def wait(self, timeout=None) -> int:
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise subprocess.TimeoutExpired("nmap", timeout)
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True


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

    def test_validate_nmap_passthrough_rejects_bad_numeric_values(self) -> None:
        with self.assertRaises(NmapPassthroughError):
            validate_nmap_passthrough(["--min-parallelism", "nope"])

    def test_validate_nmap_passthrough_rejects_bad_timeout_values(self) -> None:
        with self.assertRaises(NmapPassthroughError):
            validate_nmap_passthrough(["--host-timeout", "notatime"])

    def test_validate_nmap_passthrough_rejects_nonfinite_values(self) -> None:
        for option in ("--max-rate", "--host-timeout"):
            for value in ("nan", "inf"):
                with self.subTest(option=option, value=value):
                    with self.assertRaises(NmapPassthroughError):
                        validate_nmap_passthrough([option, value])

    def test_parse_port_spec_accepts_ranges_and_comma_lists(self) -> None:
        self.assertEqual(parse_port_spec("1-3,65342"), {1, 2, 3, 65342})

    def test_parse_port_spec_accepts_all_ports_shorthand(self) -> None:
        ports = parse_port_spec("-")
        self.assertIn(1, ports)
        self.assertIn(65535, ports)
        self.assertEqual(len(ports), 65535)

    def test_parse_port_spec_rejects_out_of_range_ports(self) -> None:
        with self.assertRaises(PortSpecError):
            parse_port_spec("65536")

    def test_default_udp_ports_for_tcp_ports_returns_only_overlaps(self) -> None:
        self.assertEqual(default_udp_ports_for_tcp_ports("445"), "")
        self.assertEqual(default_udp_ports_for_tcp_ports("53,445"), "53")
        self.assertEqual(default_udp_ports_for_tcp_ports("53-69"), "53,67,68,69")

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
                "--script",
                "banner",
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

    def test_build_initial_command_preserves_nmap_all_ports_shorthand(self) -> None:
        command = build_initial_command(
            parsed_args(ports="-"),
            ["192.0.2.10"],
            Path("out.xml"),
            [],
        )

        self.assertIn("-p-", command)
        self.assertNotIn("-", command)

    def test_build_initial_command_merges_banner_with_existing_script_arg(self) -> None:
        command = build_initial_command(
            parsed_args(ports="80"),
            ["192.0.2.10"],
            Path("out.xml"),
            ["--script", "http-title"],
        )

        script_index = command.index("--script")
        self.assertEqual(command[script_index + 1], "http-title,banner")

    def test_build_discovery_command_is_lightweight_and_scans_all_tcp_ports(self) -> None:
        command = build_discovery_command(
            parsed_args(),
            ["192.0.2.10", "192.0.2.11"],
            Path("discovery.xml"),
            [
                "-T4",
                "-Pn",
                "-A",
                "-O",
                "-sU",
                "-sV",
                "-sC",
                "--script",
                "http-title",
                "--script-args=unsafe=0",
                "--version-intensity",
                "9",
            ],
        )

        self.assertEqual(
            command,
            [
                "nmap-test",
                "-T4",
                "-Pn",
                "-p-",
                "-oX",
                "discovery.xml",
                "192.0.2.10",
                "192.0.2.11",
            ],
        )

    def test_build_detailed_command_targets_only_discovered_host_ports(self) -> None:
        command = build_detailed_command(
            parsed_args(),
            "192.0.2.10",
            [443, 22, 443],
            Path("detailed.xml"),
            ["-T4", "-A"],
        )

        self.assertEqual(
            command,
            [
                "nmap-test",
                "-T4",
                "--script",
                "banner",
                "-sV",
                "--version-light",
                "-p",
                "22,443",
                "-oX",
                "detailed.xml",
                "192.0.2.10",
            ],
        )
        self.assertNotIn("-A", command)

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

    def test_build_udp_command_filters_tcp_specific_passthrough_args(self) -> None:
        command = build_udp_command(
            parsed_args(udp_ports="53"),
            ["192.0.2.10"],
            Path("udp.xml"),
            [
                "-T4",
                "-A",
                "-sC",
                "-sS",
                "-PA80",
                "--script",
                "http-title",
                "--script-args",
                "unsafe=0",
                "--scanflags",
                "SYNFIN",
                "-p",
                "22,80",
                "--top-ports=100",
            ],
        )

        self.assertIn("-T4", command)
        self.assertIn("-sU", command)
        self.assertIn("U:53", command)
        self.assertNotIn("-A", command)
        self.assertNotIn("-sC", command)
        self.assertNotIn("-sS", command)
        self.assertNotIn("-PA80", command)
        self.assertNotIn("--script", command)
        self.assertNotIn("http-title", command)
        self.assertNotIn("--script-args", command)
        self.assertNotIn("unsafe=0", command)
        self.assertNotIn("--scanflags", command)
        self.assertNotIn("SYNFIN", command)
        self.assertNotIn("22,80", command)
        self.assertNotIn("--top-ports=100", command)

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

    def test_build_followup_batch_command_combines_ports(self) -> None:
        command = build_followup_batch_command(
            parsed_args(),
            "192.0.2.10",
            "tcp",
            [443, 80, 443],
            "web",
            Path("web.xml"),
            [],
        )

        self.assertIn("80,443", command)
        self.assertIn("web.xml", command)
        self.assertEqual(command[-1], "192.0.2.10")

    def test_run_command_converts_file_not_found_to_portweft_error(self) -> None:
        with patch("portweft.nmap_runner.subprocess.Popen", side_effect=FileNotFoundError):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(NmapNotFoundError):
                    run_command(["missing-nmap"], dry_run=False)

    def test_nmap_directory_path_is_not_available(self) -> None:
        with self.assertRaises(NmapNotFoundError):
            ensure_nmap_available(str(Path.cwd()), dry_run=False)

    def test_run_command_converts_launch_permission_error_to_portweft_error(self) -> None:
        with patch(
            "portweft.nmap_runner.subprocess.Popen",
            side_effect=PermissionError("denied"),
        ):
            with self.assertRaises(NmapNotFoundError):
                run_command(["nmap"], dry_run=False)

    def test_run_command_returns_nmap_error_text(self) -> None:
        completed = FakeProcess(
            returncode=1,
            stderr="nmap: unrecognized option '--bad-flag'\nsee nmap -h\n",
        )
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch("portweft.nmap_runner.subprocess.Popen", return_value=completed):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = run_command(["nmap", "--bad-flag"], dry_run=False)

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unrecognized option", stderr.getvalue())

    def test_run_command_keeps_only_bounded_output_tail(self) -> None:
        stderr_text = "\n".join(f"line {index}" for index in range(20))
        completed = FakeProcess(returncode=1, stderr=stderr_text)

        with patch("portweft.nmap_runner.subprocess.Popen", return_value=completed):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                result = run_command(["nmap"], dry_run=False, max_output_lines=3)

        self.assertNotIn("line 0", result.stderr)
        self.assertIn("line 17", result.stderr)
        self.assertIn("line 19", result.stderr)

    def test_run_command_times_out_and_terminates_process(self) -> None:
        process = TimeoutProcess()

        with patch("portweft.nmap_runner.subprocess.Popen", return_value=process):
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                result = run_command(["nmap"], dry_run=False, timeout_seconds=0.01)

        self.assertEqual(result.exit_code, 124)
        self.assertTrue(process.terminated)
        self.assertIn("timed out", stderr.getvalue())

    def test_extract_nmap_error_uses_stdout_when_stderr_is_empty(self) -> None:
        result = SimpleNamespace(exit_code=2, stdout="bad target\n", stderr="")
        self.assertEqual(extract_nmap_error(result), "bad target")


if __name__ == "__main__":
    unittest.main()
