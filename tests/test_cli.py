from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from portweft.cli import (
    cleanup_scan_outputs,
    main,
    print_unmatched_service,
    prune_old_runs,
    unique_run_id,
)
from portweft.errors import OutputDirectoryError
from portweft.impacket_runner import ImpacketAvailability
from portweft.models import HostObservation, ServiceObservation
from tests.helpers import temporary_directory


class CliTests(unittest.TestCase):
    def test_no_args_prints_help_and_exits_two(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = main([])

        output = stderr.getvalue()
        self.assertEqual(exit_code, 2)
        self.assertIn("usage: portweft", output)
        self.assertIn("P O R T W E F T", output)
        self.assertIn("targets", output)
        self.assertIn("--dry-run", output)

    def test_help_flag_prints_syntax(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                main(["-h"])

        output = stdout.getvalue()
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("usage: portweft", output)
        self.assertIn("P O R T W E F T", output)
        self.assertIn("--udp-ports", output)
        self.assertIn("--impacket", output)
        self.assertIn("--discovery", output)
        self.assertIn("--full", output)
        self.assertIn("--nuclei", output)
        self.assertIn("--discovery-backend", output)

    def test_full_dry_run_plans_all_stages_on_stderr_and_writes_nothing(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--full",
                        "--dry-run",
                        "--no-udp",
                        "--output-dir",
                        temp_dir,
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "")
            progress = stderr.getvalue()
            self.assertIn("Discovery backend:", progress)
            self.assertIn("Detailed service enumeration", progress)
            self.assertIn("Follow-up scans", progress)
            self.assertIn("Impacket recon", progress)
            self.assertIn("Nuclei CVE-only validation", progress)
            self.assertFalse((Path(temp_dir) / "scans").exists())
            self.assertFalse((Path(temp_dir) / "reports").exists())

    def test_full_and_no_follow_up_are_a_cli_conflict(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["127.0.0.1", "--full", "--no-follow-up", "--dry-run"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--full requires service-aware follow-ups", stderr.getvalue())

    def test_keyboard_interrupt_returns_standard_interrupt_exit_code(self) -> None:
        stderr = io.StringIO()
        with patch("portweft.cli.run", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["127.0.0.1"])

        self.assertEqual(exit_code, 130)
        self.assertIn("Interrupted by user", stderr.getvalue())

    def test_package_directory_invocation_prints_help(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, "portweft"],
            capture_output=True,
            cwd=repo_root,
            text=True,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("usage: portweft", completed.stderr)
        self.assertIn("targets", completed.stderr)

    def test_dry_run_prints_command_and_completes_without_nmap(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "-p",
                        "22,80",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                        "--",
                        "-T4",
                        "-Pn",
                    ]
                )

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("Initial Nmap scan starting", output)
            self.assertIn("-T4 -Pn --script banner -sV --version-light -p 22,80", output)
            self.assertIn("UDP companion scan complete: skipped because -p/--ports", output)
            self.assertNotIn("-sU", output)
            self.assertIn("Dry run complete", output)
            self.assertFalse((Path(temp_dir) / "scans").exists())
            self.assertFalse((Path(temp_dir) / "reports").exists())

    def test_explicit_ports_run_udp_only_when_ports_overlap_udp_defaults(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "-p",
                        "53,445",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("UDP companion scan starting", output)
            self.assertIn("-sU -p U:53", output)
            self.assertNotIn("U:53,67", output)

    def test_explicit_udp_ports_override_tcp_port_overlap_rule(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "-p",
                        "445",
                        "--udp-ports",
                        "53,123",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("UDP companion scan starting", output)
            self.assertIn("-sU -p U:53,123", output)

    def test_dry_run_resolves_domain_before_building_nmap_command(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
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
                with contextlib.redirect_stderr(stdout):
                    exit_code = main(
                        [
                            "example.test",
                            "--dry-run",
                            "--output-dir",
                            temp_dir,
                        ]
                    )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Targets: example.test", output)
        self.assertIn("Resolved scan targets: 198.51.100.10", output)
        self.assertIn("198.51.100.10", output)
        self.assertNotIn("example.test -sV", output)

    def test_dry_run_preserves_nmap_all_ports_shorthand(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "-p-",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("-p-", output)
        self.assertNotIn("-p -", output)

    def test_dry_run_accepts_port_ranges_and_comma_lists(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "-p",
                        "1-65335,65342",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("-p 1-65335,65342", output)
        self.assertIn("-sU -p U:", output)

    def test_top_ports_without_value_uses_nmap_default_count(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "--top-ports",
                        "127.0.0.1",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("--top-ports 1000", output)

    def test_top_ports_accepts_explicit_count(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--top-ports",
                        "10",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("--top-ports 10", output)

    def test_dash_prefixed_nmap_args_do_not_break_nmap_args_option(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--nmap-args",
                        "-T4",
                        "-Pn",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("-T4 -Pn --script banner", output)

    def test_nmap_args_with_values_can_appear_before_target(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "--nmap-args",
                        "--max-retries",
                        "2",
                        "127.0.0.1",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Resolved scan targets: 127.0.0.1", output)
        self.assertIn("--max-retries 2 --script banner", output)

    def test_malformed_nmap_args_exit_before_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.run_command") as run_command:
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(
                        [
                            "127.0.0.1",
                            "--nmap-args",
                            '"unterminated',
                            "--dry-run",
                            "--output-dir",
                            temp_dir,
                        ]
                    )

        self.assertEqual(exit_code, 2)
        self.assertIn("Could not parse --nmap-args", stderr.getvalue())
        run_command.assert_not_called()

    def test_nmap_args_cannot_swallow_portweft_options(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.run_command") as run_command:
                with contextlib.redirect_stderr(stderr):
                    exit_code = main(
                        [
                            "127.0.0.1",
                            "--nmap-args",
                            "unterminated --dry-run --output-dir "
                            f"{temp_dir}",
                        ]
                    )

        self.assertEqual(exit_code, 2)
        self.assertIn("cannot be embedded inside --nmap-args", stderr.getvalue())
        run_command.assert_not_called()

    def test_raw_nmap_args_with_values_can_appear_before_target(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "--max-retries",
                        "2",
                        "127.0.0.1",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Resolved scan targets: 127.0.0.1", output)
        self.assertIn("--max-retries 2 --script banner", output)

    def test_raw_nmap_value_cannot_swallow_following_portweft_option(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "--script",
                        "--json",
                        "127.0.0.1",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stderr.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("--script banner", output)
        self.assertNotIn("--json", output)

    def test_conflicting_ports_and_top_ports_exit_before_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.run_command") as run_command:
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        main(
                            [
                                "127.0.0.1",
                                "-p",
                                "80",
                                "--top-ports",
                                "10",
                                "--dry-run",
                                "--output-dir",
                                temp_dir,
                            ]
                        )

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Use either -p/--ports or --top-ports", stderr.getvalue())
        run_command.assert_not_called()

    def test_discovery_rejects_explicit_ports_and_top_ports(self) -> None:
        for port_args in (("-p", "80"), ("--top-ports", "10")):
            with self.subTest(port_args=port_args):
                stderr = io.StringIO()
                with patch("portweft.cli.run_command") as run_command:
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as raised:
                            main(
                                [
                                    "127.0.0.1",
                                    "--discovery",
                                    *port_args,
                                    "--dry-run",
                                ]
                            )

                self.assertEqual(raised.exception.code, 2)
                self.assertIn(
                    "Use --discovery without -p/--ports or --top-ports",
                    stderr.getvalue(),
                )
                run_command.assert_not_called()

    def test_discovery_rejects_raw_nmap_port_selection(self) -> None:
        stderr = io.StringIO()
        with patch("portweft.cli.run_command") as run_command:
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(
                        [
                            "127.0.0.1",
                            "--discovery",
                            "--dry-run",
                            "--",
                            "-p",
                            "80",
                        ]
                    )

        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "Use --discovery without -p/--ports or --top-ports",
            stderr.getvalue(),
        )
        run_command.assert_not_called()

    def test_no_udp_and_udp_ports_conflict_exit_before_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.run_command") as run_command:
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        main(
                            [
                                "127.0.0.1",
                                "--no-udp",
                                "--udp-ports",
                                "53",
                                "--dry-run",
                                "--output-dir",
                                temp_dir,
                            ]
                        )

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Use either --no-udp or --udp-ports", stderr.getvalue())
        run_command.assert_not_called()

    def test_large_cidr_requires_explicit_override(self) -> None:
        stderr = io.StringIO()
        with patch("portweft.cli.run_command") as run_command:
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main(["10.0.0.0/19", "--dry-run", "--no-udp"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--allow-large-scan", stderr.getvalue())
        run_command.assert_not_called()

    def test_large_cidr_override_allows_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stderr(stdout):
            exit_code = main(
                [
                    "10.0.0.0/19",
                    "--dry-run",
                    "--no-udp",
                    "--allow-large-scan",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("10.0.0.0/19", stdout.getvalue())

    def test_resolution_failure_skips_target_and_continues(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch(
                "portweft.targets.socket.getaddrinfo",
                side_effect=socket.gaierror("name not known"),
            ):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = main(
                        [
                            "missing.example,127.0.0.1",
                            "--dry-run",
                            "--output-dir",
                            temp_dir,
                        ]
                    )

        self.assertEqual(exit_code, 0)
        self.assertIn("DNS resolution failed for missing.example", stderr.getvalue())
        self.assertIn("Resolved scan targets: 127.0.0.1", stderr.getvalue())

    def test_missing_nmap_is_graceful_error_before_other_nmap_arg_validation(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--nmap-path",
                        "definitely-not-real-nmap",
                        "--output-dir",
                        temp_dir,
                        "--",
                        "-oX",
                        "conflict.xml",
                    ]
                )

            output = stderr.getvalue()
            self.assertEqual(exit_code, 127)
            self.assertIn("Nmap was not found", output)
            self.assertNotIn("owns Nmap output flags", output)

    def test_unmatched_banner_prints_graceful_message(self) -> None:
        observed_service = ServiceObservation(
            host="192.0.2.10",
            port=7777,
            protocol="tcp",
            state="open",
            service_name="unknown",
            product="MysteryThing",
            version="1.0",
        )

        stdout = io.StringIO()
        with contextlib.redirect_stderr(stdout):
            print_unmatched_service(observed_service)

        output = stdout.getvalue()
        self.assertIn("Service evidence observed but no follow-up profile matched", output)
        self.assertIn("MysteryThing", output)

    def test_no_udp_skips_udp_companion_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--dry-run",
                        "--no-udp",
                        "--output-dir",
                        temp_dir,
                    ]
                )

            output = stdout.getvalue()
            self.assertEqual(exit_code, 0)
            self.assertIn("UDP companion scan complete: skipped by --no-udp", output)
            self.assertNotIn("-sU", output)

    def test_discovery_dry_run_keeps_udp_companion_behavior(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stderr(stdout):
                exit_code = main(
                    [
                        "127.0.0.1",
                        "--discovery",
                        "--dry-run",
                        "--output-dir",
                        temp_dir,
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("TCP discovery scan starting", output)
        self.assertIn("-p-", output)
        self.assertIn("UDP companion scan starting", output)
        self.assertIn("-sU -p U:", output)
        self.assertIn("planned per host after discovery results", output)

    def test_discovery_enumerates_each_host_and_continues_after_failure(self) -> None:
        def host(address: str, *ports: int) -> HostObservation:
            return HostObservation(
                address=address,
                status="up",
                services=[
                    ServiceObservation(address, port, "tcp", "open") for port in ports
                ],
            )

        failed_host = host("192.0.2.10", 22)
        successful_host = host("192.0.2.11", 8443, 443)
        no_ports_host = host("192.0.2.12")
        detailed_host = host("192.0.2.11", 443, 8443)
        detailed_host.services[0].service_name = "https"
        detailed_host.services[0].product = "nginx"
        detailed_host.services[1].service_name = "https-alt"
        ok = SimpleNamespace(ok=True, exit_code=0)
        failed = SimpleNamespace(ok=False, exit_code=1)

        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.cli.run_command",
                    side_effect=[ok, failed, ok],
                ) as run_command:
                    with patch(
                        "portweft.cli.parse_nmap_xml",
                        side_effect=[
                            [failed_host, successful_host, no_ports_host],
                            [detailed_host],
                        ],
                    ):
                        with patch("portweft.cli.run_followups") as run_followups:
                            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                                stderr
                            ):
                                exit_code = main(
                                    [
                                        "192.0.2.10,192.0.2.11,192.0.2.12",
                                        "--discovery",
                                        "--no-udp",
                                        "--json",
                                        "--scan-timeout",
                                        "7",
                                        "--output-dir",
                                        temp_dir,
                                    ]
                                )

            commands = [call.args[0] for call in run_command.call_args_list]
            cumulative_path = next(
                (Path(temp_dir) / "reports").glob("*/CUMULATIVE-report.json")
            )
            cumulative = json.loads(cumulative_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(commands), 3)
        self.assertIn("-p-", commands[0])
        self.assertNotIn("-sV", commands[0])
        self.assertNotIn("--script", commands[0])
        self.assertEqual(commands[1][commands[1].index("-p") + 1], "22")
        self.assertEqual(commands[1][-1], "192.0.2.10")
        self.assertEqual(commands[2][commands[2].index("-p") + 1], "443,8443")
        self.assertEqual(commands[2][-1], "192.0.2.11")
        self.assertTrue(
            all(call.kwargs["timeout_seconds"] == 7.0 for call in run_command.call_args_list)
        )
        self.assertIn("continuing with other hosts", stderr.getvalue())
        self.assertEqual(cumulative["scan_mode"], "discovery")
        by_address = {host["address"]: host for host in cumulative["hosts"]}
        self.assertEqual(by_address["192.0.2.10"]["services"][0]["port"], 22)
        self.assertEqual(
            by_address["192.0.2.11"]["services"][0]["product"],
            "nginx",
        )
        self.assertNotIn("192.0.2.12", by_address)
        run_followups.assert_called_once()

    def test_impacket_missing_exits_before_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.cli.ensure_impacket_package",
                    return_value=ImpacketAvailability(
                        available=False,
                        reason="Install with pip install .[impacket]",
                    ),
                ):
                    with patch("portweft.cli.run_command") as run_command:
                        with contextlib.redirect_stderr(stderr):
                            exit_code = main(
                                [
                                    "127.0.0.1",
                                    "--impacket",
                                    "--output-dir",
                                    temp_dir,
                                ]
                            )

        self.assertEqual(exit_code, 1)
        self.assertIn("Install with pip install .[impacket]", stderr.getvalue())
        run_command.assert_not_called()

    def test_nuclei_missing_exits_before_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.nuclei_runner.resolve_executable",
                    return_value=None,
                ):
                    with patch("portweft.cli.run_command") as run_command:
                        with contextlib.redirect_stderr(stderr):
                            exit_code = main(
                                [
                                    "127.0.0.1",
                                    "--nuclei",
                                    "--output-dir",
                                    temp_dir,
                                ]
                            )
        self.assertEqual(exit_code, 127)
        self.assertIn("Nuclei was not found", stderr.getvalue())
        run_command.assert_not_called()

    def test_json_flag_writes_json_reports_without_text_reports(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            status="up",
            services=[
                ServiceObservation(
                    host="192.0.2.10",
                    port=80,
                    protocol="tcp",
                    state="open",
                    service_name="http",
                    scripts={"banner": "HTTP/1.1 200 OK"},
                )
            ],
        )
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.cli.run_command",
                    return_value=SimpleNamespace(ok=True, exit_code=0),
                ):
                    with patch("portweft.cli.parse_nmap_xml", return_value=[host]):
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                            stderr
                        ):
                            exit_code = main(
                                [
                                    "192.0.2.10",
                                    "--json",
                                    "--no-udp",
                                    "--no-follow-up",
                                    "--output-dir",
                                    temp_dir,
                                ]
                            )

            report_root = Path(temp_dir) / "reports"
            json_reports = sorted(report_root.glob("*/*.json"))
            text_reports = sorted(report_root.glob("*/*.txt"))
            cumulative = json.loads(
                next(path for path in json_reports if path.name == "CUMULATIVE-report.json")
                .read_text(encoding="utf-8")
            )
            cumulative_text = next(
                path for path in json_reports if path.name == "CUMULATIVE-report.json"
            ).read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout.getvalue()), cumulative)
        self.assertEqual(stdout.getvalue(), cumulative_text)
        self.assertNotIn("P O R T W E F T", stdout.getvalue())
        self.assertIn("P O R T W E F T", stderr.getvalue())
        self.assertEqual(len(json_reports), 2)
        self.assertEqual(text_reports, [])
        self.assertEqual(cumulative["target"], "192.0.2.10")
        self.assertEqual(cumulative["resolved_ip"], "192.0.2.10")
        banner = cumulative["hosts"][0]["services"][0]["nse_results"]["banner"]
        self.assertEqual(banner, "HTTP/1.1 200 OK")
        self.assertEqual(
            cumulative["impacket_status"],
            "not requested (--impacket not used)",
        )
        self.assertNotIn("scan_mode", cumulative)

    def test_text_stdout_matches_saved_cumulative_report(self) -> None:
        host = HostObservation(address="192.0.2.10", status="up")
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.cli.run_command",
                    return_value=SimpleNamespace(ok=True, exit_code=0),
                ):
                    with patch("portweft.cli.parse_nmap_xml", return_value=[host]):
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                            stderr
                        ):
                            exit_code = main(
                                [
                                    "192.0.2.10",
                                    "--no-udp",
                                    "--no-follow-up",
                                    "--output-dir",
                                    temp_dir,
                                ]
                            )
            cumulative_path = next(
                (Path(temp_dir) / "reports").glob("*/CUMULATIVE-report.txt")
            )
            cumulative = cumulative_path.read_text(encoding="utf-8")
        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), cumulative)
        self.assertIn("Initial Nmap scan starting", stderr.getvalue())

    def test_cleanup_failure_after_reports_does_not_fail_completed_scan(self) -> None:
        host = HostObservation(address="192.0.2.10", status="up")
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("portweft.cli.ensure_nmap_available"):
                with patch(
                    "portweft.cli.run_command",
                    return_value=SimpleNamespace(ok=True, exit_code=0),
                ):
                    with patch("portweft.cli.parse_nmap_xml", return_value=[host]):
                        with patch(
                            "portweft.cli.cleanup_scan_outputs",
                            side_effect=OutputDirectoryError("scan-dir", "locked"),
                        ):
                            with contextlib.redirect_stdout(stdout):
                                with contextlib.redirect_stderr(stderr):
                                    exit_code = main(
                                        [
                                            "192.0.2.10",
                                            "--no-udp",
                                            "--no-follow-up",
                                            "--output-dir",
                                            temp_dir,
                                        ]
                                    )

        self.assertEqual(exit_code, 0)
        self.assertIn("Could not prepare output directory", stderr.getvalue())
        self.assertIn("Temporary XML cleanup failed", stderr.getvalue())

    def test_prune_old_runs_keeps_newest_outputs(self) -> None:
        with temporary_directory() as temp_dir:
            output_root = Path(temp_dir)
            scan_root = output_root / "scans"
            report_root = output_root / "reports"
            scan_root.mkdir()
            report_root.mkdir()
            for run_id in ("20260101-000000Z", "20260102-000000Z"):
                (scan_root / run_id).mkdir()
                (report_root / f"{run_id}.txt").write_text("report", encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()):
                prune_old_runs(output_root, keep_runs=1)

            self.assertFalse((scan_root / "20260101-000000Z").exists())
            self.assertFalse((report_root / "20260101-000000Z.txt").exists())
            self.assertTrue((scan_root / "20260102-000000Z").exists())
            self.assertTrue((report_root / "20260102-000000Z.txt").exists())

    def test_prune_old_runs_keeps_newest_report_directory(self) -> None:
        with temporary_directory() as temp_dir:
            output_root = Path(temp_dir)
            report_root = output_root / "reports"
            report_root.mkdir()
            for run_id in ("20260101-000000Z", "20260102-000000Z"):
                run_report_dir = report_root / run_id
                run_report_dir.mkdir()
                (run_report_dir / "CUMULATIVE-report.txt").write_text(
                    "report",
                    encoding="utf-8",
                )

            with contextlib.redirect_stderr(io.StringIO()):
                prune_old_runs(output_root, keep_runs=1)

            self.assertFalse((report_root / "20260101-000000Z").exists())
            self.assertTrue((report_root / "20260102-000000Z").exists())

    def test_unique_run_id_does_not_reuse_existing_report_directory(self) -> None:
        with temporary_directory() as temp_dir:
            output_root = Path(temp_dir)
            existing_report_dir = (
                output_root
                / "reports"
                / "20260429-201530-000000Z"
            )
            existing_report_dir.mkdir(parents=True)
            scan_started_at = dt.datetime(
                2026,
                4,
                29,
                20,
                15,
                30,
                tzinfo=dt.timezone.utc,
            )

            self.assertEqual(
                unique_run_id(output_root, scan_started_at),
                "20260429-201530-000000Z-2",
            )

    def test_cleanup_scan_outputs_removes_temporary_xml_directory(self) -> None:
        with temporary_directory() as temp_dir:
            scan_root = Path(temp_dir) / "scans"
            scan_dir = scan_root / "20260429-201530-000000Z"
            scan_dir.mkdir(parents=True)
            (scan_dir / "20260429-201530-000000Z-initial.xml").write_text(
                "<nmaprun />",
                encoding="utf-8",
            )

            cleanup_scan_outputs(scan_dir)

            self.assertFalse(scan_dir.exists())
            self.assertFalse(scan_root.exists())


if __name__ == "__main__":
    unittest.main()
