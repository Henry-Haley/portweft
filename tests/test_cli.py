from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path

from portweft.cli import main, print_unmatched_service, prune_old_runs
from portweft.models import ServiceObservation
from tests.helpers import temporary_directory


class CliTests(unittest.TestCase):
    def test_no_args_prints_help_and_exits_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main([])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("usage: portweft", output)
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
        self.assertIn("--udp-ports", output)

    def test_package_directory_invocation_prints_help(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, "portweft"],
            capture_output=True,
            cwd=repo_root,
            text=True,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertIn("usage: portweft", completed.stdout)
        self.assertIn("targets", completed.stdout)

    def test_dry_run_prints_command_and_completes_without_nmap(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
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
            self.assertIn("-T4 -Pn -sV --version-light -p 22,80", output)
            self.assertIn("UDP companion scan starting", output)
            self.assertIn("-sU -p U:", output)
            self.assertIn("Dry run complete", output)
            self.assertFalse((Path(temp_dir) / "scans").exists())
            self.assertFalse((Path(temp_dir) / "reports").exists())

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
        with contextlib.redirect_stdout(stdout):
            print_unmatched_service(observed_service)

        output = stdout.getvalue()
        self.assertIn("Service evidence observed but no follow-up profile matched", output)
        self.assertIn("MysteryThing", output)

    def test_no_udp_skips_udp_companion_scan(self) -> None:
        with temporary_directory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
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

            with contextlib.redirect_stdout(io.StringIO()):
                prune_old_runs(output_root, keep_runs=1)

            self.assertFalse((scan_root / "20260101-000000Z").exists())
            self.assertFalse((report_root / "20260101-000000Z.txt").exists())
            self.assertTrue((scan_root / "20260102-000000Z").exists())
            self.assertTrue((report_root / "20260102-000000Z.txt").exists())


if __name__ == "__main__":
    unittest.main()
