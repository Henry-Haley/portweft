from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from portweft.cli import main, print_unmatched_service
from portweft.models import ServiceObservation
from tests.helpers import temporary_directory


class CliTests(unittest.TestCase):
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
            self.assertTrue((Path(temp_dir) / "scans").exists())
            self.assertTrue((Path(temp_dir) / "reports").exists())

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


if __name__ == "__main__":
    unittest.main()
