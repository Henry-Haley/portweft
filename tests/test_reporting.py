from __future__ import annotations

import datetime as dt
import unittest
from pathlib import Path

from portweft.models import HostObservation, ServiceObservation
from portweft.reporting import CUMULATIVE_REPORT_NAME, write_report, write_reports
from tests.helpers import temporary_directory


class ReportingTests(unittest.TestCase):
    def test_write_report_includes_host_os_service_and_script_output(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            hostname="linux.example",
            status="up",
            os_family="unix",
            os_name="Linux 5.4 - 5.15",
            os_accuracy="93",
            services=[
                ServiceObservation(
                    host="192.0.2.10",
                    port=2222,
                    protocol="tcp",
                    state="open",
                    service_name="unknown",
                    product="OpenSSH",
                    version="9.6",
                    scripts={
                        "ssh-hostkey": "fingerprint",
                        "impacket-samrdump": "SAMR users observed",
                    },
                )
            ],
        )

        with temporary_directory() as temp_dir:
            report_path = Path(temp_dir) / "report.txt"
            write_report(
                report_path,
                ["192.0.2.10"],
                Path("initial.xml"),
                [host],
            )

            report = report_path.read_text(encoding="utf-8")

        self.assertIn("PortWeft Report", report)
        self.assertIn("192.0.2.10 (linux.example)", report)
        self.assertIn("Linux 5.4 - 5.15 (93% accuracy)", report)
        self.assertIn("2222/tcp unknown OpenSSH 9.6 [profiles: ssh]", report)
        self.assertIn("ssh-hostkey:", report)
        self.assertIn("fingerprint", report)
        self.assertIn("impacket-samrdump:", report)
        self.assertIn("SAMR users observed", report)

    def test_write_reports_creates_per_host_and_cumulative_reports(self) -> None:
        scan_started_at = dt.datetime(2026, 4, 29, 20, 15, 30, tzinfo=dt.timezone.utc)
        responding_host = HostObservation(
            address="192.0.2.10",
            hostname="linux.example",
            status="up",
            services=[
                ServiceObservation(
                    host="192.0.2.10",
                    port=22,
                    protocol="tcp",
                    state="open",
                    service_name="ssh",
                    product="OpenSSH",
                    scripts={
                        "ssh-hostkey": "fingerprint",
                        "impacket-rpcdump": "rpc output",
                    },
                )
            ],
        )
        silent_host = HostObservation(address="192.0.2.99", status="down")

        with temporary_directory() as temp_dir:
            report_dir = Path(temp_dir) / "reports" / "20260429-201530-000000Z"
            written = write_reports(
                report_dir,
                ["192.0.2.0/24"],
                scan_started_at,
                [responding_host, silent_host],
            )

            cumulative_path = report_dir / CUMULATIVE_REPORT_NAME
            host_path = report_dir / "192.0.2.10-report.txt"
            silent_path = report_dir / "192.0.2.99-report.txt"
            cumulative_exists = cumulative_path.exists()
            host_exists = host_path.exists()
            silent_exists = silent_path.exists()
            host_report = host_path.read_text(encoding="utf-8")

        self.assertEqual(set(written), {cumulative_path, host_path})
        self.assertTrue(cumulative_exists)
        self.assertTrue(host_exists)
        self.assertFalse(silent_exists)
        self.assertIn("Scan started (GMT): 2026-04-29 20:15:30 GMT", host_report)
        self.assertIn("Temporary XML: removed after parsing", host_report)
        self.assertNotIn(".xml", host_report)
        self.assertIn("NMAP OUTPUT:", host_report)
        self.assertIn("IMPACKET RESULTS:", host_report)
        self.assertLess(
            host_report.index("NMAP OUTPUT:"),
            host_report.index("IMPACKET RESULTS:"),
        )
        nmap_section, impacket_section = host_report.split("IMPACKET RESULTS:", 1)
        self.assertIn("22/tcp ssh OpenSSH [profiles: ssh]", nmap_section)
        self.assertIn("ssh-hostkey:", nmap_section)
        self.assertNotIn("impacket-rpcdump:", nmap_section)
        self.assertIn("impacket-rpcdump:", impacket_section)
        self.assertIn("rpc output", impacket_section)


if __name__ == "__main__":
    unittest.main()
