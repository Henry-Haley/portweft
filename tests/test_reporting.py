from __future__ import annotations

import unittest
from pathlib import Path

from portweft.models import HostObservation, ServiceObservation
from portweft.reporting import write_report
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
                    scripts={"ssh-hostkey": "fingerprint"},
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


if __name__ == "__main__":
    unittest.main()
