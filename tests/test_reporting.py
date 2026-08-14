from __future__ import annotations

import datetime as dt
import json
import unittest
from pathlib import Path

from portweft.models import HostObservation, NucleiFinding, ServiceObservation
from portweft.reporting import (
    CUMULATIVE_JSON_REPORT_NAME,
    CUMULATIVE_REPORT_NAME,
    write_json_reports,
    write_report,
    write_reports,
)
from portweft.targets import TargetResolution
from tests.helpers import temporary_directory


class ReportingTests(unittest.TestCase):
    def test_text_report_renders_grouped_nuclei_findings(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            status="up",
            nuclei_findings=[
                NucleiFinding(
                    template_id="CVE-2021-41773",
                    name="Apache HTTP Server Path Traversal",
                    severity="high",
                    matched_at="http://192.0.2.10:80/icons/.%2e/",
                    host="192.0.2.10",
                    port=80,
                )
            ],
        )
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "report.txt"
            write_report(
                path,
                ["192.0.2.10"],
                Path("initial.xml"),
                [host],
                nuclei_status="completed",
            )
            report = path.read_text(encoding="utf-8")
        self.assertIn("NUCLEI CVE RESULTS:", report)
        self.assertIn("80/tcp:", report)
        self.assertIn("[HIGH] CVE-2021-41773", report)
        self.assertIn("Apache HTTP Server Path Traversal", report)

    def test_text_report_has_explicit_no_nuclei_findings_case(self) -> None:
        host = HostObservation(address="192.0.2.10", status="up")
        with temporary_directory() as temp_dir:
            path = Path(temp_dir) / "report.txt"
            write_report(path, ["192.0.2.10"], Path("initial.xml"), [host])
            report = path.read_text(encoding="utf-8")
        nuclei_section = report.split("NUCLEI CVE RESULTS:", 1)[1]
        self.assertIn("none observed", nuclei_section)

    def test_json_report_exposes_structured_nuclei_findings_and_stage_status(self) -> None:
        host = HostObservation(
            address="192.0.2.10",
            status="up",
            nuclei_findings=[
                NucleiFinding(
                    template_id="CVE-2024-0001",
                    name="Example",
                    severity="medium",
                    matched_at="192.0.2.10:445",
                    host="192.0.2.10",
                    port=445,
                    reference=["https://example.test/CVE-2024-0001"],
                )
            ],
        )
        resolution = TargetResolution("192.0.2.10", ("192.0.2.10",))
        with temporary_directory() as temp_dir:
            written = write_json_reports(
                Path(temp_dir),
                [resolution],
                dt.datetime.now(dt.timezone.utc),
                [host],
                nuclei_status="completed",
            )
            document = json.loads(written[0].read_text(encoding="utf-8"))
        finding = document["hosts"][0]["nuclei_findings"][0]
        self.assertEqual(document["nuclei_status"], "completed")
        self.assertEqual(finding["template_id"], "CVE-2024-0001")
        self.assertEqual(finding["port"], 445)

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
        self.assertNotIn("Scan mode:", report)
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
            original_target="linux.example",
            resolved_ip="192.0.2.10",
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
        no_ports_host = HostObservation(
            address="192.0.2.11",
            original_target="empty.example",
            resolved_ip="192.0.2.11",
            status="up",
        )
        silent_host = HostObservation(address="192.0.2.99", status="down")

        with temporary_directory() as temp_dir:
            report_dir = Path(temp_dir) / "reports" / "20260429-201530-000000Z"
            written = write_reports(
                report_dir,
                ["192.0.2.0/24"],
                scan_started_at,
                [responding_host, no_ports_host, silent_host],
                "not requested (--impacket not used)",
                discovery_mode=True,
            )

            cumulative_path = report_dir / CUMULATIVE_REPORT_NAME
            host_path = report_dir / "192.0.2.10-report.txt"
            no_ports_path = report_dir / "192.0.2.11-report.txt"
            silent_path = report_dir / "192.0.2.99-report.txt"
            cumulative_exists = cumulative_path.exists()
            host_exists = host_path.exists()
            no_ports_exists = no_ports_path.exists()
            silent_exists = silent_path.exists()
            host_report = host_path.read_text(encoding="utf-8")
            no_ports_report = no_ports_path.read_text(encoding="utf-8")

        self.assertEqual(set(written), {cumulative_path, host_path, no_ports_path})
        self.assertTrue(cumulative_exists)
        self.assertTrue(host_exists)
        self.assertTrue(no_ports_exists)
        self.assertFalse(silent_exists)
        self.assertIn("Scan started (GMT): 2026-04-29 20:15:30 GMT", host_report)
        self.assertIn("Scan mode: discovery", host_report)
        self.assertIn("linux.example -> 192.0.2.10", host_report)
        self.assertIn("Temporary XML: removed after parsing", host_report)
        self.assertNotIn(".xml", host_report)
        self.assertIn("NMAP OUTPUT:", host_report)
        self.assertIn("IMPACKET RESULTS:", host_report)
        self.assertIn("Status: not requested (--impacket not used)", host_report)
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
        self.assertIn("empty.example -> 192.0.2.11", no_ports_report)
        self.assertIn("none observed", no_ports_report)

    def test_write_json_reports_outputs_parseable_structured_data(self) -> None:
        scan_started_at = dt.datetime(2026, 4, 29, 20, 15, 30, tzinfo=dt.timezone.utc)
        host = HostObservation(
            address="198.51.100.10",
            original_target="example.test",
            resolved_ip="198.51.100.10",
            status="up",
            services=[
                ServiceObservation(
                    host="198.51.100.10",
                    port=445,
                    protocol="tcp",
                    state="open",
                    service_name="microsoft-ds",
                    product="Microsoft Windows SMB",
                    scripts={
                        "smb2-security-mode": "signing not required",
                        "impacket-samrdump": "users observed",
                    },
                )
            ],
        )
        resolutions = [
            TargetResolution(
                original="example.test",
                addresses=("198.51.100.10",),
            )
        ]

        with temporary_directory() as temp_dir:
            report_dir = Path(temp_dir) / "reports"
            written = write_json_reports(
                report_dir,
                resolutions,
                scan_started_at,
                [host],
                "completed",
                discovery_mode=True,
            )
            cumulative = json.loads(
                (report_dir / CUMULATIVE_JSON_REPORT_NAME).read_text(encoding="utf-8")
            )
            host_report = json.loads(
                (report_dir / "198.51.100.10-report.json").read_text(encoding="utf-8")
            )

        self.assertEqual(len(written), 2)
        self.assertEqual(host_report["target"], "example.test")
        self.assertEqual(host_report["resolved_ip"], "198.51.100.10")
        self.assertEqual(host_report["impacket_status"], "completed")
        self.assertEqual(host_report["scan_mode"], "discovery")
        service = host_report["hosts"][0]["services"][0]
        self.assertIn("smb", service["matched_profiles"])
        self.assertEqual(service["nse_results"]["smb2-security-mode"], "signing not required")
        self.assertEqual(service["impacket_results"]["impacket-samrdump"], "users observed")
        self.assertEqual(cumulative["targets"][0]["target"], "example.test")

    def test_text_reports_strip_terminal_control_sequences(self) -> None:
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
                    scripts={"banner": "\x1b[31mred\x1b[0m\rcontrol"},
                )
            ],
        )

        with temporary_directory() as temp_dir:
            report_path = Path(temp_dir) / "report.txt"
            write_report(report_path, ["192.0.2.10"], Path("initial.xml"), [host])
            report = report_path.read_text(encoding="utf-8")

        self.assertNotIn("\x1b", report)
        self.assertNotIn("\r", report)
        self.assertIn("red", report)
        self.assertIn("control", report)


if __name__ == "__main__":
    unittest.main()
