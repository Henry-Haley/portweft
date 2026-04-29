from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from portweft.errors import ImpacketUnavailableError
import portweft.impacket_runner as impacket_runner
from portweft.cli import run_impacket_recon
from portweft.impacket_runner import (
    ImpacketAvailability,
    ImpacketResult,
    build_impacket_command,
    ensure_impacket_package,
    import_impacket_package,
    module_supports_service,
    modules_for_profile,
    run_impacket_command,
    run_impacket_module,
)
from portweft.models import HostObservation, ServiceObservation


def smb_service(port: int = 445) -> ServiceObservation:
    return ServiceObservation(
        host="192.0.2.10",
        port=port,
        protocol="tcp",
        state="open",
        service_name="microsoft-ds",
        product="Microsoft Windows SMB",
    )


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


class ImpacketRunnerTests(unittest.TestCase):
    def test_smb_profile_has_safe_impacket_recon_modules(self) -> None:
        self.assertEqual(modules_for_profile("smb"), ["samrdump", "rpcdump"])

    def test_import_impacket_package_reports_available_package(self) -> None:
        fake_module = SimpleNamespace(__version__="0.12.0")
        with patch(
            "portweft.impacket_runner.importlib.import_module",
            return_value=fake_module,
        ) as import_module:
            availability = import_impacket_package()

        import_module.assert_called_once_with("impacket")
        self.assertTrue(availability.available)
        self.assertEqual(availability.version, "0.12.0")

    def test_import_impacket_package_reports_missing_package(self) -> None:
        with patch(
            "portweft.impacket_runner.importlib.import_module",
            side_effect=ImportError("No module named impacket"),
        ):
            availability = import_impacket_package()

        self.assertFalse(availability.available)
        self.assertIn("not importable", availability.reason)
        self.assertIn(".[impacket]", availability.reason)

    def test_ensure_impacket_package_reports_missing_without_installing(self) -> None:
        with patch.object(
            impacket_runner.importlib,
            "import_module",
            side_effect=ImportError("No module named impacket"),
        ):
            with patch.object(impacket_runner.subprocess, "Popen") as popen:
                availability = ensure_impacket_package()

        popen.assert_not_called()
        self.assertFalse(availability.available)
        self.assertIn("Install with pip install .[impacket]", availability.reason)

    def test_module_supports_only_expected_tcp_ports(self) -> None:
        self.assertTrue(module_supports_service("samrdump", smb_service(445)))
        self.assertFalse(module_supports_service("samrdump", smb_service(9445)))
        self.assertFalse(
            module_supports_service(
                "samrdump",
                ServiceObservation(
                    host="192.0.2.10",
                    port=445,
                    protocol="udp",
                    state="open",
                ),
            )
        )

    def test_build_impacket_command_uses_target_ip_port_and_no_pass(self) -> None:
        command = build_impacket_command("samrdump", "impacket-samrdump", smb_service())

        self.assertEqual(
            command,
            [
                "impacket-samrdump",
                "-target-ip",
                "192.0.2.10",
                "-port",
                "445",
                "-no-pass",
                "192.0.2.10",
            ],
        )

    def test_missing_impacket_tool_is_skipped_without_error(self) -> None:
        with patch("portweft.impacket_runner.shutil.which", return_value=None):
            result = run_impacket_module("samrdump", smb_service())

        self.assertTrue(result.skipped)
        self.assertEqual(result.exit_code, 127)
        self.assertIn("not found", result.reason)

    def test_run_impacket_command_captures_bounded_output(self) -> None:
        process = FakeProcess(returncode=0, stdout=f"line 1\n{'x' * 80}\n")
        with patch("portweft.impacket_runner.subprocess.Popen", return_value=process):
            with contextlib.redirect_stdout(io.StringIO()):
                result = run_impacket_command(
                    "samrdump",
                    ["impacket-samrdump", "192.0.2.10"],
                    max_output_chars=32,
                )

        self.assertTrue(result.ok)
        self.assertIn("line 1", result.output)
        self.assertIn("truncated", result.output)

    def test_cli_impacket_recon_attaches_module_output_to_service(self) -> None:
        service = smb_service()
        host = HostObservation(address="192.0.2.10", services=[service])
        parsed = SimpleNamespace(max_impacket_output_chars=4096)

        def fake_runner(
            module_name: str,
            _service: ServiceObservation,
            _max_chars: int,
            _timeout_seconds=None,
        ) -> ImpacketResult:
            return ImpacketResult(
                module_name=module_name,
                exit_code=0,
                output=f"{module_name} output",
            )

        with patch("portweft.cli.run_impacket_module", side_effect=fake_runner):
            with patch(
                "portweft.cli.ensure_impacket_package",
                return_value=ImpacketAvailability(available=True, version="0.12.0"),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    status = run_impacket_recon(parsed, [host])

        self.assertEqual(status, "completed")
        self.assertEqual(service.scripts["impacket-samrdump"], "samrdump output")
        self.assertEqual(service.scripts["impacket-rpcdump"], "rpcdump output")

    def test_cli_impacket_recon_exits_when_package_is_missing(self) -> None:
        service = smb_service()
        host = HostObservation(address="192.0.2.10", services=[service])
        parsed = SimpleNamespace(max_impacket_output_chars=4096)

        with patch(
            "portweft.cli.ensure_impacket_package",
            return_value=ImpacketAvailability(
                available=False,
                reason="Install with pip install .[impacket]",
            ),
        ):
            with patch("portweft.cli.run_impacket_module") as run_module:
                with self.assertRaises(ImpacketUnavailableError):
                    run_impacket_recon(parsed, [host])

        run_module.assert_not_called()
        self.assertEqual(service.scripts, {})


if __name__ == "__main__":
    unittest.main()
