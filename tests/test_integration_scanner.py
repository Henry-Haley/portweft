from __future__ import annotations

import contextlib
import io
import socket
import threading
import unittest
from pathlib import Path

from portweft.cli import main
from portweft.nmap_runner import resolve_nmap_path
from tests.helpers import temporary_directory


class LocalScannerIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(resolve_nmap_path("nmap"), "Nmap is not available")
    def test_local_listener_open_port_and_closed_port_reporting(self) -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        open_port = listener.getsockname()[1]
        listener.listen(8)
        listener.settimeout(0.2)
        closed_port = reserve_closed_port()
        stop = threading.Event()

        def serve() -> None:
            while not stop.is_set():
                try:
                    connection, _address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with connection:
                    connection.sendall(b"PortWeft integration listener\r\n")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with temporary_directory() as temp_dir:
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = main(
                        [
                            "127.0.0.1",
                            "-p",
                            f"{open_port},{closed_port}",
                            "--no-udp",
                            "--no-follow-up",
                            "--output-dir",
                            temp_dir,
                        ]
                    )

                report_text = "\n".join(
                    path.read_text(encoding="utf-8")
                    for path in sorted((Path(temp_dir) / "reports").glob("*/*.txt"))
                )
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=1)

        self.assertEqual(exit_code, 0)
        self.assertIn(f"{open_port}/tcp", report_text)
        self.assertNotIn(f"{closed_port}/tcp", report_text)


def reserve_closed_port() -> int:
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


if __name__ == "__main__":
    unittest.main()
