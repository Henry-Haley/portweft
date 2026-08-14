from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from portweft.process_runner import (
    subprocess_group_kwargs,
    terminate_process,
    wait_for_process,
)


class ProcessRunnerTests(unittest.TestCase):
    def test_terminate_oserror_falls_back_to_kill(self) -> None:
        class Process:
            killed = False

            def terminate(self) -> None:
                raise OSError("terminate failed")

            def kill(self) -> None:
                self.killed = True

            def wait(self, timeout: float) -> int:
                _ = timeout
                return 0

        process = Process()

        terminate_process(process)  # type: ignore[arg-type]

        self.assertTrue(process.killed)

    def test_timeout_terminates_spawned_process_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "child.pid"
            child_code = (
                "import os,time,pathlib; "
                f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); "
                "time.sleep(60)"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                "time.sleep(60)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", parent_code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **subprocess_group_kwargs(),
            )
            child_pid = None
            alive = False
            try:
                exit_code, timed_out = wait_for_process(process, 0.5)
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                child_pid = int(marker.read_text()) if marker.exists() else None
                alive = False
                if child_pid:
                    try:
                        os.kill(child_pid, 0)
                        alive = True
                    except OSError:
                        pass
            finally:
                if child_pid and alive:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    else:
                        os.kill(child_pid, 9)

        self.assertEqual(exit_code, 124)
        self.assertTrue(timed_out)
        self.assertFalse(alive)


if __name__ == "__main__":
    unittest.main()
