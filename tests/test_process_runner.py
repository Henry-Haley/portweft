from __future__ import annotations

import ctypes
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
from portweft.discovery_runner import run_external_command


def process_is_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_uint32()
        queried = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        return bool(queried) and exit_code.value == 259
    finally:
        kernel32.CloseHandle(handle)


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
                alive = bool(child_pid and process_is_alive(child_pid))
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
        self.assertIsNotNone(child_pid)
        self.assertFalse(alive)

    def test_parent_exit_does_not_wait_for_or_orphan_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "child.pid"
            child_code = (
                "import os,time,pathlib; "
                f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); "
                "time.sleep(5)"
            )
            parent_code = (
                "import pathlib,subprocess,sys,time; "
                f"marker=pathlib.Path({str(marker)!r}); "
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                "deadline=time.monotonic()+2; "
                "exec('while not marker.exists() and time.monotonic() < deadline: time.sleep(0.01)')"
            )
            started = time.monotonic()
            result = run_external_command(
                [sys.executable, "-c", parent_code], 10, 0, "descendant exit"
            )
            elapsed = time.monotonic() - started
            child_pid = int(marker.read_text())

        self.assertEqual(result.exit_code, 0)
        self.assertLess(elapsed, 3)
        self.assertFalse(process_is_alive(child_pid))


if __name__ == "__main__":
    unittest.main()
