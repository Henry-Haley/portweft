"""Shared subprocess waiting, heartbeat, and termination behavior."""

from __future__ import annotations

import subprocess
import os
import signal
import time

from portweft.utils import print_elapsed_step


COMMAND_TIMEOUT_EXIT_CODE = 124


def subprocess_group_kwargs() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def wait_for_process(
    process: subprocess.Popen,
    timeout_seconds: float | None = None,
    stats_every: float = 0,
    stage: str = "external command",
) -> tuple[int, bool]:
    started = time.monotonic()
    deadline = started + timeout_seconds if timeout_seconds is not None else None
    next_heartbeat = started + stats_every if stats_every > 0 else None

    while True:
        now = time.monotonic()
        waits = [value for value in (deadline, next_heartbeat) if value is not None]
        wait_until = min(waits) if waits else None
        wait_timeout = None if wait_until is None else max(0, wait_until - now)
        waiting_for_deadline = deadline is not None and wait_until == deadline
        try:
            return process.wait(timeout=wait_timeout), False
        except subprocess.TimeoutExpired:
            if waiting_for_deadline:
                terminate_process(process)
                return COMMAND_TIMEOUT_EXIT_CODE, True
            elapsed = time.monotonic() - started
            print_elapsed_step(elapsed, f"{stage} running")
            next_heartbeat = time.monotonic() + stats_every
        except KeyboardInterrupt:
            terminate_process(process)
            raise


def terminate_process(process: subprocess.Popen) -> None:
    grouped = terminate_process_group(process)
    if grouped:
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            terminate_process_group(process, force=True)
        except OSError:
            return

    try:
        process.terminate()
    except OSError:
        try:
            process.kill()
        except OSError:
            return
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def terminate_process_group(process: subprocess.Popen, force: bool = False) -> bool:
    pid = getattr(process, "pid", None)
    if not pid:
        return False
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return True
        except OSError:
            return False
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL if force else signal.SIGTERM)
        return True
    except OSError:
        return False


def close_process_streams(process: subprocess.Popen) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass
