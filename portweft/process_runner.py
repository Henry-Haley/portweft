"""Shared subprocess waiting, heartbeat, and termination behavior."""

from __future__ import annotations

import subprocess
import time

from portweft.utils import print_elapsed_step


COMMAND_TIMEOUT_EXIT_CODE = 124


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
    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    except OSError:
        pass


def close_process_streams(process: subprocess.Popen) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass
