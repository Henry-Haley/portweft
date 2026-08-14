"""Shared subprocess waiting, heartbeat, and termination behavior."""

from __future__ import annotations

import ctypes
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


def attach_process_group(process: subprocess.Popen) -> None:
    if os.name != "nt" or not getattr(process, "_handle", None):
        return
    job = _create_windows_kill_job()
    if not job:
        return
    kernel32 = ctypes.windll.kernel32
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    if kernel32.AssignProcessToJobObject(job, process._handle):
        process._portweft_job = job
    else:
        kernel32.CloseHandle(job)


def _create_windows_kill_job() -> int:
    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32
    ]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return 0
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000
    if kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        return job
    kernel32.CloseHandle(job)
    return 0


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
            if os.name != "nt":
                terminate_process_group(process, force=True)
            return
        except subprocess.TimeoutExpired:
            terminate_process_group(process, force=True)
        except OSError:
            if os.name != "nt":
                terminate_process_group(process, force=True)
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
        job = getattr(process, "_portweft_job", None)
        if job:
            ctypes.windll.kernel32.CloseHandle(job)
            process._portweft_job = None
            return True
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return result.returncode == 0
        except OSError:
            return False
    try:
        os.killpg(pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except OSError:
        return False


def close_process_group(process: subprocess.Popen) -> None:
    if os.name == "nt":
        job = getattr(process, "_portweft_job", None)
        if job:
            ctypes.windll.kernel32.CloseHandle(job)
            process._portweft_job = None
        return
    terminate_process_group(process, force=True)


def close_process_streams(process: subprocess.Popen) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass
