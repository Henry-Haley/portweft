from __future__ import annotations

import unittest

from portweft.process_runner import terminate_process


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


if __name__ == "__main__":
    unittest.main()
