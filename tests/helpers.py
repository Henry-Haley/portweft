from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path


TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


@contextmanager
def temporary_directory() -> Iterator[str]:
    TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = TEST_TMP_ROOT / f"case-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield str(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)
