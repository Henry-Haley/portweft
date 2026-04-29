"""Run PortWeft with `python -m portweft`."""

from __future__ import annotations

import sys
from pathlib import Path


try:
    from portweft.cli import main
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from portweft.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
