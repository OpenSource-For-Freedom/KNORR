#!/usr/bin/env python
"""Run Knörr without installing it: ``python knorr.py <command>``.

Adds ``src`` to the path so the package imports cleanly from a checkout, then
delegates to the CLI. Mirrors git_warden's ``gw.py`` shim.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from knorr.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
