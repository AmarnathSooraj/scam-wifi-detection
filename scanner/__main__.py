"""Enable ``python -m scanner`` in addition to ``python scanner.py``."""

from __future__ import annotations

import sys

from .scanner import main

if __name__ == "__main__":
    sys.exit(main())
