"""``python -m boundkeep`` runs the command line."""

from __future__ import annotations

import sys

from boundkeep.cli import main

if __name__ == "__main__":
    sys.exit(main())
