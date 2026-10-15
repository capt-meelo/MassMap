#!/usr/bin/env python3
"""Portable entry point; no third-party Python dependencies."""
import sys

if sys.version_info < (3, 11):
    sys.exit("MassMap requires Python 3.11 or newer.")

from massmap.cli import main

if __name__ == "__main__":
    sys.exit(main())
