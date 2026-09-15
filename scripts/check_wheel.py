# Copyright (c) 2026 doabell.
"""Verify tests will import the installed wheel rather than the source checkout."""

import sys
from importlib.metadata import distribution
from pathlib import Path

import baark


def main() -> None:
    """Check installation location and the typed public import surface."""
    package = Path(baark.__file__).resolve()
    if not package.is_relative_to(Path(sys.prefix).resolve()):
        message = "baark was imported from outside the wheel's Python environment."
        raise SystemExit(message)
    if not package.with_name("py.typed").is_file():
        message = "The installed wheel is missing its py.typed marker."
        raise SystemExit(message)
    for name in baark.__all__:
        getattr(baark, name)
    version = distribution("baark").version
    sys.stdout.write(f"Verified installed baark {version} and its public exports.\n")


if __name__ == "__main__":
    main()
