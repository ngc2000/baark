# Copyright (c) 2026 doabell.
"""Check release identity, metadata, and required files without publishing."""

import os
import sys
import tarfile
import tomllib
from email.parser import Parser
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


def _check_names(names: set[str], required: set[str]) -> None:
    missing = required - names
    if missing:
        message = f"Distribution is missing required files: {sorted(missing)}"
        raise SystemExit(message)
    for name in names:
        if any(
            part in {".env", ".git", ".venv", "__pycache__"} or part.startswith(".env.")
            for part in PurePosixPath(name).parts
        ):
            message = f"Distribution contains an excluded file: {name}"
            raise SystemExit(message)


def _check_metadata(text: str, expected: dict[str, str]) -> None:
    metadata = Parser().parsestr(text)
    for field, value in expected.items():
        if metadata[field] != value:
            message = f"Distribution metadata does not match pyproject.toml: {field}"
            raise SystemExit(message)


def main() -> None:
    """Validate the wheel and sdist built from this checkout."""
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    name, version = project["name"], project["version"]
    tag = os.environ.get("RELEASE_TAG", "")
    if tag and tag != f"v{version}":
        message = f"Release tag must match the package version: v{version}"
        raise SystemExit(message)

    stem = f"{name}-{version}"
    wheel = Path("dist", f"{stem}-py3-none-any.whl")
    sdist = Path("dist", f"{stem}.tar.gz")
    artifacts = {*Path("dist").glob("*.whl"), *Path("dist").glob("*.tar.gz")}
    if artifacts != {wheel, sdist}:
        message = "Expected exactly one wheel and one sdist for the current version."
        raise SystemExit(message)

    expected = {
        "Name": name,
        "Version": version,
        "Requires-Python": project["requires-python"],
        "License-Expression": project["license"],
    }
    metadata_path = f"{stem}.dist-info/METADATA"
    with ZipFile(wheel) as archive:
        _check_names(
            set(archive.namelist()),
            {f"{name}/py.typed", metadata_path, f"{stem}.dist-info/licenses/LICENSE"},
        )
        _check_metadata(archive.read(metadata_path).decode("utf-8"), expected)

    with tarfile.open(sdist) as archive:
        _check_names(
            set(archive.getnames()),
            {
                f"{stem}/LICENSE",
                f"{stem}/README.md",
                f"{stem}/pyproject.toml",
                f"{stem}/src/{name}/py.typed",
                f"{stem}/tests/test_client.py",
                f"{stem}/scripts/e2e.py",
            },
        )
        metadata = archive.extractfile(f"{stem}/PKG-INFO")
        if metadata is None:
            message = "Source distribution has no package metadata."
            raise SystemExit(message)
        _check_metadata(metadata.read().decode("utf-8"), expected)

    sys.stdout.write(f"Validated {wheel.name} and {sdist.name}.\n")


if __name__ == "__main__":
    main()
