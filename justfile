set default-list := true
set dotenv-load := false
set shell := ["bash", "-euo", "pipefail", "-c"]
set windows-shell := ["bash", "-euo", "pipefail", "-c"]

# Format Python source.
format:
    uv run --locked python -m ruff format .

# Check the lockfile, lint, formatting, and types without changing files.
lint:
    uv lock --check
    uv run --locked python -m ruff check .
    uv run --locked python -m ruff format --check .
    uv run --locked python -m ty check

# Validate GitHub Actions (requires actionlint).
lint-workflows:
    actionlint .github/workflows/*.yml

# Run offline tests and enforce coverage.
test:
    uv run --locked python -m coverage run
    uv run --locked python -m coverage report

# Run all source and workflow checks.
check: lint lint-workflows test

# Build fresh distributions and check their metadata and contents.
build:
    uv build --clear --no-sources
    uv run --locked python -m twine check --strict dist/*
    uv run --locked python scripts/check_dist.py

# Install the built wheel, then run the offline suite against that installation.
test-wheel:
    uv sync --locked --no-install-project
    uv pip install --no-deps --reinstall dist/*.whl
    uv run --no-sync python -I scripts/check_wheel.py
    UV_NO_SYNC=true just test
