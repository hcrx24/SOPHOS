#!/bin/bash
# run_tests.sh — Run unit tests using the client venv
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
.venv_test/bin/python -m pytest tests/ -v "$@" 2>/dev/null || \
    "$ROOT/sophos_client/.venv/bin/python" -m pytest tests/ -v "$@"
