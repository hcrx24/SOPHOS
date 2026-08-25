#!/bin/bash
# run_client.sh — Start the SOPHOS SSE PyQt6 GUI client
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/sophos_client"
exec .venv/bin/python main.py "$@"
