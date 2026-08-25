#!/bin/bash
# run_server.sh — Start the SOPHOS SSE gRPC server
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/sophos_server"
exec .venv/bin/python server.py "$@"
