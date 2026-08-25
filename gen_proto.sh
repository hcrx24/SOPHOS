#!/bin/bash
# gen_proto.sh — Compile sophos.proto and distribute generated stubs
# Requires: setup.sh must have been run first (uses sophos_server/.venv)
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$ROOT/proto"
SERVER_DIR="$ROOT/sophos_server"
CLIENT_DIR="$ROOT/sophos_client"

# Use server venv Python (grpcio-tools installed there)
VENV_PY="$SERVER_DIR/.venv/bin/python"
if [ ! -f "$VENV_PY" ]; then
    echo "[ERROR] Server venv not found. Run:  bash setup.sh"
    exit 1
fi

echo "[*] Compiling sophos.proto using $VENV_PY ..."
"$VENV_PY" -m grpc_tools.protoc \
    -I"$PROTO_DIR" \
    --python_out="$PROTO_DIR" \
    --grpc_python_out="$PROTO_DIR" \
    "$PROTO_DIR/sophos.proto"

# NOTE: Do NOT apply 'from . import' here.
# protoc generates:  import sophos_pb2 as sophos__pb2   (absolute — correct)
# Relative imports only work inside packages; our modules run as plain scripts.

echo "[*] Distributing stubs ..."
cp "$PROTO_DIR/sophos_pb2.py"      "$SERVER_DIR/"
cp "$PROTO_DIR/sophos_pb2_grpc.py" "$SERVER_DIR/"
cp "$PROTO_DIR/sophos_pb2.py"      "$CLIENT_DIR/"
cp "$PROTO_DIR/sophos_pb2_grpc.py" "$CLIENT_DIR/"

echo "[+] Done. Stubs written to sophos_server/ and sophos_client/"
