#!/bin/bash
# setup.sh — Create venvs, install deps, compile proto, download NLTK data
#
# Run once from the SOPHOS/ root directory:
#   bash setup.sh
#
# After this, use the venv launchers:
#   Server : bash run_server.sh
#   Client : bash run_client.sh

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "════════════════════════════════════════════════════"
echo "  SOPHOS SSE — Environment Setup"
echo "  Root: $ROOT"
echo "════════════════════════════════════════════════════"

# ── Helper ────────────────────────────────────────────────────────────────────
require_python() {
    if ! command -v python3 &>/dev/null; then
        echo "[ERROR] python3 not found. Install Python 3.11+ first."
        exit 1
    fi
    PY=$(python3 --version 2>&1)
    echo "[*] Using $PY"
}

# ── Server venv ───────────────────────────────────────────────────────────────
setup_server() {
    echo ""
    echo "[1/3] Setting up SERVER venv ..."
    cd "$ROOT/sophos_server"

    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        echo "      Created sophos_server/.venv"
    else
        echo "      sophos_server/.venv already exists — updating packages"
    fi

    .venv/bin/pip install --upgrade pip --quiet
    .venv/bin/pip install -r requirements.txt --quiet
    echo "      Server deps installed ✓"
    cd "$ROOT"
}

# ── Client venv ───────────────────────────────────────────────────────────────
setup_client() {
    echo ""
    echo "[2/3] Setting up CLIENT venv ..."
    cd "$ROOT/sophos_client"

    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        echo "      Created sophos_client/.venv"
    else
        echo "      sophos_client/.venv already exists — updating packages"
    fi

    .venv/bin/pip install --upgrade pip --quiet
    .venv/bin/pip install -r requirements.txt --quiet
    echo "      Client deps installed ✓"

    # Download NLTK corpora (one-time, ~15 MB)
    echo "      Downloading NLTK data ..."
    .venv/bin/python -c "
import nltk
for pkg in ['punkt','punkt_tab','averaged_perceptron_tagger',
            'averaged_perceptron_tagger_eng','wordnet','stopwords','omw-1.4']:
    nltk.download(pkg, quiet=True)
print('      NLTK data ready ✓')
"
    cd "$ROOT"
}

# ── Proto compilation ─────────────────────────────────────────────────────────
compile_proto() {
    echo ""
    echo "[3/3] Compiling sophos.proto ..."

    VENV_PY="$ROOT/sophos_server/.venv/bin/python"
    PROTO_DIR="$ROOT/proto"

    "$VENV_PY" -m grpc_tools.protoc \
        -I"$PROTO_DIR" \
        --python_out="$PROTO_DIR" \
        --grpc_python_out="$PROTO_DIR" \
        "$PROTO_DIR/sophos.proto"

    # NOTE: Do NOT convert to relative imports — modules run as plain scripts.
    # Copy stubs to both sides
    cp "$PROTO_DIR/sophos_pb2.py"      "$ROOT/sophos_server/"
    cp "$PROTO_DIR/sophos_pb2_grpc.py" "$ROOT/sophos_server/"
    cp "$PROTO_DIR/sophos_pb2.py"      "$ROOT/sophos_client/"
    cp "$PROTO_DIR/sophos_pb2_grpc.py" "$ROOT/sophos_client/"
    echo "      Proto stubs compiled and distributed ✓"
}

# ── Launcher scripts ──────────────────────────────────────────────────────────
write_launchers() {
    cat > "$ROOT/run_server.sh" <<'EOF'
#!/bin/bash
# run_server.sh — Start the SOPHOS SSE gRPC server
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/sophos_server"
exec .venv/bin/python server.py "$@"
EOF

    cat > "$ROOT/run_client.sh" <<'EOF'
#!/bin/bash
# run_client.sh — Start the SOPHOS SSE PyQt6 GUI client
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/sophos_client"
exec .venv/bin/python main.py "$@"
EOF

    cat > "$ROOT/run_tests.sh" <<'EOF'
#!/bin/bash
# run_tests.sh — Run unit tests using the client venv
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
.venv_test/bin/python -m pytest tests/ -v "$@" 2>/dev/null || \
    "$ROOT/sophos_client/.venv/bin/python" -m pytest tests/ -v "$@"
EOF

    chmod +x "$ROOT/run_server.sh" "$ROOT/run_client.sh" "$ROOT/run_tests.sh"
    echo ""
    echo "      Launcher scripts written:"
    echo "        run_server.sh"
    echo "        run_client.sh"
    echo "        run_tests.sh"
}

# ── Main ──────────────────────────────────────────────────────────────────────
require_python
setup_server
setup_client
compile_proto
write_launchers

echo ""
echo "════════════════════════════════════════════════════"
echo "  Setup complete!  Next steps:"
echo ""
echo "  1. Generate mTLS certificates:"
echo "       bash gen_certs.sh <server_ip_or_hostname>"
echo ""
echo "  2. Start the server (on server machine):"
echo "       bash run_server.sh"
echo ""
echo "  3. Start the client (on client machine):"
echo "       bash run_client.sh"
echo ""
echo "  4. In the GUI:"
echo "       🔑  Keys tab  → Generate Keys"
echo "       📄  Upload    → Select .txt file → Upload"
echo "       🔍  Search    → Type keyword → Search"
echo "       🗄️  Server State → Refresh (shows opaque encrypted index)"
echo "════════════════════════════════════════════════════"
