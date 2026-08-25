#!/bin/bash
# gen_certs.sh — Generate self-signed CA, server cert (with SAN), and client cert
#
# Usage:
#   bash gen_certs.sh <server_ip_or_hostname>
#
# Example:
#   bash gen_certs.sh 192.168.1.100
#   bash gen_certs.sh myserver.local
#
# Output: certs/ directory with ca.key, ca.crt, server.{key,crt}, client.{key,crt}
#
# IMPORTANT: gRPC requires a SubjectAltName (SAN) in the server cert.
#            A CN-only cert WILL be rejected by Python's ssl module.

set -e

SERVER_CN="${1:-localhost}"
DAYS=365
OUT="$(dirname "$0")/certs"

mkdir -p "$OUT"
cd "$OUT"

echo "════════════════════════════════════════════"
echo "  SOPHOS SSE — mTLS Certificate Generator  "
echo "  Server: $SERVER_CN"
echo "════════════════════════════════════════════"

# ── Root CA ──────────────────────────────────────────────────────────────────
echo ""
echo "[1/3] Generating Root CA ..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key \
    -sha256 -days $DAYS -out ca.crt \
    -subj "/C=IN/ST=Demo/O=SophosSSE/CN=SophosCA" 2>/dev/null
echo "      ca.key + ca.crt  ✓"

# ── Server Certificate (with SAN) ────────────────────────────────────────────
echo ""
echo "[2/3] Generating Server certificate (CN=$SERVER_CN) ..."
openssl genrsa -out server.key 2048 2>/dev/null

# Detect if SERVER_CN is an IP or hostname
if [[ "$SERVER_CN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN_LINE="IP:${SERVER_CN}"
else
    SAN_LINE="DNS:${SERVER_CN}"
fi

cat > server_ext.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[SAN]
subjectAltName=${SAN_LINE}
EOF

openssl req -new -key server.key -out server.csr \
    -subj "/C=IN/ST=Demo/O=SophosSSE/CN=${SERVER_CN}" 2>/dev/null

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days $DAYS -sha256 \
    -extfile server_ext.cnf -extensions SAN 2>/dev/null

rm -f server.csr server_ext.cnf
echo "      server.key + server.crt  ✓"

# ── Client Certificate ────────────────────────────────────────────────────────
echo ""
echo "[3/3] Generating Client certificate ..."
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/C=IN/ST=Demo/O=SophosSSE/CN=sophos-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days $DAYS -sha256 2>/dev/null
rm -f client.csr
echo "      client.key + client.crt  ✓"

echo ""
echo "════════════════════════════════════════════"
echo "  Certificates written to: $OUT/"
echo ""
echo "  Server machine needs:"
echo "    certs/ca.crt  certs/server.key  certs/server.crt"
echo ""
echo "  Client machine needs:"
echo "    certs/ca.crt  certs/client.key  certs/client.crt"
echo "════════════════════════════════════════════"
