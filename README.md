# SOPHOS SSE — Forward-Private Symmetric Searchable Encryption

> Implementation of **Σoφoς (Sophos)** — Bost, ACM CCS 2016  
> PyQt6 GUI Client · gRPC + mutual TLS · LMDB · RSA-2048 trapdoor chain

---

## Architecture

```
sophos_client/  (PyQt6 GUI)
    │  gRPC over mTLS (HTTP/2, protobuf — no REST layer)
sophos_server/  (gRPC server + LMDB)
```

The **server stores nothing readable** — only `SHA256(Kw‖ST)` → `enc_id` pairs.  
All keys, plaintext keywords, and decrypted document IDs stay on the client.

---

## Quick Start

### 1. Enter the project directory
```bash
cd SOPHOS/
```

### 2. One-shot environment setup
```bash
bash setup.sh
```
Creates:
- `sophos_server/.venv`  — `grpcio`, `lmdb`, `cryptography`, `python-dotenv`
- `sophos_client/.venv`  — `grpcio`, `PyQt6`, `cryptography`, `nltk`, `python-dotenv`, `pytest`
- Compiles `proto/sophos.proto` → stubs in both `sophos_server/` and `sophos_client/`
- Downloads NLTK corpora (~15 MB, one-time)
- Writes `run_server.sh` / `run_client.sh` / `run_tests.sh`

### 3. Configure `.env` files
Edit **before** generating certificates or starting services.

**`sophos_server/.env`** (on the server machine):
```ini
SOPHOS_HOST=sophosserver      # hostname / IP — MUST match the cert SAN
SOPHOS_PORT=50051             # gRPC listening port
SOPHOS_DB=server.db           # LMDB directory  (relative to sophos_server/)
SOPHOS_CERTS=../certs         # cert directory  (relative to sophos_server/)
SOPHOS_MAP_SIZE_GB=1          # LMDB virtual map size (not pre-allocated on disk)
SOPHOS_MAX_MSG_MB=64          # gRPC max message size in MiB
LOG_LEVEL=INFO                # DEBUG | INFO | WARNING | ERROR
```

**`sophos_client/.env`** (on the client machine):
```ini
SOPHOS_SERVER_HOST=sophosserver   # must match SOPHOS_HOST above
SOPHOS_SERVER_PORT=50051
SOPHOS_CERTS=../certs             # cert directory  (relative to sophos_client/)
SOPHOS_KEYS_DIR=keys              # master.key, rsa_private/public.pem location
SOPHOS_STATE_DB=client.db        # SQLite keyword-state database
SOPHOS_SAMPLE_DIR=../sample_docs  # folder containing sample text files for upload
SOPHOS_DOWNLOAD_DIR=../downloads  # folder where downloaded documents are saved
LOG_LEVEL=INFO
```

> **Priority rule**: Real shell environment variables always win over `.env` values.  
> Example: `SOPHOS_PORT=9999 bash run_server.sh`

### 4. Generate mTLS certificates
```bash
# Use the SOPHOS_HOST value from sophos_server/.env
bash gen_certs.sh sophosserver
```

The script auto-detects whether the argument is an IP or hostname and adds the correct `subjectAltName` extension (required by gRPC TLS).

**Distribute the generated files:**

| File | Server machine | Client machine |
|------|:-:|:-:|
| `certs/ca.crt` | ✅ | ✅ |
| `certs/server.key` | ✅ | ❌ |
| `certs/server.crt` | ✅ | ❌ |
| `certs/client.key` | ❌ | ✅ |
| `certs/client.crt` | ❌ | ✅ |

### 5. Start the server
```bash
# On the server machine, from SOPHOS/ root:
bash run_server.sh
```

Expected output:
```
13:00:00 [INFO] sophos.server — ══════════════════════════════════════════
13:00:00 [INFO] sophos.server —   SOPHOS SSE Server  —  gRPC + mTLS
13:00:00 [INFO] sophos.server —   Host      : sophosserver
13:00:00 [INFO] sophos.server —   Listening : 0.0.0.0:50051
13:00:00 [INFO] sophos.server —   Database  : /…/sophos_server/server.db
13:00:00 [INFO] sophos.server —   Config    : /…/sophos_server/.env
```

### 6. Start the client GUI
```bash
# On the client machine:
bash run_client.sh
```

The GUI pre-fills **Server** and **Port** from `sophos_client/.env` — no manual typing needed.

---

## GUI Workflow

| Tab | What to do |
|-----|-----------|
| 🔑 **Keys** | Click **Generate Keys** → creates `master.key`, `rsa_private.pem`, `rsa_public.pem` in `keys/` |
| Connection bar | Verify host/port (pre-filled from `.env`) → **Connect** |
| 📄 **Upload** | Quick select sample files from `sample_docs/` or drag & drop custom `.txt` → review extracted keywords → **Upload to Server** |
| 🔍 **Search** | Type a keyword → **Search** → results stream in live → click **Preview**, **Download Document** to `downloads/`, or **Open Downloaded File** |
| 🗄️ **Server State** | **Refresh** → shows the encrypted index: all entries are opaque hex blobs |

---

## Sample Documents & Downloads Directories

- **Upload Folder (`sample_docs/`)**: Pre-populated with test text files of various sizes:
  - `small_network_security.txt` (~1.1 KB)
  - `large_crypto_survey.txt` (~4.4 KB)
  - `medium_vpn_architecture.txt` (~6.6 KB)
  - `xlarge_security_audit_log.txt` (~256 KB)
- **Download Folder (`downloads/`)**: Target directory where decrypted documents are saved when clicking **Download Document** in the Search tab. You can open them directly using **Open Downloaded File** or open the containing folder via **Open Downloads Folder**.

---

## Configuration Reference

### `sophos_server/.env`

| Key | Default | Description |
|-----|---------|-------------|
| `SOPHOS_HOST` | `sophosserver` | Server hostname/IP — must match the cert SAN |
| `SOPHOS_PORT` | `50051` | gRPC listening port |
| `SOPHOS_DB` | `server.db` | LMDB directory (relative to `sophos_server/`) |
| `SOPHOS_CERTS` | `../certs` | Certificate directory |
| `SOPHOS_MAP_SIZE_GB` | `1` | LMDB virtual map size in GiB (not pre-allocated) |
| `SOPHOS_MAX_MSG_MB` | `64` | gRPC max message size in MiB |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### `sophos_client/.env`

| Key | Default | Description |
|-----|---------|-------------|
| `SOPHOS_SERVER_HOST` | `sophosserver` | Server to connect to (pre-fills GUI) |
| `SOPHOS_SERVER_PORT` | `50051` | gRPC port (pre-fills GUI) |
| `SOPHOS_CERTS` | `../certs` | Certificate directory |
| `SOPHOS_KEYS_DIR` | `keys` | Directory for master key + RSA keypair |
| `SOPHOS_STATE_DB` | `client.db` | SQLite keyword-state database path |
| `SOPHOS_SAMPLE_DIR` | `../sample_docs` | Directory containing sample text files for upload |
| `SOPHOS_DOWNLOAD_DIR` | `../downloads` | Target directory for downloaded decrypted documents |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Cryptographic Design

| Operation | Formula | Note |
|-----------|---------|------|
| Keyword key | `Kw = HMAC-SHA256(K, w)` | Per-keyword, derived from master key |
| First upload token | `ST_0 ∈ Z_N*` (random) | Random element of RSA group |
| Update chain (client) | `ST_{i+1} = ST_i^d mod N` | Private key = inverse permutation |
| Search chain (server) | `ST_{i-1} = ST_i^e mod N` | Public key = forward traversal |
| Index key | `UT = SHA256(Kw ‖ ST)` | Stored as LMDB key |
| Encrypted doc ID | `enc_id = doc_id XOR SHA256(Kw ‖ ST ‖ "id")` | Stored as LMDB value |
| Document encryption | `AES-256-GCM(HMAC(K, "doc"‖doc_id), plaintext)` | Per-document key |

**Forward Privacy**: every update produces a fresh `ST` from which the server cannot derive past tokens without the private key `d`.

---

## Directory Structure

```
SOPHOS/
├── certs/                    ← Generated by gen_certs.sh
│   ├── ca.{key,crt}
│   ├── server.{key,crt}
│   └── client.{key,crt}
│
├── proto/
│   └── sophos.proto          ← gRPC service definition (source of truth)
│
├── sample_docs/              ← Pre-created sample text files (1 KB to 256 KB)
├── downloads/                ← Downloaded decrypted documents folder
│
├── sophos_server/
│   ├── .venv/                ← Server virtual environment
│   ├── .env                  ← Server configuration  ← EDIT THIS
│   ├── server.py             ← gRPC server entrypoint (loads .env via python-dotenv)
│   ├── servicer.py           ← SophosServicer — RSA chain search (streaming)
│   ├── db.py                 ← LMDB helpers (2 named databases)
│   ├── sophos_pb2*.py        ← Generated proto stubs
│   ├── server.db/            ← LMDB data directory (created at runtime)
│   └── requirements.txt
│
├── sophos_client/
│   ├── .venv/                ← Client virtual environment
│   ├── .env                  ← Client configuration  ← EDIT THIS
│   ├── main.py               ← PyQt6 app entrypoint
│   ├── ui/
│   │   ├── main_window.py    ← Loads .env, pre-fills connection fields
│   │   ├── keygen_panel.py
│   │   ├── upload_panel.py
│   │   ├── search_panel.py
│   │   └── server_state_panel.py
│   ├── workers/
│   │   ├── upload_worker.py  ← QThread: extract → encrypt → RSA chain → gRPC
│   │   ├── search_worker.py  ← QThread: trapdoor → streaming gRPC → decrypt
│   │   └── fetch_worker.py   ← QThread: gRPC fetch → AES-GCM decrypt
│   ├── core/
│   │   ├── crypto.py         ← RSA-2048, HMAC-SHA256, AES-256-GCM
│   │   ├── keywords.py       ← NLTK POS-lemmatizer + crypto whitelist
│   │   └── state_db.py       ← SQLite: keyword → (ST blob, counter)
│   ├── keys/                 ← master.key, rsa_private.pem, rsa_public.pem
│   ├── client.db             ← SQLite keyword state (created at runtime)
│   ├── sophos_pb2*.py        ← Generated proto stubs
│   └── requirements.txt
│
├── tests/
│   ├── test_crypto.py        ← RSA roundtrip, HMAC, AES-GCM, chain consistency
│   └── test_keywords.py      ← Tokenizer, stopwords, lemmatization, whitelist
│
├── setup.sh                  ← One-shot: venvs + deps + proto + NLTK data
├── gen_certs.sh              ← mTLS cert generator (SAN-aware)
├── gen_proto.sh              ← Recompile proto stubs (uses server venv)
├── run_server.sh             ← Sources .env → starts server venv Python
├── run_client.sh             ← Sources .env → starts client venv Python
└── run_tests.sh              ← Runs pytest via client venv
```

---

## Running Tests

```bash
bash run_tests.sh
# or explicitly:
sophos_client/.venv/bin/python -m pytest tests/ -v
```

All 17 tests pass out of the box after `bash setup.sh`.

---

## Security Notes

- **Master key and RSA private key must never leave the client machine.**
- RSA-2048 is the NIST-recommended minimum. RSA-1024 would be faster but is deprecated.
- mTLS (mutual TLS) ensures both sides authenticate — the server rejects any client without a valid certificate, and vice versa.
- The server's LMDB index is **append-only** by design (Sophos construction — no entry is ever modified or deleted).
- **Forward privacy**: newly uploaded document index entries are cryptographically unlinkable to past search queries without the client's RSA private key.
- Inspect `server.db` at any time with `python -c "import lmdb; ..."` — you will see only opaque SHA-256 and XOR-masked byte blobs.
