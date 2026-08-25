"""
sophos_server/server.py
SOPHOS SSE gRPC server with mutual TLS.

Configuration is loaded from sophos_server/.env (via python-dotenv).
All values can be overridden by real environment variables (dotenv_values
loads the file but real env vars take precedence when using load_dotenv).

.env keys:
  SOPHOS_HOST        — server hostname (informational; used in cert SAN)
  SOPHOS_PORT        — gRPC listening port          (default: 50051)
  SOPHOS_DB          — LMDB directory path          (default: server.db)
  SOPHOS_CERTS       — cert directory               (default: ../certs)
  SOPHOS_MAP_SIZE_GB — LMDB virtual map size in GiB (default: 1)
  SOPHOS_MAX_MSG_MB  — gRPC max message size in MiB (default: 64)
  LOG_LEVEL          — logging level                (default: INFO)
"""

import grpc
import logging
import os
import signal
import sys
from concurrent import futures
from pathlib import Path

# ── Load .env FIRST, before reading os.environ ────────────────────────────────
from dotenv import load_dotenv

HERE = Path(__file__).parent.resolve()
_env_path = HERE / ".env"
load_dotenv(dotenv_path=_env_path, override=False)   # real env vars win
# ─────────────────────────────────────────────────────────────────────────────

import sophos_pb2_grpc
from servicer import SophosServicer
from db import SophosDB

# ── Config (all read after .env is loaded) ────────────────────────────────────
LOG_LEVEL    = os.environ.get("LOG_LEVEL",          "INFO").upper()
PORT         = int(os.environ.get("SOPHOS_PORT",    "50051"))
MAP_SIZE_GB  = int(os.environ.get("SOPHOS_MAP_SIZE_GB", "1"))
MAX_MSG_MB   = int(os.environ.get("SOPHOS_MAX_MSG_MB",  "64"))

CWD = Path(os.getcwd())

# Paths from env vars are relative to CWD (where the user launched the binary).
# Default fallback paths are relative to HERE (the source/bundle directory).
_db_env    = os.environ.get("SOPHOS_DB")
_certs_env = os.environ.get("SOPHOS_CERTS")

if _db_env:
    DB_PATH  = str(Path(_db_env) if Path(_db_env).is_absolute() else CWD / _db_env)
else:
    DB_PATH  = str(HERE / "server.db")

if _certs_env:
    CERT_DIR = str(Path(_certs_env) if Path(_certs_env).is_absolute() else CWD / _certs_env)
else:
    CERT_DIR = str((HERE / ".." / "certs").resolve())

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sophos.server")



def _load_mtls_credentials() -> grpc.ServerCredentials:
    ca_path  = os.path.join(CERT_DIR, "ca.crt")
    key_path = os.path.join(CERT_DIR, "server.key")
    crt_path = os.path.join(CERT_DIR, "server.crt")

    for p in (ca_path, key_path, crt_path):
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"Certificate file not found: {p}\n"
                f"Run:  bash gen_certs.sh <server_ip>"
            )

    return grpc.ssl_server_credentials(
        [(open(key_path, "rb").read(), open(crt_path, "rb").read())],
        root_certificates=open(ca_path, "rb").read(),
        require_client_auth=True,   # enforce mutual TLS
    )


def serve() -> None:
    db        = SophosDB(DB_PATH, map_size=MAP_SIZE_GB * 1024 ** 3)
    servicer  = SophosServicer(db)

    msg_bytes = MAX_MSG_MB * 1024 * 1024
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=[
            ("grpc.max_receive_message_length", msg_bytes),
            ("grpc.max_send_message_length",    msg_bytes),
        ],
    )
    sophos_pb2_grpc.add_SophosServerServicer_to_server(servicer, server)

    credentials = _load_mtls_credentials()
    listen_addr = f"0.0.0.0:{PORT}"
    server.add_secure_port(listen_addr, credentials)

    server.start()
    sophos_host = os.environ.get("SOPHOS_HOST", "(not set)")
    logger.info("══════════════════════════════════════════")
    logger.info("  SOPHOS SSE Server  —  gRPC + mTLS")
    logger.info("  Host      : %s", sophos_host)
    logger.info("  Listening : %s", listen_addr)
    logger.info("  Database  : %s", os.path.abspath(DB_PATH))
    logger.info("  Certs     : %s", os.path.abspath(CERT_DIR))
    logger.info("  Map size  : %d GiB  |  Max msg: %d MiB", MAP_SIZE_GB, MAX_MSG_MB)
    logger.info("  Config    : %s", _env_path)
    logger.info("══════════════════════════════════════════")

    def _shutdown(sig, frame):
        logger.info("Shutting down (signal %s) ...", sig)
        server.stop(grace=5)
        db.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
