"""
sophos_client/ui/main_window.py
Main application window: tab container, connection config, status bar.

Reads sophos_client/.env via python-dotenv to pre-fill default values:
  SOPHOS_SERVER_HOST — default server hostname (e.g. sophosserver)
  SOPHOS_SERVER_PORT — default gRPC port
  SOPHOS_CERTS       — path to cert dir
  SOPHOS_KEYS_DIR    — path to keys dir
  SOPHOS_STATE_DB    — path to SQLite state db
"""
from __future__ import annotations
import os
from pathlib import Path
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QStatusBar, QGroupBox, QMessageBox,
)
from PyQt6.QtGui import QFont

from dotenv import load_dotenv

from ui.keygen_panel       import KeygenPanel
from ui.upload_panel       import UploadPanel
from ui.search_panel       import SearchPanel
from ui.server_state_panel import ServerStatePanel

HERE = Path(__file__).parent.parent.resolve()   # sophos_client/

# Load .env before reading os.environ — real env vars take precedence
load_dotenv(dotenv_path=HERE / ".env", override=False)

# ── Defaults from .env ────────────────────────────────────────────────────────
_DEFAULT_HOST = os.environ.get("SOPHOS_SERVER_HOST", "sophosserver")
_DEFAULT_PORT = os.environ.get("SOPHOS_SERVER_PORT", "50051")

CWD = Path(os.getcwd())

def _resolve_env(env_key: str, default_relative_to_here: Path) -> str:
    """Return the path for a config value.
    - If the env var is set: resolve relative to CWD (where the binary was launched).
    - Otherwise:            use the default path relative to HERE (source/bundle dir).
    """
    val = os.environ.get(env_key)
    if val:
        p = Path(val)
        return str(p if p.is_absolute() else CWD / p)
    return str(default_relative_to_here)

_DEFAULT_CERT_DIR     = _resolve_env("SOPHOS_CERTS",        HERE / ".." / "certs")
_DEFAULT_KEYS_DIR     = _resolve_env("SOPHOS_KEYS_DIR",     HERE / "keys")
_DEFAULT_STATE_DB     = _resolve_env("SOPHOS_STATE_DB",     HERE / "client.db")
_DEFAULT_SAMPLE_DIR   = _resolve_env("SOPHOS_SAMPLE_DIR",   HERE / ".." / "sample_docs")
_DEFAULT_DOWNLOAD_DIR = _resolve_env("SOPHOS_DOWNLOAD_DIR", HERE / ".." / "downloads")
# ─────────────────────────────────────────────────────────────────────────────



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOPHOS SSE — Forward-Private Searchable Encryption")
        self.setMinimumSize(950, 700)
        self._channel = None
        self._stub    = None
        self._state_db = None
        self._master_key = None
        self._rsa_priv = self._rsa_pub = None
        self._keys_dir     = _DEFAULT_KEYS_DIR
        self._cert_dir     = _DEFAULT_CERT_DIR
        self._sample_dir   = _DEFAULT_SAMPLE_DIR
        self._download_dir = _DEFAULT_DOWNLOAD_DIR
        self._apply_dark_theme()
        self._build_ui()

    # ─── Dark theme ────────────────────────────────────────────────────────────
    def _apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #0d1117; color: #e8f4fd; font-family: 'Inter', sans-serif; }
            QTabWidget::pane   { border: 1px solid #2a3a4a; border-radius: 8px; background: #111921; }
            QTabBar::tab       { background: #141e2b; color: #8899aa; padding: 10px 22px;
                                 border-top-left-radius: 6px; border-top-right-radius: 6px; }
            QTabBar::tab:selected { background: #1a2d44; color: #c3e6fb; font-weight: 600; }
            QTabBar::tab:hover    { background: #1a2535; }
            QScrollBar:vertical   { background: #0d1117; width: 8px; }
            QScrollBar::handle:vertical { background: #2a3a4a; border-radius: 4px; }
            QToolTip { background: #1a2d44; color: #e8f4fd; border: 1px solid #2a3a4a; }
        """)

    # ─── UI Build ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setSpacing(0); root.setContentsMargins(0,0,0,0)

        # Top bar
        root.addWidget(self._make_topbar())

        # Connection bar
        root.addWidget(self._make_conn_bar())

        # Tabs
        self._tabs = QTabWidget()
        self._keygen_panel  = KeygenPanel(self._keys_dir)
        self._upload_panel  = UploadPanel(sample_dir=self._sample_dir)
        self._search_panel  = SearchPanel(download_dir=self._download_dir)
        self._state_panel   = ServerStatePanel()

        self._tabs.addTab(self._keygen_panel,  "🔑  Keys")
        self._tabs.addTab(self._upload_panel,  "📄  Upload")
        self._tabs.addTab(self._search_panel,  "🔍  Search")
        self._tabs.addTab(self._state_panel,   "🗄️  Server State")
        root.addWidget(self._tabs, stretch=1)

        # Status bar
        self._sb = QStatusBar(); self.setStatusBar(self._sb)
        self._sb.setStyleSheet("background:#0a0f18; color:#8899aa; font-size:12px;")
        self._conn_indicator = QLabel("⚫  Disconnected")
        self._sb.addPermanentWidget(self._conn_indicator)
        self._sb.showMessage("Welcome to SOPHOS SSE — generate keys, then connect to server.")

        # Wire signals
        self._keygen_panel.keys_generated.connect(self._on_keys_generated)
        self._upload_panel.upload_complete.connect(
            lambda d, f: self._sb.showMessage(f"Uploaded: {f}  (doc_id {d[:12]}…)")
        )

    def _make_topbar(self):
        bar = QWidget(); bar.setFixedHeight(56)
        bar.setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                          "stop:0 #0d1f35,stop:1 #101a27);")
        lay = QHBoxLayout(bar); lay.setContentsMargins(20,0,20,0)
        logo = QLabel("Σoφoς  SSE")
        logo.setFont(QFont("Inter", 18, QFont.Weight.Bold))
        logo.setStyleSheet("color:#c3e6fb; letter-spacing:2px;")
        lay.addWidget(logo)
        lay.addStretch()
        sub = QLabel("Forward-Private Symmetric Searchable Encryption  ·  Bost CCS 2016")
        sub.setStyleSheet("color:#556677; font-size:11px;")
        lay.addWidget(sub)
        return bar

    def _make_conn_bar(self):
        bar = QWidget(); bar.setFixedHeight(50)
        bar.setStyleSheet("background:#111921; border-bottom:1px solid #1e2d3a;")
        lay = QHBoxLayout(bar); lay.setContentsMargins(20,6,20,6); lay.setSpacing(10)

        lay.addWidget(QLabel("Server:"))
        self._host_edit = QLineEdit(_DEFAULT_HOST)
        self._host_edit.setFixedWidth(160)
        self._host_edit.setStyleSheet(self._is())
        lay.addWidget(self._host_edit)

        lay.addWidget(QLabel("Port:"))
        self._port_edit = QLineEdit(_DEFAULT_PORT)
        self._port_edit.setFixedWidth(70)
        self._port_edit.setStyleSheet(self._is())
        lay.addWidget(self._port_edit)

        self._conn_btn = QPushButton("Connect")
        self._conn_btn.setFixedWidth(90)
        self._conn_btn.setStyleSheet(self._bs("#1a6eb5"))
        self._conn_btn.clicked.connect(self._connect)
        lay.addWidget(self._conn_btn)

        self._disc_btn = QPushButton("Disconnect")
        self._disc_btn.setFixedWidth(100)
        self._disc_btn.setEnabled(False)
        self._disc_btn.setStyleSheet(self._bs("#5a2a2a"))
        self._disc_btn.clicked.connect(self._disconnect)
        lay.addWidget(self._disc_btn)
        lay.addStretch()
        return bar

    # ─── Connection Logic ──────────────────────────────────────────────────────
    def _connect(self):
        host = self._host_edit.text().strip()
        port = self._port_edit.text().strip()
        cert_dir = self._cert_dir

        # Load certs
        try:
            ca  = open(os.path.join(cert_dir, "ca.crt"),     "rb").read()
            ck  = open(os.path.join(cert_dir, "client.key"), "rb").read()
            cc  = open(os.path.join(cert_dir, "client.crt"), "rb").read()
        except FileNotFoundError as e:
            QMessageBox.critical(self, "Certificate Error",
                f"Cannot find certificate files in certs/:\n{e}\n\n"
                "Run:  bash gen_certs.sh <server_ip>")
            return

        import grpc, sophos_pb2_grpc
        creds = grpc.ssl_channel_credentials(
            root_certificates=ca, private_key=ck, certificate_chain=cc
        )
        target = f"{host}:{port}"
        self._channel = grpc.secure_channel(target, creds, options=[
            ("grpc.max_receive_message_length", 64*1024*1024),
            ("grpc.max_send_message_length",    64*1024*1024),
        ])
        self._stub = sophos_pb2_grpc.SophosServerStub(self._channel)

        # Test connection
        try:
            import sophos_pb2
            ack = self._stub.Ping(sophos_pb2.PingRequest(), timeout=5)
            if not ack.ok: raise RuntimeError(ack.msg)
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed", str(e))
            self._channel.close(); self._channel = self._stub = None
            return

        self._conn_indicator.setText(f"🟢  {target}")
        self._conn_btn.setEnabled(False); self._disc_btn.setEnabled(True)
        self._sb.showMessage(f"Connected to {target}")
        self._push_config()
        self._state_panel.configure(self._stub, self._state_db)

    def _disconnect(self):
        if self._channel: self._channel.close()
        self._channel = self._stub = None
        self._conn_indicator.setText("⚫  Disconnected")
        self._conn_btn.setEnabled(True); self._disc_btn.setEnabled(False)
        self._sb.showMessage("Disconnected.")

    def _on_keys_generated(self, keys_dir: str):
        self._keys_dir = keys_dir
        self._load_keys()

    def _load_keys(self):
        from core.crypto import (
            load_master_key, load_rsa_private, load_rsa_public,
            rsa_extract_private, rsa_extract_public,
        )
        from core.state_db import KeywordStateDB
        try:
            self._master_key = load_master_key(os.path.join(self._keys_dir, "master.key"))
            priv = load_rsa_private(os.path.join(self._keys_dir, "rsa_private.pem"))
            pub  = load_rsa_public( os.path.join(self._keys_dir, "rsa_public.pem"))
            self._rsa_d, self._rsa_n = rsa_extract_private(priv)
            self._rsa_e, _           = rsa_extract_public(pub)
            db_path = os.path.join(self._keys_dir, "..", "client.db")
            self._state_db = KeywordStateDB(os.path.normpath(db_path))
            self._sb.showMessage("Keys loaded. Connect to server to begin.")
            self._push_config()
        except FileNotFoundError:
            pass   # Keys not yet generated — that's fine

    def _push_config(self):
        """Push connection + key config to all panels."""
        if self._stub and self._master_key:
            self._upload_panel.configure(
                self._stub, self._master_key, self._rsa_d, self._rsa_n, self._state_db
            )
            self._search_panel.configure(
                self._stub, self._master_key, self._rsa_e, self._rsa_n, self._state_db
            )

    def closeEvent(self, event):
        if self._channel: self._channel.close()
        if self._state_db: self._state_db.close()
        super().closeEvent(event)

    def _is(self):
        return ("QLineEdit{background:#0d1117;color:#c3e6fb;border:1px solid #2a3a4a;"
                "border-radius:5px;padding:5px;font-size:12px;}")

    def _bs(self, bg):
        return (
            f"QPushButton{{background:{bg};color:#e8f4fd;border:none;"
            f"border-radius:5px;padding:5px 12px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{background:#2a80c8;}}"
            f"QPushButton:disabled{{background:#2a3a4a;color:#556677;}}"
        )

