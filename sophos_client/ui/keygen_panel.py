"""
sophos_client/ui/keygen_panel.py
Key Generation tab — generates master key + RSA-2048 keypair and writes keyfiles.
"""

from __future__ import annotations
import os
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QGroupBox, QFileDialog, QMessageBox,
)
from PyQt6.QtGui import QFont


class _KeygenWorker(QThread):
    done  = pyqtSignal(str)   # fingerprint summary
    error = pyqtSignal(str)

    def __init__(self, keys_dir: str):
        super().__init__()
        self.keys_dir = keys_dir

    def run(self):
        try:
            import hashlib
            from core.crypto import (
                generate_master_key, generate_rsa_keypair,
                save_master_key, save_rsa_private, save_rsa_public,
            )
            os.makedirs(self.keys_dir, exist_ok=True)
            K      = generate_master_key()
            priv, pub = generate_rsa_keypair()
            save_master_key(K,    os.path.join(self.keys_dir, "master.key"))
            save_rsa_private(priv, os.path.join(self.keys_dir, "rsa_private.pem"))
            save_rsa_public(pub,   os.path.join(self.keys_dir, "rsa_public.pem"))

            fp = hashlib.sha256(K).hexdigest()[:16]
            summary = (
                f"Master key fingerprint : {fp}\n"
                f"RSA key size           : 2048-bit\n"
                f"Keys directory         : {os.path.abspath(self.keys_dir)}\n\n"
                f"Files written:\n"
                f"  master.key        (32 bytes  — keep SECRET)\n"
                f"  rsa_private.pem   (PEM       — keep SECRET)\n"
                f"  rsa_public.pem    (PEM       — distribute to server host)\n"
            )
            self.done.emit(summary)
        except Exception as exc:
            self.error.emit(str(exc))


class KeygenPanel(QWidget):
    keys_generated = pyqtSignal(str)   # keys_dir path — emitted to MainWindow

    def __init__(self, keys_dir: str, parent=None):
        super().__init__(parent)
        self.keys_dir = keys_dir
        self._worker  = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # ── Title ─────────────────────────────────────────────────────────────
        title = QLabel("🔑  Key Generation")
        title.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #c3e6fb;")
        layout.addWidget(title)

        desc = QLabel(
            "Generates a 256-bit master key K and an RSA-2048 keypair.\n"
            "The RSA private key drives the trapdoor chain; the public key\n"
            "is needed by the server to walk the chain during Search."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9aa8b8; font-size: 13px;")
        layout.addWidget(desc)

        # ── Keys dir picker ────────────────────────────────────────────────────
        dir_grp = QGroupBox("Keys Directory")
        dir_grp.setStyleSheet(self._grp_style())
        dir_lay = QHBoxLayout(dir_grp)

        self._dir_edit = QLineEdit(self.keys_dir)
        self._dir_edit.setReadOnly(True)
        self._dir_edit.setStyleSheet(self._input_style())
        dir_lay.addWidget(self._dir_edit)

        browse_btn = QPushButton("Browse …")
        browse_btn.setFixedWidth(90)
        browse_btn.setStyleSheet(self._btn_style("#3a4a5a"))
        browse_btn.clicked.connect(self._browse)
        dir_lay.addWidget(browse_btn)
        layout.addWidget(dir_grp)

        # ── Generate button ────────────────────────────────────────────────────
        self._gen_btn = QPushButton("⚡  Generate Keys")
        self._gen_btn.setFixedHeight(46)
        self._gen_btn.setStyleSheet(self._btn_style("#1a6eb5"))
        self._gen_btn.clicked.connect(self._generate)
        layout.addWidget(self._gen_btn)

        # ── Output log ────────────────────────────────────────────────────────
        out_grp = QGroupBox("Output")
        out_grp.setStyleSheet(self._grp_style())
        out_lay = QVBoxLayout(out_grp)
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setFont(QFont("Monospace", 11))
        self._log.setStyleSheet("background:#0d1117; color:#58d68d; border:none;")
        self._log.setMinimumHeight(180)
        out_lay.addWidget(self._log)
        layout.addWidget(out_grp)

        layout.addStretch()

        # ── Check if keys already exist ───────────────────────────────────────
        self._refresh_existing()

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Keys Directory", self.keys_dir)
        if d:
            self.keys_dir = d
            self._dir_edit.setText(d)
            self._refresh_existing()

    def _refresh_existing(self):
        have = all(
            os.path.exists(os.path.join(self.keys_dir, f))
            for f in ("master.key", "rsa_private.pem", "rsa_public.pem")
        )
        if have:
            self._log.setPlainText(
                f"✓ Keys already exist in:\n  {os.path.abspath(self.keys_dir)}\n\n"
                "Click 'Generate Keys' to regenerate (will overwrite)."
            )
            self.keys_generated.emit(self.keys_dir)

    def _generate(self):
        self._gen_btn.setEnabled(False)
        self._log.setPlainText("Generating RSA-2048 keypair …  (may take 1–2 s)")
        self._worker = _KeygenWorker(self.keys_dir)
        self._worker.done.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, summary: str):
        self._log.setPlainText(summary)
        self._gen_btn.setEnabled(True)
        self.keys_generated.emit(self.keys_dir)

    def _on_error(self, msg: str):
        self._log.setPlainText(f"ERROR:\n{msg}")
        self._gen_btn.setEnabled(True)
        QMessageBox.critical(self, "Key Generation Failed", msg)

    # ── Styles ─────────────────────────────────────────────────────────────────
    def _grp_style(self):
        return (
            "QGroupBox { color:#8899aa; border:1px solid #2a3a4a; border-radius:8px;"
            "  margin-top:10px; padding:8px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:10px; }"
        )

    def _btn_style(self, bg):
        return (
            f"QPushButton {{ background:{bg}; color:#e8f4fd; border:none;"
            "  border-radius:6px; padding:8px 18px; font-size:13px; font-weight:600; }"
            "QPushButton:hover { background: #2a80c8; }"
            "QPushButton:disabled { background:#2a3a4a; color:#556677; }"
        )

    def _input_style(self):
        return (
            "QLineEdit { background:#0d1117; color:#c3e6fb; border:1px solid #2a3a4a;"
            "  border-radius:5px; padding:6px; font-size:12px; }"
        )
