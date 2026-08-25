"""
sophos_client/ui/server_state_panel.py
Server State tab: shows the encrypted index as stored on the server.
Demonstrates forward privacy: the server holds only opaque byte blobs.
Also provides a button to clear/reset both server LMDB and client state DB.
"""
from __future__ import annotations
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QCheckBox, QMessageBox,
)
from PyQt6.QtGui import QFont


class ServerStatePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._stub = None
        self._state_db = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._build_ui()

    def configure(self, stub, state_db=None):
        self._stub = stub
        self._state_db = state_db
        self._refresh()

    def _build_ui(self):
        lay = QVBoxLayout(self); lay.setSpacing(14); lay.setContentsMargins(24,24,24,24)

        t = QLabel("🗄️  Server Encrypted Index")
        t.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        t.setStyleSheet("color:#c3e6fb;"); lay.addWidget(t)

        info = QLabel(
            "This is what the server sees — every key and value is cryptographically opaque.\n"
            "No keyword, filename, or document ID is readable without the client's master key."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#9aa8b8;font-size:12px;"); lay.addWidget(info)

        # Stats row
        sg = QGroupBox("Statistics"); sg.setStyleSheet(self._gs())
        sl = QHBoxLayout(sg)
        self._idx_lbl  = QLabel("Index entries: —")
        self._doc_lbl  = QLabel("Documents: —")
        for lbl in (self._idx_lbl, self._doc_lbl):
            lbl.setStyleSheet("color:#58d68d;font-size:13px;font-weight:600;")
            sl.addWidget(lbl)
        sl.addStretch(); lay.addWidget(sg)

        # Controls
        ctl = QHBoxLayout()
        self._refresh_btn = QPushButton("⟳  Refresh"); self._refresh_btn.setFixedWidth(100)
        self._refresh_btn.setStyleSheet(self._bs("#3a4a5a"))
        self._refresh_btn.clicked.connect(self._refresh); ctl.addWidget(self._refresh_btn)
        
        self._auto_cb = QCheckBox("Auto-refresh (5 s)")
        self._auto_cb.setStyleSheet("color:#8899aa;")
        self._auto_cb.toggled.connect(self._toggle_auto)
        ctl.addWidget(self._auto_cb)
        
        ctl.addStretch()

        self._reset_btn = QPushButton("🗑️  Reset Database")
        self._reset_btn.setFixedWidth(140)
        self._reset_btn.setStyleSheet(self._bs("#b03a2e"))
        self._reset_btn.clicked.connect(self._reset_database)
        ctl.addWidget(self._reset_btn)

        lay.addLayout(ctl)

        # Index table
        ig = QGroupBox("Encrypted Index  (UT → EncID)  — first 500 entries")
        ig.setStyleSheet(self._gs()); il = QVBoxLayout(ig)
        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(["Update Token  UT  (SHA-256 hex)", "Encrypted Doc ID  (XOR hex)"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setStyleSheet(
            "QTableWidget{background:#0d1117;color:#e8f4fd;border:none;gridline-color:#1e2d3a;font-family:monospace;font-size:11px;}"
            "QHeaderView::section{background:#141e2b;color:#8899aa;padding:6px;border:none;}"
        )
        il.addWidget(self._table); lay.addWidget(ig, stretch=1)

    def _reset_database(self):
        if not self._stub:
            QMessageBox.warning(self, "Not Connected", "Please connect to the server first.")
            return

        reply = QMessageBox.question(
            self,
            "Reset Server Database",
            "Are you sure you want to clear the server database?\n\n"
            "This will delete ALL encrypted index entries and stored documents from the server, "
            "and reset client keyword state.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                ack = self._stub.ResetDatabase(self._grpc_pb2().ResetRequest())
                if ack.ok:
                    if self._state_db:
                        self._state_db.clear_all()
                    QMessageBox.information(self, "Success", "Server and client databases reset successfully.")
                    self._refresh()
                else:
                    QMessageBox.critical(self, "Error", f"Failed to reset server database: {ack.msg}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"RPC failed: {e}")

    def _refresh(self):
        if not self._stub: return
        try:
            # Ping for stats
            ack = self._stub.Ping(self._grpc_pb2().PingRequest())
            if ack.ok:
                parts = dict(p.split("=") for p in ack.msg.split(",") if "=" in p)
                self._idx_lbl.setText(f"Index entries: {parts.get('index_entries','?')}")
                self._doc_lbl.setText(f"Documents: {parts.get('documents','?')}")
            # Dump index entries
            self._table.setRowCount(0)
            for entry in self._stub.DumpIndex(self._grpc_pb2().DumpRequest()):
                row = self._table.rowCount(); self._table.insertRow(row)
                self._table.setItem(row, 0, QTableWidgetItem(entry.ut.hex()))
                self._table.setItem(row, 1, QTableWidgetItem(entry.enc_id.hex()))
        except Exception as e:
            self._idx_lbl.setText(f"Error: {e}")

    def _grpc_pb2(self):
        import sophos_pb2; return sophos_pb2

    def _toggle_auto(self, checked: bool):
        if checked: self._timer.start(5000)
        else:       self._timer.stop()

    def _gs(self):
        return ("QGroupBox{color:#8899aa;border:1px solid #2a3a4a;border-radius:8px;"
                "margin-top:10px;padding:8px;}QGroupBox::title{subcontrol-origin:margin;left:10px;}")

    def _bs(self, bg):
        return (
            f"QPushButton{{background:{bg};color:#e8f4fd;border:none;"
            f"border-radius:6px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#2a80c8;}}"
        )
