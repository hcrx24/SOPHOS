"""
sophos_client/ui/search_panel.py
Search tab: keyword input, streaming results table, document preview, download & open.
Dynamically tracks local download status based on actual filesystem state.
"""
from __future__ import annotations
import os
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QTextEdit,
    QGroupBox, QHeaderView, QDialog, QDialogButtonBox, QMessageBox,
)
from PyQt6.QtGui import QFont, QDesktopServices, QShowEvent


class DocViewDialog(QDialog):
    """Simple read-only dialog to display decrypted document content."""
    def __init__(self, filename: str, content: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"📄  {filename}")
        self.resize(700, 500)
        lay = QVBoxLayout(self)
        te = QTextEdit(); te.setReadOnly(True)
        te.setFont(QFont("Monospace", 11))
        te.setStyleSheet("background:#0d1117;color:#e8f4fd;border:none;")
        te.setPlainText(content)
        lay.addWidget(te)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject); lay.addWidget(bb)


class SearchPanel(QWidget):
    def __init__(self, download_dir: str = "", parent=None):
        super().__init__(parent)
        self._download_dir = download_dir
        self._stub = self._master_key = self._rsa_e = self._rsa_n = self._state_db = None
        self._search_worker = self._fetch_worker = None
        self._results: dict[str, int] = {}   # doc_id_hex → step
        self._build_ui()

    def set_download_dir(self, download_dir: str):
        self._download_dir = download_dir
        os.makedirs(self._download_dir, exist_ok=True)

    def configure(self, stub, master_key, rsa_e, rsa_n, state_db):
        self._stub, self._master_key = stub, master_key
        self._rsa_e, self._rsa_n, self._state_db = rsa_e, rsa_n, state_db
        self._search_btn.setEnabled(True)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._refresh_download_statuses()

    def _build_ui(self):
        lay = QVBoxLayout(self); lay.setSpacing(14); lay.setContentsMargins(24,24,24,24)

        t = QLabel("🔍  Keyword Search")
        t.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        t.setStyleSheet("color:#c3e6fb;"); lay.addWidget(t)

        # Search bar
        sb = QGroupBox("Search"); sb.setStyleSheet(self._gs())
        sl = QHBoxLayout(sb)
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Enter keyword (e.g.  vpn,  rsa,  encrypt,  audit) ...")
        self._search_input.setStyleSheet(self._is())
        self._search_input.returnPressed.connect(self._search)
        sl.addWidget(self._search_input)
        self._search_btn = QPushButton("🔍  Search")
        self._search_btn.setFixedWidth(110); self._search_btn.setEnabled(False)
        self._search_btn.setStyleSheet(self._bs("#1a6eb5"))
        self._search_btn.clicked.connect(self._search)
        sl.addWidget(self._search_btn); lay.addWidget(sb)

        # Status
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#8899aa;font-size:12px;")
        lay.addWidget(self._status_lbl)

        # Results table
        rg = QGroupBox("Results  (double-click row to decrypt & view)")
        rg.setStyleSheet(self._gs()); rl = QVBoxLayout(rg)
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Doc ID (hex)", "Filename", "Chain Step", "Download Status"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setStyleSheet(
            "QTableWidget{background:#0d1117;color:#e8f4fd;border:none;gridline-color:#1e2d3a;}"
            "QHeaderView::section{background:#141e2b;color:#8899aa;padding:6px;border:none;}"
            "QTableWidget::item:selected{background:#1a3a5a;}"
        )
        self._table.doubleClicked.connect(self._view_doc)
        rl.addWidget(self._table); lay.addWidget(rg, stretch=1)

        # Actions bar
        act_box = QHBoxLayout(); act_box.setSpacing(10)

        self._view_btn = QPushButton("👁  Preview")
        self._view_btn.setEnabled(False)
        self._view_btn.setStyleSheet(self._bs("#2a5a2a"))
        self._view_btn.clicked.connect(self._view_selected)
        act_box.addWidget(self._view_btn)

        self._dl_btn = QPushButton("⬇  Download Document")
        self._dl_btn.setEnabled(False)
        self._dl_btn.setStyleSheet(self._bs("#1a6eb5"))
        self._dl_btn.clicked.connect(self._download_selected)
        act_box.addWidget(self._dl_btn)

        self._open_btn = QPushButton("📄  Open Downloaded File")
        self._open_btn.setEnabled(False)
        self._open_btn.setStyleSheet(self._bs("#6c3483"))
        self._open_btn.clicked.connect(self._open_selected)
        act_box.addWidget(self._open_btn)

        self._open_folder_btn = QPushButton("📁  Open Downloads Folder")
        self._open_folder_btn.setStyleSheet(self._bs("#3a4a5a"))
        self._open_folder_btn.clicked.connect(self._open_downloads_folder)
        act_box.addWidget(self._open_folder_btn)

        lay.addLayout(act_box)

        self._table.itemSelectionChanged.connect(self._update_action_buttons)

    def _refresh_download_statuses(self):
        """Re-check filesystem state for all rows in the results table."""
        for row in range(self._table.rowCount()):
            item_doc = self._table.item(row, 0)
            item_fn  = self._table.item(row, 1)
            item_st  = self._table.item(row, 3)
            if not item_doc or not item_fn or not item_st:
                continue

            doc_id_hex = item_doc.data(Qt.ItemDataRole.UserRole)
            filename   = item_fn.text()
            filepath   = self._get_local_download_path(filename, doc_id_hex)

            if os.path.exists(filepath):
                item_st.setText(f"Saved: {os.path.basename(filepath)}")
                item_st.setForeground(Qt.GlobalColor.green)
            else:
                item_st.setText("Not Downloaded")
                item_st.setForeground(Qt.GlobalColor.white)

    def _update_action_buttons(self):
        self._refresh_download_statuses()
        selected = self._table.selectedItems()
        has_sel = len(selected) > 0
        self._view_btn.setEnabled(has_sel)
        self._dl_btn.setEnabled(has_sel)

        if has_sel:
            row = selected[0].row()
            doc_id_hex = self._table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            filename = self._table.item(row, 1).text()
            filepath = self._get_local_download_path(filename, doc_id_hex)
            self._open_btn.setEnabled(os.path.exists(filepath))
        else:
            self._open_btn.setEnabled(False)

    def _get_local_download_path(self, filename: str, doc_id_hex: str) -> str:
        safe_fn = filename if filename and filename != "—" else f"doc_{doc_id_hex[:12]}.txt"
        if not self._download_dir:
            self._download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(self._download_dir, exist_ok=True)
        return os.path.join(self._download_dir, safe_fn)

    def _search(self):
        kw = self._search_input.text().strip()
        if not kw or not self._stub: return
        from workers.search_worker import SearchWorker
        self._search_btn.setEnabled(False)
        self._table.setRowCount(0)
        self._results.clear()
        self._status_lbl.setText(f"Searching for '{kw}' ...")
        self._search_worker = SearchWorker(kw, self._master_key, self._rsa_e,
                                           self._rsa_n, self._state_db, self._stub)
        self._search_worker.result_ready.connect(self._on_result)
        self._search_worker.status.connect(self._status_lbl.setText)
        self._search_worker.finished.connect(self._on_search_done)
        self._search_worker.error.connect(self._on_err)
        self._search_worker.start()

    def _on_result(self, doc_id_hex: str, step: int):
        self._results[doc_id_hex] = step
        row = self._table.rowCount(); self._table.insertRow(row)
        filename = "—"
        if self._state_db:
            meta = self._state_db.get_doc_meta(bytes.fromhex(doc_id_hex))
            if meta: filename = meta["filename"]

        dl_path = self._get_local_download_path(filename, doc_id_hex)
        dl_status = "Saved: " + os.path.basename(dl_path) if os.path.exists(dl_path) else "Not Downloaded"

        for col, val in enumerate([doc_id_hex[:20]+"…", filename, str(step), dl_status]):
            item = QTableWidgetItem(val)
            item.setData(Qt.ItemDataRole.UserRole, doc_id_hex)
            if col == 3 and os.path.exists(dl_path):
                item.setForeground(Qt.GlobalColor.green)
            self._table.setItem(row, col, item)

    def _on_search_done(self, count: int):
        self._search_btn.setEnabled(True)
        self._status_lbl.setText(f"✓  {count} document(s) found.")

    def _on_err(self, msg):
        self._search_btn.setEnabled(True)
        self._status_lbl.setText(f"✗ Error: {msg}")

    def _view_selected(self):
        rows = self._table.selectedItems()
        if not rows: return
        doc_id_hex = rows[0].data(Qt.ItemDataRole.UserRole)
        self._fetch_and_show(doc_id_hex)

    def _view_doc(self, index):
        item = self._table.item(index.row(), 0)
        if item: self._fetch_and_show(item.data(Qt.ItemDataRole.UserRole))

    def _fetch_and_show(self, doc_id_hex: str):
        from workers.fetch_worker import FetchWorker
        self._fetch_worker = FetchWorker(doc_id_hex, self._master_key, self._stub)
        self._fetch_worker.plaintext_ready.connect(
            lambda fn, ct: DocViewDialog(fn, ct, self).exec()
        )
        self._fetch_worker.error.connect(self._on_err)
        self._fetch_worker.start()

    def _download_selected(self):
        rows = self._table.selectedItems()
        if not rows: return
        row = rows[0].row()
        doc_id_hex = self._table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        filename = self._table.item(row, 1).text()

        self._status_lbl.setText(f"Downloading document {doc_id_hex[:12]}… ...")
        from workers.fetch_worker import FetchWorker
        self._fetch_worker = FetchWorker(doc_id_hex, self._master_key, self._stub)
        self._fetch_worker.plaintext_ready.connect(
            lambda fn, content: self._on_download_complete(row, doc_id_hex, fn, content)
        )
        self._fetch_worker.error.connect(self._on_err)
        self._fetch_worker.start()

    def _on_download_complete(self, row: int, doc_id_hex: str, filename: str, content: str):
        filepath = self._get_local_download_path(filename, doc_id_hex)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            self._status_lbl.setText(f"✓ Downloaded successfully: {filepath}")
            
            # Re-check and update all statuses dynamically
            self._refresh_download_statuses()
            self._update_action_buttons()
            
            QMessageBox.information(
                self, "Download Complete",
                f"File decrypted and downloaded to:\n{filepath}"
            )
        except Exception as e:
            self._on_err(f"Failed to write file: {e}")

    def _open_selected(self):
        rows = self._table.selectedItems()
        if not rows: return
        row = rows[0].row()
        doc_id_hex = self._table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        filename = self._table.item(row, 1).text()
        filepath = self._get_local_download_path(filename, doc_id_hex)

        if os.path.exists(filepath):
            QDesktopServices.openUrl(QUrl.fromLocalFile(filepath))
        else:
            self._refresh_download_statuses()
            self._update_action_buttons()
            QMessageBox.warning(self, "File Not Found", f"File does not exist:\n{filepath}")

    def _open_downloads_folder(self):
        if not self._download_dir:
            self._download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(self._download_dir, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(self._download_dir))

    def _gs(self):
        return ("QGroupBox{color:#8899aa;border:1px solid #2a3a4a;border-radius:8px;"
                "margin-top:10px;padding:8px;}QGroupBox::title{subcontrol-origin:margin;left:10px;}")

    def _bs(self, bg):
        return (
            f"QPushButton{{background:{bg};color:#e8f4fd;border:none;"
            f"border-radius:6px;padding:8px 18px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#2a80c8;}}"
            f"QPushButton:disabled{{background:#2a3a4a;color:#556677;}}"
        )

    def _is(self):
        return ("QLineEdit{background:#0d1117;color:#c3e6fb;border:1px solid #2a3a4a;"
                "border-radius:5px;padding:8px;font-size:13px;}")
