"""
sophos_client/ui/upload_panel.py
Upload tab: multi-file picker with expandable file list, keyword preview, view all keywords dialog,
activity log with View & Export options, batch upload progress.
"""
from __future__ import annotations
import os
from PyQt6.QtCore import pyqtSignal, Qt, QSize
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QProgressBar, QTextEdit, QGroupBox, QFileDialog, QSizePolicy,
    QDialog, QLineEdit, QMessageBox, QApplication,
)
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent, QWheelEvent


class FileItemWidget(QWidget):
    """Custom item widget displaying filename, size, and an 'x' discard button."""
    remove_requested = pyqtSignal(str)   # filepath

    def __init__(self, filepath: str, parent=None):
        super().__init__(parent)
        self._filepath = filepath
        fn = os.path.basename(filepath)
        size_kb = os.path.getsize(filepath) / 1024 if os.path.exists(filepath) else 0

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 2, 8, 2)
        lay.setSpacing(8)

        lbl = QLabel(f"📄  {fn}  ({size_kb:.1f} KB)")
        lbl.setStyleSheet("color:#c3e6fb; font-size:12px;")
        lbl.setToolTip(filepath)
        lay.addWidget(lbl, stretch=1)

        btn = QPushButton("✖")
        btn.setFixedSize(22, 22)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setToolTip(f"Discard {fn}")
        btn.setStyleSheet(
            "QPushButton{background:#3a1e1e;color:#ff6b6b;border:none;border-radius:11px;"
            "font-size:11px;font-weight:bold;}"
            "QPushButton:hover{background:#b03a2e;color:#ffffff;}"
        )
        btn.clicked.connect(lambda: self.remove_requested.emit(self._filepath))
        lay.addWidget(btn)

    def wheelEvent(self, event: QWheelEvent) -> None:
        event.ignore()


class LogViewDialog(QDialog):
    """Modal dialog to view full activity log with text copy option."""
    def __init__(self, log_text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("📜 Client Activity Log")
        self.resize(680, 480)
        self.setStyleSheet("background-color: #0d1117; color: #e8f4fd;")
        self._build_ui(log_text)

    def _build_ui(self, log_text: str):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)

        t = QLabel("📜  Client Activity Log")
        t.setFont(QFont("Inter", 13, QFont.Weight.Bold))
        t.setStyleSheet("color: #c3e6fb;")
        lay.addWidget(t)

        self._te = QTextEdit()
        self._te.setReadOnly(True)
        self._te.setFont(QFont("Monospace", 11))
        self._te.setStyleSheet("background:#161b22;color:#9aa8b8;border:1px solid #2a3a4a;border-radius:6px;padding:8px;")
        self._te.setPlainText(log_text)
        lay.addWidget(self._te, stretch=1)

        btn_box = QHBoxLayout()
        btn_box.addStretch()

        copy_btn = QPushButton("📋 Copy Log")
        copy_btn.setStyleSheet(
            "QPushButton{background:#1f2d3d;color:#58d68d;border:none;border-radius:6px;padding:6px 14px;font-size:12px;font-weight:600;}"
            "QPushButton:hover{background:#2a3d52;}"
        )
        copy_btn.clicked.connect(self._copy_to_clipboard)
        btn_box.addWidget(copy_btn)

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(90)
        close_btn.setStyleSheet(
            "QPushButton{background:#3a4a5a;color:#e8f4fd;border:none;border-radius:6px;padding:6px 14px;font-size:12px;font-weight:600;}"
            "QPushButton:hover{background:#4a5a6a;}"
        )
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)

        lay.addLayout(btn_box)

    def _copy_to_clipboard(self):
        QApplication.clipboard().setText(self._te.toPlainText())
        QMessageBox.information(self, "Copied", "Log content copied to clipboard.")


class KeywordsDialog(QDialog):
    """Modal dialog to view and filter all extracted keywords from selected documents."""
    def __init__(self, title_str: str, keywords: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle(title_str)
        self.setMinimumSize(520, 480)
        self.setStyleSheet("background-color: #0d1117; color: #e8f4fd;")
        self._all_keywords = keywords
        self._build_ui(title_str)

    def _build_ui(self, title_str: str):
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(20, 20, 20, 20)

        title = QLabel(f"🔑  {title_str}")
        title.setFont(QFont("Inter", 13, QFont.Weight.Bold))
        title.setStyleSheet("color: #c3e6fb;")
        lay.addWidget(title)

        # Filter bar
        filter_layout = QHBoxLayout()
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("🔍 Filter keywords...")
        self._filter_edit.setStyleSheet(
            "QLineEdit{background:#161b22;color:#e8f4fd;border:1px solid #2a3a4a;"
            "border-radius:6px;padding:8px 12px;font-size:12px;}"
            "QLineEdit:focus{border:1px solid #1a6eb5;}"
        )
        self._filter_edit.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self._filter_edit, stretch=1)

        self._count_lbl = QLabel(f"Total: {len(self._all_keywords)}")
        self._count_lbl.setStyleSheet("color:#58d68d; font-size:12px; font-weight:bold;")
        filter_layout.addWidget(self._count_lbl)
        lay.addLayout(filter_layout)

        # Keywords list
        self._list_widget = QListWidget()
        self._list_widget.setStyleSheet(
            "QListWidget{background:#161b22;color:#58d68d;border:1px solid #2a3a4a;"
            "border-radius:6px;padding:6px;font-family:Monospace;font-size:12px;}"
            "QListWidget::item{padding:4px 8px;border-bottom:1px solid #1c2733;}"
            "QListWidget::item:hover{background:#1f2d3d;}"
        )
        lay.addWidget(self._list_widget, stretch=1)

        # Populate initial list
        self._populate_list(self._all_keywords)

        # Bottom close button
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.setStyleSheet(
            "QPushButton{background:#3a4a5a;color:#e8f4fd;border:none;"
            "border-radius:6px;padding:8px 18px;font-size:12px;font-weight:600;}"
            "QPushButton:hover{background:#4a5a6a;}"
        )
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)
        lay.addLayout(btn_box)

    def _populate_list(self, keywords: list[str]):
        self._list_widget.clear()
        for kw in keywords:
            self._list_widget.addItem(kw)

    def _apply_filter(self, text: str):
        query = text.strip().lower()
        if not query:
            filtered = self._all_keywords
        else:
            filtered = [k for k in self._all_keywords if query in k.lower()]
        self._populate_list(filtered)
        self._count_lbl.setText(f"Showing {len(filtered)} of {len(self._all_keywords)}")


class UploadPanel(QWidget):
    upload_complete = pyqtSignal(str, str)   # doc_id_hex, filename

    def __init__(self, sample_dir: str = "", parent=None):
        super().__init__(parent)
        self._sample_dir = sample_dir
        self._stub = self._master_key = self._rsa_d = self._rsa_n = self._state_db = None
        self._worker = None
        self._selected_files: list[str] = []
        self._extracted_keywords: list[str] = []
        self._build_ui()
        self.setAcceptDrops(True)

    def set_sample_dir(self, sample_dir: str):
        self._sample_dir = sample_dir

    def configure(self, stub, master_key, rsa_d, rsa_n, state_db):
        self._stub, self._master_key = stub, master_key
        self._rsa_d, self._rsa_n, self._state_db = rsa_d, rsa_n, state_db
        self._upload_btn.setEnabled(bool(self._selected_files))

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls(): e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        urls = e.mimeData().urls()
        paths = []
        for u in urls:
            p = u.toLocalFile()
            if p.endswith(".txt") and os.path.exists(p):
                paths.append(p)
        if paths:
            self._add_files(paths)
        else:
            self._log("Only .txt files are supported.")

    def _build_ui(self):
        lay = QVBoxLayout(self); lay.setSpacing(14); lay.setContentsMargins(24,24,24,24)

        t = QLabel("📄  Upload Documents")
        t.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        t.setStyleSheet("color:#c3e6fb;"); lay.addWidget(t)

        # Multi-file picker group with enlarged list and Browse button
        fg = QGroupBox("Selected Files  (drag & drop .txt or Browse)")
        fg.setStyleSheet(self._gs())
        fl = QHBoxLayout(fg)

        # File list with item widgets containing 'x' buttons (increased height for batch view)
        self._file_list = QListWidget()
        self._file_list.setMinimumHeight(140)
        self._file_list.setMaximumHeight(180)
        self._file_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self._file_list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self._file_list.setStyleSheet(
            "QListWidget{background:#0d1117;color:#c3e6fb;border:1px solid #1c2733;"
            "border-radius:4px;font-size:12px;outline:none;}"
            "QListWidget::item{padding:0px;border-bottom:1px solid #141e2b;}"
            "QScrollBar:vertical{background:#0d1117;width:10px;margin:2px;border-radius:4px;}"
            "QScrollBar::handle:vertical{background:#2a3a4a;min-height:20px;border-radius:4px;}"
            "QScrollBar::handle:vertical:hover{background:#1a6eb5;}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical{height:0px;}"
        )
        fl.addWidget(self._file_list, stretch=1)

        self._browse_btn = QPushButton("Browse …")
        self._browse_btn.setFixedWidth(100)
        self._browse_btn.setFixedHeight(36)
        self._browse_btn.setStyleSheet(self._bs("#3a4a5a"))
        self._browse_btn.clicked.connect(self._browse)
        fl.addWidget(self._browse_btn)

        lay.addWidget(fg)

        # Keywords preview group with header button
        kg = QGroupBox("Extracted Keywords")
        kg.setStyleSheet(self._gs())
        kl = QVBoxLayout(kg)

        hdr_bar = QHBoxLayout()
        hdr_lbl = QLabel("Preview extracted keywords:")
        hdr_lbl.setStyleSheet("color:#8899aa; font-size:11px;")
        hdr_bar.addWidget(hdr_lbl)
        hdr_bar.addStretch()

        self._view_kws_btn = QPushButton("🔍  View All Keywords")
        self._view_kws_btn.setEnabled(False)
        self._view_kws_btn.setStyleSheet(
            "QPushButton{background:#1f2d3d;color:#58d68d;border:1px solid #2a3a4a;"
            "border-radius:4px;padding:4px 10px;font-size:11px;font-weight:600;}"
            "QPushButton:hover{background:#2a3d52;color:#70e8a0;}"
            "QPushButton:disabled{background:#161b22;color:#445566;border-color:#1c2733;}"
        )
        self._view_kws_btn.clicked.connect(self._show_keywords_dialog)
        hdr_bar.addWidget(self._view_kws_btn)
        kl.addLayout(hdr_bar)

        self._kw = QListWidget()
        self._kw.setStyleSheet("QListWidget{background:#0d1117;color:#58d68d;border:none;font-size:12px;}")
        self._kw.setMaximumHeight(85); kl.addWidget(self._kw); lay.addWidget(kg)

        # Progress
        self._prog = QProgressBar(); self._prog.setValue(0)
        self._prog.setStyleSheet(
            "QProgressBar{background:#1a2430;border:1px solid #2a3a4a;border-radius:5px;color:#e8f4fd;}"
            "QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #1a6eb5,stop:1 #58d68d);border-radius:4px;}"
        ); lay.addWidget(self._prog)

        self._upload_btn = QPushButton("⬆  Upload to Server")
        self._upload_btn.setFixedHeight(46); self._upload_btn.setEnabled(False)
        self._upload_btn.setStyleSheet(self._bs("#1a6eb5"))
        self._upload_btn.clicked.connect(self._upload); lay.addWidget(self._upload_btn)

        # Log section with View and Export buttons
        lg = QGroupBox("Log")
        lg.setStyleSheet(self._gs())
        ll = QVBoxLayout(lg)

        log_hdr = QHBoxLayout()
        log_lbl = QLabel("Activity Log:")
        log_lbl.setStyleSheet("color:#8899aa; font-size:11px;")
        log_hdr.addWidget(log_lbl)
        log_hdr.addStretch()

        self._view_log_btn = QPushButton("👁  View Log")
        self._view_log_btn.setStyleSheet(
            "QPushButton{background:#1f2d3d;color:#c3e6fb;border:1px solid #2a3a4a;"
            "border-radius:4px;padding:3px 8px;font-size:11px;font-weight:600;}"
            "QPushButton:hover{background:#2a3d52;}"
        )
        self._view_log_btn.clicked.connect(self._view_log)
        log_hdr.addWidget(self._view_log_btn)

        self._export_log_btn = QPushButton("💾  Export Log")
        self._export_log_btn.setStyleSheet(
            "QPushButton{background:#1f2d3d;color:#58d68d;border:1px solid #2a3a4a;"
            "border-radius:4px;padding:3px 8px;font-size:11px;font-weight:600;}"
            "QPushButton:hover{background:#2a3d52;}"
        )
        self._export_log_btn.clicked.connect(self._export_log)
        log_hdr.addWidget(self._export_log_btn)

        self._clear_log_btn = QPushButton("🗑️  Clear Log")
        self._clear_log_btn.setStyleSheet(
            "QPushButton{background:#1f2d3d;color:#ff6b6b;border:1px solid #2a3a4a;"
            "border-radius:4px;padding:3px 8px;font-size:11px;font-weight:600;}"
            "QPushButton:hover{background:#3a1e1e;}"
        )
        self._clear_log_btn.clicked.connect(self._clear_log)
        log_hdr.addWidget(self._clear_log_btn)

        ll.addLayout(log_hdr)

        self._log_v = QTextEdit()
        self._log_v.setReadOnly(True)
        self._log_v.setFont(QFont("Monospace", 10))
        self._log_v.setStyleSheet("background:#0d1117;color:#9aa8b8;border:none;")
        self._log_v.setMaximumHeight(100)
        ll.addWidget(self._log_v)

        lay.addWidget(lg); lay.addStretch()

        self._refresh_selected_files()

    def _browse(self):
        init_dir = self._sample_dir if (self._sample_dir and os.path.exists(self._sample_dir)) else ""
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Text Files", init_dir, "Text Files (*.txt)")
        if paths:
            self._add_files(paths)

    def _add_files(self, paths: list[str]):
        new_added = False
        for p in paths:
            if p not in self._selected_files:
                self._selected_files.append(p)
                new_added = True

        if new_added:
            self._refresh_selected_files()

    def _remove_file(self, path: str):
        if path in self._selected_files:
            self._selected_files.remove(path)
            self._refresh_selected_files()

    def _refresh_selected_files(self):
        self._file_list.clear()
        if not self._selected_files:
            item = QListWidgetItem("No files selected  (drag & drop .txt or click Browse)")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            item.setForeground(Qt.GlobalColor.gray)
            self._file_list.addItem(item)
        else:
            for p in self._selected_files:
                item = QListWidgetItem()
                item.setSizeHint(QSize(0, 32))
                widget = FileItemWidget(p)
                widget.remove_requested.connect(self._remove_file)
                self._file_list.addItem(item)
                self._file_list.setItemWidget(item, widget)

        self._kw.clear()
        self._prog.setValue(0)
        self._extracted_keywords = []

        n = len(self._selected_files)
        if n > 0:
            try:
                from core.keywords import extract_keywords
                all_kws = set()
                for p in self._selected_files:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        txt = f.read()
                    all_kws.update(extract_keywords(txt))
                self._extracted_keywords = sorted(all_kws)
                for k in self._extracted_keywords:
                    self._kw.addItem(k)
                self._view_kws_btn.setEnabled(bool(self._extracted_keywords))
                self._log(f"Extracted {len(self._extracted_keywords)} unique keywords across {n} file(s)")
            except Exception as e:
                self._log(f"Extract error: {e}")
                self._view_kws_btn.setEnabled(False)
        else:
            self._view_kws_btn.setEnabled(False)

        if self._stub:
            self._upload_btn.setEnabled(bool(self._selected_files))

    def _show_keywords_dialog(self):
        if not self._selected_files or not self._extracted_keywords:
            return
        n = len(self._selected_files)
        title_str = f"Extracted Keywords from {n} file(s)" if n > 1 else f"Extracted Keywords — {os.path.basename(self._selected_files[0])}"
        dlg = KeywordsDialog(title_str, self._extracted_keywords, parent=self)
        dlg.exec()

    def _view_log(self):
        log_content = self._log_v.toPlainText()
        if not log_content.strip():
            log_content = "(Log is currently empty)"
        dlg = LogViewDialog(log_content, parent=self)
        dlg.exec()

    def _export_log(self):
        log_content = self._log_v.toPlainText()
        if not log_content.strip():
            QMessageBox.information(self, "Export Log", "The activity log is currently empty.")
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Activity Log",
            "sophos_upload_log.txt",
            "Text Files (*.txt);;All Files (*)",
        )
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(log_content)
                QMessageBox.information(self, "Log Exported", f"Activity log exported successfully to:\n{filepath}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to save log file:\n{e}")

    def _clear_log(self):
        self._log_v.clear()

    def _upload(self):
        if not self._selected_files or not self._stub: return
        from workers.upload_worker import UploadWorker
        self._upload_btn.setEnabled(False)
        self._browse_btn.setEnabled(False)
        self._prog.setValue(0)

        self._worker = UploadWorker(self._selected_files, self._master_key,
                                    self._rsa_d, self._rsa_n, self._state_db, self._stub)
        self._worker.progress.connect(self._prog.setValue)
        self._worker.status.connect(self._log)
        self._worker.finished_file.connect(self._on_file_done)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_err)
        self._worker.start()

    def _on_file_done(self, did: str, fn: str):
        self._log(f"✓ Uploaded '{fn}' — doc_id: {did[:16]}…")
        self.upload_complete.emit(did, fn)

    def _clear_selection(self):
        self._selected_files = []
        self._refresh_selected_files()

    def _on_done(self, count: int):
        self._log(f"✓ Batch upload complete — {count} file(s) uploaded successfully.")
        self._browse_btn.setEnabled(True)
        self._clear_selection()

    def _on_err(self, msg):
        self._browse_btn.setEnabled(True)
        self._upload_btn.setEnabled(bool(self._selected_files))
        self._log(f"✗ {msg}")

    def _log(self, m): self._log_v.append(m)

    def _gs(self):
        return ("QGroupBox{color:#8899aa;border:1px solid #2a3a4a;border-radius:8px;"
                "margin-top:10px;padding:8px;}QGroupBox::title{subcontrol-origin:margin;left:10px;}")

    def _bs(self, bg):
        return (
            f"QPushButton{{background:{bg};color:#e8f4fd;border:none;"
            f"border-radius:6px;padding:6px 12px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{background:#2a80c8;}}"
            f"QPushButton:disabled{{background:#2a3a4a;color:#556677;}}"
        )
