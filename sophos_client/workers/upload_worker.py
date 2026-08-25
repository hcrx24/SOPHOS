"""
sophos_client/workers/upload_worker.py
QThread worker for SOPHOS SSE document upload (single or batch files).

Workflow:
  For each file:
    1. Read the text file.
    2. Extract keywords using NLTK pipeline.
    3. Generate doc_id.
    4. Derive per-document AES key, encrypt document with AES-256-GCM.
    5. For each keyword:
         a. Load current (ST, counter) from client.db, or generate fresh ST_0.
         b. Advance chain: ST_new = pow(ST_cur, d, N)  (RSA-2048 private key).
         c. Compute UT = SHA256(Kw ‖ ST_new).
         d. Compute enc_id = doc_id XOR mask(Kw, ST_new).
         e. Save (ST_new, counter+1) back to client.db.
    6. gRPC: UploadDocument  (encrypted blob)
    7. gRPC: UploadIndex     (batch of UT→enc_id entries)
    8. Emit progress and result signals.
"""

from __future__ import annotations

import os
import logging
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger("sophos.upload_worker")


class UploadWorker(QThread):
    """
    Signals
    -------
    progress(int)       — 0..100 overall percentage
    status(str)         — human-readable status line
    keywords_ready(list[str])  — extracted keyword list (shown in GUI)
    finished_file(str, str)    — (doc_id_hex, filename) per completed file
    finished(int)              — total count of files uploaded
    error(str)                 — error message on failure
    """

    progress       = pyqtSignal(int)
    status         = pyqtSignal(str)
    keywords_ready = pyqtSignal(list)
    finished_file  = pyqtSignal(str, str)   # (doc_id_hex, filename)
    finished       = pyqtSignal(int)        # total count of files
    error          = pyqtSignal(str)

    def __init__(
        self,
        filepaths: str | list[str],
        master_key: bytes,
        rsa_d: int,
        rsa_n: int,
        state_db,             # KeywordStateDB instance
        grpc_stub,            # SophosServerStub instance
        parent=None,
    ) -> None:
        super().__init__(parent)
        if isinstance(filepaths, str):
            self.filepaths = [filepaths]
        else:
            self.filepaths = list(filepaths)
        self.master_key = master_key
        self.rsa_d      = rsa_d
        self.rsa_n      = rsa_n
        self.state_db   = state_db
        self.stub       = grpc_stub

    def run(self) -> None:
        try:
            self._upload_all()
        except Exception as exc:
            logger.exception("UploadWorker failed")
            self.error.emit(str(exc))

    def _upload_all(self) -> None:
        from core.crypto import (
            make_doc_id, doc_key, aes_gcm_encrypt,
            prf, random_st, apply_trapdoor,
            make_ut, encrypt_doc_id, st_to_bytes, st_from_bytes,
        )
        from core.keywords import extract_keywords
        import sophos_pb2

        total_files = len(self.filepaths)
        completed_files = 0

        for f_idx, filepath in enumerate(self.filepaths):
            filename = os.path.basename(filepath)
            prefix = f"[{f_idx + 1}/{total_files}] " if total_files > 1 else ""
            self.status.emit(f"{prefix}Reading {filename} ...")
            base_pct = int(100 * f_idx / total_files)
            file_weight = 100 / total_files
            self.progress.emit(base_pct + int(file_weight * 0.05))

            # ── 1. Read file ──────────────────────────────────────────────────────
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()

            # ── 2. Extract keywords ───────────────────────────────────────────────
            self.status.emit(f"{prefix}Extracting keywords from {filename} ...")
            keywords = sorted(extract_keywords(text))
            self.keywords_ready.emit(keywords)
            self.progress.emit(base_pct + int(file_weight * 0.20))

            # ── 3. Generate doc_id ────────────────────────────────────────────────
            doc_id = make_doc_id(filename)

            # ── 4. Encrypt document ───────────────────────────────────────────────
            self.status.emit(f"{prefix}Encrypting {filename} ...")
            k_doc = doc_key(self.master_key, doc_id)
            iv, ciphertext, tag = aes_gcm_encrypt(k_doc, text.encode("utf-8"))
            self.progress.emit(base_pct + int(file_weight * 0.35))

            # ── 5. Build index entries ────────────────────────────────────────────
            self.status.emit(f"{prefix}Building index entries for {filename} ...")
            entries = []
            n_kw = len(keywords)
            for idx, word in enumerate(keywords):
                kw_bytes = prf(self.master_key, word)

                state = self.state_db.get_state(word)
                if state is None:
                    st_cur = random_st(self.rsa_n)
                    counter = 0
                else:
                    st_blob, counter = state
                    st_cur = st_from_bytes(st_blob)
                    st_cur = apply_trapdoor(st_cur, self.rsa_d, self.rsa_n)
                    counter += 1

                ut     = make_ut(kw_bytes, st_cur)
                enc_id = encrypt_doc_id(doc_id, kw_bytes, st_cur)
                entries.append((ut, enc_id, word, st_to_bytes(st_cur), counter))

                if n_kw > 0:
                    pct = base_pct + int(file_weight * (0.35 + 0.40 * (idx + 1) / n_kw))
                    self.progress.emit(pct)

            # ── 6. gRPC: UploadDocument ───────────────────────────────────────────
            self.status.emit(f"{prefix}Sending encrypted document '{filename}' ...")
            req_doc = sophos_pb2.UploadDocRequest(
                doc_id=doc_id,
                iv=iv,
                ciphertext=ciphertext,
                tag=tag,
                filename=filename,
            )
            ack = self.stub.UploadDocument(req_doc)
            if not ack.ok:
                raise RuntimeError(f"Server rejected document upload ({filename}): {ack.msg}")

            # ── 7. gRPC: UploadIndex ──────────────────────────────────────────────
            self.status.emit(f"{prefix}Sending encrypted index entries for '{filename}' ...")
            index_entries = [
                sophos_pb2.IndexEntry(ut=ut, enc_id=enc_id)
                for ut, enc_id, *_ in entries
            ]
            req_idx = sophos_pb2.UploadIndexRequest(entries=index_entries)
            ack = self.stub.UploadIndex(req_idx)
            if not ack.ok:
                raise RuntimeError(f"Server rejected index upload ({filename}): {ack.msg}")

            # ── 8. Save state to client.db ────────────────────────────────────────
            self.status.emit(f"{prefix}Saving client state for '{filename}' ...")
            for ut, enc_id, word, st_blob, counter in entries:
                self.state_db.set_state(word, st_blob, counter)
            self.state_db.save_doc_meta(doc_id, filename, keywords)

            completed_files += 1
            self.finished_file.emit(doc_id.hex(), filename)
            self.progress.emit(int(100 * completed_files / total_files))

        self.status.emit(f"✓ Uploaded {completed_files} document(s) successfully.")
        self.finished.emit(completed_files)
