"""
sophos_client/workers/fetch_worker.py
QThread worker to fetch and decrypt a single document from the server.

Workflow:
  1. gRPC FetchDocument(doc_id) → EncryptedDoc(iv, ciphertext, tag, filename)
  2. Derive K_doc = HMAC(master_key, b"doc" ‖ doc_id)
  3. AES-256-GCM decrypt
  4. Emit plaintext_ready(filename, plaintext_str)
"""

from __future__ import annotations
import logging
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger("sophos.fetch_worker")


class FetchWorker(QThread):
    """
    Signals
    -------
    plaintext_ready(str, str)  — (filename, plaintext content)
    error(str)                 — error message
    """

    plaintext_ready = pyqtSignal(str, str)   # filename, content
    error           = pyqtSignal(str)

    def __init__(
        self,
        doc_id_hex: str,
        master_key: bytes,
        grpc_stub,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.doc_id_hex = doc_id_hex
        self.master_key = master_key
        self.stub       = grpc_stub

    def run(self) -> None:
        try:
            self._fetch()
        except Exception as exc:
            logger.exception("FetchWorker failed")
            self.error.emit(str(exc))

    def _fetch(self) -> None:
        from core.crypto import doc_key, aes_gcm_decrypt
        import sophos_pb2

        doc_id = bytes.fromhex(self.doc_id_hex)
        req    = sophos_pb2.FetchDocRequest(doc_id=doc_id)
        enc    = self.stub.FetchDocument(req)

        k_doc     = doc_key(self.master_key, doc_id)
        plaintext = aes_gcm_decrypt(k_doc, enc.iv, enc.ciphertext, enc.tag)
        content   = plaintext.decode("utf-8", errors="replace")
        filename  = enc.filename or self.doc_id_hex

        self.plaintext_ready.emit(filename, content)
