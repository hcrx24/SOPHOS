"""
sophos_client/workers/search_worker.py
QThread worker for SOPHOS SSE keyword search.

Workflow:
  1. Look up (ST_latest, counter) for the keyword in client.db.
  2. Compute Kw = HMAC(master_key, keyword).
  3. Send gRPC SearchRequest(kw_bytes, st_bytes, counter, rsa_e, rsa_n).
  4. Receive streaming SearchResult messages (step, enc_id).
     Results arrive ordered: step = counter → 0.
  5. For each result, recompute ST at that step and decrypt doc_id.
     ST for step i = apply_public^(counter-i) times from ST_latest.
     Since results arrive in order, we evolve st_cur with each result.
  6. Emit result_ready(doc_id_hex, step) for each hit.
  7. Emit finished(total_count).
"""

from __future__ import annotations
import logging
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger("sophos.search_worker")


class SearchWorker(QThread):
    """
    Signals
    -------
    result_ready(str, int)  — (doc_id_hex, chain_step) for each matched doc
    status(str)             — status messages
    finished(int)           — total hits found
    error(str)              — error message
    """

    result_ready = pyqtSignal(str, int)   # doc_id_hex, step
    status       = pyqtSignal(str)
    finished     = pyqtSignal(int)
    error        = pyqtSignal(str)

    def __init__(
        self,
        keyword: str,
        master_key: bytes,
        rsa_e: int,
        rsa_n: int,
        state_db,
        grpc_stub,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.keyword    = keyword.strip().lower()
        self.master_key = master_key
        self.rsa_e      = rsa_e
        self.rsa_n      = rsa_n
        self.state_db   = state_db
        self.stub       = grpc_stub

    def run(self) -> None:
        try:
            self._search()
        except Exception as exc:
            logger.exception("SearchWorker failed")
            self.error.emit(str(exc))

    def _search(self) -> None:
        from core.crypto import (
            prf, st_from_bytes, apply_public,
            decrypt_doc_id, st_to_bytes,
        )
        from core.keywords import extract_keywords
        import sophos_pb2

        # ── Normalize keyword through the same pipeline used at upload ────────
        normalized = extract_keywords(self.keyword)
        if not normalized:
            self.status.emit(f"Keyword '{self.keyword}' reduced to nothing after normalization.")
            self.finished.emit(0)
            return
        # Use the first (and usually only) result
        canonical = sorted(normalized)[0]
        self.status.emit(f"Searching for '{canonical}' (canonical form of '{self.keyword}') ...")

        # ── Look up client state ──────────────────────────────────────────────
        state = self.state_db.get_state(canonical)
        if state is None:
            self.status.emit(f"No documents indexed for '{canonical}'.")
            self.finished.emit(0)
            return

        st_blob, counter = state
        st_latest = st_from_bytes(st_blob)
        kw_bytes  = prf(self.master_key, canonical)

        self.status.emit(
            f"Sending trapdoor to server  (counter={counter}) ..."
        )

        # ── Build gRPC SearchRequest ──────────────────────────────────────────
        e_bytes = self.rsa_e.to_bytes((self.rsa_e.bit_length() + 7) // 8, "big")
        n_bytes = self.rsa_n.to_bytes(256, "big")  # 256 bytes for RSA-2048

        req = sophos_pb2.SearchRequest(
            kw_bytes=kw_bytes,
            st_bytes=st_to_bytes(st_latest),
            counter=counter,
            rsa_e=e_bytes,
            rsa_n=n_bytes,
        )

        # ── Receive streaming results ─────────────────────────────────────────
        hits     = 0
        st_cur   = st_latest   # we'll evolve downward with each result

        # Server streams results from step=counter down to step=0 in order.
        # We evolve st_cur to match the step of each returned result.
        current_step = counter

        for result in self.stub.Search(req):
            step   = result.step
            enc_id = result.enc_id

            # Evolve st_cur from current_step down to step.
            # Steps arrive in decreasing order: counter, counter-1, ..., 0
            # Each decrease of 1 requires one apply_public.
            steps_to_evolve = current_step - step
            for _ in range(steps_to_evolve):
                st_cur = apply_public(st_cur, self.rsa_e, self.rsa_n)
            current_step = step

            # Decrypt doc_id using st_cur at this step
            doc_id_bytes = decrypt_doc_id(enc_id, kw_bytes, st_cur)
            hits += 1
            self.result_ready.emit(doc_id_bytes.hex(), step)

        self.status.emit(f"Search complete — {hits} document(s) found for '{canonical}'")
        self.finished.emit(hits)
