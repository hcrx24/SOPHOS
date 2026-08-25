"""
sophos_server/servicer.py
gRPC service implementation for the SOPHOS SSE server.

The server:
  - Stores encrypted documents and the encrypted index (LMDB).
  - On Search(), walks the RSA-2048 trapdoor chain using the PUBLIC key
    (e, N) received in the request, performing one point-lookup per step.
  - Streams SearchResult messages so the GUI shows results in real time.

Security note:
  - The server never sees plaintext keywords, doc IDs, or document content.
  - The server uses only the RSA public key (e, N) — received in the request.
"""

import hashlib
import logging
import grpc

import sophos_pb2
import sophos_pb2_grpc
from db import SophosDB

logger = logging.getLogger("sophos.servicer")


class SophosServicer(sophos_pb2_grpc.SophosServerServicer):
    """Implements the SophosServer gRPC service."""

    ST_BYTE_LEN = 256  # RSA-2048 → 256-byte integers

    def __init__(self, db: SophosDB) -> None:
        self.db = db

    # ─────────────────────────────────────────────
    #  Upload
    # ─────────────────────────────────────────────

    def UploadDocument(self, request, context):
        try:
            filename = (
                request.filename.encode("utf-8")
                if isinstance(request.filename, str)
                else request.filename
            )
            self.db.put_document(
                doc_id=request.doc_id,
                iv=request.iv,
                ciphertext=request.ciphertext,
                tag=request.tag,
                filename=filename,
            )
            stats = self.db.stats()
            logger.info("UploadDocument OK  docs=%d", stats["documents"])
            return sophos_pb2.Ack(ok=True, msg="Document stored")
        except Exception as exc:
            logger.exception("UploadDocument failed")
            return sophos_pb2.Ack(ok=False, msg=str(exc))

    def UploadIndex(self, request, context):
        try:
            entries = [(e.ut, e.enc_id) for e in request.entries]
            self.db.put_index_batch(entries)
            stats = self.db.stats()
            logger.info(
                "UploadIndex OK  +%d entries  total=%d",
                len(entries),
                stats["index_entries"],
            )
            return sophos_pb2.Ack(ok=True, msg=f"Stored {len(entries)} index entries")
        except Exception as exc:
            logger.exception("UploadIndex failed")
            return sophos_pb2.Ack(ok=False, msg=str(exc))

    # ─────────────────────────────────────────────
    #  Search  (server-streaming)
    # ─────────────────────────────────────────────

    def Search(self, request, context):
        """
        Walk the RSA trapdoor chain from step=counter down to step=0.

        For each step i:
          ST_i is the current state (RSA-2048 integer).
          UT_i = SHA256(kw_bytes ‖ ST_i_bytes)
          Look up UT_i in the encrypted index.
          If found, stream SearchResult(enc_id, step=i).
          Evolve: ST_{i-1} = pow(ST_i, e, N)  [using RSA public key]
        """
        kw_bytes = request.kw_bytes        # 32 bytes
        st_bytes = request.st_bytes        # 256 bytes (RSA-2048 big-endian)
        counter  = request.counter         # inclusive upper bound of chain
        rsa_e    = int.from_bytes(request.rsa_e, "big")
        rsa_n    = int.from_bytes(request.rsa_n, "big")

        if not kw_bytes or not st_bytes or rsa_n == 0:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Missing required search fields")
            return

        st_int   = int.from_bytes(st_bytes, "big")
        hits     = 0

        for step in range(counter, -1, -1):
            # Check if client has cancelled (GUI closed mid-search)
            if context.is_active() is False:
                break

            # Compute Update Token for this step
            st_cur_bytes = st_int.to_bytes(self.ST_BYTE_LEN, "big")
            ut = hashlib.sha256(kw_bytes + st_cur_bytes).digest()

            # Point lookup in LMDB
            enc_id = self.db.get_index_entry(ut)
            if enc_id is not None:
                hits += 1
                yield sophos_pb2.SearchResult(enc_id=enc_id, step=step)

            # Evolve to previous token using RSA public exponentiation
            if step > 0:
                st_int = pow(st_int, rsa_e, rsa_n)

        logger.info("Search done  counter=%d  hits=%d", counter, hits)

    # ─────────────────────────────────────────────
    #  Fetch
    # ─────────────────────────────────────────────

    def FetchDocument(self, request, context):
        doc = self.db.get_document(request.doc_id)
        if doc is None:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Document not found")
            return sophos_pb2.EncryptedDoc()
        return sophos_pb2.EncryptedDoc(
            iv=doc["iv"],
            ciphertext=doc["ciphertext"],
            tag=doc["tag"],
            filename=doc["filename"].decode("utf-8", errors="replace"),
        )

    # ─────────────────────────────────────────────
    #  Debug / Demo
    # ─────────────────────────────────────────────

    def DumpIndex(self, request, context):
        """Stream up to 500 index entries for the Server State panel."""
        for ut, enc_id in self.db.dump_index(limit=500):
            yield sophos_pb2.IndexEntry(ut=ut, enc_id=enc_id)

    def ResetDatabase(self, request, context):
        """Clear all entries from LMDB encrypted index and document store."""
        try:
            self.db.clear_all()
            logger.info("ResetDatabase OK — all LMDB data cleared")
            return sophos_pb2.Ack(ok=True, msg="Database reset successfully")
        except Exception as exc:
            logger.exception("ResetDatabase failed")
            return sophos_pb2.Ack(ok=False, msg=str(exc))

    def Ping(self, request, context):
        stats = self.db.stats()
        msg = f"index_entries={stats['index_entries']},documents={stats['documents']}"
        return sophos_pb2.Ack(ok=True, msg=msg)
