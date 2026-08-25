"""
sophos_server/db.py
LMDB storage backend for the SOPHOS SSE server.

Two named databases in a single LMDB environment:
  - encrypted_index : UT (32 bytes) → EncID (16 bytes)
  - doc_store       : doc_id (16 bytes) → packed(filename_len, filename, iv, tag, ciphertext)
"""

import lmdb
import struct
import os


class SophosDB:
    # Packing layout for doc_store values:
    #   [2B filename_len][filename][12B iv][16B tag][variable ciphertext]
    IV_LEN  = 12
    TAG_LEN = 16

    def __init__(self, db_path: str = "server.db", map_size: int = 1 * 1024 ** 3):
        """
        Open (or create) the LMDB environment.

        Args:
            db_path:  Path to the LMDB directory.
            map_size: Maximum database size in bytes (virtual, not pre-allocated).
                      Default: 1 GiB — more than enough for a demo.
        """
        os.makedirs(db_path, exist_ok=True)
        self.env = lmdb.open(
            db_path,
            max_dbs=2,
            map_size=map_size,
            metasync=True,
            sync=True,
        )
        self.index_db = self.env.open_db(b"encrypted_index")
        self.doc_db   = self.env.open_db(b"doc_store")

    # ─────────────────────────────────────────────
    #  Encrypted Index  (UT → EncID)
    # ─────────────────────────────────────────────

    def put_index_batch(self, entries: list[tuple[bytes, bytes]]) -> None:
        """Atomically insert a list of (ut, enc_id) pairs."""
        with self.env.begin(write=True) as txn:
            for ut, enc_id in entries:
                txn.put(ut, enc_id, db=self.index_db)

    def get_index_entry(self, ut: bytes) -> bytes | None:
        """Lookup a single UT. Returns enc_id bytes or None."""
        with self.env.begin() as txn:
            return txn.get(ut, db=self.index_db)

    def count_index_entries(self) -> int:
        with self.env.begin() as txn:
            return txn.stat(db=self.index_db)["entries"]

    def dump_index(self, limit: int = 500) -> list[tuple[bytes, bytes]]:
        """Return up to `limit` (ut, enc_id) pairs for display."""
        results = []
        with self.env.begin() as txn:
            cursor = txn.cursor(db=self.index_db)
            if cursor.first():
                while True:
                    results.append((bytes(cursor.key()), bytes(cursor.value())))
                    if len(results) >= limit or not cursor.next():
                        break
        return results

    # ─────────────────────────────────────────────
    #  Document Store  (doc_id → blob)
    # ─────────────────────────────────────────────

    def put_document(
        self,
        doc_id: bytes,
        iv: bytes,
        ciphertext: bytes,
        tag: bytes,
        filename: bytes,
    ) -> None:
        """Pack and store an encrypted document."""
        fn_len = struct.pack(">H", len(filename))
        packed = fn_len + filename + iv + tag + ciphertext
        with self.env.begin(write=True) as txn:
            txn.put(doc_id, packed, db=self.doc_db)

    def get_document(self, doc_id: bytes) -> dict | None:
        """Retrieve and unpack a document. Returns dict or None."""
        with self.env.begin() as txn:
            data = txn.get(doc_id, db=self.doc_db)
        if data is None:
            return None
        fn_len = struct.unpack(">H", data[:2])[0]
        offset   = 2
        filename = data[offset : offset + fn_len];  offset += fn_len
        iv       = data[offset : offset + self.IV_LEN];  offset += self.IV_LEN
        tag      = data[offset : offset + self.TAG_LEN]; offset += self.TAG_LEN
        ciphertext = data[offset:]
        return {
            "filename":   filename,
            "iv":         iv,
            "tag":        tag,
            "ciphertext": ciphertext,
        }

    def count_documents(self) -> int:
        with self.env.begin() as txn:
            return txn.stat(db=self.doc_db)["entries"]

    # ─────────────────────────────────────────────
    #  Lifecycle
    # ─────────────────────────────────────────────

    def clear_all(self) -> None:
        """Clear all entries from both encrypted_index and doc_store."""
        with self.env.begin(write=True) as txn:
            txn.drop(db=self.index_db, delete=False)
            txn.drop(db=self.doc_db, delete=False)

    def close(self) -> None:
        self.env.close()

    def stats(self) -> dict:
        return {
            "index_entries": self.count_index_entries(),
            "documents":     self.count_documents(),
        }
