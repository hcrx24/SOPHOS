"""
sophos_client/core/state_db.py
SQLite-backed client-side keyword state store.

Schema:
  keyword_state(keyword TEXT PRIMARY KEY, st_blob BLOB, counter INTEGER)

  keyword  — plaintext keyword string (stored only on client, never sent to server)
  st_blob  — latest ST as 256-byte big-endian blob (RSA-2048 integer)
  counter  — number of times this keyword has been uploaded (0-indexed)

Thread safety:
  SQLite WAL mode allows one writer + multiple readers. The client serializes
  uploads (one at a time via UploadWorker) so concurrent writes cannot occur.
"""

import sqlite3
import os
import logging

logger = logging.getLogger("sophos.state_db")


class KeywordStateDB:
    """Manages per-keyword (ST, counter) state for the SOPHOS client."""

    def __init__(self, db_path: str = "client.db") -> None:
        self.db_path = db_path
        self._conn   = self._open()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keyword_state (
                keyword  TEXT    PRIMARY KEY,
                st_blob  BLOB    NOT NULL,
                counter  INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS doc_meta (
                doc_id   TEXT    PRIMARY KEY,   -- hex string
                filename TEXT    NOT NULL,
                keywords TEXT    NOT NULL        -- JSON list
            )
        """)
        conn.commit()
        logger.debug("State DB opened: %s", os.path.abspath(self.db_path))
        return conn

    # ─────────────────────────────────────────────
    #  Keyword State
    # ─────────────────────────────────────────────

    def get_state(self, keyword: str) -> tuple[bytes, int] | None:
        """
        Returns (st_blob, counter) for a keyword, or None if first occurrence.
        """
        row = self._conn.execute(
            "SELECT st_blob, counter FROM keyword_state WHERE keyword = ?",
            (keyword,),
        ).fetchone()
        return (bytes(row[0]), row[1]) if row else None

    def set_state(self, keyword: str, st_blob: bytes, counter: int) -> None:
        """Insert or replace keyword state."""
        self._conn.execute(
            """
            INSERT INTO keyword_state (keyword, st_blob, counter)
            VALUES (?, ?, ?)
            ON CONFLICT(keyword) DO UPDATE SET
                st_blob = excluded.st_blob,
                counter = excluded.counter
            """,
            (keyword, st_blob, counter),
        )
        self._conn.commit()

    def all_keywords(self) -> list[tuple[str, int]]:
        """Return [(keyword, counter), ...] for all tracked keywords."""
        rows = self._conn.execute(
            "SELECT keyword, counter FROM keyword_state ORDER BY keyword"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    # ─────────────────────────────────────────────
    #  Document Metadata
    # ─────────────────────────────────────────────

    def save_doc_meta(self, doc_id: bytes, filename: str, keywords: list[str]) -> None:
        import json
        self._conn.execute(
            """
            INSERT INTO doc_meta (doc_id, filename, keywords)
            VALUES (?, ?, ?)
            ON CONFLICT(doc_id) DO UPDATE SET
                filename = excluded.filename,
                keywords = excluded.keywords
            """,
            (doc_id.hex(), filename, json.dumps(keywords)),
        )
        self._conn.commit()

    def get_doc_meta(self, doc_id: bytes) -> dict | None:
        import json
        row = self._conn.execute(
            "SELECT filename, keywords FROM doc_meta WHERE doc_id = ?",
            (doc_id.hex(),),
        ).fetchone()
        if row is None:
            return None
        return {"filename": row[0], "keywords": json.loads(row[1])}

    def all_docs(self) -> list[dict]:
        import json
        rows = self._conn.execute(
            "SELECT doc_id, filename, keywords FROM doc_meta ORDER BY filename"
        ).fetchall()
        return [
            {"doc_id": bytes.fromhex(r[0]), "filename": r[1], "keywords": json.loads(r[2])}
            for r in rows
        ]

    def clear_all(self) -> None:
        """Clear all keyword state and document metadata from local SQLite DB."""
        self._conn.execute("DELETE FROM keyword_state")
        self._conn.execute("DELETE FROM doc_meta")
        self._conn.commit()

    # ─────────────────────────────────────────────
    #  Lifecycle
    # ─────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
