import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class FindingsDB:
    def __init__(self, db_path: str = "scanner.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT UNIQUE NOT NULL,
                    rule_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    commit_sha TEXT NOT NULL,
                    masked_secret TEXT NOT NULL,
                    entropy REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_findings(self, findings: list[dict], target_path: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with self._connect() as conn:
            for item in findings:
                cursor = conn.execute("""
                    INSERT INTO findings (
                        fingerprint, rule_id, description, severity,
                        target_path, file_path, line_number, commit_sha,
                        masked_secret, entropy, status, first_seen, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        commit_sha = excluded.commit_sha,
                        line_number = excluded.line_number
                """, (
                    item["fingerprint"],
                    item["rule_id"],
                    item["description"],
                    item["severity"],
                    target_path,
                    item["file"],
                    item["line"],
                    item["commit"],
                    item["masked_secret"],
                    item["entropy"],
                    now,
                    now,
                ))
                if cursor.rowcount == 1:
                    inserted += 1
            conn.commit()
        return inserted

    def list_findings(self, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM findings"
        params: list[str] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY id DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
