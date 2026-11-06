"""
SQLite storage (standard library only - no extra dependency).

Tables:
  batches - one row per sealed batch (root, anchoring status)
  logs    - every log; batch_id is NULL while the log is still pending
  alerts  - detection results and tamper alerts

The database file survives restarts, so batches and their logs are no
longer lost when the server stops.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .merkle import MerkleTree

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class PendingLimitError(Exception):
    """Raised when too many un-sealed logs are waiting."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dump(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id      INTEGER PRIMARY KEY,
    merkle_root   TEXT    NOT NULL,
    log_count     INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    anchored      INTEGER NOT NULL DEFAULT 0,
    tx_hash       TEXT,
    block_number  INTEGER,
    chain_id      INTEGER,
    anchor_error  TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id   INTEGER REFERENCES batches(batch_id),
    idx        INTEGER,
    entry_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_batch ON logs(batch_id, idx);
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    message      TEXT NOT NULL,
    batch_id     INTEGER,
    log_index    INTEGER,
    created_at   TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
"""


class Store:
    def __init__(self, db_path: str, max_pending: int = 10_000):
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _scalar(self, sql: str, params: Iterable = ()) -> Any:
        return self._db.execute(sql, tuple(params)).fetchone()[0]

    # ---------------------------------------------------------------- logs
    def add_log(self, entry: dict) -> int:
        with self._lock:
            pending = self._scalar("SELECT COUNT(*) FROM logs WHERE batch_id IS NULL")
            if pending >= self.max_pending:
                raise PendingLimitError(
                    f"{pending} logs are already pending (limit {self.max_pending}); seal a batch first"
                )
            self._db.execute("INSERT INTO logs(batch_id, idx, entry_json) VALUES (NULL, NULL, ?)", (_dump(entry),))
            self._db.commit()
            return pending

    def pending_count(self) -> int:
        with self._lock:
            return self._scalar("SELECT COUNT(*) FROM logs WHERE batch_id IS NULL")

    # ------------------------------------------------------------- batches
    def seal_batch(self, min_batch_id: int = 1) -> Dict[str, Any]:
        """Turn all pending logs into a batch. min_batch_id lets the caller skip past ids already used on-chain."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, entry_json FROM logs WHERE batch_id IS NULL ORDER BY id"
            ).fetchall()
            if not rows:
                raise ValueError("No pending logs to seal into a batch")
            entries = [json.loads(r["entry_json"]) for r in rows]
            root = MerkleTree(entries).root
            batch_id = max(self._scalar("SELECT COALESCE(MAX(batch_id), 0) FROM batches") + 1, min_batch_id)
            try:
                self._db.execute(
                    "INSERT INTO batches(batch_id, merkle_root, log_count, created_at) VALUES (?,?,?,?)",
                    (batch_id, root, len(entries), _now()),
                )
                for idx, row in enumerate(rows):
                    self._db.execute("UPDATE logs SET batch_id=?, idx=? WHERE id=?", (batch_id, idx, row["id"]))
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
            return self.get_batch(batch_id)

    def _logs_of(self, batch_id: int) -> List[dict]:
        rows = self._db.execute(
            "SELECT entry_json FROM logs WHERE batch_id=? ORDER BY idx", (batch_id,)
        ).fetchall()
        return [json.loads(r["entry_json"]) for r in rows]

    def get_batch(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self._db.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
            if row is None:
                raise KeyError(f"No batch with id {batch_id}")
            record = dict(row)
            record["anchored"] = bool(record["anchored"])
            record["logs"] = self._logs_of(batch_id)
            return record

    def list_batches(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM batches ORDER BY batch_id DESC").fetchall()
            out = []
            for row in rows:
                rec = dict(row)
                rec["anchored"] = bool(rec["anchored"])
                out.append(rec)
            return out

    def update_anchor(self, batch_id: int, anchored: bool, tx_hash: Optional[str] = None,
                      block_number: Optional[int] = None, chain_id: Optional[int] = None,
                      error: Optional[str] = None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE batches SET anchored=?, tx_hash=?, block_number=?, chain_id=?, anchor_error=? WHERE batch_id=?",
                (int(anchored), tx_hash, block_number, chain_id, error, batch_id),
            )
            self._db.commit()

    # ---------------------------------------------------------- demo attack
    def tamper(self, batch_id: int, log_index: int, new_detail: str, rewrite_root: bool = False) -> None:
        """DEMO ONLY: edit a stored log; optionally also rewrite the locally stored root."""
        with self._lock:
            self.get_batch(batch_id)  # raises KeyError if missing
            row = self._db.execute(
                "SELECT id, entry_json FROM logs WHERE batch_id=? AND idx=?", (batch_id, log_index)
            ).fetchone()
            if row is None:
                raise IndexError("log index out of range for this batch")
            entry = json.loads(row["entry_json"])
            entry["detail"] = new_detail
            self._db.execute("UPDATE logs SET entry_json=? WHERE id=?", (_dump(entry), row["id"]))
            if rewrite_root:
                new_root = MerkleTree(self._logs_of(batch_id)).root
                self._db.execute("UPDATE batches SET merkle_root=? WHERE batch_id=?", (new_root, batch_id))
            self._db.commit()

    # -------------------------------------------------------------- alerts
    def _insert_alert(self, a: Dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO alerts(rule, severity, message, batch_id, log_index, created_at, details_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (a["rule"], a["severity"], a["message"], a.get("batch_id"), a.get("log_index"),
             _now(), _dump(a.get("details", {}))),
        )

    def replace_alerts(self, batch_id: int, alerts: List[Dict[str, Any]],
                       keep_rules: Iterable[str] = ("LOG_TAMPERING",)) -> None:
        """Replace detection alerts of a batch (tamper alerts are kept)."""
        keep = tuple(keep_rules)
        with self._lock:
            marks = ",".join("?" for _ in keep) or "''"
            self._db.execute(f"DELETE FROM alerts WHERE batch_id=? AND rule NOT IN ({marks})", (batch_id, *keep))
            for a in alerts:
                self._insert_alert({**a, "batch_id": batch_id})
            self._db.commit()

    def add_alert_once(self, alert: Dict[str, Any]) -> bool:
        """Insert unless the same rule already exists for that batch. Returns True if created."""
        with self._lock:
            exists = self._scalar(
                "SELECT COUNT(*) FROM alerts WHERE rule=? AND batch_id IS ?", (alert["rule"], alert.get("batch_id"))
            )
            if exists:
                return False
            self._insert_alert(alert)
            self._db.commit()
            return True

    def alert_count(self, batch_id: int) -> int:
        with self._lock:
            return self._scalar("SELECT COUNT(*) FROM alerts WHERE batch_id=?", (batch_id,))

    def list_alerts(self, severity: Optional[str] = None, batch_id: Optional[int] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM alerts WHERE 1=1", []
        if severity:
            sql += " AND severity=?"
            params.append(severity.upper())
        if batch_id is not None:
            sql += " AND batch_id=?"
            params.append(batch_id)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        alerts = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json") or "{}")
            alerts.append(d)
        alerts.sort(key=lambda a: (-SEVERITY_RANK.get(a["severity"], 0), -a["id"]))
        return alerts[:limit]

    def alert_summary(self) -> Dict[str, Any]:
        with self._lock:
            by_sev = {r["severity"]: r["n"] for r in self._db.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")}
            by_rule = {r["rule"]: r["n"] for r in self._db.execute(
                "SELECT rule, COUNT(*) AS n FROM alerts GROUP BY rule")}
            total = self._scalar("SELECT COUNT(*) FROM alerts")
        return {"total": total, "by_severity": by_sev, "by_rule": by_rule}

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "batches": self._scalar("SELECT COUNT(*) FROM batches"),
                "pending_logs": self._scalar("SELECT COUNT(*) FROM logs WHERE batch_id IS NULL"),
                "alerts": self._scalar("SELECT COUNT(*) FROM alerts"),
            }
