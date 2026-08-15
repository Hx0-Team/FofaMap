"""Small SQLAlchemy metadata store; SQLite by default, PostgreSQL by URL."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text


class JobStore:
    def __init__(self, database_url: str = "sqlite:///./fofamap.sqlite3") -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args, future=True)
        with self.engine.begin() as conn:
            conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS fofamap_jobs (
                    id VARCHAR(64) PRIMARY KEY,
                    kind VARCHAR(32) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    payload TEXT NOT NULL,
                    result TEXT,
                    error TEXT,
                    artifact_path TEXT,
                    created_at VARCHAR(64) NOT NULL,
                    updated_at VARCHAR(64) NOT NULL,
                    expires_at VARCHAR(64),
                    consumed BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            )

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    def create(self, kind: str, payload: dict[str, Any], *, expires_at: str | None = None) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        now = self._now()
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO fofamap_jobs "
                    "(id, kind, status, payload, created_at, updated_at, expires_at, consumed) "
                    "VALUES (:id,:kind,:status,:payload,:created,:updated,:expires,false)"
                ),
                {
                    "id": job_id,
                    "kind": kind,
                    "status": "pending",
                    "payload": json.dumps(payload, ensure_ascii=False),
                    "created": now,
                    "updated": now,
                    "expires": expires_at,
                },
            )
        return self.get(job_id)

    def purge_expired(self, artifact_root: Path) -> int:
        """Delete expired self-hosted metadata and only artifacts inside the configured root."""
        root = artifact_root.resolve()
        now = self._now()
        with self.engine.begin() as conn:
            rows = (
                conn.execute(
                    text("SELECT id, artifact_path FROM fofamap_jobs WHERE expires_at IS NOT NULL AND expires_at < :now"),
                    {"now": now},
                )
                .mappings()
                .all()
            )
            for row in rows:
                if not row.get("artifact_path"):
                    continue
                try:
                    path = Path(row["artifact_path"]).resolve(strict=True)
                    path.relative_to(root)
                    if path.is_file():
                        path.unlink()
                except (FileNotFoundError, ValueError):
                    continue
            conn.execute(
                text("DELETE FROM fofamap_jobs WHERE expires_at IS NOT NULL AND expires_at < :now"),
                {"now": now},
            )
        return len(rows)

    def get(self, job_id: str) -> dict[str, Any]:
        with self.engine.connect() as conn:
            row = conn.execute(text("SELECT * FROM fofamap_jobs WHERE id=:id"), {"id": job_id}).mappings().first()
        if row is None:
            raise KeyError(job_id)
        result = dict(row)
        for key in ("payload", "result", "error"):
            if result.get(key):
                result[key] = json.loads(result[key])
        result["consumed"] = bool(result.get("consumed"))
        return result

    def update(
        self,
        job_id: str,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        artifact_path: str | None = None,
        consumed: bool | None = None,
    ) -> dict[str, Any]:
        current = self.get(job_id)
        values = {
            "id": job_id,
            "status": status,
            "result": json.dumps(result, ensure_ascii=False)
            if result is not None
            else json.dumps(current.get("result"), ensure_ascii=False)
            if current.get("result") is not None
            else None,
            "error": json.dumps(error, ensure_ascii=False)
            if error is not None
            else json.dumps(current.get("error"), ensure_ascii=False)
            if current.get("error") is not None
            else None,
            "artifact": artifact_path if artifact_path is not None else current.get("artifact_path"),
            "updated": self._now(),
            "consumed": current["consumed"] if consumed is None else consumed,
        }
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE fofamap_jobs SET status=:status,result=:result,error=:error,"
                    "artifact_path=:artifact,updated_at=:updated,consumed=:consumed WHERE id=:id"
                ),
                values,
            )
        return self.get(job_id)
