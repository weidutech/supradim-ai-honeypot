from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    """Small append-only event store for the single-node MVP."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    surface TEXT NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    data_json TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );

                CREATE INDEX IF NOT EXISTS idx_events_session_time
                    ON events(session_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_events_kind
                    ON events(kind);

                CREATE TABLE IF NOT EXISTS actor_analyses (
                    actor_ip TEXT PRIMARY KEY,
                    analysis TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    event_count_at_analysis INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS prompt_leaks (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source_ip TEXT,
                    model TEXT,
                    system_prompt TEXT,
                    mission TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def ensure_session(
        self, session_id: str, source_ip: str | None, user_agent: str | None
    ) -> None:
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sessions(id, created_at, last_seen_at, source_ip, user_agent)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen_at=excluded.last_seen_at,
                    source_ip=COALESCE(sessions.source_ip, excluded.source_ip),
                    user_agent=COALESCE(sessions.user_agent, excluded.user_agent)
                """,
                (session_id, now, now, source_ip, user_agent),
            )

    def append(
        self,
        *,
        session_id: str,
        kind: str,
        surface: str,
        path: str,
        method: str,
        source_ip: str | None,
        user_agent: str | None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure_session(session_id, source_ip, user_agent)
        event = {
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "created_at": utc_now(),
            "kind": kind,
            "surface": surface,
            "path": path,
            "method": method,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "data": data or {},
        }
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO events(
                    id, session_id, created_at, kind, surface, path, method,
                    source_ip, user_agent, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["id"],
                    event["session_id"],
                    event["created_at"],
                    event["kind"],
                    event["surface"],
                    event["path"],
                    event["method"],
                    event["source_ip"],
                    event["user_agent"],
                    json.dumps(event["data"], sort_keys=True),
                ),
            )
        return event

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["data"] = json.loads(result.pop("data_json"))
        return result

    def events_for_session(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY created_at, rowid",
                (session_id,),
            ).fetchall()
        return [self._event(row) for row in rows]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT s.*, COUNT(e.id) AS event_count
                FROM sessions s
                LEFT JOIN events e ON e.session_id=s.id
                GROUP BY s.id
                ORDER BY s.last_seen_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_actors(self, limit: int = 50) -> list[dict[str, Any]]:
        """Aggregate sessions and activity by source_ip (actor cluster)."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    COALESCE(s.source_ip, 'unknown') as actor_ip,
                    COUNT(DISTINCT s.id) as session_count,
                    COUNT(e.id) as total_events,
                    MIN(s.created_at) as first_seen,
                    MAX(s.last_seen_at) as last_seen,
                    GROUP_CONCAT(DISTINCT s.user_agent) as user_agents,
                    GROUP_CONCAT(DISTINCT e.surface) as surfaces_probed,
                    GROUP_CONCAT(DISTINCT e.kind) as kinds_observed
                FROM sessions s
                LEFT JOIN events e ON e.session_id = s.id
                GROUP BY actor_ip
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_events_for_actor(self, actor_ip: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE source_ip = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (actor_ip, limit),
            ).fetchall()
        return [self._event(row) for row in rows]

    def get_actor_analysis(self, actor_ip: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM actor_analyses WHERE actor_ip = ?", (actor_ip,)
            ).fetchone()
        return dict(row) if row else None

    def save_actor_analysis(
        self, actor_ip: str, analysis: str, event_count: int
    ) -> None:
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO actor_analyses(actor_ip, analysis, analyzed_at, event_count_at_analysis)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(actor_ip) DO UPDATE SET
                    analysis = excluded.analysis,
                    analyzed_at = excluded.analyzed_at,
                    event_count_at_analysis = excluded.event_count_at_analysis
                """,
                (actor_ip, analysis, now, event_count),
            )

    def save_prompt_leak(
        self, session_id: str, source_ip: str | None, model: str | None, system_prompt: str, mission: str | None = None
    ) -> dict[str, Any]:
        leak_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO prompt_leaks (id, session_id, source_ip, model, system_prompt, mission, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (leak_id, session_id, source_ip, model or "unknown", system_prompt, mission or "unspecified", now),
            )
        return {
            "id": leak_id,
            "session_id": session_id,
            "source_ip": source_ip,
            "model": model,
            "system_prompt": system_prompt,
            "mission": mission,
            "created_at": now,
        }

    def get_prompt_leaks(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM prompt_leaks ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_deception_stats(self) -> dict[str, int]:
        with self._connect() as connection:
            row_events = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN path LIKE '%.env%' THEN 1 ELSE 0 END) as env_hits,
                    SUM(CASE WHEN path LIKE '%.git%' THEN 1 ELSE 0 END) as git_hits,
                    SUM(CASE WHEN path LIKE '%docker-compose%' THEN 1 ELSE 0 END) as compose_hits,
                    SUM(CASE WHEN path LIKE '%/internal/v1/%' THEN 1 ELSE 0 END) as tarpit_hits,
                    SUM(CASE WHEN kind LIKE 'canary.oob%' THEN 1 ELSE 0 END) as oob_hits
                FROM events
                """
            ).fetchone()
            leaks_count = connection.execute("SELECT COUNT(*) FROM prompt_leaks").fetchone()[0]

        return {
            "env_hits": (row_events[0] or 0) if row_events else 0,
            "git_hits": (row_events[1] or 0) if row_events else 0,
            "compose_hits": (row_events[2] or 0) if row_events else 0,
            "tarpit_hits": (row_events[3] or 0) if row_events else 0,
            "oob_hits": (row_events[4] or 0) if row_events else 0,
            "prompt_leaks": leaks_count,
        }

    def delete_session(self, session_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
            connection.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            connection.execute("DELETE FROM prompt_leaks WHERE session_id = ?", (session_id,))

    def delete_actor(self, actor_ip: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM events WHERE source_ip = ?", (actor_ip,))
            connection.execute("DELETE FROM sessions WHERE source_ip = ?", (actor_ip,))
            connection.execute("DELETE FROM actor_analyses WHERE actor_ip = ?", (actor_ip,))
            connection.execute("DELETE FROM prompt_leaks WHERE source_ip = ?", (actor_ip,))

    def clear(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM events")
            connection.execute("DELETE FROM sessions")
            connection.execute("DELETE FROM actor_analyses")
            connection.execute("DELETE FROM prompt_leaks")

