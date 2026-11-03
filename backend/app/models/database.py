"""SQLite persistence layer (async via aiosqlite).

Two tables: `scans` and `findings`. Kept deliberately small and dependency-light
so the whole toolkit runs with a single file database and no external services.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from app.config import settings
from app.scanners.base import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    target_url      TEXT NOT NULL,
    modules         TEXT NOT NULL,
    status          TEXT NOT NULL,
    progress        INTEGER NOT NULL DEFAULT 0,
    stage           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    finished_at     TEXT,
    pages_crawled   INTEGER NOT NULL DEFAULT 0,
    requests_sent   INTEGER NOT NULL DEFAULT 0,
    duration_s      REAL NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    error           TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    type        TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    url         TEXT NOT NULL,
    parameter   TEXT,
    evidence    TEXT,
    description TEXT,
    remediation TEXT,
    cwe         TEXT,
    payload     TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def init_db() -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def create_scan(scan_id: str, target_url: str, modules: List[str]) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "INSERT INTO scans (id, target_url, modules, status, created_at, severity_counts) "
            "VALUES (?,?,?,?,?,?)",
            (scan_id, target_url, json.dumps(modules), "queued", _now(), "{}"),
        )
        await db.commit()


async def update_progress(scan_id: str, stage: str, progress: int, status: str = "running") -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "UPDATE scans SET stage=?, progress=?, status=? WHERE id=?",
            (stage, progress, status, scan_id),
        )
        await db.commit()


async def finalize_scan(
    scan_id: str, status: str, severity_counts: Dict[str, int],
    pages_crawled: int, requests_sent: int, duration_s: float,
    error: Optional[str] = None,
) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "UPDATE scans SET status=?, progress=100, finished_at=?, "
            "severity_counts=?, pages_crawled=?, requests_sent=?, duration_s=?, error=? "
            "WHERE id=?",
            (status, _now(), json.dumps(severity_counts), pages_crawled,
             requests_sent, duration_s, error, scan_id),
        )
        await db.commit()


async def add_findings(scan_id: str, findings: List[Finding]) -> None:
    if not findings:
        return
    rows = [
        (scan_id, f.type, f.title, f.severity.value, f.confidence.value, f.url,
         f.parameter, f.evidence, f.description, f.remediation, f.cwe, f.payload)
        for f in findings
    ]
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executemany(
            "INSERT INTO findings (scan_id, type, title, severity, confidence, url, "
            "parameter, evidence, description, remediation, cwe, payload) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows,
        )
        await db.commit()


def _scan_row_to_dict(row: aiosqlite.Row) -> Dict[str, Any]:
    d = dict(row)
    d["modules"] = json.loads(d.get("modules") or "[]")
    d["severity_counts"] = json.loads(d.get("severity_counts") or "{}")
    for key in ("critical", "high", "medium", "low", "info"):
        d["severity_counts"].setdefault(key, 0)
    return d


async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        row = await cur.fetchone()
        if not row:
            return None
        scan = _scan_row_to_dict(row)
        cur = await db.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id", (scan_id,),
        )
        scan["findings"] = [dict(r) for r in await cur.fetchall()]
        return scan


async def list_scans(limit: int = 100) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,),
        )
        return [_scan_row_to_dict(r) for r in await cur.fetchall()]


async def delete_scan(scan_id: str) -> bool:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        cur = await db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        await db.commit()
        return cur.rowcount > 0
