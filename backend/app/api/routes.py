"""HTTP API for the toolkit."""
from __future__ import annotations

import asyncio
import uuid
from typing import Dict, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from app.core.engine import ScanConfig, ScanEngine
from app.models import database as db
from app.models.schemas import ScanRequest, ScanSummary
from app.reporting.report import render_html
from app.scanners import SCANNERS

router = APIRouter(prefix="/api")

# Keep references to running tasks so they are not garbage-collected.
_running: Dict[str, asyncio.Task] = {}

MODULE_INFO = [
    {"key": "sqli", "name": "SQL Injection",
     "description": "Error-, boolean- and time-based SQL injection detection."},
    {"key": "xss", "name": "Cross-Site Scripting",
     "description": "Reflected and stored XSS via unencoded-reflection canaries."},
    {"key": "misconfig", "name": "Security Misconfiguration",
     "description": "Security headers, cookie flags, exposed files, verbose errors."},
    {"key": "components", "name": "Vulnerable Components",
     "description": "Fingerprints libraries/server and flags known-vulnerable versions."},
]


async def _run_scan(scan_id: str, config: ScanConfig) -> None:
    async def cb(stage: str, percent: int) -> None:
        await db.update_progress(scan_id, stage, percent)

    try:
        result = await ScanEngine(config).run(on_progress=cb)
        await db.add_findings(scan_id, result.findings)
        fatal = bool(result.error) and result.pages_crawled == 0
        await db.finalize_scan(
            scan_id,
            status="failed" if fatal else "completed",
            severity_counts=result.severity_counts,
            pages_crawled=result.pages_crawled,
            requests_sent=result.requests_sent,
            duration_s=result.duration_s,
            error=result.error,
        )
    except Exception as exc:  # pragma: no cover - defensive
        await db.finalize_scan(
            scan_id, status="failed",
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            pages_crawled=0, requests_sent=0, duration_s=0.0, error=str(exc),
        )
    finally:
        _running.pop(scan_id, None)


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/modules")
async def modules() -> List[dict]:
    return MODULE_INFO


@router.post("/scans", status_code=202)
async def create_scan(req: ScanRequest) -> ScanSummary:
    valid = [m for m in req.modules if m in SCANNERS]
    if not valid:
        raise HTTPException(400, f"No valid modules. Choose from: {list(SCANNERS)}")

    scan_id = uuid.uuid4().hex[:12]
    await db.create_scan(scan_id, req.target_url, valid)

    config = ScanConfig(
        target_url=req.target_url,
        modules=valid,
        extra_hosts=req.extra_hosts,
        same_host_only=req.same_host_only,
    )
    _running[scan_id] = asyncio.create_task(_run_scan(scan_id, config))

    scan = await db.get_scan(scan_id)
    return ScanSummary(**_summary_fields(scan))


@router.get("/scans")
async def list_scans() -> List[dict]:
    scans = await db.list_scans()
    return [_summary_fields(s) for s in scans]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    ok = await db.delete_scan(scan_id)
    if not ok:
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def report_html(scan_id: str) -> HTMLResponse:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return HTMLResponse(render_html(scan))


@router.get("/scans/{scan_id}/report.json")
async def report_json(scan_id: str) -> JSONResponse:
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(scan)


def _summary_fields(scan: dict) -> dict:
    return {
        "id": scan["id"],
        "target_url": scan["target_url"],
        "status": scan["status"],
        "progress": scan["progress"],
        "stage": scan["stage"],
        "created_at": scan["created_at"],
        "finished_at": scan.get("finished_at"),
        "severity_counts": scan["severity_counts"],
        "error": scan.get("error"),
    }
