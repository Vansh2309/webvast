"""Scan engine: orchestrates crawl + scanners for one scan.

Usage:
    engine = ScanEngine(config)
    result = await engine.run(on_progress=cb)

`on_progress(stage, percent)` is an optional async callback used to stream
progress to the database / UI.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

from app.config import settings
from app.core.crawler import Crawler
from app.core.http_client import HttpClient
from app.core.scope import Scope, ScopeError
from app.scanners import SCANNERS
from app.scanners.base import Finding

ProgressCb = Callable[[str, int], Awaitable[None]]


@dataclass
class ScanConfig:
    target_url: str
    modules: List[str]                       # subset of SCANNERS keys
    extra_hosts: List[str] = field(default_factory=list)
    same_host_only: bool = True


@dataclass
class ScanResult:
    findings: List[Finding]
    pages_crawled: int
    requests_sent: int
    duration_s: float
    severity_counts: Dict[str, int]
    error: Optional[str] = None


async def _noop(stage: str, percent: int) -> None:
    return None


class ScanEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def run(self, on_progress: Optional[ProgressCb] = None) -> ScanResult:
        progress = on_progress or _noop
        start = time.monotonic()
        findings: List[Finding] = []

        try:
            scope = Scope(
                self.config.target_url,
                extra_hosts=self.config.extra_hosts,
                blocklist=settings.blocklist_hosts,
                same_host_only=self.config.same_host_only,
            )
        except ScopeError as exc:
            return ScanResult([], 0, 0, 0.0, _empty_counts(), error=str(exc))

        await progress("initialising", 2)

        async with HttpClient(scope) as http:
            # --- crawl ----------------------------------------------------
            await progress("crawling", 5)
            crawler = Crawler(http, self.config.target_url)
            crawl = await crawler.crawl()
            await progress(
                f"crawled {len(crawl.pages)} pages, "
                f"{len(crawl.injection_points)} injection points", 25,
            )

            if not crawl.pages:
                return ScanResult(
                    [], 0, http.request_count, time.monotonic() - start,
                    _empty_counts(),
                    error="Target did not return any pages (unreachable or empty).",
                )

            # --- scanners -------------------------------------------------
            active = [k for k in self.config.modules if k in SCANNERS]
            if not active:
                active = list(SCANNERS.keys())

            span = 70 / max(len(active), 1)
            for i, key in enumerate(active):
                scanner_cls = SCANNERS[key]
                await progress(f"running {scanner_cls.name}", int(25 + i * span))
                scanner = scanner_cls(http, crawl)
                try:
                    findings.extend(await scanner.run())
                except Exception as exc:  # a broken scanner shouldn't kill the scan
                    await progress(f"{scanner_cls.name} error: {exc}", int(25 + (i + 1) * span))

            await progress("compiling report", 98)
            requests_sent = http.request_count
            pages = len(crawl.pages)

        findings = _dedupe(findings)
        duration = time.monotonic() - start
        await progress("done", 100)
        return ScanResult(
            findings=findings,
            pages_crawled=pages,
            requests_sent=requests_sent,
            duration_s=round(duration, 2),
            severity_counts=_count(findings),
        )


def _dedupe(findings: List[Finding]) -> List[Finding]:
    out: Dict[str, Finding] = {}
    for f in findings:
        out.setdefault(f.dedupe_key(), f)
    # sort by severity rank desc, then type
    return sorted(out.values(), key=lambda f: (-f.severity.rank, f.type))


def _empty_counts() -> Dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _count(findings: List[Finding]) -> Dict[str, int]:
    counts = _empty_counts()
    for f in findings:
        counts[f.severity.value] += 1
    return counts
