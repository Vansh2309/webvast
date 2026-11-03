"""Shared types for scanners.

A Finding is the unit of output. An InjectionPoint is a single place a scanner
can test (a query/form parameter on a specific request).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycle at runtime
    from app.core.http_client import HttpClient
    from app.core.crawler import CrawlResult


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, enum.Enum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CERTAIN = "certain"


@dataclass
class InjectionPoint:
    """A single testable parameter on a request."""
    url: str                         # URL without the tested param's value
    method: str                      # GET or POST
    param: str                       # the parameter name being tested
    params: Dict[str, str]           # full baseline parameter set
    origin: str = "query"            # "query" or "form"

    def with_value(self, value: str) -> Dict[str, str]:
        merged = dict(self.params)
        merged[self.param] = value
        return merged


@dataclass
class Finding:
    type: str                        # e.g. "sqli", "xss"
    title: str
    severity: Severity
    url: str
    description: str
    remediation: str
    confidence: Confidence = Confidence.FIRM
    parameter: Optional[str] = None
    evidence: str = ""
    cwe: Optional[str] = None
    payload: Optional[str] = None

    def dedupe_key(self) -> str:
        return f"{self.type}|{self.url}|{self.parameter}|{self.title}"

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence.value,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "payload": self.payload,
        }


class BaseScanner:
    """Base class for all scanners.

    Subclasses set `key`/`name` and implement `run`, appending Finding objects
    to the list returned. `run` receives the shared HttpClient and the crawl
    result so scanners can reuse discovered pages and injection points.
    """

    key: str = "base"
    name: str = "Base Scanner"

    def __init__(self, http: "HttpClient", crawl: "CrawlResult") -> None:
        self.http = http
        self.crawl = crawl

    async def run(self) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError
