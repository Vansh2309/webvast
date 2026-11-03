"""Breadth-first crawler.

Discovers pages, forms, and parameterised URLs within scope. Produces a
CrawlResult that scanners consume. Honours max_pages / max_depth and never
leaves scope (the HttpClient enforces that too, as defence in depth).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlencode

from bs4 import BeautifulSoup

from app.config import settings
from app.core.http_client import HttpClient
from app.scanners.base import InjectionPoint


@dataclass
class PageInfo:
    url: str
    status: int
    content_type: str
    body: str
    headers: Dict[str, str]


@dataclass
class CrawlResult:
    pages: List[PageInfo] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    root_page: PageInfo | None = None

    def html_pages(self) -> List[PageInfo]:
        return [p for p in self.pages if "html" in p.content_type.lower()]


def _normalize(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/") if url.endswith("/") and urlparse(url).path != "/" else url


class Crawler:
    def __init__(self, http: HttpClient, base_url: str) -> None:
        self.http = http
        self.base_url = base_url
        self.seen: Set[str] = set()
        self._ip_keys: Set[str] = set()

    def _add_injection_points(self, result: CrawlResult, url: str) -> None:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not query:
            return
        base = parsed._replace(query="").geturl()
        for param in query:
            key = f"GET|{base}|{param}"
            if key in self._ip_keys:
                continue
            self._ip_keys.add(key)
            result.injection_points.append(
                InjectionPoint(url=base, method="GET", param=param,
                               params=dict(query), origin="query")
            )

    def _extract_forms(self, result: CrawlResult, page_url: str, soup: BeautifulSoup) -> None:
        if not settings.follow_forms:
            return
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            action_url = urljoin(page_url, action)
            if not self.http.scope.is_allowed(action_url):
                continue
            method = (form.get("method") or "get").strip().lower()
            method = "POST" if method == "post" else "GET"
            fields: Dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields[name] = inp.get("value") or "test"
            for name in fields:
                key = f"{method}|{action_url}|{name}"
                if key in self._ip_keys:
                    continue
                self._ip_keys.add(key)
                result.injection_points.append(
                    InjectionPoint(url=action_url, method=method, param=name,
                                   params=dict(fields), origin="form")
                )

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        queue: deque[Tuple[str, int]] = deque([(self.base_url, 0)])
        self.seen.add(_normalize(self.base_url))

        while queue and len(result.pages) < settings.max_pages:
            url, depth = queue.popleft()
            resp = await self.http.get(url)
            if resp is None:
                continue

            content_type = resp.headers.get("content-type", "")
            body = resp.text if "text" in content_type or "html" in content_type else ""
            page = PageInfo(
                url=str(resp.url),
                status=resp.status_code,
                content_type=content_type,
                body=body,
                headers={k.lower(): v for k, v in resp.headers.items()},
            )
            result.pages.append(page)
            if result.root_page is None:
                result.root_page = page

            self._add_injection_points(result, str(resp.url))

            if "html" not in content_type.lower() or depth >= settings.max_depth:
                continue

            soup = BeautifulSoup(body, "html.parser")
            self._extract_forms(result, str(resp.url), soup)

            for a in soup.find_all("a", href=True):
                nxt = urljoin(str(resp.url), a["href"])
                if urlparse(nxt).scheme not in ("http", "https"):
                    continue
                if not self.http.scope.is_allowed(nxt):
                    continue
                norm = _normalize(nxt)
                if norm in self.seen:
                    # still capture query-param injection points on seen bases
                    self._add_injection_points(result, nxt)
                    continue
                self.seen.add(norm)
                queue.append((nxt, depth + 1))

        return result
