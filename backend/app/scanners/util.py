"""Helpers shared by scanners: sending payloads and comparing responses."""
from __future__ import annotations

import difflib
from typing import Optional, Tuple

import httpx

from app.core.http_client import HttpClient
from app.scanners.base import InjectionPoint


async def send(http: HttpClient, ip: InjectionPoint, value: str) -> Optional[httpx.Response]:
    """Send a request injecting `value` into the point's parameter."""
    payload = ip.with_value(value)
    if ip.method == "GET":
        return await http.get(ip.url, params=payload)
    return await http.post(ip.url, data=payload)


def body_of(resp: Optional[httpx.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text
    except Exception:
        return ""


def similarity(a: str, b: str) -> float:
    """Ratio in [0,1]; 1.0 == identical. Uses a quick length guard first."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # quick ratio is cheap; good enough to tell "same page" from "different page"
    return difflib.SequenceMatcher(None, a, b).quick_ratio()
