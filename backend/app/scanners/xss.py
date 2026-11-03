"""Cross-site scripting (XSS) scanner.

Detects reflected and (lightweight) stored XSS using a unique, harmless canary
token. The scanner does NOT inject working exploit script; it injects a marker
containing HTML metacharacters and checks whether the application reflects them
*unencoded*. Unencoded reflection of `<`, `>` and quotes is the precondition for
XSS, so this is a reliable, non-destructive signal.

  * Reflected: inject canary into a parameter, inspect the immediate response.
  * Stored:    inject canary via a form, then re-fetch crawled pages and look for
               the unencoded canary appearing elsewhere.
"""
from __future__ import annotations

import secrets
from typing import List

from app.scanners.base import BaseScanner, Confidence, Finding, InjectionPoint, Severity
from app.scanners.util import body_of, send

REMEDIATION = (
    "Contextually output-encode all user-controlled data (HTML, attribute, JS, URL "
    "contexts). Prefer a templating engine with auto-escaping, set a restrictive "
    "Content-Security-Policy, and sanitise rich input with a vetted library (e.g. "
    "DOMPurify) rather than allowlisting tags by hand."
)


def _canary() -> str:
    return "wv" + secrets.token_hex(4)


class XssScanner(BaseScanner):
    key = "xss"
    name = "Cross-Site Scripting"

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        # --- reflected -----------------------------------------------------
        for ip in self.crawl.injection_points:
            f = await self._test_reflected(ip)
            if f and f.dedupe_key() not in seen:
                seen.add(f.dedupe_key())
                findings.append(f)

        # --- stored (forms only) ------------------------------------------
        for ip in [p for p in self.crawl.injection_points if p.origin == "form"]:
            f = await self._test_stored(ip)
            if f and f.dedupe_key() not in seen:
                seen.add(f.dedupe_key())
                findings.append(f)

        return findings

    async def _test_reflected(self, ip: InjectionPoint) -> Finding | None:
        canary = _canary()
        payload = f"\"'><{canary}>"
        resp = await send(self.http, ip, payload)
        body = body_of(resp)
        if not body:
            return None
        marker = f"<{canary}>"
        if marker in body:
            return Finding(
                type="xss", title="Reflected Cross-Site Scripting",
                severity=Severity.HIGH, confidence=Confidence.FIRM,
                url=ip.url, parameter=ip.param, payload=payload,
                evidence=f"canary {marker!r} reflected unencoded in response",
                cwe="CWE-79",
                description=(
                    f"Input to the '{ip.param}' parameter ({ip.method}) is reflected "
                    "into the response without HTML encoding, so an attacker-supplied "
                    "script tag would execute in a victim's browser."
                ),
                remediation=REMEDIATION,
            )
        # encoded reflection -> lower-severity informational signal
        if canary in body and (f"&lt;{canary}" in body or f"&#60;{canary}" in body):
            return None  # properly encoded; not vulnerable
        return None

    async def _test_stored(self, ip: InjectionPoint) -> Finding | None:
        canary = _canary()
        payload = f"<{canary}>"
        await send(self.http, ip, payload)
        # Re-fetch known HTML pages and look for the unencoded canary turning up.
        for page in self.crawl.html_pages():
            resp = await self.http.get(page.url)
            body = body_of(resp)
            if payload in body:
                return Finding(
                    type="xss", title="Stored Cross-Site Scripting",
                    severity=Severity.CRITICAL, confidence=Confidence.FIRM,
                    url=page.url, parameter=ip.param, payload=payload,
                    evidence=f"canary {payload!r} submitted via form persisted on {page.url}",
                    cwe="CWE-79",
                    description=(
                        f"A value submitted through the '{ip.param}' form field is stored "
                        f"and later rendered unencoded on {page.url}, allowing persistent "
                        "script injection affecting every visitor to that page."
                    ),
                    remediation=REMEDIATION,
                )
        return None
