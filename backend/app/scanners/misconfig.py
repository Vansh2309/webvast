"""Security misconfiguration scanner.

Checks that require no injection, only observation and a few safe probe requests:

  * Missing / weak HTTP security headers (CSP, HSTS, X-Frame-Options, ...).
  * Insecure cookie flags (HttpOnly, Secure, SameSite).
  * Server / framework version disclosure.
  * Directory listing enabled.
  * Verbose error pages / stack traces.
  * Sensitive files exposed at well-known paths (.env, .git/config, ...).
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from app.scanners.base import BaseScanner, Confidence, Finding, Severity
from app.scanners.util import body_of

# header -> (severity, human description, remediation)
SECURITY_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy, so the browser has no restriction on script/resource origins.",
        "Add a restrictive Content-Security-Policy (e.g. default-src 'self').",
    ),
    "x-frame-options": (
        Severity.LOW,
        "No X-Frame-Options / frame-ancestors, exposing the app to clickjacking.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "No X-Content-Type-Options, allowing MIME-type sniffing.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "No Referrer-Policy; full URLs may leak to third parties.",
        "Set Referrer-Policy: strict-origin-when-cross-origin or stricter.",
    ),
}

STACK_TRACE_SIGNS = re.compile(
    r"(traceback \(most recent call last\)|stack trace:|"
    r"exception in thread|at [\w.$]+\([\w.]+\.java:\d+\)|"
    r"fatal error:|warning: .* on line \d+|undefined index)",
    re.IGNORECASE,
)

# Safe, read-only probes for commonly-exposed sensitive files.
SENSITIVE_PATHS = {
    "/.env": r"(APP_KEY|DB_PASSWORD|SECRET|AWS_)",
    "/.git/config": r"\[core\]|repositoryformatversion",
    "/server-status": r"Apache Server Status",
    "/phpinfo.php": r"phpinfo\(\)|PHP Version",
    "/.htaccess": r"RewriteEngine|AuthType",
    "/config.php.bak": r"<\?php|password",
}

REMEDIATION_COOKIE = (
    "Set cookies with HttpOnly (block JS access), Secure (HTTPS only) and an explicit "
    "SameSite attribute (Lax or Strict) to reduce XSS token theft and CSRF."
)


class MisconfigScanner(BaseScanner):
    key = "misconfig"
    name = "Security Misconfiguration"

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []
        root = self.crawl.root_page
        if root is None:
            return findings
        is_https = urlparse(root.url).scheme == "https"

        findings.extend(self._check_headers(root.url, root.headers, is_https))
        findings.extend(self._check_cookies(root.url, root.headers, is_https))
        findings.extend(self._check_version_disclosure(root.url, root.headers))
        findings.extend(self._check_directory_listing())
        findings.extend(self._check_stack_traces())
        findings.extend(await self._check_sensitive_files(root.url))
        return findings

    def _check_headers(self, url: str, headers: Dict[str, str], is_https: bool) -> List[Finding]:
        out: List[Finding] = []
        for header, (sev, desc, rem) in SECURITY_HEADERS.items():
            if header not in headers:
                out.append(Finding(
                    type="misconfig", title=f"Missing security header: {header}",
                    severity=sev, confidence=Confidence.CERTAIN, url=url,
                    evidence=f"response has no '{header}' header",
                    cwe="CWE-693", description=desc, remediation=rem,
                ))
        if is_https and "strict-transport-security" not in headers:
            out.append(Finding(
                type="misconfig", title="Missing HSTS header",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN, url=url,
                evidence="HTTPS response without Strict-Transport-Security",
                cwe="CWE-319",
                description="HTTPS is served without HSTS, permitting downgrade/SSL-strip attacks.",
                remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            ))
        return out

    def _check_cookies(self, url: str, headers: Dict[str, str], is_https: bool) -> List[Finding]:
        raw = headers.get("set-cookie")
        if not raw:
            return []
        low = raw.lower()
        issues = []
        if "httponly" not in low:
            issues.append("HttpOnly")
        if is_https and "secure" not in low:
            issues.append("Secure")
        if "samesite" not in low:
            issues.append("SameSite")
        if not issues:
            return []
        return [Finding(
            type="misconfig", title="Insecure cookie attributes",
            severity=Severity.MEDIUM, confidence=Confidence.FIRM, url=url,
            evidence=f"Set-Cookie missing: {', '.join(issues)}",
            cwe="CWE-614", description=f"A cookie is set without: {', '.join(issues)}.",
            remediation=REMEDIATION_COOKIE,
        )]

    def _check_version_disclosure(self, url: str, headers: Dict[str, str]) -> List[Finding]:
        out: List[Finding] = []
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            val = headers.get(h)
            if val and re.search(r"\d", val):
                out.append(Finding(
                    type="misconfig", title=f"Version disclosure via '{h}'",
                    severity=Severity.INFO, confidence=Confidence.CERTAIN, url=url,
                    evidence=f"{h}: {val}", cwe="CWE-200",
                    description=f"The '{h}' header reveals software and version ({val}), aiding attackers.",
                    remediation=f"Suppress or genericise the '{h}' header in your server/framework config.",
                ))
        return out

    def _check_directory_listing(self) -> List[Finding]:
        out: List[Finding] = []
        for page in self.crawl.html_pages():
            if "<title>index of /" in page.body.lower() or ">Parent Directory<" in page.body:
                out.append(Finding(
                    type="misconfig", title="Directory listing enabled",
                    severity=Severity.MEDIUM, confidence=Confidence.FIRM, url=page.url,
                    evidence="auto-generated directory index detected", cwe="CWE-548",
                    description=f"{page.url} returns an automatic directory listing, exposing file names.",
                    remediation="Disable automatic directory indexing (e.g. 'Options -Indexes' / autoindex off).",
                ))
        return out

    def _check_stack_traces(self) -> List[Finding]:
        out: List[Finding] = []
        for page in self.crawl.html_pages():
            m = STACK_TRACE_SIGNS.search(page.body)
            if m:
                out.append(Finding(
                    type="misconfig", title="Verbose error / stack trace exposed",
                    severity=Severity.LOW, confidence=Confidence.FIRM, url=page.url,
                    evidence=page.body[m.start():m.start() + 100].replace("\n", " "),
                    cwe="CWE-209",
                    description=f"{page.url} leaks internal error details / a stack trace.",
                    remediation="Return generic error pages in production; log details server-side only.",
                ))
                break
        return out

    async def _check_sensitive_files(self, base_url: str) -> List[Finding]:
        out: List[Finding] = []
        root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        for path, sign in SENSITIVE_PATHS.items():
            resp = await self.http.get(urljoin(root, path))
            if resp is None or resp.status_code != 200:
                continue
            body = body_of(resp)
            if re.search(sign, body):
                out.append(Finding(
                    type="misconfig", title=f"Sensitive file exposed: {path}",
                    severity=Severity.HIGH, confidence=Confidence.FIRM,
                    url=urljoin(root, path),
                    evidence=f"{path} returned 200 with matching content", cwe="CWE-538",
                    description=f"{path} is publicly accessible and may leak secrets or source.",
                    remediation=f"Block public access to {path}; move secrets out of the web root.",
                ))
        return out
