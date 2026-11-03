"""SQL injection scanner.

Three detection strategies, all non-destructive (read-only probes):

  1. Error-based  - inject a quote and look for database error signatures.
  2. Boolean-based - compare a TRUE condition against a FALSE condition; a real
     injection makes the TRUE page resemble the baseline and the FALSE page differ.
  3. Time-based   - inject a database sleep and measure the response delay.

The scanner never injects destructive SQL (no DROP/DELETE/UPDATE); payloads only
read or delay.
"""
from __future__ import annotations

import re
from typing import List

from app.scanners.base import BaseScanner, Confidence, Finding, InjectionPoint, Severity
from app.scanners.util import body_of, send, similarity

# Signatures of common DBMS error messages.
DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"psql:\s+error",
    r"sqlite3?::",
    r"sqlite3?\.\w*error",
    r"sqlite_error",
    r"unrecognized token",
    r'near ".*?": syntax error',
    r"operationalerror",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"syntax error at or near",
    r"supplied argument is not a valid mysql",
]
ERROR_RE = re.compile("|".join(DB_ERROR_PATTERNS), re.IGNORECASE)

REMEDIATION = (
    "Use parameterised queries / prepared statements for all database access. "
    "Never build SQL by string concatenation with user input. Apply least-privilege "
    "database accounts and validate/allowlist input where a fixed set of values is expected."
)

# Time-based probe. SLEEP_SECONDS must be clearly above network jitter but small.
SLEEP_SECONDS = 3.0


class SqlInjectionScanner(BaseScanner):
    key = "sqli"
    name = "SQL Injection"

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()
        for ip in self.crawl.injection_points:
            f = await self._test_point(ip)
            if f and f.dedupe_key() not in seen:
                seen.add(f.dedupe_key())
                findings.append(f)
        return findings

    async def _test_point(self, ip: InjectionPoint) -> Finding | None:
        # --- 1. error-based ------------------------------------------------
        for probe in ("'", '"', "')", "';"):
            resp = await send(self.http, ip, (ip.params.get(ip.param, "") + probe))
            body = body_of(resp)
            m = ERROR_RE.search(body)
            if m:
                return Finding(
                    type="sqli", title="SQL Injection (error-based)",
                    severity=Severity.HIGH, confidence=Confidence.FIRM,
                    url=ip.url, parameter=ip.param,
                    payload=probe,
                    evidence=_snippet(body, m.start()),
                    cwe="CWE-89",
                    description=(
                        f"Injecting {probe!r} into the '{ip.param}' parameter "
                        f"({ip.method}) produced a database error message, indicating "
                        "the input reaches a SQL query unsanitised."
                    ),
                    remediation=REMEDIATION,
                )

        # --- 2. boolean-based ---------------------------------------------
        original = ip.params.get(ip.param, "1")
        base = body_of(await send(self.http, ip, original))
        true_body = body_of(await send(self.http, ip, f"{original}' AND '1'='1"))
        false_body = body_of(await send(self.http, ip, f"{original}' AND '1'='2"))
        if base and true_body and false_body:
            sim_true = similarity(base, true_body)
            sim_false = similarity(base, false_body)
            # TRUE page ~ baseline, FALSE page clearly different => boolean SQLi
            if sim_true > 0.95 and sim_false < 0.90 and (sim_true - sim_false) > 0.10:
                return Finding(
                    type="sqli", title="SQL Injection (boolean-based blind)",
                    severity=Severity.HIGH, confidence=Confidence.FIRM,
                    url=ip.url, parameter=ip.param,
                    payload="' AND '1'='1  vs  ' AND '1'='2",
                    evidence=f"similarity TRUE={sim_true:.2f}, FALSE={sim_false:.2f}",
                    cwe="CWE-89",
                    description=(
                        f"The '{ip.param}' parameter responds differently to a logically "
                        "TRUE vs FALSE SQL condition, a hallmark of blind SQL injection."
                    ),
                    remediation=REMEDIATION,
                )

        # --- 3. time-based -------------------------------------------------
        payloads = [
            f"{original}' AND SLEEP({int(SLEEP_SECONDS)})-- -",      # MySQL
            f"{original}'; WAITFOR DELAY '0:0:{int(SLEEP_SECONDS)}'--",  # MSSQL
            f"{original}' AND pg_sleep({int(SLEEP_SECONDS)})-- -",   # PostgreSQL
        ]
        for payload in payloads:
            resp = await send(self.http, ip, payload)
            if resp is None:
                continue
            elapsed = resp.elapsed.total_seconds()
            if elapsed >= SLEEP_SECONDS - 0.5:
                # confirm with a no-sleep control to rule out a slow endpoint
                control = await send(self.http, ip, original)
                control_t = control.elapsed.total_seconds() if control else 0.0
                if elapsed - control_t >= SLEEP_SECONDS - 1.0:
                    return Finding(
                        type="sqli", title="SQL Injection (time-based blind)",
                        severity=Severity.HIGH, confidence=Confidence.FIRM,
                        url=ip.url, parameter=ip.param, payload=payload,
                        evidence=f"delayed {elapsed:.1f}s vs control {control_t:.1f}s",
                        cwe="CWE-89",
                        description=(
                            f"Injecting a database sleep into '{ip.param}' delayed the "
                            f"response by ~{elapsed:.1f}s, confirming blind SQL injection."
                        ),
                        remediation=REMEDIATION,
                    )
        return None


def _snippet(body: str, idx: int, span: int = 120) -> str:
    start = max(0, idx - 20)
    return body[start:start + span].strip().replace("\n", " ")
