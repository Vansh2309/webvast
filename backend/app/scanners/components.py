"""Outdated / vulnerable component scanner.

Fingerprints front-end libraries (from <script> URLs and inline banners) and the
server banner, then matches detected versions against a local signature database
(app/signatures/components.json). A component is flagged when its version is below
the 'fixed_in' version of a known vulnerability.

The signature DB is intentionally offline and small; it can be extended with
entries from the NVD or GitHub Advisory databases for production use.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from app.scanners.base import BaseScanner, Confidence, Finding, Severity

SIGNATURE_FILE = Path(__file__).resolve().parent.parent / "signatures" / "components.json"

_SEV_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _parse_version(v: str) -> Tuple[int, ...]:
    parts = re.split(r"[.\-]", v)
    nums: List[int] = []
    for p in parts:
        m = re.match(r"\d+", p)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums) if nums else (0,)


def _lt(a: str, b: str) -> bool:
    """Return True if version a < version b."""
    va, vb = _parse_version(a), _parse_version(b)
    length = max(len(va), len(vb))
    va += (0,) * (length - len(va))
    vb += (0,) * (length - len(vb))
    return va < vb


class ComponentScanner(BaseScanner):
    key = "components"
    name = "Vulnerable Components"

    def __init__(self, http, crawl) -> None:
        super().__init__(http, crawl)
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as fh:
            self.sig = json.load(fh)

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        # --- front-end libraries ------------------------------------------
        detected = self._detect_libraries()
        for name, version, source in detected:
            for finding in self._match(self.sig.get("libraries", []), name, version, source):
                if finding.dedupe_key() not in seen:
                    seen.add(finding.dedupe_key())
                    findings.append(finding)

        # --- server banner ------------------------------------------------
        root = self.crawl.root_page
        if root:
            banner = root.headers.get("server", "")
            for lib in self.sig.get("servers", []):
                version = self._first_match(lib["patterns"], banner)
                if version:
                    for finding in self._vulns_for(lib, lib["name"], version,
                                                   root.url, f"Server: {banner}"):
                        if finding.dedupe_key() not in seen:
                            seen.add(finding.dedupe_key())
                            findings.append(finding)
        return findings

    def _detect_libraries(self) -> List[Tuple[str, str, str]]:
        found: List[Tuple[str, str, str]] = []
        seen_pairs: set = set()
        for page in self.crawl.html_pages():
            soup = BeautifulSoup(page.body, "html.parser")
            candidates: List[str] = []
            for s in soup.find_all("script", src=True):
                candidates.append(s["src"])
            for link in soup.find_all("link", href=True):
                candidates.append(link["href"])
            # inline banners like /*! jQuery v3.4.1 */
            candidates.append(page.body[:4000])

            for lib in self.sig.get("libraries", []):
                for text in candidates:
                    version = self._first_match(lib["patterns"], text)
                    if version:
                        key = (lib["name"], version)
                        if key not in seen_pairs:
                            seen_pairs.add(key)
                            found.append((lib["name"], version, _short(text)))
                        break
        return found

    def _first_match(self, patterns: List[str], text: str) -> Optional[str]:
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _match(self, libs, name, version, source) -> List[Finding]:
        for lib in libs:
            if lib["name"] == name:
                url = self.crawl.root_page.url if self.crawl.root_page else name
                return self._vulns_for(lib, name, version, url, source)
        return []

    def _vulns_for(self, lib, name, version, url, source) -> List[Finding]:
        out: List[Finding] = []
        for vuln in lib.get("vulnerabilities", []):
            if _lt(version, vuln["fixed_in"]):
                sev = _SEV_MAP.get(vuln.get("severity", "medium"), Severity.MEDIUM)
                out.append(Finding(
                    type="components",
                    title=f"Outdated {name} {version} ({vuln['cve']})",
                    severity=sev, confidence=Confidence.FIRM, url=url,
                    parameter=None, payload=None,
                    evidence=f"detected {name} {version} via {source}; fixed in {vuln['fixed_in']}",
                    cwe="CWE-1035",
                    description=(
                        f"{name} {version} is in use. {vuln['summary']} "
                        f"Fixed in {name} {vuln['fixed_in']}."
                    ),
                    remediation=(
                        f"Upgrade {name} to {vuln['fixed_in']} or later and establish a process "
                        "(e.g. Dependabot / npm audit) to track component advisories."
                    ),
                ))
        return out


def _short(text: str, n: int = 60) -> str:
    text = text.strip().replace("\n", " ")
    return text[:n]
