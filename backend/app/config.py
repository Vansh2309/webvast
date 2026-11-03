"""Central configuration for the WebVAST scan engine.

Values are intentionally conservative. This is a tool for testing applications
you own or are explicitly authorized to test; the defaults favour low request
volume and non-destructive behaviour.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

_DEFAULT_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]


def _parse_origins(raw: str) -> List[str]:
    """Merge the built-in local-dev origins with any from WEBVAST_CORS_ORIGINS."""
    extra = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    return list(dict.fromkeys(_DEFAULT_ORIGINS + extra))  # de-dup, keep order


@dataclass
class Settings:
    # --- networking / politeness -----------------------------------------
    request_timeout: float = 12.0           # seconds per HTTP request
    max_concurrency: int = 6                # simultaneous in-flight requests
    requests_per_second: float = 8.0        # global rate cap (lab-friendly)
    user_agent: str = "WebVAST/0.1 (+authorized-security-testing)"
    verify_tls: bool = False                # lab targets often use self-signed certs

    # --- crawler limits ---------------------------------------------------
    max_pages: int = 60                     # safety ceiling on pages crawled
    max_depth: int = 3                      # link-following depth
    follow_forms: bool = True

    # --- storage ----------------------------------------------------------
    db_path: str = os.environ.get("WEBVAST_DB", "webvast.db")

    # --- CORS -------------------------------------------------------------
    # Browser origins allowed to call the API. Defaults cover local dev.
    # To let a hosted frontend (e.g. a Vercel deployment) reach a backend you
    # run yourself, set WEBVAST_CORS_ORIGINS to a comma-separated list, e.g.:
    #   WEBVAST_CORS_ORIGINS="https://webvast.vercel.app,https://webvast-you.vercel.app"
    cors_origins: List[str] = field(default_factory=lambda: _parse_origins(
        os.environ.get("WEBVAST_CORS_ORIGINS", "")
    ))

    # --- safety -----------------------------------------------------------
    # Hosts that must NEVER be scanned, even if a user puts them in scope.
    # Protects against pointing the tool at infrastructure or third parties.
    blocklist_hosts: List[str] = field(default_factory=lambda: [
        "google.com", "www.google.com",
        "facebook.com", "amazon.com",
        "login.gov", "irs.gov",
    ])

    @property
    def min_request_interval(self) -> float:
        return 1.0 / self.requests_per_second if self.requests_per_second > 0 else 0.0


settings = Settings()
