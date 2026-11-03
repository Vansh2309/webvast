"""Scope enforcement.

Every outbound request passes through a Scope object. A request is only allowed
if its host matches the authorized target host (or an explicit allowlist) and is
not on the global blocklist. This is the single most important safety control in
the toolkit: it keeps a scan from wandering onto systems you are not permitted to
test.
"""
from __future__ import annotations

from typing import Iterable, List, Set
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a request is attempted against an out-of-scope host."""


class Scope:
    def __init__(
        self,
        base_url: str,
        extra_hosts: Iterable[str] | None = None,
        blocklist: Iterable[str] | None = None,
        same_host_only: bool = True,
    ) -> None:
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ScopeError(f"Invalid target URL: {base_url!r}")

        self.base_url = base_url
        self.base_host = parsed.hostname or ""
        self.same_host_only = same_host_only
        self.allowed_hosts: Set[str] = {self.base_host.lower()}
        for h in (extra_hosts or []):
            self.allowed_hosts.add(h.strip().lower())
        self.blocklist: Set[str] = {h.strip().lower() for h in (blocklist or [])}

    def host_of(self, url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def is_allowed(self, url: str) -> bool:
        host = self.host_of(url)
        if not host:
            return False
        if host in self.blocklist:
            return False
        # Block any host whose registrable portion is blocklisted (e.g. sub.google.com)
        for bad in self.blocklist:
            if host == bad or host.endswith("." + bad):
                return False
        if not self.same_host_only:
            return True
        return host in self.allowed_hosts

    def assert_allowed(self, url: str) -> None:
        if not self.is_allowed(url):
            raise ScopeError(
                f"Refusing out-of-scope request to {self.host_of(url)!r}. "
                f"Allowed: {sorted(self.allowed_hosts)}"
            )

    def allowed_hosts_list(self) -> List[str]:
        return sorted(self.allowed_hosts)
