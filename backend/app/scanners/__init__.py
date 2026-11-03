"""Scanner plugins. Each scanner implements BaseScanner and yields Findings."""
from app.scanners.base import BaseScanner, Finding, Severity, InjectionPoint
from app.scanners.sqli import SqlInjectionScanner
from app.scanners.xss import XssScanner
from app.scanners.misconfig import MisconfigScanner
from app.scanners.components import ComponentScanner

# Registry: key -> scanner class. The API exposes these keys as toggles.
SCANNERS = {
    "sqli": SqlInjectionScanner,
    "xss": XssScanner,
    "misconfig": MisconfigScanner,
    "components": ComponentScanner,
}

__all__ = [
    "BaseScanner", "Finding", "Severity", "InjectionPoint",
    "SqlInjectionScanner", "XssScanner", "MisconfigScanner", "ComponentScanner",
    "SCANNERS",
]
