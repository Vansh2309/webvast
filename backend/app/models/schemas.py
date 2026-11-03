"""Pydantic request/response models for the API."""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    target_url: str = Field(..., examples=["http://localhost:5001"])
    modules: List[str] = Field(default_factory=lambda: ["sqli", "xss", "misconfig", "components"])
    extra_hosts: List[str] = Field(default_factory=list)
    same_host_only: bool = True
    # Authorization gate: the user must affirm they are permitted to test this target.
    authorized: bool = False

    @field_validator("target_url")
    @classmethod
    def _must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @field_validator("authorized")
    @classmethod
    def _must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm you are authorized to test this target "
                "(set authorized=true). Only scan systems you own or have "
                "written permission to test."
            )
        return v


class FindingOut(BaseModel):
    id: int
    type: str
    title: str
    severity: str
    confidence: str
    url: str
    parameter: Optional[str] = None
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    payload: Optional[str] = None


class ScanSummary(BaseModel):
    id: str
    target_url: str
    status: str
    progress: int
    stage: str
    created_at: str
    finished_at: Optional[str] = None
    severity_counts: Dict[str, int]
    error: Optional[str] = None


class ScanDetail(ScanSummary):
    modules: List[str]
    pages_crawled: int
    requests_sent: int
    duration_s: float
    findings: List[FindingOut]
