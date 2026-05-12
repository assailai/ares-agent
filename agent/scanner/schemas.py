"""Pydantic schemas for the local_network_scan task contract.

These mirror ``libraries/ares_shared/src/ares_shared/scan_task_schemas.py``
in the main Ares repo. Both repos MUST agree on field names and types;
field-level drift breaks the agent silently. If you change either side,
update the other in the same change set.

Source of truth: ares_shared.scan_task_schemas (assailai/ares).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LocalScanTaskConfig(BaseModel):
    """Input — agent receives this in ``hunt_agent_tasks.tool_config``."""

    ports: list[int]
    rate_pps: int = Field(default=10_000, ge=100, le=100_000)
    scan_request_id: str
    body_preview_bytes: int = Field(default=4096, ge=256, le=65536)
    per_chunk_timeout_seconds: int = Field(default=300, ge=30, le=1800)

    model_config = {"extra": "forbid"}


class LocalScanDiscoveryHttp(BaseModel):
    """Raw HTTP probe evidence; intentionally not pre-classified.

    Headers are filtered by the agent to a small, classification-relevant
    set (Content-Type, Server, X-Powered-By, Location, WWW-Authenticate)
    so we don't accidentally exfiltrate Authorization or Cookie values
    into Ares-side logs / LLM context.
    """

    status: int
    headers: dict[str, str]
    body_preview_b64: str
    tls_cert_san: Optional[list[str]] = None

    model_config = {"extra": "forbid"}


class LocalScanDiscovery(BaseModel):
    ip: str
    port: int
    alive: bool
    http: Optional[LocalScanDiscoveryHttp] = None

    model_config = {"extra": "forbid"}


class LocalScanTaskResult(BaseModel):
    """Output — agent POSTs this back as ``hunt_agent_tasks.results``."""

    cidr_chunk: str
    ports_scanned: list[int]
    scan_started_at: str  # ISO-8601 UTC
    scan_completed_at: str
    tool_used: str  # "masscan" or "tcp_connect" — informational
    rate_pps_used: int
    discoveries: list[LocalScanDiscovery]
    errors: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


# Sentinel values — must stay in sync with ares_shared.constants.
TASK_TYPE_LOCAL_NETWORK_SCAN = "local_network_scan"
TOOL_MASSCAN = "masscan"
TOOL_TCP_CONNECT = "tcp_connect"
CAPABILITY_LOCAL_NETWORK_SCAN = "local_network_scan"
MAX_DISCOVERIES_PER_CHUNK = 1000

# Headers the agent forwards back to Ares. Anything not in this set is
# dropped before the discovery is serialized — keeps secrets out of logs
# / LLM context.
ALLOWED_PROBE_HEADERS = frozenset({
    "content-type",
    "server",
    "x-powered-by",
    "location",
    "www-authenticate",
})
