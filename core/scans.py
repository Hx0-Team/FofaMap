"""One-time, scope-bound approval for optional Nuclei execution."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import socket
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from service.store import JobStore
from utils.helpers import is_blocked_ssrf_address

ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
DEFAULT_NUCLEI_PROFILE = "web-baseline"
# Keep the default scan useful without handing the model an unbounded Nuclei
# command line. These IDs are stable, generic checks shipped by the official
# nuclei-templates project and are all shown to the user before approval.
DEFAULT_NUCLEI_TEMPLATE_IDS = (
    "http-missing-security-headers",
    "cors-misconfig",
    "options-method",
    "tech-detect",
    "waf-detect",
    "weak-cipher-suites",
    "deprecated-tls",
    "expired-ssl",
    "self-signed-ssl",
    "mismatched-ssl-certificate",
)
DEFAULT_NUCLEI_ID_ALLOWLIST = set(DEFAULT_NUCLEI_TEMPLATE_IDS)
TEMPLATE_ID_SEVERITIES = {
    "http-missing-security-headers": "info",
    "cors-misconfig": "info",
    "options-method": "info",
    "tech-detect": "info",
    "waf-detect": "info",
    "weak-cipher-suites": "low",
    "deprecated-tls": "info",
    "expired-ssl": "low",
    "self-signed-ssl": "low",
    "mismatched-ssl-certificate": "info",
}


def nuclei_id_allowlist() -> set[str]:
    extra = {item.strip() for item in os.getenv("FOFAMAP_NUCLEI_ID_ALLOWLIST", "").split(",") if item.strip()}
    return DEFAULT_NUCLEI_ID_ALLOWLIST | extra


def default_nuclei_template_ids() -> list[str]:
    """Return the deterministic, bounded default Nuclei profile."""
    return list(DEFAULT_NUCLEI_TEMPLATE_IDS)


def align_scan_severities(template_ids: list[str], severities: list[str]) -> list[str]:
    """Keep user-selected severities, and include known severities of pinned template IDs."""
    aligned = list(dict.fromkeys(item.lower() for item in severities if item and item.lower() in ALLOWED_SEVERITIES))
    for template_id in template_ids:
        severity = TEMPLATE_ID_SEVERITIES.get(template_id)
        if severity and severity not in aligned:
            aligned.append(severity)
    return aligned


def nuclei_severity_filter(
    template_ids: list[str], severities: list[str], *, all_severities: bool = False
) -> list[str] | None:
    """Return Nuclei -severity values, or None to omit the filter.

    `-id` already pins exact templates. If any selected ID has an unknown
    severity, omit the filter so Nuclei cannot drop an approved template.
    """
    if all_severities:
        return None
    if template_ids and any(item not in TEMPLATE_ID_SEVERITIES for item in template_ids):
        return None
    aligned = align_scan_severities(template_ids, severities)
    return aligned or None


class ScanPlanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=10_000)
    templates: list[str] = Field(default_factory=list, max_length=100)
    template_ids: list[str] = Field(default_factory=list, max_length=100)
    severities: list[str] = Field(default_factory=lambda: ["medium", "high", "critical"])
    all_templates: bool = False
    all_severities: bool = False
    ttl_seconds: int = Field(default=900, ge=60, le=3600)

    @model_validator(mode="before")
    @classmethod
    def normalize_all_sentinels(cls, value: Any) -> Any:
        """Accept user-facing `all` while persisting an explicit approval scope."""
        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        template_ids = normalized.get("template_ids") or []
        if any(str(item).strip().lower() == "all" for item in template_ids):
            normalized["all_templates"] = True
            normalized["templates"] = []
            normalized["template_ids"] = []
        severities = normalized.get("severities") or []
        if any(str(item).strip().lower() == "all" for item in severities):
            normalized["all_severities"] = True
            normalized["severities"] = []
        return normalized

    @field_validator("severities")
    @classmethod
    def validate_severity(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.lower() for value in values))
        if any(value not in ALLOWED_SEVERITIES for value in normalized):
            raise ValueError("unsupported Nuclei severity")
        return normalized

    @model_validator(mode="after")
    def require_allowlisted_scope(self) -> ScanPlanRequest:
        if self.all_templates and (self.templates or self.template_ids):
            raise ValueError("all_templates cannot be combined with template paths or template IDs")
        if self.all_severities and self.severities:
            raise ValueError("all_severities cannot be combined with explicit severities")
        if not self.all_templates and not self.templates and not self.template_ids:
            raise ValueError("at least one allowlisted Nuclei template or template ID is required")
        if not self.all_severities:
            self.severities = align_scan_severities(self.template_ids, self.severities)
        return self


class ScanApproval:
    def __init__(self, store: JobStore, secret: str | None = None, *, allow_private: bool = False) -> None:
        self.store = store
        self.secret = (secret or os.getenv("FOFAMAP_SCAN_APPROVAL_SECRET", "")).encode()
        self.allow_private = allow_private
        if len(self.secret) < 24:
            raise ValueError("FOFAMAP_SCAN_APPROVAL_SECRET must contain at least 24 characters")

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

    def _assert_target(self, target: str) -> None:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"invalid scan target: {target}")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ValueError(f"cannot resolve scan target: {target}") from exc
        if any(is_blocked_ssrf_address(value, allow_private=self.allow_private) for value in addresses):
            raise ValueError(f"private, loopback, link-local, reserved and metadata targets are blocked: {target}")

    def create(self, request: ScanPlanRequest) -> tuple[dict[str, Any], str]:
        template_allowlist = {item for item in os.getenv("FOFAMAP_NUCLEI_TEMPLATE_ALLOWLIST", "").split(",") if item}
        id_allowlist = nuclei_id_allowlist()
        if not request.all_templates and any(item not in template_allowlist for item in request.templates):
            raise ValueError("one or more Nuclei templates are not in FOFAMAP_NUCLEI_TEMPLATE_ALLOWLIST")
        if not request.all_templates and any(item not in id_allowlist for item in request.template_ids):
            raise ValueError("one or more Nuclei template IDs are not in FOFAMAP_NUCLEI_ID_ALLOWLIST")
        for target in request.targets:
            self._assert_target(target)
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=request.ttl_seconds)
        job = self.store.create("scan_plan", request.model_dump(), expires_at=expires.isoformat())
        payload = json.dumps(
            {
                "id": job["id"],
                "sha256": hashlib.sha256(json.dumps(request.model_dump(), sort_keys=True).encode()).hexdigest(),
                "exp": int(expires.timestamp()),
            },
            separators=(",", ":"),
        ).encode()
        encoded = self._b64(payload)
        signature = self._b64(hmac.new(self.secret, encoded.encode(), hashlib.sha256).digest())
        return job, f"{encoded}.{signature}"

    def consume(self, plan_id: str, token: str) -> dict[str, Any]:
        encoded, separator, signature = token.partition(".")
        expected = self._b64(hmac.new(self.secret, encoded.encode(), hashlib.sha256).digest())
        if not separator or not hmac.compare_digest(signature, expected):
            raise ValueError("invalid scan approval token")
        claims = json.loads(self._unb64(encoded))
        job = self.store.get(plan_id)
        expected_hash = hashlib.sha256(json.dumps(job["payload"], sort_keys=True).encode()).hexdigest()
        if claims.get("id") != plan_id or claims.get("sha256") != expected_hash:
            raise ValueError("scan approval token scope mismatch")
        if int(claims.get("exp", 0)) < int(dt.datetime.now(dt.timezone.utc).timestamp()):
            raise ValueError("scan approval token expired")
        if job["consumed"]:
            raise ValueError("scan approval token already consumed")
        return self.store.update(plan_id, status="approved", consumed=True)
