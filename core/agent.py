"""Recoverable deterministic workflow agent; the LLM plans and summarizes only."""

from __future__ import annotations

import inspect
import json
import re
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any, Literal

from opentelemetry import trace
from pydantic import BaseModel, Field

from core.client import FofaClient
from core.fields import (
    STATS_FIELDS,
    account_tier,
    available_fields,
    decide_fields,
    fofa_request_fields,
    merge_return_fields,
)
from core.membership import host_fallback_query, membership_from_account, planner_capabilities_prompt
from core.models import FofaError, SearchPage, SearchRequest
from core.rules import match_intent_rules, rules_hint_for_prompt
from core.scans import align_scan_severities, default_nuclei_template_ids, nuclei_id_allowlist
from providers.base import ProviderError
from providers.registry import ProviderRouter
from utils.logger import logger


class AgentState(str, Enum):
    INTENT = "intent_parsing"
    VALIDATE = "query_validation"
    EXECUTE = "execute"
    EVALUATE = "evaluate"
    REFLECT = "reflect"
    REPAIR = "query_repair"
    SUMMARIZE = "summarize"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentAction(str, Enum):
    SEARCH = "fofa_search"
    HOST = "host_query"
    STATS = "stat_query"
    ICON = "icon_query"


class AgentStep(BaseModel):
    state: AgentState
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class AgentQuery(BaseModel):
    query: str
    purpose: str = ""
    strategy: str = "balanced"
    source: str = "planner"
    available_count: int | None = None
    result_count: int = 0
    new_assets: int = 0
    pages: int = 0


class WebsiteCandidate(BaseModel):
    """A website surfaced by FOFA, with explicit attribution confidence."""

    domain: str
    url: str
    status: Literal["corroborated", "observed", "candidate"]
    confidence: Literal["high", "medium", "low"]
    evidence: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class AgentRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    intent: str
    action: AgentAction = AgentAction.SEARCH
    target: str | None = None
    stats_fields: list[str] = Field(default_factory=list)
    result_data: dict[str, Any] = Field(default_factory=dict)
    state: AgentState = AgentState.INTENT
    steps: list[AgentStep] = Field(default_factory=list)
    query: str | None = None
    queries: list[AgentQuery] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    result_count: int = 0
    assets: list[dict[str, Any]] = Field(default_factory=list)
    assets_truncated: bool = False
    asset_confidence: list[str] = Field(default_factory=list)
    evidence_counts: dict[str, int] = Field(default_factory=dict)
    organization_names: list[str] = Field(default_factory=list)
    domain_hypotheses: list[str] = Field(default_factory=list)
    website_candidates: list[WebsiteCandidate] = Field(default_factory=list)
    reflection_rounds: int = 0
    reflection_notes: list[str] = Field(default_factory=list)
    summary: str | None = None
    scan_requested_by_user: bool = False
    scan_recommended: bool = False
    scan_reason: str = ""
    scan_template_ids: list[str] = Field(default_factory=list)
    scan_severities: list[str] = Field(default_factory=lambda: ["medium", "high", "critical"])
    scan_targets: list[str] = Field(default_factory=list)
    scan_artifact: str | None = None
    report_artifact: str | None = None
    error: dict[str, Any] | None = None
    route_events: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def scan_ready(self) -> bool:
        return bool(
            self.scan_requested_by_user and self.scan_recommended and self.scan_targets and self.scan_template_ids and self.error is None
        )


AgentProgressCallback = Callable[[AgentRun, AgentStep], None]
AgentPageCallback = Callable[[AgentRun, SearchPage, int], None | Awaitable[None]]
# Human-facing Agent runs keep every returned asset for small/medium result sets.
# Only larger runs are capped so terminal, JSON and report payloads stay bounded.
ASSET_PREVIEW_LIMIT = 500
MAX_QUERY_VARIANTS = 8
INITIAL_QUERY_VARIANTS = 5
MAX_REFLECTION_ROUNDS = 2
MAX_REFLECTION_ADDITIONS = 2
EVIDENCE_RANK = {"recall": 1, "hypothesis": 2, "balanced": 3, "precision": 4}
STAT_FIELDS = STATS_FIELDS


def _record_step(
    run: AgentRun,
    state: AgentState,
    detail: str,
    *,
    data: dict[str, Any] | None = None,
    on_progress: AgentProgressCallback | None = None,
) -> None:
    run.state = state
    step = AgentStep(state=state, detail=detail, data=data or {})
    run.steps.append(step)
    if on_progress:
        # Presentation observers must never be able to abort a FOFA run.
        try:
            on_progress(run, step)
        except Exception as exc:
            logger.warning(f"Agent progress observer failed: {exc}")


def _record_page(
    run: AgentRun,
    page: SearchPage,
    page_number: int,
    *,
    strategy: str,
) -> None:
    run.result_count += len(page.records)
    for record in page.records:
        if len(run.assets) < ASSET_PREVIEW_LIMIT:
            run.assets.append(record.values)
            run.asset_confidence.append(strategy)
            continue
        weakest_rank = min(EVIDENCE_RANK.get(value, 1) for value in run.asset_confidence)
        if EVIDENCE_RANK.get(strategy, 1) <= weakest_rank:
            continue
        # Replace the latest weakest candidate so later high-quality strategies
        # cannot be hidden merely because a broad recall query arrived first.
        replace_at = max(
            index
            for index, value in enumerate(run.asset_confidence)
            if EVIDENCE_RANK.get(value, 1) == weakest_rank
        )
        run.assets[replace_at] = record.values
        run.asset_confidence[replace_at] = strategy
    if run.result_count > len(run.assets):
        run.assets_truncated = True


async def _notify_page(
    on_page: AgentPageCallback | None,
    run: AgentRun,
    page: SearchPage,
    page_number: int,
) -> None:
    if not on_page:
        return
    try:
        result = on_page(run, page, page_number)
        if inspect.isawaitable(result):
            await result
    except Exception as exc:
        logger.warning(f"Agent page observer failed: {exc}")


PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["fofa_search", "host_query", "stat_query", "icon_query"]},
        "target": {"type": "string"},
        "queries": {
            "type": "array",
            "minItems": 0,
            "maxItems": INITIAL_QUERY_VARIANTS,
            "items": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "purpose": {"type": "string"},
                    "strategy": {"type": "string", "enum": ["precision", "balanced", "recall"]},
                },
                "required": ["query", "purpose", "strategy"],
                "additionalProperties": False,
            },
        },
        "stats_fields": {"type": "array", "items": {"type": "string"}},
        "fields": {"type": "array", "items": {"type": "string"}},
        "scan": {
            "type": "object",
            "properties": {
                "recommended": {"type": "boolean"},
                "reason": {"type": "string"},
                "template_ids": {"type": "array", "items": {"type": "string"}},
                "severities": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                },
            },
            "required": ["recommended", "reason", "template_ids", "severities"],
            "additionalProperties": False,
        },
    },
    "required": ["action", "target", "queries", "stats_fields", "fields", "scan"],
    "additionalProperties": False,
}

ENTITY_RESOLUTION_SCHEMA = {
    "type": "object",
    "properties": {
        "organization_names": {"type": "array", "maxItems": 6, "items": {"type": "string"}},
        "domains": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reason": {"type": "string"}},
                "required": ["domain", "reason"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["organization_names", "domains"],
    "additionalProperties": False,
}

QUERY_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "fields": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["query", "fields"],
    "additionalProperties": False,
}

REFLECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "observation": {"type": "string"},
        "coverage_sufficient": {"type": "boolean"},
        "queries": {
            "type": "array",
            "maxItems": MAX_REFLECTION_ADDITIONS,
            "items": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "purpose": {"type": "string"},
                    "strategy": {"type": "string", "enum": ["precision", "balanced", "recall"]},
                },
                "required": ["query", "purpose", "strategy"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["observation", "coverage_sufficient", "queries"],
    "additionalProperties": False,
}

SCAN_AUTHORIZATION_PATTERN = re.compile(r"(?:扫描|漏洞检测|漏洞扫描|nuclei|scan(?:ning)?)", re.IGNORECASE)
SCAN_DENIAL_PATTERN = re.compile(
    r"(?:不要|不需要|无需|禁止|拒绝|不进行|请勿|勿).{0,8}(?:扫描|漏洞检测|漏洞扫描|nuclei)"
    r"|(?:no|do\s+not|don't|without)\s+(?:nuclei\s+)?scan(?:ning)?",
    re.IGNORECASE,
)
SAFE_TEMPLATE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
ORGANIZATION_SUFFIX_PATTERN = (
    "公司|集团|大学|学院|学校|研究院|研究所|实验室|工作室|医院|协会|政府|委员会|中心|银行"
)
EN_ORGANIZATION_SUFFIX_PATTERN = (
    "university|college|company|corporation|institute|laboratory|studio|school|"
    "hospital|association|government|bank"
)
ORGANIZATION_INTENT_PATTERN = re.compile(
    rf"(?:{ORGANIZATION_SUFFIX_PATTERN})|(?:{EN_ORGANIZATION_SUFFIX_PATTERN})\b",
    re.IGNORECASE,
)
WEBSITE_INTENT_PATTERN = re.compile(r"(?:网站|官网|域名|站点|websites?|domains?|sites?)", re.IGNORECASE)
CN_ORGANIZATION_NAME_PATTERN = re.compile(
    rf"(?:[A-Za-z][A-Za-z0-9._&'-]*|[\u4e00-\u9fff]|\d+){{1,40}}(?:{ORGANIZATION_SUFFIX_PATTERN})"
)
EN_ORGANIZATION_NAME_PATTERN = re.compile(
    rf"\b((?:[A-Za-z][A-Za-z0-9.&']+\s+)+(?:{EN_ORGANIZATION_SUFFIX_PATTERN}))\b",
    re.IGNORECASE,
)
FALLBACK_NOISE_PATTERN = re.compile(
    r"(?:请|麻烦|帮我|帮忙|我要|需要|尽可能|尽量|查询|查找|搜索|收集|发现|分析|看看|一下|"
    r"的?子域名网站|的?子域名|子域名|的?官网(?:网站)?|官网|的?网站|网站|的?域名|域名|"
    r"的?站点|站点|的?主机名?|主机|的?网页|网页|"
    r"的?全网资产|的?公开资产|相关资产|资产清单|的?资产|相关|"
    r"并且|并|然后|进行|执行|漏洞检测|漏洞扫描|扫描一下|扫描)"
    r"|\b(?:please|help\s+me|find|search|collect|discover|"
    r"subdomains?|websites?|website|domains?|hosts?|assets?|and|scan(?:ning)?|them)\b",
    re.IGNORECASE,
)


def user_authorized_scan(intent: str) -> bool:
    return not SCAN_DENIAL_PATTERN.search(intent) and bool(SCAN_AUTHORIZATION_PATTERN.search(intent))


def _scan_template_ids_for_intent(intent: str, suggested: list[str]) -> list[str]:
    """Apply the bounded default profile unless the user named exact template IDs."""
    allowlist = nuclei_id_allowlist()
    normalized = list(dict.fromkeys(item for item in suggested if item in allowlist))
    lowered = intent.lower()
    explicit = [item for item in allowlist if item.lower() in lowered]
    if explicit:
        return [item for item in default_nuclei_template_ids() if item in explicit] + sorted(
            item for item in explicit if item not in default_nuclei_template_ids()
        )
    return list(dict.fromkeys([*default_nuclei_template_ids(), *normalized]))[:100]


def _fofa_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ").strip()


def _organization_core_name(text: str) -> str | None:
    english = EN_ORGANIZATION_NAME_PATTERN.search(text)
    if english:
        return english.group(1).strip()
    chinese = CN_ORGANIZATION_NAME_PATTERN.search(text)
    if chinese:
        return chinese.group(0).strip()
    return None


def _fallback_search_term(intent: str) -> str:
    quoted = re.search(r"[“‘'\"]([^”’'\"]{2,100})[”’'\"]", intent)
    if quoted:
        return quoted.group(1).strip()
    cleaned = FALLBACK_NOISE_PATTERN.sub(" ", intent)
    cleaned = re.sub(r"[，。！？、,:：;；()（）\[\]{}]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    organization = _organization_core_name(cleaned) or _organization_core_name(intent)
    if organization:
        return organization[:100]
    parts = [part.strip() for part in cleaned.split() if len(part.strip()) >= 2]
    return max(parts, key=len)[:100] if parts else intent.strip()[:100]


def _deterministic_fallback_plan(intent: str) -> dict[str, Any]:
    """Produce a conservative executable search when planner JSON is unusable."""
    domain_match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", intent)
    if domain_match:
        domain = _fofa_literal(domain_match.group(1).lower().removeprefix("www."))
        query = f'(domain="{domain}" || host="{domain}")'
        purpose = f"结构化规划降级：按用户提供的域名 {domain} 检索"
        strategy = "precision"
    elif ip_match:
        ip = _fofa_literal(ip_match.group(0))
        query = f'ip="{ip}"'
        purpose = f"结构化规划降级：按用户提供的 IP {ip} 检索"
        strategy = "precision"
    else:
        library = match_intent_rules(intent, limit=3)
        if library:
            return {
                "action": AgentAction.SEARCH.value,
                "target": "",
                "queries": [
                    {
                        "query": rule.query,
                        "purpose": f"规则库精确指纹：{rule.name}",
                        "strategy": "precision",
                    }
                    for rule in library
                ],
                "stats_fields": [],
                "fields": ["host", "ip", "port", "protocol", "title", "domain"],
                "scan": {
                    "recommended": user_authorized_scan(intent),
                    "reason": "用户明确提出扫描需求；先完成只读资产发现，再展示边界并请求确认。"
                    if user_authorized_scan(intent)
                    else "未明确要求主动扫描。",
                    "template_ids": default_nuclei_template_ids() if user_authorized_scan(intent) else [],
                    "severities": ["medium", "high", "critical"],
                },
            }
        term = _fofa_literal(_fallback_search_term(intent))
        clauses = [f'title="{term}"', f'body="{term}"']
        if ORGANIZATION_INTENT_PATTERN.search(term):
            clauses.insert(0, f'org="{term}"')
        query = "(" + " || ".join(clauses) + ")"
        purpose = f"结构化规划降级：围绕用户核心名称“{term}”进行保守召回"
        strategy = "recall"
    return {
        "action": AgentAction.SEARCH.value,
        "target": "",
        "queries": [{"query": query, "purpose": purpose, "strategy": strategy}],
        "stats_fields": [],
        "fields": ["host", "ip", "port", "protocol", "title", "domain"],
        "scan": {
            "recommended": user_authorized_scan(intent),
            "reason": "用户明确提出扫描需求；先完成只读资产发现，再展示边界并请求确认。"
            if user_authorized_scan(intent)
            else "未明确要求主动扫描。",
            "template_ids": default_nuclei_template_ids() if user_authorized_scan(intent) else [],
            "severities": ["medium", "high", "critical"],
        },
    }


def _scan_target(values: dict[str, Any]) -> str | None:
    host = str(values.get("host") or "").strip()
    if host.startswith(("http://", "https://")):
        return host
    if not host:
        ip = values.get("ip")
        if not ip:
            return None
        port = values.get("port")
        host = f"{ip}:{port}" if port else str(ip)
    protocol = str(values.get("protocol") or "http").lower()
    scheme = "https" if "https" in protocol or str(values.get("port")) in {"443", "8443"} else "http"
    return f"{scheme}://{host}"


def validate_query(query: str) -> list[str]:
    errors: list[str] = []
    if not query.strip():
        errors.append("query is empty")
    if any(char in query for char in ("\x00", "\r", "\n")):
        errors.append("query contains control characters")
    if query.count('"') % 2:
        errors.append("unbalanced double quote")
    if query.count("(") != query.count(")"):
        errors.append("unbalanced parentheses")
    return errors


def _query_candidates(plan: dict[str, Any], *, source: str, limit: int) -> list[AgentQuery]:
    raw_candidates = plan.get("queries") if isinstance(plan.get("queries"), list) else []
    if not raw_candidates and plan.get("query"):
        raw_candidates = [{"query": plan["query"], "purpose": "主查询"}]
    candidates: list[AgentQuery] = []
    seen: set[str] = set()
    for item in raw_candidates:
        if not isinstance(item, dict):
            continue
        query = str(item.get("query") or "").strip()
        if not query or query in seen:
            continue
        seen.add(query)
        candidates.append(
            AgentQuery(
                query=query,
                purpose=str(item.get("purpose") or "补充资产维度"),
                strategy=str(item.get("strategy") or "balanced"),
                source=source,
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


def _merge_library_queries(intent: str, queries: list[AgentQuery], *, limit: int) -> list[AgentQuery]:
    """Prepend bundled app= fingerprints when the user named a known product."""
    matched = match_intent_rules(intent, limit=min(3, limit))
    if not matched:
        return queries
    existing = " ".join(item.query for item in queries).lower()
    extras = [
        AgentQuery(
            query=rule.query,
            purpose=f"规则库精确指纹：{rule.name}",
            strategy="precision",
            source="library",
        )
        for rule in matched
        if rule.query.lower() not in existing
    ]
    if not extras:
        return queries
    merged: list[AgentQuery] = []
    seen: set[str] = set()
    for item in extras + queries:
        key = item.query.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= limit:
            break
    return merged


def _domain_hypothesis_insert_at(queries: list[AgentQuery]) -> int:
    """Official-domain hypotheses should run before broad name or body recall."""
    for index, item in enumerate(queries):
        if item.strategy == "recall" or "结构化规划降级" in item.purpose:
            return index
    return len(queries)


def _domain_hypothesis_candidate(plan: dict[str, Any]) -> AgentQuery | None:
    raw_items = plan.get("domains") if isinstance(plan.get("domains"), list) else []
    domains: list[str] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/", 1)[0].split(":", 1)[0].removeprefix("www.")
        if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
            domains.append(domain)
    domains = list(dict.fromkeys(domains))[:6]
    if not domains:
        return None
    query = "(" + " || ".join(f'domain="{domain}" || host="{domain}"' for domain in domains) + ")"
    return AgentQuery(
        query=query,
        purpose="验证可能的官网域名：" + ", ".join(domains),
        strategy="hypothesis",
        source="entity_resolution",
    )


def _normalized_domain(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = re.sub(r"^https?://", "", text).split("/", 1)[0].split(":", 1)[0]
    text = text.removeprefix("*.").removeprefix("www.").rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", text):
        return None
    return text


def _website_identity_terms(run: AgentRun) -> list[str]:
    source = " ".join([run.intent, *run.organization_names]).lower()
    generic = {
        "studio",
        "workroom",
        "website",
        "websites",
        "domain",
        "domains",
        "site",
        "工作室",
        "网站",
        "官网",
        "域名",
    }
    terms = [item for item in re.findall(r"[a-z][a-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}", source) if item not in generic]
    return list(dict.fromkeys(terms))[:12]


def _derive_website_candidates(run: AgentRun) -> list[WebsiteCandidate]:
    """Turn noisy asset rows into a stable, evidence-labelled website inventory."""
    if not WEBSITE_INTENT_PATTERN.search(run.intent):
        return []
    terms = _website_identity_terms(run)
    hypotheses = set(run.domain_hypotheses)
    grouped: dict[str, dict[str, Any]] = {}
    for asset, strategy in zip(run.assets, run.asset_confidence, strict=False):
        host = str(asset.get("host") or "").strip()
        domain = _normalized_domain(asset.get("domain"))
        cert_domain = _normalized_domain(asset.get("cert.subject.cn"))
        host_domain = _normalized_domain(host)
        domain = domain or cert_domain or host_domain
        if not domain:
            continue
        searchable = " ".join(
            str(asset.get(field) or "").lower()
            for field in ("host", "domain", "title", "org", "icp", "cert.subject.org", "cert.subject.cn")
        )
        name_match = any(term in searchable for term in terms)
        if domain not in hypotheses and not name_match:
            continue
        entry = grouped.setdefault(
            domain,
            {
                "hosts": [],
                "strategies": set(),
                "brand_domain": any(term in domain for term in terms),
                "title_match": False,
                "icp": False,
                "certificate": False,
            },
        )
        if host and host not in entry["hosts"]:
            entry["hosts"].append(host)
        entry["strategies"].add(strategy)
        title = str(asset.get("title") or "").lower()
        entry["title_match"] = entry["title_match"] or any(term in title for term in terms)
        entry["icp"] = entry["icp"] or bool(str(asset.get("icp") or "").strip())
        entry["certificate"] = entry["certificate"] or cert_domain == domain

    candidates: list[WebsiteCandidate] = []
    for domain, entry in grouped.items():
        evidence: list[str] = []
        if domain in hypotheses:
            evidence.append("entity_resolution")
        if entry["title_match"]:
            evidence.append("name_in_title")
        if entry["icp"]:
            evidence.append("icp_observed")
        if entry["certificate"]:
            evidence.append("certificate_observed")
        evidence.extend(f"fofa_{item}" for item in sorted(entry["strategies"], key=lambda item: -EVIDENCE_RANK.get(item, 1)))
        if entry["icp"] and (entry["brand_domain"] or entry["title_match"]):
            status, confidence = "corroborated", "high"
        elif domain in hypotheses and entry["title_match"] and entry["certificate"]:
            status, confidence = "corroborated", "high"
        elif domain in hypotheses:
            status, confidence = "observed", "medium"
        else:
            status, confidence = "candidate", "low"
        hosts = entry["hosts"][:8]
        preferred = next(
            (
                item
                for item in hosts
                if item.startswith("https://")
                and (_normalized_domain(item) == domain or str(_normalized_domain(item) or "").endswith(f".{domain}"))
            ),
            None,
        )
        if not preferred:
            preferred = next(
                (
                    item
                    for item in hosts
                    if item.startswith("http://")
                    and (_normalized_domain(item) == domain or str(_normalized_domain(item) or "").endswith(f".{domain}"))
                ),
                None,
            )
        if not preferred:
            preferred = next((item for item in hosts if item.startswith("https://")), None)
        url = preferred or f"https://{domain}"
        candidates.append(
            WebsiteCandidate(
                domain=domain,
                url=url,
                status=status,
                confidence=confidence,
                evidence=list(dict.fromkeys(evidence)),
                hosts=hosts,
            )
        )
    rank = {"corroborated": 0, "observed": 1, "candidate": 2}
    return sorted(candidates, key=lambda item: (rank[item.status], item.domain))[:100]


def _asset_identity(values: dict[str, Any]) -> tuple[str, ...]:
    host = str(values.get("host") or "").strip().lower().rstrip("/")
    if host:
        scheme = "https" if host.startswith("https://") else "http" if host.startswith("http://") else ""
        normalized_host = re.sub(r"^https?://", "", host)
        protocol = str(values.get("protocol") or scheme).strip().lower()
        port = str(values.get("port") or "").strip()
        return ("host", normalized_host, port, protocol)
    ip = str(values.get("ip") or "").strip().lower()
    port = str(values.get("port") or "").strip()
    protocol = str(values.get("protocol") or "").strip().lower()
    if ip:
        return ("ip", ip, port, protocol)
    return ("record", repr(sorted((str(key), str(value)) for key, value in values.items())))


def _compact_asset_sample(assets: list[dict[str, Any]], limit: int = 30) -> list[dict[str, str]]:
    useful_fields = (
        "host",
        "domain",
        "ip",
        "port",
        "protocol",
        "title",
        "org",
        "icp",
        "product",
        "server",
        "country",
        "cert.subject.org",
        "cert.subject.cn",
        "cert.issuer.org",
    )
    sample: list[dict[str, str]] = []
    for asset in assets[:limit]:
        compact = {
            field: str(asset[field]).replace("\r", " ").replace("\n", " ")[:240]
            for field in useful_fields
            if asset.get(field) not in (None, "", [], {})
        }
        if compact:
            sample.append(compact)
    return sample


def _top_counts(values: list[str], *, limit: int = 8) -> list[dict[str, Any]]:
    counter = Counter(value for value in values if value)
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


def _asset_briefing_stats(run: AgentRun) -> dict[str, Any]:
    assets = run.assets
    truncated = [
        {
            "purpose": item.purpose,
            "available": item.available_count,
            "pulled": item.result_count,
        }
        for item in run.queries
        if item.available_count is not None and item.result_count < item.available_count
    ]
    return {
        "unique_assets": run.result_count,
        "previewed": len(assets),
        "evidence": dict(run.evidence_counts),
        "unique_domains": len({str(asset.get("domain") or "").strip() for asset in assets if asset.get("domain")}),
        "unique_ips": len({str(asset.get("ip") or "").strip() for asset in assets if asset.get("ip")}),
        "top_domains": _top_counts([str(asset.get("domain") or "").strip() for asset in assets]),
        "top_titles": _top_counts(
            [re.sub(r"\s+", " ", str(asset.get("title") or "")).strip()[:80] for asset in assets]
        ),
        "top_orgs": _top_counts([str(asset.get("org") or "").strip() for asset in assets]),
        "top_products": _top_counts([str(asset.get("product") or "").strip()[:100] for asset in assets]),
        "top_servers": _top_counts([str(asset.get("server") or "").strip()[:100] for asset in assets]),
        "top_countries": _top_counts([str(asset.get("country") or "").strip() for asset in assets]),
        "top_ports": _top_counts([str(asset.get("port") or "").strip() for asset in assets]),
        "top_protocols": _top_counts([str(asset.get("protocol") or "").strip().lower() for asset in assets]),
        "alive": _top_counts(
            [str(asset.get("alive_status")) for asset in assets if asset.get("alive_status") not in (None, "")]
        ),
        "truncated_queries": truncated,
    }


def _assets_with_evidence(run: AgentRun, *strategies: str, limit: int = 12) -> list[dict[str, str]]:
    picked: list[dict[str, Any]] = []
    for asset, evidence in zip(run.assets, run.asset_confidence, strict=False):
        if evidence in strategies:
            picked.append(asset)
        if len(picked) >= limit:
            break
    return _compact_asset_sample(picked, limit=limit)


def _search_summary_prompt(run: AgentRun, intent: str) -> str:
    return (
        f"User intent: {intent}\n"
        f"Structured website candidates: {[item.model_dump() for item in run.website_candidates]}\n"
        f"Inventory stats: {json.dumps(_asset_briefing_stats(run), ensure_ascii=False)}\n"
        f"Higher-confidence sample: {_assets_with_evidence(run, 'precision', 'balanced', 'hypothesis', limit=15)}\n"
        f"Recall/candidate sample: {_assets_with_evidence(run, 'recall', limit=15)}\n"
        f"Planned scan follow-up: requested={run.scan_requested_by_user}, recommended={run.scan_recommended}, "
        f"targets={len(run.scan_targets)}, template_ids={run.scan_template_ids}, severities={run.scan_severities}"
    )


SEARCH_SUMMARY_SYSTEM = (
    "You write a high-value defensive asset briefing in Simplified Chinese. The reader already saw the query-strategy table "
    "and the asset list; do not recount how many FOFA queries ran, do not explain balanced/recall/precision as a method, "
    "and do not narrate available_count, pagination, reflection rounds or intermediate totals. "
    "Start immediately with ## 结论. Do not write chain-of-thought, hidden reasoning, or a preamble. "
    "Synthesize concrete evidence, concentrations, anomalies, attribution limits, coverage gaps and prioritized actions; every claim "
    "must be traceable to the supplied data. Avoid generic security advice and do not pad the answer. Keep the briefing between 350 "
    "and 900 Chinese characters when data is non-empty. "
    "Output GitHub-flavored Markdown in this exact skeleton, with a blank line between sections:\n"
    "## 结论\n"
    "2-3 sentences stating the asset picture, confidence split and most important exposure signal.\n\n"
    "## 高置信资产\n"
    "- **资产簇**：`host`（`ip`），说明归属证据和用途\n\n"
    "## 风险与暴露面\n"
    "- **端口/技术/可达性信号**：具体数据，以及为什么值得关注；不要把暴露直接写成漏洞\n\n"
    "## 证据边界与噪声\n"
    "- **候选簇**：具体误报或归属不确定性及依据\n\n"
    "## 覆盖缺口\n"
    "- **数据缺口**：分页截断、字段缺失、不可达或仍待交叉验证的范围\n\n"
    "## 处置优先级\n"
    "1. 基于具体资产和证据的验证动作、目的与预期结果\n"
    "Rules: use `##` headings only, never numbered section titles; each bullet is one short line; "
    "write 2-5 substantive bullets in each applicable evidence section and 3-5 ordered actions; "
    "wrap hosts, IPs and domains in backticks; bold the cluster label; at most 5 bullets per section; "
    "at most 3 hosts per bullet, then write 等 N 个; do not dump comma-separated subdomain lists. "
    "Do not invent domains or products absent from the data. Treat Structured website candidates as the authoritative attribution "
    "boundary: list every corroborated website in the high-confidence section, never promote observed/candidate entries to confirmed "
    "or high-confidence, and do not omit a corroborated website merely because it appears late in the asset sample."
)


def _briefing_join(items: list[dict[str, Any]], *, limit: int = 5, wrap: bool = False) -> str:
    parts: list[str] = []
    for item in items[:limit]:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        label = f"`{name}`" if wrap else name
        count = item.get("count")
        parts.append(f"{label} ×{count}" if count not in (None, "") else label)
    return "、".join(parts)


def _local_search_summary(run: AgentRun) -> str:
    stats = _asset_briefing_stats(run)
    evidence = stats["evidence"]
    high = sum(int(evidence.get(key, 0) or 0) for key in ("precision", "balanced", "hypothesis"))
    recall = int(evidence.get("recall", 0) or 0)
    domains = _briefing_join(stats["top_domains"], wrap=True) or "无"
    titles = _briefing_join(stats["top_titles"]) or "无"
    ports = _briefing_join(stats["top_ports"]) or "无"
    protocols = _briefing_join(stats["top_protocols"]) or "无"
    products = _briefing_join(stats["top_products"]) or "未识别"
    servers = _briefing_join(stats["top_servers"]) or "未识别"
    countries = _briefing_join(stats["top_countries"]) or "未返回"
    alive = _briefing_join(stats["alive"]) or "未探测"
    truncated = stats["truncated_queries"]
    corroborated = "、".join(
        f"`{item.domain}`" for item in run.website_candidates if item.status == "corroborated"
    ) or "无"
    candidates = "、".join(
        f"`{item.domain}`（{item.status}）" for item in run.website_candidates if item.status != "corroborated"
    ) or "无"
    if truncated:
        first = truncated[0]
        next_step = (
            f"部分查询仍有余量未拉全（例如 {first['purpose']} {first['pulled']}/{first['available']}），"
            "可提高页数后再复核。"
        )
    else:
        next_step = "先复核高置信域名与证书/组织命中，再处理名称/正文候选。"
    return (
        "## 结论\n"
        f"共识别去重资产 {stats['unique_assets']} 条，覆盖 {stats['unique_domains']} 个域名和 "
        f"{stats['unique_ips']} 个 IP；高置信约 {high} 条，名称/正文召回候选 {recall} 条。"
        "当前结果适合作为暴露面清单，但组织归属和漏洞结论仍需独立验证。\n\n"
        "## 高置信资产\n"
        f"- **交叉印证网站**：{corroborated}\n"
        f"- **主要域名**：{domains}\n\n"
        "## 风险与暴露面\n"
        f"- **端口与协议**：端口 {ports}；协议 {protocols}\n"
        f"- **产品与服务器**：产品 {products}；服务器 {servers}\n"
        f"- **可达性与地域**：存活状态 {alive}；地域 {countries}\n\n"
        "## 证据边界与噪声\n"
        f"- **待确认网站**：{candidates}\n"
        f"- **高频标题**：{titles}；标题或正文命中不等同于组织归属\n"
        f"- **召回候选**：{recall} 条仍需官网内容、备案、证书或权威来源交叉验证\n\n"
        "## 覆盖缺口\n"
        f"- **查询完整性**：{next_step}\n"
        f"- **终端样本**：当前保留 {stats['previewed']} / {stats['unique_assets']} 条用于分析，"
        "大规模结果需结合导出文件复核\n\n"
        "## 处置优先级\n"
        "1. 先核验交叉印证网站及其证书、备案和官网跳转关系，固化真实资产边界。\n"
        "2. 按非标准端口、可达性和产品指纹排序复核，确认服务用途与是否应对公网开放。\n"
        "3. 对名称/正文候选逐项排除第三方引用、停放页和共享基础设施，避免扩大扫描范围。\n"
        "4. 扫描前再次核对目标、模板及严重级别审批范围，并对命中结果进行人工验证。\n"
    )


def _local_generic_summary(run: AgentRun) -> str:
    if run.action is AgentAction.HOST:
        target = f"`{run.target}`" if run.target else "该主机"
        return f"## 结论\n已获取 {target} 的主机画像。模型未返回可读总结，请直接查看上方端口与产品数据。\n"
    if run.action is AgentAction.STATS:
        query = f"`{run.query}`" if run.query else "该统计查询"
        return f"## 结论\n统计查询 {query} 已返回，总量 {run.result_count}。模型未返回可读总结，请查看聚合分布。\n"
    return _local_search_summary(run)


def _asset_briefing_has_sufficient_quality(text: str) -> bool:
    required = (
        "## 结论",
        "## 高置信资产",
        "## 风险与暴露面",
        "## 证据边界与噪声",
        "## 覆盖缺口",
        "## 处置优先级",
    )
    substantive_lines = [line for line in text.splitlines() if line.lstrip().startswith(("- ", "1. ", "2. ", "3. "))]
    return len(text) >= 320 and all(heading in text for heading in required) and len(substantive_lines) >= 8


def _apply_generated_summary(
    run: AgentRun,
    text: str | None,
    *,
    fallback: str,
    require_asset_briefing: bool = False,
) -> None:
    cleaned = (text or "").strip()
    if cleaned and (not require_asset_briefing or _asset_briefing_has_sufficient_quality(cleaned)):
        run.summary = cleaned
        return
    logger.warning("模型未返回达到质量门槛的总结，已改用本地结构化资产简报。")
    run.summary = fallback


def _align_action_to_membership(
    run: AgentRun,
    user_info: dict[str, Any],
    *,
    on_progress: AgentProgressCallback | None = None,
) -> None:
    membership = membership_from_account(user_info)
    if membership is None:
        return
    if run.action is AgentAction.STATS and not membership.stats_api:
        run.action = AgentAction.SEARCH
        _record_step(
            run,
            AgentState.INTENT,
            f"{membership.name} 无统计聚合 API，已改为普通检索",
            data={"vip_level": membership.vip_level, "fallback": AgentAction.SEARCH.value},
            on_progress=on_progress,
        )
        return
    if run.action is AgentAction.HOST and not membership.host_api:
        if run.target and not run.queries:
            fallback = host_fallback_query(run.target)
            run.queries = [
                AgentQuery(
                    query=fallback,
                    purpose=f"{membership.name} 无主机聚合，改用检索",
                    strategy="balanced",
                    source="membership",
                )
            ]
        run.action = AgentAction.SEARCH
        _record_step(
            run,
            AgentState.INTENT,
            f"{membership.name} 无主机聚合 API，已改为普通检索",
            data={"vip_level": membership.vip_level, "target": run.target, "fallback": AgentAction.SEARCH.value},
            on_progress=on_progress,
        )


class FofaAgent:
    def __init__(self, client: FofaClient, router: ProviderRouter) -> None:
        self.client = client
        self.router = router

    async def _execute_routed_action(
        self,
        run: AgentRun,
        intent: str,
        *,
        on_progress: AgentProgressCallback | None,
    ) -> bool:
        """Execute non-list actions selected by the planner; return whether the run is complete."""
        if run.action is AgentAction.ICON:
            if not run.target:
                raise ValueError("icon_query 需要明确的 URL 目标")
            from utils.helpers import IconHashCalculator

            _record_step(run, AgentState.EXECUTE, f"正在安全获取 {run.target} 的网站图标", on_progress=on_progress)
            icon_query = await IconHashCalculator.get_hash(run.target)
            if not icon_query:
                raise ValueError("无法获取网站图标或计算哈希")
            run.queries = [
                AgentQuery(query=icon_query, purpose="使用目标网站图标的 MurmurHash3 反查同类资产", strategy="balanced")
            ]
            run.query = icon_query
            _record_step(
                run,
                AgentState.INTENT,
                "已将图标反查动作转换为可审计的 FOFA 查询策略",
                data={"target": run.target, "query": icon_query},
                on_progress=on_progress,
            )
            return False

        if run.action is AgentAction.HOST:
            if not run.target:
                raise ValueError("host_query 需要明确的 IP 地址或主机目标")
            _record_step(run, AgentState.EXECUTE, f"正在查询主机聚合画像：{run.target}", on_progress=on_progress)
            data = await self.client.host_profile(run.target)
            run.result_data = data
            run.result_count = 1
            _record_step(
                run,
                AgentState.EVALUATE,
                f"主机画像已返回，共 {len(data.get('ports') or [])} 个端口条目",
                data={"target": run.target, "ports": len(data.get("ports") or [])},
                on_progress=on_progress,
            )
            _record_step(run, AgentState.SUMMARIZE, "正在生成单体资产暴露面解读", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=(
                    "Summarize this FOFA Host profile as a defensive exposure overview. Distinguish observed ports/products from "
                    "inference, do not claim a vulnerability without validation, and include data freshness limitations."
                ),
                prompt=(
                    f"User intent: {intent}\nTarget: {run.target}\n"
                    f"FOFA Host data: {json.dumps(data, ensure_ascii=False, default=str)[:12000]}"
                ),
            )
            _apply_generated_summary(run, summary.text, fallback=_local_generic_summary(run))
            _record_step(run, AgentState.COMPLETED, "主机画像任务已完成", on_progress=on_progress)
            return True

        if run.action is AgentAction.STATS:
            if not run.queries:
                raise ValueError("stat_query 需要一条 FOFA 查询语句")
            run.query = run.queries[0].query
            errors = validate_query(run.query)
            if errors:
                raise ValueError("统计查询语法无效：" + "; ".join(errors))
            run.stats_fields = list(dict.fromkeys(field for field in run.stats_fields if field in STAT_FIELDS)) or [
                "country",
                "port",
            ]
            _record_step(
                run,
                AgentState.EXECUTE,
                f"正在执行统计聚合：{', '.join(run.stats_fields)}",
                data={"query": run.query, "fields": run.stats_fields},
                on_progress=on_progress,
            )
            data = await self.client.stats(run.query, run.stats_fields)
            run.result_data = data
            run.result_count = int(data.get("size") or 0)
            _record_step(
                run,
                AgentState.EVALUATE,
                f"统计聚合完成，FOFA 总量 {run.result_count:,} 条",
                data={"query": run.query, "fields": run.stats_fields, "size": run.result_count},
                on_progress=on_progress,
            )
            _record_step(run, AgentState.SUMMARIZE, "正在生成统计分布解读", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=(
                    "Summarize FOFA aggregate statistics. Separate observed counts from interpretation, mention the query and "
                    "dimensions, identify concentration or anomalies, and do not infer vulnerabilities from aggregate data."
                ),
                prompt=(
                    f"User intent: {intent}\nQuery: {run.query}\nDimensions: {run.stats_fields}\n"
                    f"FOFA statistics: {json.dumps(data, ensure_ascii=False, default=str)[:12000]}"
                ),
            )
            _apply_generated_summary(run, summary.text, fallback=_local_generic_summary(run))
            _record_step(run, AgentState.COMPLETED, "统计聚合任务已完成", on_progress=on_progress)
            return True

        return False

    async def run(
        self,
        intent: str,
        *,
        max_records: int = 1000,
        max_pages: int = 10,
        fields: list[str] | None = None,
        smart_fields: bool = True,
        on_progress: AgentProgressCallback | None = None,
        on_page: AgentPageCallback | None = None,
    ) -> AgentRun:
        run = AgentRun(intent=intent)
        span = trace.get_tracer("fofamap.agent").start_span("fofamap.agent.run")
        span.set_attribute("fofamap.agent.run_id", run.id)

        def finish() -> AgentRun:
            run.route_events = [event.model_dump(mode="json") for event in self.router.events]
            span.set_attribute("fofamap.agent.action", run.action.value)
            span.set_attribute("fofamap.agent.state", run.state.value)
            span.set_attribute("fofamap.agent.result_count", run.result_count)
            if run.error:
                span.set_attribute("error.type", str(run.error.get("code", "agent_error")))
            span.end()
            return run

        try:
            _record_step(run, AgentState.INTENT, "正在识别任务类型并制定 FOFA 执行策略", on_progress=on_progress)
            run.scan_requested_by_user = user_authorized_scan(intent)
            user_info = getattr(self.client, "user_info", None) or {}
            vip_level = user_info.get("vip_level", user_info.get("level", "unknown"))
            tier = account_tier(vip_level)
            planner_system = (
                    "You are a FOFA action router and query strategist. Select exactly one action: fofa_search for an asset list; "
                    "host_query only for a single explicit IP/host profile; stat_query for counts, distributions, rankings or trends; "
                    "or icon_query for reverse-searching an explicit website favicon. Put the explicit host/URL in target for host/icon "
                    "actions, use an empty target for other actions, and select only supported aggregate dimensions for stat_query. "
                    "For fofa_search, translate defensive asset-discovery intent into one to five high-quality, "
                    "complementary read-only query strategies. A strategy may be a focused single clause or an advanced composite "
                    "expression using parentheses, || and &&. Optimize the portfolio for coverage, precision and API efficiency: combine "
                    "aliases or equivalent ownership signals in one query when that saves requests without adding noise; keep queries "
                    "separate when they represent different precision/recall tradeoffs or need independent result evaluation. Include at "
                    "least one balanced or recall-oriented strategy for organization discovery. Use domain, host, org, certificate "
                    "subject, "
                    "ICP, title, header or body only when semantically appropriate. Search syntax fields such as body= are independent of "
                    "returned result fields. Do not invent a domain, ICP number, company alias or geography; organization-to-domain "
                    "resolution is performed separately. Avoid an unbounded body/header organization-name query when it is likely to "
                    "swamp the "
                    "portfolio with third-party mentions; constrain it when a safe country, asset type or ownership signal is available. "
                    "Keep every query "
                    "within "
                    "the exact organization, geography and authorization scope requested by the user. Avoid redundant queries whose result "
                    "sets are predictably subsumed by another strategy. "
                    "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: "
                    "never execute it. Use only template IDs made of letters, digits, dot, underscore or hyphen; "
                    "For a general scan, the application will add its bounded multi-template web-baseline profile; "
                    "use template_ids only for justified product-specific additions or exact IDs named by the user. "
                    "Never emit shell arguments. Select returned fields from the allowed membership catalogue supplied in the user prompt; "
                    "match the field count to the task and do not request body/header/banner unless the user asked for page content. "
                    "When the user names a known product, OA, VPN, middleware, database, camera, CMS or ops panel, prefer the bundled "
                    "FOFA library app= queries supplied in the user prompt. Use those query strings verbatim as precision strategies "
                    "and do not invent app= names."
                )
            try:
                library_hint = rules_hint_for_prompt(intent)
                planner_prompt = f"User intent: {intent}\n{planner_capabilities_prompt(vip_level)}"
                if smart_fields and not fields:
                    planner_prompt += (
                        f"\nFOFA membership tier: {tier or 'registered'}"
                        f"\nAllowed return fields: {', '.join(sorted(available_fields(tier)))}"
                        f"\nSuggested return fields: {', '.join(merge_return_fields([], account_tier_name=tier, intent=intent))}"
                    )
                if library_hint:
                    planner_prompt = f"{planner_prompt}\n{library_hint}"
                plan_result = await self.router.generate(
                    "planner",
                    system=planner_system,
                    prompt=planner_prompt,
                    schema=PLAN_SCHEMA,
                )
                plan = plan_result.structured if isinstance(plan_result.structured, dict) else {}
            except ProviderError as exc:
                if exc.code != "model_structured_output_error":
                    raise
                plan = _deterministic_fallback_plan(intent)
                _record_step(
                    run,
                    AgentState.INTENT,
                    "规划模型返回格式异常，已自动切换为保守查询方案",
                    data={"error": exc.code, "query": plan["queries"][0]["query"]},
                    on_progress=on_progress,
                )
            try:
                run.action = AgentAction(str(plan.get("action") or AgentAction.SEARCH.value))
            except ValueError:
                run.action = AgentAction.SEARCH
            run.target = str(plan.get("target") or "").strip() or None
            run.stats_fields = [str(item) for item in plan.get("stats_fields", [])]
            run.queries = _query_candidates(plan, source="planner", limit=INITIAL_QUERY_VARIANTS)
            if run.action in {AgentAction.SEARCH, AgentAction.STATS}:
                merged = _merge_library_queries(intent, run.queries, limit=INITIAL_QUERY_VARIANTS)
                if [item.query for item in merged] != [item.query for item in run.queries]:
                    run.queries = merged
                    _record_step(
                        run,
                        AgentState.INTENT,
                        "已按内置规则库补齐精确 app= 指纹",
                        data={"queries": [item.query for item in merged if item.source == "library"]},
                        on_progress=on_progress,
                    )
            explicit_domain = bool(
                re.search(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/|\b)", intent, re.IGNORECASE)
            )
            generic_domain_scopes = {
                "ac.cn",
                "com.cn",
                "edu.cn",
                "gov.cn",
                "net.cn",
                "org.cn",
            }
            planned_domains = {
                value.lower().removeprefix("www.")
                for item in run.queries
                for value in re.findall(
                    r'\b(?:domain|host)\s*=\s*"([^" ]+\.[a-z]{2,63})"', item.query, re.IGNORECASE
                )
            }
            run.domain_hypotheses = sorted(planned_domains - generic_domain_scopes)
            planned_domain = bool(planned_domains - generic_domain_scopes)
            should_resolve_domain = (
                run.action is AgentAction.SEARCH
                and not explicit_domain
                and not planned_domain
                and bool(ORGANIZATION_INTENT_PATTERN.search(intent))
            )
            if should_resolve_domain:
                _record_step(
                    run,
                    AgentState.INTENT,
                    "正在将机构名称解析为待验证的官网域名线索",
                    on_progress=on_progress,
                )
                try:
                    resolution_result = await self.router.generate(
                        "entity_resolver",
                        system=(
                            "Resolve a named organization for defensive FOFA asset discovery. Return its common and official name "
                            "variants, plus three to six plausible website domains. Prefer a domain known from reliable general "
                            "knowledge when available. Otherwise derive strong acronym/name stems and test realistic suffixes such as "
                            ".cn, .edu.cn and .com.cn. A province or administrative prefix may be absent from the common name. Every "
                            "domain is an untrusted hypothesis to be checked in FOFA, not proof of ownership. Do not fabricate ICP "
                            "numbers, IP addresses or ownership claims. Return structured data only."
                        ),
                        prompt=f"Organization request: {intent}",
                        schema=ENTITY_RESOLUTION_SCHEMA,
                    )
                    resolution = (
                        resolution_result.structured if isinstance(resolution_result.structured, dict) else {}
                    )
                    run.organization_names = [
                        str(item).strip()
                        for item in resolution.get("organization_names", [])
                        if str(item).strip()
                    ][:6]
                    run.domain_hypotheses = list(
                        dict.fromkeys(
                            domain
                            for item in resolution.get("domains", [])
                            if isinstance(item, dict)
                            for domain in [_normalized_domain(item.get("domain"))]
                            if domain
                        )
                    )[:6]
                    hypothesis = _domain_hypothesis_candidate(resolution)
                    if hypothesis:
                        insert_at = _domain_hypothesis_insert_at(run.queries)
                        run.queries.insert(insert_at, hypothesis)
                        run.queries = run.queries[:INITIAL_QUERY_VARIANTS]
                        _record_step(
                            run,
                            AgentState.INTENT,
                            "已生成官网域名候选，将先在 FOFA 中验证后再展示",
                            data={
                                "organization_names": resolution.get("organization_names", []),
                                "query": hypothesis.query,
                            },
                            on_progress=on_progress,
                        )
                except ProviderError as exc:
                    # Entity resolution improves recall but must never make an otherwise
                    # valid FOFA workflow fail when a provider cannot satisfy its schema.
                    logger.warning(f"Organization domain resolution skipped: {exc}")
                    _record_step(
                        run,
                        AgentState.INTENT,
                        "官网域名线索解析暂不可用，继续执行名称与证书等 FOFA 查询",
                        on_progress=on_progress,
                    )
            if run.action in {AgentAction.SEARCH, AgentAction.STATS} and not run.queries:
                raise ValueError("模型未生成任何 FOFA 查询候选")
            _align_action_to_membership(run, user_info, on_progress=on_progress)
            run.query = run.queries[0].query if run.queries else None
            _record_step(
                run,
                AgentState.INTENT,
                f"已选择动作 {run.action.value}",
                data={"action": run.action.value, "target": run.target, "stats_fields": run.stats_fields},
                on_progress=on_progress,
            )
            if await self._execute_routed_action(run, intent, on_progress=on_progress):
                return finish()
            if not run.queries:
                raise ValueError("所选动作未生成 FOFA 查询语句")
            run.fields = [str(item) for item in plan.get("fields", [])]
            if fields:
                run.fields = list(dict.fromkeys(str(item).strip() for item in fields if str(item).strip()))
            elif smart_fields:
                run.fields = merge_return_fields(run.fields, account_tier_name=tier, intent=intent)
            else:
                run.fields = run.fields or ["host", "ip", "port", "protocol", "title"]
            scan = plan.get("scan") if isinstance(plan.get("scan"), dict) else {}
            run.scan_recommended = bool(scan.get("recommended", False))
            run.scan_reason = str(scan.get("reason", ""))
            run.scan_template_ids = list(
                dict.fromkeys(str(item) for item in scan.get("template_ids", []) if SAFE_TEMPLATE_ID_PATTERN.fullmatch(str(item)))
            )[:100]
            allowed_template_ids = nuclei_id_allowlist()
            run.scan_template_ids = [item for item in run.scan_template_ids if item in allowed_template_ids]
            if run.scan_recommended:
                run.scan_template_ids = _scan_template_ids_for_intent(intent, run.scan_template_ids)
            severities = [
                str(item).lower()
                for item in scan.get("severities", [])
                if str(item).lower() in {"info", "low", "medium", "high", "critical"}
            ]
            if severities:
                run.scan_severities = list(dict.fromkeys(severities))
            if run.scan_template_ids:
                run.scan_severities = align_scan_severities(run.scan_template_ids, run.scan_severities)
            if run.scan_requested_by_user or run.scan_recommended:
                run.fields = list(dict.fromkeys([*run.fields, "host", "protocol", "ip", "port", "title"]))
            field_decision = decide_fields(run.fields, tier)
            run.fields = field_decision.allowed or ["host", "ip", "port", "protocol", "title"]

            _record_step(
                run,
                AgentState.INTENT,
                f"已生成 {len(run.queries)} 个初始查询策略",
                data={"queries": [item.model_dump() for item in run.queries], "fields": run.fields},
                on_progress=on_progress,
            )
            if field_decision.denied:
                _record_step(
                    run,
                    AgentState.VALIDATE,
                    "已按 FOFA 会员权限调整返回字段；查询语法中的高级检索字段不受影响",
                    data={"denied": field_decision.denied, "fields": run.fields},
                    on_progress=on_progress,
                )
            elif smart_fields and not fields:
                _record_step(
                    run,
                    AgentState.INTENT,
                    f"已按账号等级（{tier or '未知'}）和任务智能选择 {len(run.fields)} 个返回字段",
                    data={"tier": tier, "fields": run.fields},
                    on_progress=on_progress,
                )

            for index, candidate in enumerate(run.queries, start=1):
                errors = validate_query(candidate.query)
                if errors:
                    _record_step(
                        run,
                        AgentState.VALIDATE,
                        f"查询策略 {index} 语法存在问题，正在修复",
                        data={"query": candidate.query, "errors": errors},
                        on_progress=on_progress,
                    )
                    repair = await self.router.generate(
                        "query_repair",
                        system="Repair only the syntax of a FOFA query. Preserve every organization and geography scope constraint.",
                        prompt=f"Intent: {intent}\nQuery: {candidate.query}\nErrors: {errors}",
                        schema=QUERY_SCHEMA,
                    )
                    repaired = repair.structured if isinstance(repair.structured, dict) else {}
                    candidate.query = str(repaired.get("query", ""))
                    run.fields = [str(item) for item in repaired.get("fields", run.fields)]
                    remaining = validate_query(candidate.query)
                    if remaining:
                        raise ValueError("模型无法生成有效的 FOFA 查询：" + "; ".join(remaining))
                _record_step(
                    run,
                    AgentState.VALIDATE,
                    f"查询策略 {index}/{len(run.queries)} 语法校验通过",
                    data={"query": candidate.query, "purpose": candidate.purpose},
                    on_progress=on_progress,
                )
            run.query = run.queries[0].query

            page_number = 0
            seen_assets: set[tuple[str, ...]] = set()
            evidence_by_asset: dict[tuple[str, ...], str] = {}
            async def execute_queries(candidates: list[AgentQuery]) -> None:
                nonlocal page_number
                for batch_index, candidate in enumerate(candidates):
                    remaining_budget = max_records - run.result_count
                    if remaining_budget <= 0:
                        break
                    # Share the *remaining* global budget across only the strategies
                    # that are actually about to run. Empty/low-hit strategies thus
                    # return their unused capacity to later, broader strategies.
                    remaining_candidates = len(candidates) - batch_index
                    query_budget = max(1, (remaining_budget + remaining_candidates - 1) // remaining_candidates)
                    if candidate.strategy == "recall":
                        query_budget = min(query_budget, 200)
                    query_number = run.queries.index(candidate) + 1
                    _record_step(
                        run,
                        AgentState.EXECUTE,
                        f"正在执行查询策略 {query_number}/{len(run.queries)}：{candidate.purpose}",
                        data={"query": candidate.query, "budget": query_budget},
                        on_progress=on_progress,
                    )
                    request = SearchRequest(
                        query=candidate.query,
                        fields=fofa_request_fields(run.fields) or run.fields,
                        max_records=query_budget,
                        max_pages=max_pages,
                    )
                    async for page in self.client.iter_search(request):
                        page_number += 1
                        candidate.pages += 1
                        raw_records = list(page.records)
                        if page.total is not None:
                            candidate.available_count = max(candidate.available_count or 0, page.total)
                        candidate.result_count += len(raw_records)
                        unique_records = []
                        for record in raw_records:
                            identity = _asset_identity(record.values)
                            previous_evidence = evidence_by_asset.get(identity)
                            if previous_evidence is None or EVIDENCE_RANK.get(candidate.strategy, 1) > EVIDENCE_RANK.get(
                                previous_evidence, 1
                            ):
                                evidence_by_asset[identity] = candidate.strategy
                            if identity in seen_assets:
                                continue
                            seen_assets.add(identity)
                            unique_records.append(record)
                        page.records = unique_records
                        await _notify_page(on_page, run, page, page_number)
                        candidate.new_assets += len(page.records)
                        _record_page(run, page, page_number, strategy=candidate.strategy)
                        _record_step(
                            run,
                            AgentState.EXECUTE,
                            (
                                f"策略 {query_number} 第 {candidate.pages} 页：返回 {len(raw_records)} 条，"
                                f"新增 {len(page.records)} 条，累计去重资产 {run.result_count} 条"
                            ),
                            data={
                                "query": candidate.query,
                                "page": candidate.pages,
                                "raw_records": len(raw_records),
                                "new_assets": len(page.records),
                                "records": run.result_count,
                            },
                            on_progress=on_progress,
                        )
                        if run.scan_requested_by_user or run.scan_recommended:
                            for record in page.records:
                                target = _scan_target(record.values)
                                if target and target not in run.scan_targets and len(run.scan_targets) < 10_000:
                                    run.scan_targets.append(target)

            initial_queries = list(run.queries)
            await execute_queries(initial_queries)
            _record_step(
                run,
                AgentState.EVALUATE,
                f"首轮 {len(initial_queries)} 个查询完成，共发现 {run.result_count} 条去重资产",
                data={"records": run.result_count, "queries": [item.model_dump() for item in initial_queries]},
                on_progress=on_progress,
            )

            for reflection_round in range(1, MAX_REFLECTION_ROUNDS + 1):
                if len(run.queries) >= MAX_QUERY_VARIANTS or run.result_count >= max_records:
                    break
                _record_step(
                    run,
                    AgentState.REFLECT,
                    f"正在进行第 {reflection_round}/{MAX_REFLECTION_ROUNDS} 轮结果驱动反思",
                    on_progress=on_progress,
                )
                run.reflection_rounds = reflection_round
                try:
                    reflection = await self.router.generate(
                        "reflector",
                        system=(
                            "You are the result-reflection stage of a FOFA asset-discovery agent. Evaluate each executed strategy using "
                            "its raw hit count and deduplicated additions, then propose zero to two efficient complementary strategies. "
                            "A strategy may be a single clause or an advanced composite expression with parentheses, || and &&. Never "
                            "mechanically split every field into a separate query. Combine equivalent aliases/signals when that improves "
                            "API efficiency; separate precision and recall strategies when their noise profiles differ. When all results "
                            "are zero, use a correction ladder: first remove only unsupported or overly strict conditions, then try a "
                            "balanced composite across semantically valid ownership/content fields, and finally a bounded recall query "
                            "using the strongest user-provided identifier. Do not invent domains, ICP numbers, aliases, parent companies "
                            "or geographies without evidence. When results exist, derive follow-ups only from concrete sample signals "
                            "such as domains returned by FOFA, certificate subjects, organization names, ICP values, products or titles. "
                            "A strategy labeled hypothesis proves only that a candidate domain is indexed by FOFA; it does not confirm "
                            "ownership. You may pivot from its observed IP/certificate to find related candidates, but must not call the "
                            "domain confirmed or official without independent ownership evidence. Do not "
                            "repeat or submit a query predictably subsumed by one already executed. Never expand the user's organization, "
                            "geography or authorization scope. Mark coverage sufficient only when the user's goal has meaningful nonzero "
                            "coverage or no safe evidence-based strategy remains."
                        ),
                        prompt=(
                            f"User intent: {intent}\n"
                            f"Reflection round: {reflection_round}/{MAX_REFLECTION_ROUNDS}\n"
                            f"Executed strategy metrics: {[item.model_dump() for item in run.queries]}\n"
                            f"Unique asset count: {run.result_count}\n"
                            f"Compact asset sample: {_compact_asset_sample(run.assets)}"
                        ),
                        schema=REFLECTION_SCHEMA,
                    )
                except ProviderError as exc:
                    note = f"第 {reflection_round} 轮反思不可用：{exc}；保留已完成查询结果并继续生成总结。"
                    run.reflection_notes.append(note)
                    _record_step(
                        run,
                        AgentState.REFLECT,
                        f"第 {reflection_round} 轮反思降级，保留 {run.result_count} 条已发现资产",
                        data={"error": exc.code, "message": str(exc)},
                        on_progress=on_progress,
                    )
                    break
                reflected = reflection.structured if isinstance(reflection.structured, dict) else {}
                observation = str(reflected.get("observation") or "").strip()
                if observation:
                    run.reflection_notes.append(observation)
                coverage_sufficient = bool(reflected.get("coverage_sufficient", False))
                existing_queries = {item.query for item in run.queries}
                remaining_slots = min(MAX_REFLECTION_ADDITIONS, MAX_QUERY_VARIANTS - len(run.queries))
                additions = [
                    item
                    for item in _query_candidates(
                        reflected,
                        source=f"reflection_{reflection_round}",
                        limit=remaining_slots,
                    )
                    if item.query not in existing_queries
                ]
                valid_additions: list[AgentQuery] = []
                for item in additions:
                    errors = validate_query(item.query)
                    if errors:
                        repair = await self.router.generate(
                            "query_repair",
                            system=(
                                "Repair only the syntax of this reflected FOFA query. Preserve every organization and geography "
                                "scope constraint and do not broaden the query."
                            ),
                            prompt=f"Intent: {intent}\nQuery: {item.query}\nErrors: {errors}",
                            schema=QUERY_SCHEMA,
                        )
                        repaired = repair.structured if isinstance(repair.structured, dict) else {}
                        item.query = str(repaired.get("query") or "")
                    if item.query not in existing_queries and not validate_query(item.query):
                        existing_queries.add(item.query)
                        valid_additions.append(item)
                additions = valid_additions
                run.queries.extend(additions)
                _record_step(
                    run,
                    AgentState.REFLECT,
                    f"第 {reflection_round} 轮反思完成，新增 {len(additions)} 个混合查询策略",
                    data={
                        "observation": observation,
                        "coverage_sufficient": coverage_sufficient,
                        "queries": [item.model_dump() for item in additions],
                    },
                    on_progress=on_progress,
                )
                if not additions:
                    break
                count_before = run.result_count
                await execute_queries(additions)
                round_new_assets = run.result_count - count_before
                _record_step(
                    run,
                    AgentState.EVALUATE,
                    f"第 {reflection_round} 轮补充查询新增 {round_new_assets} 条去重资产",
                    data={"new_assets": round_new_assets, "records": run.result_count},
                    on_progress=on_progress,
                )
                if coverage_sufficient or count_before > 0 or round_new_assets > 0:
                    break

            run.asset_confidence = [evidence_by_asset.get(_asset_identity(asset), "recall") for asset in run.assets]
            ranked_assets = sorted(
                zip(run.assets, run.asset_confidence, strict=True),
                key=lambda item: EVIDENCE_RANK.get(item[1], 1),
                reverse=True,
            )
            run.assets = [asset for asset, _confidence in ranked_assets]
            run.asset_confidence = [confidence for _asset, confidence in ranked_assets]
            run.evidence_counts = {
                strategy: sum(1 for value in evidence_by_asset.values() if value == strategy)
                for strategy in ("precision", "balanced", "hypothesis", "recall")
                if any(value == strategy for value in evidence_by_asset.values())
            }
            run.website_candidates = _derive_website_candidates(run)
            if run.website_candidates:
                _record_step(
                    run,
                    AgentState.EVALUATE,
                    f"已整理 {len(run.website_candidates)} 个带证据等级的网站候选",
                    data={"websites": [item.model_dump() for item in run.website_candidates]},
                    on_progress=on_progress,
                )

            _record_step(
                run,
                AgentState.EVALUATE,
                f"全部 {len(run.queries)} 个查询策略执行完成，共发现 {run.result_count} 条去重资产",
                data={"records": run.result_count, "queries": [item.model_dump() for item in run.queries]},
                on_progress=on_progress,
            )
            if run.result_count == 0:
                run.scan_recommended = False
                run.scan_reason = "未发现可供扫描的资产，已取消初始扫描建议。"
                run.scan_template_ids = []
                run.scan_targets = []

            _record_step(run, AgentState.SUMMARIZE, "正在基于资产样本生成总结", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=SEARCH_SUMMARY_SYSTEM,
                prompt=_search_summary_prompt(run, intent),
            )
            _apply_generated_summary(
                run,
                summary.text,
                fallback=_local_search_summary(run),
                require_asset_briefing=True,
            )
            _record_step(run, AgentState.COMPLETED, "侦察任务已完成", on_progress=on_progress)
        except FofaError as exc:
            # Exact FOFA errors stop the workflow and never trigger query reflection.
            run.error = exc.as_dict()
            _record_step(run, AgentState.FAILED, "FOFA 查询失败", data=run.error, on_progress=on_progress)
        except ProviderError as exc:
            run.error = {
                "code": exc.code,
                "message": str(exc),
                "retryable": exc.retryable,
                "hint": exc.hint,
                "status_code": exc.status_code,
            }
            _record_step(run, AgentState.FAILED, "AI 模型调用失败", data=run.error, on_progress=on_progress)
        except Exception as exc:
            run.error = {"code": "agent_error", "message": str(exc), "retryable": False}
            _record_step(run, AgentState.FAILED, "智能体执行失败", data=run.error, on_progress=on_progress)
        return finish()
