"""FofaMap MCP 2.0 server (stdio by default, authenticated Streamable HTTP optionally)."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from config import settings
from core.agent import FofaAgent, validate_query
from core.client import FofaClient
from core.exporter import export_pages
from core.fields import field_catalog
from core.models import ExportRequest, FofaError, SearchRequest
from core.scanner import NucleiScanner
from core.scans import ScanApproval, ScanPlanRequest
from providers.registry import ProviderRegistry, ProviderRouter
from service.store import JobStore

try:
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import Context, MCPServer
except ImportError as exc:  # clear migration failure instead of corrupting stdio
    raise RuntimeError("FofaMap 2.0.1 requires mcp>=2,<3; install the 2.0.1 dependencies") from exc


READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
LOCAL_READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
WRITE_SAFE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
SCAN_EXECUTE = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}

MCP_INSTRUCTIONS = (
    "FofaMap searches internet assets via FOFA. "
    "When the user names a product, OA, VPN, middleware, database, camera, CMS or ops panel, "
    "call fofa_rules first (no FOFA quota) and use the returned query values verbatim in fofa_search or fofa_stats. "
    "Never invent app= names. An empty keyword lists the bundled catalog. "
    "Host aggregation and stats APIs depend on FOFA vip_level; call fofa_account and fofa_fields first "
    "(the equivalent Resources are available on hosts that support them). "
    "Registered users have no host API; personal/education accounts have no stats API. "
    "Validate queries before spending quota. Never plan Nuclei scans without an explicit authorized scope."
)


class _TokenVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        service_token = os.getenv("FOFAMAP_SERVICE_TOKEN", "")
        if service_token and hmac.compare_digest(token, service_token):
            return AccessToken(
                token=token,
                client_id="fofamap-static-token",
                scopes=["fofamap"],
                expires_at=None,
                resource=os.getenv("FOFAMAP_MCP_RESOURCE_URL"),
            )
        public_key = os.getenv("FOFAMAP_JWT_PUBLIC_KEY", "")
        issuer = os.getenv("FOFAMAP_JWT_ISSUER", "")
        if not public_key or not issuer:
            return None
        try:
            import jwt

            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256", "ES256"],
                issuer=issuer,
                audience=os.getenv("FOFAMAP_JWT_AUDIENCE", "fofamap"),
            )
        except Exception:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("sub") or "jwt-client"),
            subject=claims.get("sub"),
            scopes=str(claims.get("scope", "fofamap")).split(),
            expires_at=int(claims["exp"]) if claims.get("exp") else None,
            resource=os.getenv("FOFAMAP_MCP_RESOURCE_URL"),
            claims=claims,
        )


def _build_mcp() -> MCPServer:
    issuer = os.getenv("FOFAMAP_MCP_ISSUER_URL")
    resource = os.getenv("FOFAMAP_MCP_RESOURCE_URL")
    if issuer and resource:
        return MCPServer(
            "fofamap_mcp",
            instructions=MCP_INSTRUCTIONS,
            auth=AuthSettings(issuer_url=issuer, resource_server_url=resource, required_scopes=[]),
            token_verifier=_TokenVerifier(),
        )
    return MCPServer("fofamap_mcp", instructions=MCP_INSTRUCTIONS)


mcp = _build_mcp()
store = JobStore(os.getenv("FOFAMAP_DATABASE_URL", "sqlite:///./fofamap.sqlite3"))


class SearchToolResult(BaseModel):
    summary: str
    query: str
    fields: list[str]
    records: list[dict[str, Any]]
    total: int | None = None
    next_cursor: str | None = None
    consumed: int | float | None = None


class GenericResult(BaseModel):
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)


@mcp.tool(name="fofa_validate_query", annotations=LOCAL_READ)
async def fofa_validate_query(query: str) -> GenericResult:
    """Perform local syntax checks without spending FOFA quota."""
    errors = validate_query(query)
    return GenericResult(
        summary="query is valid" if not errors else "query is invalid", data={"valid": not errors, "query": query, "errors": errors}
    )


@mcp.tool(name="fofa_fields", annotations=LOCAL_READ)
async def fofa_fields() -> GenericResult:
    """Return the versioned FOFA field and membership capability catalogue without using quota."""
    catalog = field_catalog()
    return GenericResult(summary="FOFA field and membership catalogue", data=catalog)


@mcp.tool(name="fofa_account", annotations=READ_ONLY)
async def fofa_account() -> GenericResult:
    """Return the current FOFA account tier, API capabilities and quota information."""
    async with FofaClient() as client:
        data = await client.account()
    return GenericResult(summary="FOFA account capabilities loaded", data=data)


async def _search(request: SearchRequest) -> SearchToolResult:
    async with FofaClient() as client:
        page = await client.search_page(request)
    return SearchToolResult(
        summary=f"FOFA returned {len(page.records)} records; use next_cursor for continuation or fofa_export for large results.",
        query=page.query,
        fields=page.fields,
        records=[record.values for record in page.records],
        total=page.total,
        next_cursor=page.next_cursor,
        consumed=page.consumed,
    )


@mcp.tool(name="fofa_search", annotations=READ_ONLY)
async def fofa_search(query: str, fields: list[str] | None = None, size: int = 100, full: bool = False) -> SearchToolResult:
    """Run one read-only FOFA search page. If the user named a product/OA/VPN, call fofa_rules first and paste its query verbatim."""
    return await _search(SearchRequest(query=query, fields=fields or settings.search.fields.split(","), size=size, full=full))


@mcp.tool(name="fofa_search_next", annotations=READ_ONLY)
async def fofa_search_next(query: str, cursor: str, fields: list[str], size: int = 100, full: bool = False) -> SearchToolResult:
    """Continue a FOFA search using the opaque cursor returned by fofa_search."""
    return await _search(SearchRequest(query=query, cursor=cursor, continuous=True, fields=fields, size=size, full=full))


@mcp.tool(name="fofa_icon_search", annotations=READ_ONLY)
async def fofa_icon_search(
    url: str,
    fields: list[str] | None = None,
    size: int = 100,
    full: bool = False,
) -> SearchToolResult:
    """Fetch a public website favicon safely, calculate its FOFA MurmurHash3 value, and search matching assets."""
    from utils.helpers import IconHashCalculator

    query = await IconHashCalculator.get_hash(url)
    if not query:
        raise ValueError("unable to fetch a favicon or calculate its hash")
    return await _search(SearchRequest(query=query, fields=fields or settings.search.fields.split(","), size=size, full=full))


@mcp.tool(name="fofa_host_profile", annotations=READ_ONLY)
async def fofa_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Get FOFA Host aggregation for one IP or DNS name. Registered users have no Host API."""
    async with FofaClient() as client:
        data = await client.host_profile(host, detail=detail)
    return GenericResult(summary=f"Host profile loaded for {host}", data=data)


@mcp.tool(name="fofa_stats", annotations=READ_ONLY)
async def fofa_stats(query: str, fields: list[str], size: int = 5) -> GenericResult:
    """Get FOFA stats. Personal/education accounts have no stats API. size is Top-N (default 5)."""
    async with FofaClient() as client:
        data = await client.stats(query, fields, size=size)
    return GenericResult(summary=f"Statistics loaded for {query}", data=data)


@mcp.tool(name="fofa_syntax", annotations=LOCAL_READ)
async def fofa_syntax() -> GenericResult:
    """Return official FOFA query operators and syntax fields from the API appendix."""
    from core.syntax import syntax_catalog

    catalog = syntax_catalog()
    return GenericResult(summary="FOFA official query syntax", data=catalog)


@mcp.tool(name="fofa_rules", annotations=LOCAL_READ)
async def fofa_rules(keyword: str = "") -> GenericResult:
    """Search bundled official app= names; call before product searches and use returned queries verbatim."""
    from core.rules import rules_catalog

    catalog = rules_catalog(keyword)
    return GenericResult(summary=f"{catalog['count']} of {catalog['total']} FOFA library rules matched", data=catalog)


async def _export(job_id: str, request: ExportRequest) -> None:
    store.update(job_id, status="running")
    try:
        path = Path(settings.system.output_dir).resolve() / Path(request.filename or f"{job_id}.{request.format}").name
        async with FofaClient() as client:
            artifact, count = await export_pages(client.iter_search(request.search), path, request.format)
        store.update(job_id, status="completed", result={"records": count}, artifact_path=str(artifact.resolve()))
    except FofaError as exc:
        store.update(job_id, status="failed", error=exc.as_dict())
    except Exception as exc:
        store.update(job_id, status="failed", error={"code": "export_error", "message": str(exc)})


@mcp.tool(name="fofa_export", annotations=WRITE_SAFE)
async def fofa_export(request: ExportRequest) -> GenericResult:
    """Start a bounded export job; retrieve status and artifact through MCP resources."""
    job = store.create("export", request.model_dump(mode="json"))
    asyncio.create_task(_export(job["id"], request))
    return GenericResult(summary=f"Export job {job['id']} started", data=job)


@mcp.tool(name="fofa_job_status", annotations=LOCAL_READ)
async def fofa_job_status(job_id: str) -> GenericResult:
    """Read local export, agent or scan job state."""
    job = store.get(job_id)
    return GenericResult(summary=f"Job {job_id} is {job['status']}", data=job)


@mcp.tool(name="fofa_agent_run", annotations=READ_ONLY)
async def fofa_agent_run(intent: str, max_records: int = 1000, max_pages: int = 10, ctx: Context | None = None) -> GenericResult:
    """Run planning with bundled app= fingerprints and evidence-labelled website candidates; never scan."""
    job = store.create("agent", {"intent": intent, "max_records": max_records, "max_pages": max_pages})
    store.update(job["id"], status="running")
    if ctx:
        await ctx.report_progress(0, 3, "planning")
    registry = ProviderRegistry(settings, execution_mode="service")
    router = ProviderRouter(registry)
    async with FofaClient() as client:
        run = await FofaAgent(client, router).run(intent, max_records=max_records, max_pages=max_pages)
    await registry.aclose()
    status = "completed" if run.error is None else "failed"
    store.update(job["id"], status=status, result=run.model_dump(mode="json"), error=run.error)
    if ctx:
        await ctx.report_progress(3, 3, "complete")
    data = run.model_dump(mode="json")
    data["job_id"] = job["id"]
    return GenericResult(summary=run.summary or f"Agent run {run.state}", data=data)


@mcp.tool(name="nuclei_plan", annotations=WRITE_SAFE)
async def nuclei_plan(request: ScanPlanRequest) -> GenericResult:
    """Create an exact, expiring Nuclei plan and one-time approval token. Scanning must be enabled."""
    if os.getenv("FOFAMAP_ENABLE_SCANNING", "false").lower() != "true":
        raise ValueError("active scanning is disabled")
    job, token = ScanApproval(store, allow_private=settings.system.allow_private_network).create(request)
    return GenericResult(
        summary="Review target/template/severity scope before calling nuclei_execute", data={"plan": job, "approval_token": token}
    )


@mcp.tool(name="nuclei_execute", annotations=SCAN_EXECUTE)
async def nuclei_execute(plan_id: str, approval_token: str) -> GenericResult:
    """Consume a scope-bound approval exactly once and execute that exact plan."""
    if os.getenv("FOFAMAP_ENABLE_SCANNING", "false").lower() != "true":
        raise ValueError("active scanning is disabled")
    job = ScanApproval(store, allow_private=settings.system.allow_private_network).consume(plan_id, approval_token)
    store.update(plan_id, status="running")
    try:
        scan = await NucleiScanner().run_plan(
            ScanPlanRequest.model_validate(job["payload"]),
            Path(settings.system.output_dir).resolve() / f"scan-{plan_id}",
        )
        job = store.update(
            plan_id,
            status="completed",
            artifact_path=str(scan.artifact.resolve()),
            result=scan.to_job_payload(),
        )
    except Exception as exc:
        store.update(plan_id, status="failed", error={"code": "scan_error", "message": str(exc)})
        raise
    return GenericResult(summary=scan.headline(), data=job)


@mcp.resource("fofamap://fields")
def fields_resource() -> dict[str, Any]:
    """Current versioned FOFA field catalogue."""
    return field_catalog()


@mcp.resource("fofamap://rules")
def rules_resource() -> dict[str, Any]:
    """Bundled FOFA app= fingerprint library (official names from fofa.info/library)."""
    from core.rules import rules_catalog

    return rules_catalog()


@mcp.resource("fofamap://account")
async def account_resource() -> dict[str, Any]:
    """Current FOFA account capability and usage data."""
    async with FofaClient() as client:
        return await client.account()


@mcp.resource("fofamap://jobs/{job_id}")
def job_resource(job_id: str) -> dict[str, Any]:
    """Job metadata; artifact_path points to large local results."""
    return store.get(job_id)


def _loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def run_server() -> None:
    parser = argparse.ArgumentParser(description="FofaMap MCP 2.0 服务")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio", help="传输方式")
    parser.add_argument("--host", default=os.getenv("FOFAMAP_BIND_HOST", "127.0.0.1"), help="HTTP 绑定地址")
    parser.add_argument("--port", type=int, default=int(os.getenv("FOFAMAP_MCP_PORT", "8001")), help="HTTP 端口")
    args = parser.parse_args()
    if args.transport == "streamable-http" and not _loopback(args.host):
        if not (
            (os.getenv("FOFAMAP_SERVICE_TOKEN") or os.getenv("FOFAMAP_JWT_PUBLIC_KEY"))
            and os.getenv("FOFAMAP_MCP_ISSUER_URL")
            and os.getenv("FOFAMAP_MCP_RESOURCE_URL")
        ):
            parser.error("非回环 Streamable HTTP 需要令牌校验器，以及 FOFAMAP_MCP_ISSUER_URL 和 FOFAMAP_MCP_RESOURCE_URL")
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
        )


if __name__ == "__main__":
    run_server()
