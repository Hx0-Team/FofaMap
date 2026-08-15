"""Optional real-provider smoke tests; never enabled in normal CI."""

from __future__ import annotations

import os

import pytest

from config import settings
from core.agent import AgentState, FofaAgent
from core.client import FofaClient
from core.models import SearchRequest
from providers.registry import ProviderRegistry, ProviderRouter

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.getenv("FOFAMAP_RUN_LIVE_TESTS") != "true", reason="real API smoke tests are opt-in"),
]


@pytest.mark.asyncio
async def test_live_fofa_account_and_one_record_search():
    async with FofaClient(max_retries=1, requests_per_second=10) as client:
        account = await client.account()
        assert account
        page = await client.search_page(
            SearchRequest(
                query='domain="harvard.edu"',
                fields=["host", "status_code"],
                size=1,
                max_records=1,
                max_pages=1,
                continuous=True,
            )
        )
    assert page.fields == ["host", "status_code"]
    assert len(page.records) <= 1


@pytest.mark.asyncio
async def test_live_model_and_agent_without_scan():
    registry = ProviderRegistry(settings, execution_mode="interactive")
    try:
        async with FofaClient(max_retries=1, requests_per_second=10) as client:
            run = await FofaAgent(client, ProviderRouter(registry)).run(
                "查找美国哈佛大学公开网站资产，不要扫描",
                max_records=1,
                max_pages=1,
            )
    finally:
        await registry.aclose()
    assert run.state is AgentState.COMPLETED, run.error
    assert run.error is None
    assert run.result_count <= 1
    assert run.summary
    assert run.scan_requested_by_user is False
    assert run.scan_artifact is None
