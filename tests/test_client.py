import base64
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from core.client import FofaClient
from core.models import FofaError, FofaErrorCode, SearchRequest


def test_retry_after_supports_seconds_http_dates_and_a_safe_cap():
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=5), usegmt=True)

    assert FofaClient._retry_after_seconds("1.5", 0.5) == 1.5
    assert 0 < FofaClient._retry_after_seconds(future, 0.5) <= 5
    assert FofaClient._retry_after_seconds("999", 0.5) == 30
    assert FofaClient._retry_after_seconds("invalid", 2.0) == 2.0


@pytest.mark.asyncio
async def test_cursor_paging_maps_fields_without_misalignment():
    requests = []

    def handler(request: httpx.Request):
        requests.append(request)
        assert request.url.params["next"] == "cursor-1"
        return httpx.Response(
            200, json={"results": [["1.1.1.1", 443, 200]], "fields": "ip,port,status_code", "next": "cursor-2", "size": 10}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        page = await client.search_page(
            SearchRequest(
                query='port="443"',
                fields=["ip", "port", "status_code"],
                cursor="cursor-1",
                continuous=True,
            )
        )
    assert page.records[0].values == {"ip": "1.1.1.1", "port": 443, "status_code": 200}
    assert page.next_cursor == "cursor-2"
    assert requests[0].url.path == "/api/v1/search/next"


@pytest.mark.asyncio
async def test_search_drops_local_alive_status_field_before_calling_fofa():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request.url.params["fields"])
        return httpx.Response(200, json={"results": [["example.com"]], "fields": "host", "size": 1})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=1000)
        await client.search_page(
            SearchRequest(query='app="nginx"', fields=["host", "alive_status", "evidence"], continuous=False)
        )
    assert seen == ["host"]


@pytest.mark.asyncio
async def test_permission_error_is_not_empty_result():
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"error": True, "errmsg": "820001 字段权限不足"}))
    async with httpx.AsyncClient(transport=transport) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query='app="nginx"', fields=["fid"]))
    assert captured.value.code is FofaErrorCode.PERMISSION_DENIED
    assert "host" in captured.value.alternatives


@pytest.mark.asyncio
async def test_response_field_mismatch_is_rejected():
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"results": [["1.1.1.1"]], "fields": "ip,port"}))
    async with httpx.AsyncClient(transport=transport) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["ip", "port"]))
    assert captured.value.code is FofaErrorCode.INVALID_RESPONSE


@pytest.mark.asyncio
async def test_cursor_iteration_deduplicates_explicit_key():
    calls = 0

    def handler(_: httpx.Request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json={"results": [["a"], ["b"]], "fields": "host", "next": "next"})
        return httpx.Response(200, json={"results": [["b"], ["c"]], "fields": "host"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        pages = [page async for page in client.iter_search(SearchRequest(query='app="x"', fields=["host"], size=2, dedupe_by=["host"]))]
    assert [r.values["host"] for page in pages for r in page.records] == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_duplicate_only_page_does_not_stop_cursor_iteration():
    payloads = iter(
        [
            {"results": [["a"]], "fields": "host", "next": "one"},
            {"results": [["a"]], "fields": "host", "next": "two"},
            {"results": [["b"]], "fields": "host"},
        ]
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=next(payloads)))) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        pages = [page async for page in client.iter_search(SearchRequest(query='app="x"', fields=["host"], size=1, dedupe_by=["host"]))]
    assert [record.values["host"] for page in pages for record in page.records] == ["a", "b"]


@pytest.mark.asyncio
async def test_account_host_and_stats_use_documented_endpoints_and_parameters():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path == "/api/v1/info/my":
            return httpx.Response(200, json={"username": "sanitized-user", "fofa_point": 1000})
        if request.url.path == "/api/v1/host/8.8.8.8":
            assert request.url.params["detail"] == "true"
            return httpx.Response(200, json={"host": "8.8.8.8", "ports": []})
        if request.url.path == "/api/v1/search/stats":
            decoded = base64.b64decode(request.url.params["qbase64"]).decode()
            assert decoded == 'app="redis"'
            assert request.url.params["fields"] == "country,org"
            assert request.url.params["size"] == "5"
            return httpx.Response(200, json={"distinct": {"countries": []}})
        return httpx.Response(404, json={"error": True, "errmsg": "unexpected test path"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="sanitized-key", client=http, requests_per_second=1000)
        assert (await client.account())["username"] == "sanitized-user"
        assert (await client.host_profile("8.8.8.8"))["host"] == "8.8.8.8"
        assert "distinct" in await client.stats('app="redis"', ["country", "org"])
    assert [request.url.path for request in seen] == [
        "/api/v1/info/my",
        "/api/v1/host/8.8.8.8",
        "/api/v1/search/stats",
    ]
    assert seen[0].url.params["lang"] == "zh-CN"
    assert seen[2].url.params["size"] == "5"


@pytest.mark.asyncio
async def test_membership_caps_rate_and_blocks_unsupported_host_stats():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        if request.url.path == "/api/v1/info/my":
            return httpx.Response(200, json={"username": "edu", "vip_level": 22, "remain_api_query": -1})
        return httpx.Response(200, json={"host": "8.8.8.8"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=5)
        await client.account()
        assert client._limiter._interval == 1.0
        assert (await client.host_profile("8.8.8.8"))["host"] == "8.8.8.8"
        with pytest.raises(FofaError) as captured:
            await client.stats('app="redis"', ["country"])
    assert captured.value.code is FofaErrorCode.PERMISSION_DENIED
    assert "统计聚合" in captured.value.message
    assert "/api/v1/search/stats" not in seen


@pytest.mark.asyncio
async def test_registered_user_cannot_call_host_aggregation():
    def handler(request: httpx.Request):
        if request.url.path == "/api/v1/info/my":
            return httpx.Response(200, json={"username": "free", "vip_level": 0})
        raise AssertionError(f"unexpected path {request.url.path}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        await client.account()
        with pytest.raises(FofaError) as captured:
            await client.host_profile("8.8.8.8")
    assert captured.value.code is FofaErrorCode.PERMISSION_DENIED
    assert "主机聚合" in captured.value.message


@pytest.mark.asyncio
async def test_search_maps_official_consumed_fpoint_and_total_size():
    def handler(_: httpx.Request):
        return httpx.Response(
            200,
            json={
                "error": False,
                "consumed_fpoint": 0,
                "required_fpoints": 1,
                "size": 321,
                "page": 1,
                "mode": "extended",
                "query": 'app="nginx"',
                "results": [["example.com"]],
                "fields": "host",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=1000)
        page = await client.search_page(SearchRequest(query='app="nginx"', fields=["host"], continuous=False))
    assert page.consumed == 0
    assert page.total == 321
    assert page.metadata["required_fpoints"] == 1


@pytest.mark.asyncio
async def test_host_profile_rejects_path_or_credential_injection_before_network():
    transport = httpx.MockTransport(lambda _: pytest.fail("invalid host must not reach network"))
    async with httpx.AsyncClient(transport=transport) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=100)
        for invalid in ("example.com/path", "user@example.com", "example.com?x=1"):
            with pytest.raises(FofaError) as captured:
                await client.host_profile(invalid)
            assert captured.value.code is FofaErrorCode.INVALID_QUERY


@pytest.mark.asyncio
async def test_start_page_uses_numbered_search_all_window():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        page = request.url.params.get("page")
        return httpx.Response(200, json={"results": [[f"p{page}"]], "fields": "host"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=1000)
        pages = [
            page
            async for page in client.iter_search(
                SearchRequest(query='app="x"', fields=["host"], page=3, max_pages=2, size=1)
            )
        ]
    assert [record.values["host"] for page in pages for record in page.records] == ["p3", "p4"]
    assert [request.url.path for request in seen] == ["/api/v1/search/all", "/api/v1/search/all"]
    assert [request.url.params["page"] for request in seen] == ["3", "4"]
