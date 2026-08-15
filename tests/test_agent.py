from io import StringIO

import pytest
from rich.console import Console

from config import Config
from core.agent import (
    SEARCH_SUMMARY_SYSTEM,
    AgentQuery,
    AgentRun,
    AgentState,
    FofaAgent,
    _asset_briefing_has_sufficient_quality,
    _asset_briefing_stats,
    _derive_website_candidates,
    _deterministic_fallback_plan,
    _local_search_summary,
    _search_summary_prompt,
    user_authorized_scan,
)
from core.models import AssetRecord, FofaError, FofaErrorCode, SearchPage
from core.scans import default_nuclei_template_ids
from providers.base import ModelResult, ProviderError
from providers.registry import ProviderRegistry, ProviderRouter
from utils import cli_ui


class FakeRouter:
    def __init__(self):
        self.calls = []
        self.events = []

    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text='{"query":"app=\\"nginx\\"","fields":["host"]}',
                structured={"query": 'app="nginx"', "fields": ["host"]},
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "coverage is sufficient", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


@pytest.mark.parametrize(
    "intent",
    ["不要扫描", "不需要漏洞检测", "请勿进行 nuclei 扫描", "do not scan", "without scanning"],
)
def test_explicit_scan_denial_is_never_treated_as_authorization(intent):
    assert user_authorized_scan(intent) is False


@pytest.mark.parametrize("intent", ["扫描一下", "执行漏洞扫描", "run a nuclei scan", "start scanning"])
def test_explicit_scan_request_is_authorized(intent):
    assert user_authorized_scan(intent) is True


class AuthFailureClient:
    async def iter_search(self, request):
        raise FofaError(FofaErrorCode.AUTH_FAILED, "bad key")
        yield


class SuccessfulClient:
    async def iter_search(self, request):
        assert {"host", "protocol", "ip", "port"}.issubset(request.fields)
        yield SearchPage(
            query=request.query,
            fields=request.fields,
            records=[
                AssetRecord(
                    values={
                        field: {
                            "host": "https://www.harvard.edu",
                            "protocol": "https",
                            "ip": "1.1.1.1",
                            "port": 443,
                            "title": "Harvard University",
                        }.get(field, "")
                        for field in request.fields
                    }
                )
            ],
        )


class ScanRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "query": 'domain="harvard.edu"',
                    "fields": ["domain", "title"],
                    "scan": {
                        "recommended": True,
                        "reason": "User requested an authorized HTTP configuration scan.",
                        "template_ids": ["http-missing-security-headers", "not-allowlisted"],
                        "severities": ["medium", "high"],
                    },
                },
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class ZeroRepairRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={"query": 'domain="example.invalid"', "fields": ["host"], "scan": {"recommended": False}},
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={
                    "observation": "the domain query returned no assets",
                    "coverage_sufficient": True,
                    "queries": [{"query": 'host="example.invalid"', "purpose": "补充主机名维度"}],
                },
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class MultiQueryRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "queries": [
                        {
                            "query": '(domain="example.edu" || cert="example.edu") && country="US"',
                            "purpose": "域名与证书域组合召回",
                            "strategy": "balanced",
                        },
                        {
                            "query": '(org="Example University" || cert.subject.org="Example University") && country="US"',
                            "purpose": "组织主体组合匹配",
                            "strategy": "precision",
                        },
                    ],
                    "fields": ["host", "ip", "port", "protocol", "title"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={
                    "observation": "organization names provide another ownership signal",
                    "coverage_sufficient": True,
                    "queries": [
                        {
                            "query": '(body="Example University" || title="Example University") && country="US"',
                            "purpose": "网页内容组合补充召回",
                            "strategy": "recall",
                        }
                    ],
                },
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class MultiQueryClient:
    async def iter_search(self, request):
        hosts = {
            '(domain="example.edu" || cert="example.edu") && country="US"': ["a.example.edu", "shared.example.edu"],
            '(org="Example University" || cert.subject.org="Example University") && country="US"': [
                "shared.example.edu",
                "b.example.edu",
            ],
            '(body="Example University" || title="Example University") && country="US"': [
                "b.example.edu",
                "c.example.edu",
            ],
        }[request.query]
        yield SearchPage(
            query=request.query,
            fields=request.fields,
            records=[AssetRecord(values={"host": f"https://{host}"}) for host in hosts],
        )


class DynamicBudgetRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "queries": [
                        {"query": 'org="Example"', "purpose": "主体", "strategy": "precision"},
                        {"query": 'cert="Example"', "purpose": "证书", "strategy": "balanced"},
                        {"query": 'body="Example"', "purpose": "内容", "strategy": "balanced"},
                    ],
                    "fields": ["host"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "no safe additions", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class BudgetRecordingClient:
    def __init__(self):
        self.budgets = []

    async def iter_search(self, request):
        self.budgets.append(request.max_records)
        yield SearchPage(query=request.query, fields=request.fields, records=[])


class OrganizationHypothesisRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "queries": [
                        {
                            "query": 'body="安徽邮电职业技术学院" && country="CN"',
                            "purpose": "正文名称召回",
                            "strategy": "recall",
                        }
                    ],
                    "fields": ["host", "domain"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "entity_resolver":
            return ModelResult(
                text="entities",
                structured={
                    "organization_names": ["安徽省邮电职业技术学院", "安徽邮电职业技术学院"],
                    "domains": [
                        {"domain": "ahptc.edu.cn", "reason": "英文缩写教育域名"},
                        {"domain": "https://www.ahptc.cn/", "reason": "英文缩写 CN 域名"},
                    ],
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "enough", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class OrganizationHypothesisClient:
    async def iter_search(self, request):
        if 'domain="ahptc.cn"' in request.query:
            records = [
                AssetRecord(values={"host": host, "domain": "ahptc.cn"})
                for host in (
                    "https://www.ahptc.cn",
                    "https://img.ahptc.cn",
                    "https://zj.ahptc.cn",
                    "https://ahptc.cn",
                )
            ]
            yield SearchPage(query=request.query, fields=request.fields, records=records, total=4)
            return
        records = [
            AssetRecord(values={"host": f"https://noise-{index}.example.com", "domain": "example.com"})
            for index in range(request.max_records)
        ]
        yield SearchPage(query=request.query, fields=request.fields, records=records, total=670)


class LatePrecisionRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "queries": [{"query": 'body="Example"', "purpose": "初始样本", "strategy": "balanced"}],
                    "fields": ["host"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={
                    "observation": "found precise domain",
                    "coverage_sufficient": True,
                    "queries": [
                        {"query": 'domain="official.example"', "purpose": "验证官网", "strategy": "precision"}
                    ],
                },
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class LatePrecisionClient:
    async def iter_search(self, request):
        if request.query == 'domain="official.example"':
            records = [AssetRecord(values={"host": "https://official.example"})]
        else:
            records = [AssetRecord(values={"host": f"https://noise-{index}.example"}) for index in range(500)]
        yield SearchPage(query=request.query, fields=request.fields, records=records, total=len(records))


class TwoRoundReflectionRouter(FakeRouter):
    def __init__(self):
        super().__init__()
        self.reflection_calls = 0

    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "queries": [
                        {
                            "query": '(org="示例科技有限公司" || cert.subject.org="示例科技有限公司")',
                            "purpose": "主体精确匹配",
                            "strategy": "precision",
                        }
                    ],
                    "fields": ["host", "ip", "port", "protocol", "title"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            self.reflection_calls += 1
            query = (
                '(body="示例科技有限公司" || header="示例科技有限公司")'
                if self.reflection_calls == 1
                else '(body="示例科技" || title="示例科技")'
            )
            return ModelResult(
                text="reflection",
                structured={
                    "observation": f"correction round {self.reflection_calls}",
                    "coverage_sufficient": self.reflection_calls == 2,
                    "queries": [
                        {
                            "query": query,
                            "purpose": "逐级放宽内容匹配",
                            "strategy": "balanced" if self.reflection_calls == 1 else "recall",
                        }
                    ],
                },
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class TwoRoundReflectionClient:
    async def iter_search(self, request):
        records = []
        if request.query == '(body="示例科技" || title="示例科技")':
            records = [AssetRecord(values={"host": "https://example.cn", "title": "示例科技"})]
        yield SearchPage(query=request.query, fields=request.fields, records=records)


class ZeroThenResultClient:
    def __init__(self):
        self.calls = 0

    async def iter_search(self, request):
        self.calls += 1
        records = []
        if self.calls == 2:
            records = [AssetRecord(values={"host": "https://example.invalid"})]
        yield SearchPage(query=request.query, fields=request.fields, records=records)


class BulkResultClient:
    def __init__(self, count):
        self.count = count

    async def iter_search(self, request):
        yield SearchPage(
            query=request.query,
            fields=request.fields,
            records=[AssetRecord(values={"host": f"https://asset-{index}.example.com"}) for index in range(self.count)],
        )


class ProfessionalTierClient:
    user_info = {"vip_level": 2}

    def __init__(self):
        self.request = None

    async def iter_search(self, request):
        self.request = request
        yield SearchPage(query=request.query, fields=request.fields, records=[])


class FieldPermissionRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "query": 'body="Example University"',
                    "fields": ["host", "body", "product"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "done", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class ReflectionFailureRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={"query": 'domain="example.com"', "fields": ["host"], "scan": {"recommended": False}},
                model="m",
                provider="p",
            )
        if task == "reflector":
            from providers.base import ProviderError

            raise ProviderError("invalid reflection JSON", code="model_structured_output_error")
        return ModelResult(text="summary", model="m", provider="p")


class PlannerStructuredFailureRouter(FakeRouter):
    def __init__(self, domains=None):
        super().__init__()
        self.domains = domains or []

    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            raise ProviderError("invalid planner JSON", code="model_structured_output_error")
        if task == "entity_resolver":
            return ModelResult(
                text="entities",
                structured={
                    "organization_names": ["Hx0工作室"],
                    "domains": self.domains,
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "done", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


class RoutedActionRouter(FakeRouter):
    def __init__(self, action):
        super().__init__()
        self.action = action

    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            if self.action == "host_query":
                structured = {
                    "action": "host_query",
                    "target": "8.8.8.8",
                    "queries": [],
                    "stats_fields": [],
                    "fields": [],
                    "scan": {"recommended": False},
                }
            else:
                structured = {
                    "action": "stat_query",
                    "target": None,
                    "queries": [
                        {"query": 'app="Redis"', "purpose": "统计 Redis 暴露", "strategy": "balanced"}
                    ],
                    "stats_fields": ["country", "port", "unsupported"],
                    "fields": [],
                    "scan": {"recommended": False},
                }
            return ModelResult(text="plan", structured=structured, model="m", provider="p")
        return ModelResult(text="# 分析\n\n已完成。", model="m", provider="p")


class RoutedActionClient:
    def __init__(self):
        self.host_calls = []
        self.stats_calls = []

    async def host_profile(self, target):
        self.host_calls.append(target)
        return {"host": target, "ip": target, "ports": [{"port": 53, "protocol": "udp", "products": []}]}

    async def stats(self, query, fields):
        self.stats_calls.append((query, fields))
        return {"size": 1234, "aggs": {"country": [{"name": "US", "count": 700}]}}


@pytest.mark.asyncio
async def test_agent_never_reflects_on_auth_failure():
    router = FakeRouter()
    run = await FofaAgent(AuthFailureClient(), router).run("find nginx")
    assert run.state is AgentState.FAILED
    assert run.error["code"] == "auth_failed"
    assert router.calls == ["planner"]


@pytest.mark.asyncio
async def test_agent_routes_single_host_profile_without_running_asset_search():
    client = RoutedActionClient()
    router = RoutedActionRouter("host_query")

    run = await FofaAgent(client, router).run("分析 8.8.8.8 的开放端口")

    assert run.state is AgentState.COMPLETED
    assert run.action.value == "host_query"
    assert run.target == "8.8.8.8"
    assert run.result_data["ports"][0]["port"] == 53
    assert client.host_calls == ["8.8.8.8"]
    assert router.calls == ["planner", "summarizer"]


@pytest.mark.asyncio
async def test_agent_routes_statistics_and_filters_dimensions():
    client = RoutedActionClient()
    router = RoutedActionRouter("stat_query")

    run = await FofaAgent(client, router).run("统计全球 Redis 的国家和端口分布")

    assert run.state is AgentState.COMPLETED
    assert run.action.value == "stat_query"
    assert run.result_count == 1234
    assert run.stats_fields == ["country", "port"]
    assert client.stats_calls == [('app="Redis"', ["country", "port"])]
    assert router.calls == ["planner", "summarizer"]


class PersonalMembershipClient(RoutedActionClient):
    user_info = {"vip_level": 11}

    def __init__(self):
        super().__init__()
        self.search_request = None

    async def iter_search(self, request):
        self.search_request = request
        yield SearchPage(query=request.query, fields=request.fields, records=[])


class RegisteredMembershipClient(RoutedActionClient):
    user_info = {"vip_level": 0}

    def __init__(self):
        super().__init__()
        self.search_request = None

    async def iter_search(self, request):
        self.search_request = request
        yield SearchPage(query=request.query, fields=request.fields, records=[])


class MembershipAwareStatsRouter(FakeRouter):
    async def generate(self, task, **kwargs):
        self.calls.append(task)
        if task == "planner":
            return ModelResult(
                text="plan",
                structured={
                    "action": "stat_query",
                    "target": None,
                    "queries": [{"query": 'app="Redis"', "purpose": "统计 Redis 暴露", "strategy": "balanced"}],
                    "stats_fields": ["country", "port"],
                    "fields": ["host"],
                    "scan": {"recommended": False},
                },
                model="m",
                provider="p",
            )
        if task == "reflector":
            return ModelResult(
                text="reflection",
                structured={"observation": "done", "coverage_sufficient": True, "queries": []},
                model="m",
                provider="p",
            )
        return ModelResult(text="summary", model="m", provider="p")


@pytest.mark.asyncio
async def test_personal_membership_downgrades_stats_to_search():
    client = PersonalMembershipClient()
    run = await FofaAgent(client, MembershipAwareStatsRouter()).run("统计全球 Redis 的国家和端口分布")

    assert run.action.value == "fofa_search"
    assert client.stats_calls == []
    assert client.search_request is not None
    assert client.search_request.query == 'app="Redis"'
    assert any("无统计聚合" in step.detail for step in run.steps)


@pytest.mark.asyncio
async def test_registered_membership_downgrades_host_to_search():
    client = RegisteredMembershipClient()
    run = await FofaAgent(client, RoutedActionRouter("host_query")).run("分析 8.8.8.8 的开放端口")

    assert run.action.value == "fofa_search"
    assert client.host_calls == []
    assert client.search_request is not None
    assert client.search_request.query == 'ip="8.8.8.8"'
    assert any("无主机聚合" in step.detail for step in run.steps)


@pytest.mark.asyncio
async def test_agent_builds_bounded_scan_plan_when_user_explicitly_requests_it():
    router = ScanRouter()
    progress = []
    run = await FofaAgent(SuccessfulClient(), router).run(
        "收集哈佛大学子域名网站，并扫描一下",
        on_progress=lambda current, step: progress.append((current.state, step.detail)),
    )
    assert run.state is AgentState.COMPLETED
    assert run.assets[0]["host"] == "https://www.harvard.edu"
    assert run.assets[0]["ip"] == "1.1.1.1"
    assert run.assets[0]["port"] == 443
    assert run.assets[0]["title"] == "Harvard University"
    assert {"host", "protocol", "ip", "port", "title", "domain"} <= set(run.fields)
    assert any(state is AgentState.EXECUTE and "累计去重资产 1 条" in detail for state, detail in progress)
    assert progress[-1] == (AgentState.COMPLETED, "侦察任务已完成")
    assert run.scan_requested_by_user is True
    assert run.scan_recommended is True
    assert run.scan_template_ids == default_nuclei_template_ids()
    assert run.scan_severities == ["medium", "high", "info", "low"]
    assert run.scan_targets == ["https://www.harvard.edu"]
    assert run.scan_ready is True


@pytest.mark.asyncio
async def test_agent_respects_an_exact_template_id_named_by_the_user():
    run = await FofaAgent(SuccessfulClient(), ScanRouter()).run(
        "收集哈佛大学子域名网站，并只用 cors-misconfig 扫描"
    )

    assert run.scan_template_ids == ["cors-misconfig"]
    assert run.scan_severities == ["medium", "high", "info"]


@pytest.mark.asyncio
async def test_agent_page_observer_can_annotate_alive_status_before_assets_are_stored():
    seen = []

    async def on_page(run, page, _page_number):
        seen.append(len(run.assets))
        for record in page.records:
            record.values["alive_status"] = 200

    run = await FofaAgent(SuccessfulClient(), ScanRouter()).run(
        "收集哈佛大学子域名网站，并扫描一下",
        on_page=on_page,
    )
    assert seen == [0]
    assert run.assets[0]["alive_status"] == 200


def test_agent_renderer_shows_assets_before_ai_summary(monkeypatch):
    from core.agent import AgentRun

    run = AgentRun(
        intent="find asset",
        state=AgentState.COMPLETED,
        query='domain="example.com"',
        fields=["host", "ip", "port", "title"],
        result_count=1,
        assets=[{"host": "https://example.com", "ip": "203.0.113.10", "port": 443, "title": "Example"}],
        summary="AI summary",
    )
    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=140, color_system=None))

    cli_ui.render_agent(run)

    output = stream.getvalue()
    assert "查询到的资产" in output
    assert "https://example.com" in output
    assert output.index("查询到的资产") < output.index("AI 总结")


def test_agent_renderer_parses_markdown_summary(monkeypatch):
    from core.agent import AgentRun

    run = AgentRun(
        intent="summarize",
        state=AgentState.COMPLETED,
        summary=(
            "## 查询概况\n\n"
            "- **返回总数**：2 条\n"
            "- 查询：`domain=example.com`\n\n"
            "| 类型 | 数量 |\n"
            "|---|---:|\n"
            "| 网站 | 2 |"
        ),
    )
    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=100, color_system=None))

    cli_ui.render_agent(run)

    output = stream.getvalue()
    assert "查询概况" in output
    assert "返回总数" in output
    assert "domain=example.com" in output
    assert "网站" in output
    assert "## 查询概况" not in output
    assert "**返回总数**" not in output
    assert "|---|---:|" not in output


def test_summary_markdown_normalizes_numbered_walls_into_headings():
    from utils.cli_ui import normalize_summary_markdown

    text = normalize_summary_markdown(
        "1. 结论\n共发现 59 条。\n2. 高置信资产\n官网 www.chinaccs.cn、szyc、hos、phone、mt-shxy 挤在一行。\n"
    )
    assert text.startswith("## 结论\n")
    assert "\n## 高置信资产\n" in text
    assert "1. 结论" not in text


def test_summary_panel_expands_to_the_same_console_width_as_scan_decision(monkeypatch):
    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=160, color_system=None))
    cli_ui.console.print(
        cli_ui._summary_panel("## 结论\n高置信约 40 条。\n\n## 高置信资产\n- **官网**：`www.chinaccs.cn`\n")
    )
    output = stream.getvalue()
    assert "AI 总结" in output
    assert "结论" in output
    assert "www.chinaccs.cn" in output
    boxed_lines = [line for line in output.splitlines() if line.strip()]
    assert boxed_lines
    assert max(len(line) for line in boxed_lines) == 160


def test_search_summary_is_an_asset_briefing_not_a_methods_report():
    from core.agent import AgentRun

    run = AgentRun(
        intent="收集中国通服的全网资产",
        result_count=4,
        assets=[
            {"host": "https://www.chinaccs.cn", "domain": "chinaccs.cn", "title": "中国通信服务", "port": "443"},
            {"host": "imap.chinaccs.cn:993", "domain": "chinaccs.cn", "title": "", "port": "993", "protocol": "imaps"},
            {"host": "https://www.swjtu.edu.cn", "domain": "swjtu.edu.cn", "title": "西南交通大学", "port": "443"},
            {"host": "https://gamble.example", "domain": "example", "title": "世界杯开户平台", "port": "80"},
        ],
        asset_confidence=["balanced", "balanced", "recall", "recall"],
        evidence_counts={"balanced": 2, "recall": 2},
        queries=[
            AgentQuery(query='org="x"', purpose="组织字段", strategy="balanced", available_count=47, result_count=47),
            AgentQuery(query='body="x"', purpose="正文召回", strategy="recall", available_count=4383, result_count=200),
        ],
    )
    stats = _asset_briefing_stats(run)
    assert stats["top_domains"][0] == {"name": "chinaccs.cn", "count": 2}
    assert stats["truncated_queries"] == [{"purpose": "正文召回", "available": 4383, "pulled": 200}]
    prompt = _search_summary_prompt(run, run.intent)
    assert "chinaccs.cn" in prompt
    assert "西南交通大学" in prompt
    assert "世界杯开户平台" in prompt
    assert "do not recount how many FOFA queries ran" in SEARCH_SUMMARY_SYSTEM
    assert "## 结论" in SEARCH_SUMMARY_SYSTEM
    assert "at most 3 hosts per bullet" in SEARCH_SUMMARY_SYSTEM
    assert "Do not write chain-of-thought" in SEARCH_SUMMARY_SYSTEM
    local = _local_search_summary(run)
    assert local.startswith("## 结论")
    assert "`chinaccs.cn` ×2" in local
    assert "世界杯开户平台" in local
    assert "正文召回 200/4383" in local
    assert "## 风险与暴露面" in local
    assert "## 覆盖缺口" in local
    assert "## 处置优先级" in local


def test_asset_briefing_quality_gate_rejects_placeholder_and_accepts_evidence_sections():
    rich_summary = """## 结论
共识别 12 条资产，其中 8 条具有域名与证书交叉证据，主要风险信号集中在非标准管理端口。

## 高置信资产
- **官网簇**：`www.example.com`（`192.0.2.10`），官网内容与证书主体一致。
- **业务簇**：`api.example.com`（`192.0.2.11`），与官网使用同一证书组织。

## 风险与暴露面
- **管理端口**：`192.0.2.12:8443` 可达，需要确认是否应对公网开放。
- **服务版本**：样本返回 Nginx，但仅代表指纹，不构成漏洞结论。

## 证据边界与噪声
- **名称候选**：2 条仅命中页面正文，可能来自第三方引用。
- **共享设施**：1 个 IP 承载多个无关域名，不能据此确认归属。

## 覆盖缺口
- **分页余量**：召回查询仍有未拉取记录，当前清单不代表穷尽结果。

## 处置优先级
1. 核验官网与 API 的证书、备案和跳转关系。
2. 复核 `8443` 端口用途及访问控制。
3. 排除正文候选中的第三方引用。
"""

    assert _asset_briefing_has_sufficient_quality("summary") is False
    assert _asset_briefing_has_sufficient_quality(rich_summary) is True


def test_markdown_level_one_headings_are_left_aligned():
    stream = StringIO()
    markdown_console = Console(file=stream, width=80, color_system=None)

    markdown_console.print(cli_ui.LeftAlignedMarkdown("# 查询与统计范围\n\n正文"))

    assert stream.getvalue().splitlines()[0].startswith("查询与统计范围")


@pytest.mark.asyncio
async def test_agent_reflects_on_zero_results_and_tries_a_complementary_query():
    router = ZeroRepairRouter()
    client = ZeroThenResultClient()
    run = await FofaAgent(client, router).run("查找 example.invalid")
    assert run.state is AgentState.COMPLETED
    assert run.result_count == 1
    assert client.calls == 2
    assert router.calls == ["planner", "reflector", "summarizer"]


@pytest.mark.asyncio
async def test_agent_cancels_scan_recommendation_when_no_assets_exist():
    router = ScanRouter()

    run = await FofaAgent(ZeroThenResultClient(), router).run("查找并扫描不存在的测试资产")

    assert run.result_count == 0
    assert run.scan_recommended is False
    assert run.scan_template_ids == []
    assert run.scan_targets == []
    assert "未发现" in run.scan_reason


@pytest.mark.asyncio
async def test_agent_plans_reflects_and_deduplicates_multiple_query_dimensions():
    router = MultiQueryRouter()

    run = await FofaAgent(MultiQueryClient(), router).run("尽可能从多维度发现 Example University 资产")

    assert run.state is AgentState.COMPLETED
    assert [item.query for item in run.queries] == [
        '(domain="example.edu" || cert="example.edu") && country="US"',
        '(org="Example University" || cert.subject.org="Example University") && country="US"',
        '(body="Example University" || title="Example University") && country="US"',
    ]
    assert [item.source for item in run.queries] == ["planner", "planner", "reflection_1"]
    assert [item.new_assets for item in run.queries] == [2, 1, 1]
    assert run.result_count == 4
    assert run.asset_confidence == ["precision", "precision", "balanced", "recall"]
    assert run.evidence_counts == {"precision": 2, "balanced": 1, "recall": 1}
    assert {asset["host"] for asset in run.assets} == {
        "https://a.example.edu",
        "https://shared.example.edu",
        "https://b.example.edu",
        "https://c.example.edu",
    }
    assert router.calls == ["planner", "reflector", "summarizer"]


@pytest.mark.asyncio
async def test_unused_query_budget_flows_to_later_strategies():
    client = BudgetRecordingClient()

    run = await FofaAgent(client, DynamicBudgetRouter()).run("find Example assets", max_records=500)

    assert run.state is AgentState.COMPLETED
    assert client.budgets == [167, 250, 500]


@pytest.mark.asyncio
async def test_organization_domain_hypotheses_are_queried_before_broad_recall_and_labeled():
    run = await FofaAgent(OrganizationHypothesisClient(), OrganizationHypothesisRouter()).run(
        "帮我收集安徽省邮电职业技术学院的全网资产"
    )

    assert run.state is AgentState.COMPLETED
    assert [item.source for item in run.queries] == ["entity_resolution", "planner"]
    assert 'domain="ahptc.cn"' in run.queries[0].query
    assert run.queries[0].available_count == 4
    assert run.queries[1].available_count == 670
    assert run.queries[1].result_count == 200
    assert run.assets[0]["host"] == "https://www.ahptc.cn"
    assert run.asset_confidence[:4] == ["hypothesis"] * 4
    assert run.evidence_counts == {"hypothesis": 4, "recall": 200}


@pytest.mark.asyncio
async def test_late_precision_assets_replace_early_lower_confidence_preview_rows():
    run = await FofaAgent(LatePrecisionClient(), LatePrecisionRouter()).run("find Example assets")

    assert run.result_count == 501
    assert len(run.assets) == 500
    assert run.assets_truncated is True
    assert run.assets[0] == {"host": "https://official.example"}
    assert run.asset_confidence[0] == "precision"
    assert run.evidence_counts == {"precision": 1, "balanced": 500}


@pytest.mark.asyncio
async def test_agent_uses_two_correction_rounds_instead_of_stopping_after_first_zero_result():
    router = TwoRoundReflectionRouter()

    run = await FofaAgent(TwoRoundReflectionClient(), router).run("查找示例科技有限公司的公开资产")

    assert run.state is AgentState.COMPLETED
    assert run.reflection_rounds == 2
    assert len(run.reflection_notes) == 2
    assert [item.strategy for item in run.queries] == ["precision", "balanced", "recall"]
    assert [item.source for item in run.queries] == ["planner", "reflection_1", "reflection_2"]
    assert run.result_count == 1
    assert run.assets == [{"host": "https://example.cn", "title": "示例科技"}]


@pytest.mark.parametrize(
    ("intent", "expected_term"),
    [
        ("帮我查询Hx0工作室的全网资产并扫描", "Hx0工作室"),
        ("收集美国哈佛大学的子域名网站，并扫描一下", "美国哈佛大学"),
        ("收集哈佛大学子域名网站，并扫描一下", "哈佛大学"),
        ("查找安徽省邮电职业技术学院的全网资产", "安徽省邮电职业技术学院"),
        ('find "Example Corp" assets', "Example Corp"),
        ("find Harvard University subdomain websites and scan them", "Harvard University"),
    ],
)
def test_fallback_plan_extracts_organization_core_name(intent, expected_term):
    plan = _deterministic_fallback_plan(intent)
    query = plan["queries"][0]["query"]
    assert expected_term in query
    assert "子域名网站" not in query
    assert plan["queries"][0]["strategy"] == "recall"


def test_website_inventory_surfaces_hx0_sites_with_explicit_evidence_status():
    run = AgentRun(
        intent="收集全网 Hx0 工作室的网站",
        organization_names=["Hx0工作室", "Hx0 Studio"],
        domain_hypotheses=["hx0.com.cn", "hx0studio.com"],
        assets=[
            {
                "host": "https://www.hx0.com.cn",
                "domain": "hx0.com.cn",
                "title": "HxO - 构建未来的数字生态",
                "icp": "京ICP备12345678号",
                "cert.subject.cn": "hx0.com.cn",
            },
            {
                "host": "https://hx0studio.com",
                "domain": "hx0studio.com",
                "title": "Hx0 Studio - 创新工作室",
                "icp": "皖ICP备20260133",
                "cert.subject.cn": "hx0studio.com",
            },
            {
                "host": "http://www.hx0.store",
                "domain": "hx0.store",
                "title": "Hx0 Store｜安全工具产品矩阵",
                "icp": "皖ICP备20260133",
            },
            {
                "host": "https://unrelated.example",
                "domain": "example",
                "title": "unrelated",
            },
        ],
        asset_confidence=["balanced", "hypothesis", "recall", "balanced"],
    )

    candidates = _derive_website_candidates(run)

    assert [item.domain for item in candidates] == ["hx0.com.cn", "hx0.store", "hx0studio.com"]
    assert all(item.status == "corroborated" for item in candidates)
    assert all(item.confidence == "high" for item in candidates)
    assert "name_in_title" in candidates[1].evidence
    assert "icp_observed" in candidates[1].evidence


def test_same_name_certificate_without_icp_is_not_promoted_to_corrobated():
    run = AgentRun(
        intent="收集全网 Hx0 工作室的网站",
        organization_names=["Hx0工作室"],
        assets=[
            {
                "host": "https://hx0.de",
                "domain": "hx0.de",
                "title": "Welcome to hx0.de!",
                "cert.subject.cn": "hx0.de",
            }
        ],
        asset_confidence=["recall"],
    )

    candidate = _derive_website_candidates(run)[0]

    assert candidate.domain == "hx0.de"
    assert candidate.status == "candidate"
    assert candidate.confidence == "low"


@pytest.mark.asyncio
async def test_invalid_planner_json_falls_back_to_safe_executable_search():
    router = PlannerStructuredFailureRouter()

    run = await FofaAgent(BulkResultClient(1), router).run("帮我查询Hx0工作室的全网资产并扫描")

    assert run.state is AgentState.COMPLETED
    assert run.error is None
    assert run.scan_requested_by_user is True
    assert run.query == '(org="Hx0工作室" || title="Hx0工作室" || body="Hx0工作室")'
    assert run.queries[0].strategy == "recall"
    assert any("已自动切换为保守查询方案" in step.detail for step in run.steps)
    assert router.calls == ["planner", "entity_resolver", "reflector", "summarizer"]


@pytest.mark.asyncio
async def test_fallback_name_query_runs_after_official_domain_hypotheses():
    router = PlannerStructuredFailureRouter(
        domains=[
            {"domain": "harvard.edu", "reason": "official"},
            {"domain": "hbs.edu", "reason": "business school"},
        ]
    )

    run = await FofaAgent(BulkResultClient(1), router).run("收集美国哈佛大学的子域名网站，并扫描一下")

    assert [item.source for item in run.queries] == ["entity_resolution", "planner"]
    assert 'domain="harvard.edu"' in run.queries[0].query
    assert run.queries[1].query == '(org="美国哈佛大学" || title="美国哈佛大学" || body="美国哈佛大学")'
    assert run.queries[1].strategy == "recall"
    assert run.query == run.queries[0].query


@pytest.mark.asyncio
async def test_agent_keeps_all_assets_when_result_count_is_at_most_500():
    run = await FofaAgent(BulkResultClient(500), FakeRouter()).run("find example assets")

    assert run.result_count == 500
    assert len(run.assets) == 500
    assert run.assets_truncated is False


@pytest.mark.asyncio
async def test_agent_caps_asset_preview_only_above_500():
    run = await FofaAgent(BulkResultClient(501), FakeRouter()).run("find example assets")

    assert run.result_count == 501
    assert len(run.assets) == 500
    assert run.assets_truncated is True


@pytest.mark.asyncio
async def test_query_syntax_fields_are_independent_from_membership_limited_return_fields():
    client = ProfessionalTierClient()

    run = await FofaAgent(client, FieldPermissionRouter()).run("find Example University content")

    assert run.query == 'body="Example University"'
    assert client.request.query == 'body="Example University"'
    assert "body" not in run.fields
    assert "host" in run.fields
    assert "product" in run.fields
    assert client.request.fields == run.fields


@pytest.mark.asyncio
async def test_empty_summarizer_text_falls_back_to_local_briefing():
    class EmptySummaryRouter(FakeRouter):
        async def generate(self, task, **kwargs):
            result = await super().generate(task, **kwargs)
            if task == "summarizer":
                return ModelResult(text="  ", model="m", provider="p", output_tokens=4096)
            return result

    run = await FofaAgent(SuccessfulClient(), EmptySummaryRouter()).run("查找 harvard.edu")
    assert run.state is AgentState.COMPLETED
    assert "## 结论" in run.summary
    assert "去重资产 1 条" in run.summary
    assert "## 风险与暴露面" in run.summary
    assert "## 处置优先级" in run.summary


@pytest.mark.asyncio
async def test_optional_reflection_failure_preserves_successful_asset_results():
    router = ReflectionFailureRouter()

    run = await FofaAgent(BulkResultClient(1), router).run("find example.com")

    assert run.state is AgentState.COMPLETED
    assert run.error is None
    assert run.result_count == 1
    assert run.summary != "summary"
    assert "## 风险与暴露面" in run.summary
    assert "## 处置优先级" in run.summary
    assert "反思不可用" in run.reflection_notes[-1]
    assert router.calls == ["planner", "reflector", "summarizer"]


@pytest.mark.asyncio
async def test_agent_unconfigured_model_renders_where_to_fix_without_scan_panel(monkeypatch):
    run = await FofaAgent(SuccessfulClient(), ProviderRouter(ProviderRegistry(Config()))).run("查找并扫描资产")
    assert run.state is AgentState.FAILED
    assert run.error["code"] == "model_provider_not_configured"
    assert "fofamap init" in run.error["hint"]

    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=140, color_system=None))
    cli_ui.render_agent(run)
    output = stream.getvalue()
    assert "fofamap init" in output
    assert "配置文件位置" in output
    assert "扫描决策" not in output
