from __future__ import annotations

import os
import sys
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

import fofamap
from core.models import AssetRecord, SearchPage
from core.scans import default_nuclei_template_ids
from utils import cli_ui
from utils.cli_ui import build_asset_table


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["-ai", "收集资产", "--check-alive"], {"ai_query": "收集资产", "check_alive": True}),
        (["-q", 'app="ThinkPHP" && country="CN"'], {"query": 'app="ThinkPHP" && country="CN"'}),
        (["-hq", "8.8.8.8"], {"host_query": "8.8.8.8"}),
        (["-cq", 'app="redis"', "-f", "country,org"], {"count_query": 'app="redis"', "query_fields": "country,org"}),
        (["-ico", "https://www.bing.com"], {"icon_query": "https://www.bing.com"}),
        (["-bq", "targets.txt"], {"bat_query": "targets.txt"}),
        (
            ["-q", 'domain="baidu.com"', "-i", "200", "-k", "文心,旅游"],
            {"query": 'domain="baidu.com"', "include": "200", "key_word": "文心,旅游"},
        ),
        (["-q", 'app="nginx"', "--export-format", "csv"], {"export_format": "csv"}),
        (["-q", 'app="nginx"', "--outdir", "results"], {"outdir": "results"}),
        (["-q", 'app="nginx"', "-o", "result.xlsx"], {"outfile": "result.xlsx"}),
        (
            ["-q", 'app="nginx"', "-n", "--nuclei-id", "all", "--severity", "all"],
            {"nuclei": True, "nuclei_ids": ("all",), "severity": "all"},
        ),
        (["-q", 'app=\"nginx\" && country=\"CN\"'], {"query": 'app=\"nginx\" && country=\"CN\"'}),
        (["--rule", "ThinkPHP"], {"query": 'app="ThinkPHP"'}),
    ],
)
def test_v2_readme_command_matrix_routes_without_semantic_loss(monkeypatch, arguments, expected):
    captured = {}

    async def fake_main_async(**options):
        captured.update(options)
        return 0

    monkeypatch.setattr(fofamap, "_main_async", fake_main_async)
    result = CliRunner().invoke(fofamap.main, [*arguments, "--no-save"])
    assert result.exit_code == 0, result.output
    for name, value in expected.items():
        assert captured[name] == value


def test_default_asset_table_displays_all_one_hundred_records():
    page = SearchPage(
        query='app="nginx"',
        fields=["host", "ip", "port", "status_code"],
        records=[
            AssetRecord(
                values={
                    "host": f"https://asset-{index}.example.com",
                    "ip": f"192.0.2.{index % 255}",
                    "port": 443,
                    "status_code": 200,
                }
            )
            for index in range(100)
        ],
    )
    table = build_asset_table(page, terminal_width=160)
    assert len(table.rows) == 100


def test_rendered_hundredth_asset_is_visible_without_truncation_notice(monkeypatch):
    stream = StringIO()
    test_console = Console(file=stream, width=160, color_system=None)
    monkeypatch.setattr(cli_ui, "console", test_console)
    page = SearchPage(
        query='app="nginx"',
        fields=["host", "status_code"],
        records=[
            AssetRecord(values={"host": f"https://asset-{index:03}.example.com", "status_code": 200})
            for index in range(1, 101)
        ],
    )
    cli_ui.render_search_page(page, 1)
    output = stream.getvalue()
    assert "asset-100.example.com" in output
    assert "仅展示前" not in output


@pytest.mark.asyncio
async def test_status_then_keyword_filter_uses_fofa_status_without_network_probe(monkeypatch):
    page = SearchPage(
        query='domain="example.com"',
        fields=["host", "status_code", "title"],
        records=[
            AssetRecord(values={"host": "https://docs.example.com", "status_code": 200, "title": "文档"}),
            AssetRecord(values={"host": "https://travel.example.com", "status_code": 200, "title": "旅游"}),
            AssetRecord(values={"host": "https://old.example.com", "status_code": 404, "title": "旅游"}),
        ],
    )

    async def pages():
        yield page

    async def forbidden_probe(*_args, **_kwargs):
        raise AssertionError("FOFA status_code 可用时不应额外访问目标")

    monkeypatch.setattr(fofamap.FastChecker, "check_alive", forbidden_probe)
    counters = {"pages": 0, "records": 0, "targets": []}
    options = {
        "include": "200",
        "key_word": "旅游",
        "check_alive": False,
        "output_format": "json",
    }
    result = [item async for item in fofamap._decorate_pages(pages(), options=options, counters=counters)]
    assert [record.values["host"] for record in result[0].records] == ["https://travel.example.com"]
    assert counters == {"pages": 1, "records": 1, "targets": ["https://travel.example.com"]}


@pytest.mark.asyncio
async def test_agent_results_honor_check_alive_and_include_filters(monkeypatch):
    from core.agent import AgentRun, AgentState

    async def fake_probe(targets, timeout=5):
        return {
            "https://live.example.com": 200,
            "https://gone.example.com": "Timeout",
            "https://forbid.example.com": 403,
        }

    monkeypatch.setattr(fofamap.FastChecker, "check_alive", fake_probe)
    run = AgentRun(
        intent="收集示例资产并扫描",
        state=AgentState.COMPLETED,
        fields=["host", "title"],
        result_count=3,
        assets=[
            {"host": "https://live.example.com", "title": "官网"},
            {"host": "https://gone.example.com", "title": "旧站"},
            {"host": "https://forbid.example.com", "title": "后台"},
        ],
        asset_confidence=["precision", "balanced", "hypothesis"],
        scan_targets=[
            "https://live.example.com",
            "https://gone.example.com",
            "https://forbid.example.com",
            "https://extra-unpreviewed.example.com",
        ],
        scan_requested_by_user=True,
        scan_recommended=True,
        scan_template_ids=["http-missing-security-headers"],
    )
    await fofamap._apply_agent_result_filters(
        run,
        {"check_alive": True, "include": "200", "key_word": None},
        machine=True,
    )
    assert [asset["host"] for asset in run.assets] == ["https://live.example.com"]
    assert run.assets[0]["alive_status"] == 200
    assert run.fields == ["host", "alive_status", "title"]
    assert run.result_count == 1
    assert run.asset_confidence == ["precision"]
    assert run.scan_targets == ["https://live.example.com"]
    assert "存活检测与本地过滤完成" in run.steps[-1].detail


@pytest.mark.asyncio
async def test_empty_alive_status_placeholder_is_probed_again(monkeypatch):
    from core.agent import AgentRun, AgentState

    async def fake_probe(targets, timeout=5):
        assert targets == ["https://later.example.com"]
        return {"https://later.example.com": 200}

    monkeypatch.setattr(fofamap.FastChecker, "check_alive", fake_probe)
    run = AgentRun(
        intent="监测存活性",
        state=AgentState.COMPLETED,
        fields=["host", "alive_status", "title"],
        result_count=2,
        assets=[
            {"host": "https://first.example.com", "alive_status": 412, "title": "官网"},
            {"host": "https://later.example.com", "alive_status": "", "title": "招标"},
        ],
        asset_confidence=["balanced", "recall"],
    )
    await fofamap._apply_agent_result_filters(run, {"check_alive": True, "include": None, "key_word": None}, machine=True)
    assert run.assets[0]["alive_status"] == 412
    assert run.assets[1]["alive_status"] == 200
    assert "存活检测与本地过滤完成" in run.steps[-1].detail


@pytest.mark.asyncio
async def test_scan_prompt_uses_ask_async_inside_running_event_loop(monkeypatch):
    import questionary

    class Answer:
        def ask(self):
            raise AssertionError("must not start a nested event loop")

        async def ask_async(self):
            return "report"

    monkeypatch.setattr(questionary, "select", lambda *_args, **_kwargs: Answer())
    assert await fofamap._maybe_await(fofamap._prompt_scan_action()) == "report"


def test_alive_status_column_is_inserted_beside_protocol():
    from utils.helpers import insert_alive_status_field

    assert insert_alive_status_field(["host", "ip", "port", "protocol", "title", "domain"]) == [
        "host",
        "ip",
        "port",
        "protocol",
        "alive_status",
        "title",
        "domain",
    ]


def test_v2_batch_lines_normalize_ip_domain_and_keep_fofa_syntax(tmp_path: Path):
    source = tmp_path / "targets.txt"
    source.write_text(
        "# 2.0 README examples\n8.8.8.8\nbaidu.com\nicp=\"京ICP备00000000号\"\n",
        encoding="utf-8",
    )
    assert fofamap._load_batch(str(source)) == [
        'ip="8.8.8.8"',
        'domain="baidu.com"',
        'icp="京ICP备00000000号"',
    ]


def test_batch_ip_and_domain_clues_are_combined_without_rewriting_custom_queries():
    queries = [
        'ip="1.1.1.1"',
        'domain="example.com"',
        'ip="8.8.8.8"',
        'domain="example.org"',
        'icp="京ICP备00000000号"',
        'ip="1.1.1.1"',
    ]

    assert fofamap._combine_batch_queries(queries, group_size=100) == [
        '(ip="1.1.1.1" || ip="8.8.8.8")',
        '(domain="example.com" || domain="example.org")',
        'icp="京ICP备00000000号"',
    ]


def test_batch_query_combination_respects_group_and_query_length_limits():
    queries = [f'domain="asset-{index}.example.com"' for index in range(5)]

    grouped = fofamap._combine_batch_queries(queries, group_size=2, max_query_length=80)

    assert len(grouped) == 3
    assert all(len(query) <= 80 for query in grouped)


def test_explicit_export_path_infers_format_and_suffix():
    path, format_name = fofamap._query_export_path(
        {"outfile": "reports/result.csv", "export_format": None},
        'app="nginx"',
        1,
        1,
    )
    assert path == Path("reports/result.csv")
    assert format_name == "csv"


@pytest.mark.parametrize("argument", ["init", "-init", "--init"])
def test_init_command_starts_safe_interactive_wizard_without_nested_event_loop(monkeypatch, argument):
    called = {"count": 0}

    def fake_init():
        called["count"] += 1
        return 0

    def forbidden_asyncio_run(*_args, **_kwargs):
        raise AssertionError("interactive init must run before asyncio.run")

    monkeypatch.setattr(fofamap, "_interactive_init", fake_init)
    monkeypatch.setattr(fofamap.asyncio, "run", forbidden_asyncio_run)
    result = CliRunner().invoke(fofamap.main, [argument])
    assert result.exit_code == 0
    assert called["count"] == 1


def test_public_version_is_2_0_1():
    result = CliRunner().invoke(fofamap.main, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == "FofaMap, version 2.0.1"
    assert "3.0" not in result.output


def test_setup_config_rejects_secret_values(tmp_path: Path):
    with pytest.raises(ValueError, match="不得包含密钥"):
        fofamap._save_setup_config(tmp_path / "settings.yaml", {"fofa": {"api_key": "must-not-be-written"}})
    assert not (tmp_path / "settings.yaml").exists()


def test_setup_config_allows_explicit_secret_opt_in_and_sets_private_permissions(tmp_path: Path):
    target = tmp_path / "settings.yaml"
    fofamap._save_setup_config(
        target,
        {
            "fofa": {"email": "user@example.test", "api_key": "fofa-test-key"},
            "providers": {"deepseek": {"api_key": "model-test-key"}},
        },
        allow_secrets=True,
    )
    content = target.read_text(encoding="utf-8")
    assert "fofa-test-key" in content
    assert "model-test-key" in content
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_init_falls_back_to_confirmed_yaml_when_keyring_is_unavailable(tmp_path: Path, monkeypatch):
    import questionary
    import yaml

    class Answer:
        def __init__(self, value):
            self.value = value

        def ask(self):
            return self.value

    text_answers = iter(
        [
            "user@example.test",
            "https://api.deepseek.com/v1",
            "deepseek-test-model",
            "host,ip,port,status_code",
            "100",
            "2",
            "5",
            "10",
            "results",
        ]
    )
    password_answers = iter(["fofa-test-key", "deepseek-test-key"])
    select_answers = iter(["deepseek", "xlsx"])
    monkeypatch.setattr(questionary, "text", lambda *_args, **_kwargs: Answer(next(text_answers)))
    monkeypatch.setattr(questionary, "password", lambda *_args, **_kwargs: Answer(next(password_answers)))
    monkeypatch.setattr(questionary, "select", lambda *_args, **_kwargs: Answer(next(select_answers)))
    monkeypatch.setattr(questionary, "confirm", lambda *_args, **_kwargs: Answer(True))
    monkeypatch.setattr(fofamap, "_store_keyring", lambda *_args, **_kwargs: False)
    target = tmp_path / "settings.yaml"
    monkeypatch.setattr(fofamap, "config_write_path", lambda: target)

    assert fofamap._interactive_init() == 0
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert data["fofa"]["api_key"] == "fofa-test-key"
    assert data["providers"]["deepseek"]["api_key"] == "deepseek-test-key"
    assert data["providers"]["deepseek"]["structured_output_mode"] == "prompt"
    assert data["providers"]["deepseek"]["max_output_tokens"] == 32768
    assert data["providers"]["deepseek"]["timeout"] == 120
    assert data["search"]["full"] is True
    assert data["fast_check"]["check_alive"] is True
    assert data["fast_check"]["timeout"] == 5
    assert data["system"]["sheet_merge"] is True
    assert data["system"]["concurrency"] == 10
    assert data["system"]["output_dir"] == "results"
    assert data["security"]["local_yaml_secrets_confirmed"] is True
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_windows_local_yaml_notice_does_not_claim_posix_permissions(monkeypatch):
    monkeypatch.setattr(fofamap.os, "name", "nt")
    notice = fofamap._local_yaml_security_notice()
    assert "Windows" in notice
    assert "无法用 POSIX 0600 表示" in notice
    assert "系统钥匙串或环境变量" in notice


def test_keyring_diagnostic_explains_missing_package(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "keyring":
            raise ModuleNotFoundError("No module named 'keyring'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    reason = fofamap._keyring_unavailable_reason()
    assert "未安装 keyring" in reason
    assert sys.executable in reason


@pytest.mark.asyncio
async def test_scan_plan_is_never_executed_when_user_declines(monkeypatch):
    monkeypatch.setattr(fofamap, "_prompt_scan_action", lambda: "cancel")
    status, artifact, error = await fofamap._approve_and_execute_scan(
        targets=["https://example.com"],
        template_ids=["http-missing-security-headers"],
        severities=["medium"],
        reason="explicit test",
        options={"outdir": None},
        machine=False,
        directory_name="declined",
    )
    assert (status, artifact, error) == ("declined", None, None)


@pytest.mark.asyncio
async def test_explicit_all_reaches_typed_approval_and_scanner_without_filters(tmp_path, monkeypatch):
    captured = {}

    class FakeStore:
        def __init__(self, *_args, **_kwargs):
            pass

        def update(self, *_args, **_kwargs):
            return None

    class FakeApproval:
        def __init__(self, *_args, **_kwargs):
            pass

        def create(self, request):
            captured["approved_request"] = request
            return {"id": "plan-all"}, "token"

        def consume(self, *_args):
            return {"id": "plan-all"}

    class FakeScanner:
        async def run_plan(self, request, _output, **_kwargs):
            captured["executed_request"] = request
            return type("Result", (), {"artifact": tmp_path / "nuclei.jsonl"})()

    monkeypatch.setattr(fofamap, "_prompt_scan_action", lambda: "execute")
    monkeypatch.setattr(fofamap, "render_scan_approval", lambda **kwargs: captured.update({"rendered": kwargs}))
    monkeypatch.setattr(fofamap, "render_nuclei_results", lambda _result: None)
    monkeypatch.setattr("service.store.JobStore", FakeStore)
    monkeypatch.setattr("core.scans.ScanApproval", FakeApproval)
    monkeypatch.setattr("core.scanner.NucleiScanner", FakeScanner)

    status, _artifact, error = await fofamap._approve_and_execute_scan(
        targets=["https://example.com"],
        template_ids=["all"],
        severities=["all"],
        reason="用户明确选择全部范围",
        options={"outdir": str(tmp_path)},
        machine=False,
        directory_name=str(tmp_path / "all-scan"),
    )

    assert status == "completed"
    assert error is None
    assert captured["rendered"]["all_templates"] is True
    assert captured["rendered"]["all_severities"] is True
    assert captured["approved_request"].all_templates is True
    assert captured["approved_request"].all_severities is True
    assert captured["executed_request"].template_ids == []
    assert captured["executed_request"].severities == []


def test_all_scope_approval_is_visibly_labeled_and_warned(monkeypatch):
    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=120, color_system=None))

    cli_ui.render_scan_approval(
        targets=["https://example.com"],
        template_ids=[],
        severities=[],
        reason="用户明确选择全部范围",
        all_templates=True,
        all_severities=True,
    )

    output = stream.getvalue()
    assert "ALL（全部已安装模板）" in output
    assert "ALL（全部严重级别）" in output
    assert "范围警告" in output


@pytest.mark.asyncio
async def test_classic_nuclei_flag_creates_approval_flow_after_search(monkeypatch):
    captured = {}

    class FakeClient:
        async def iter_search(self, request):
            yield SearchPage(
                query=request.query,
                fields=["host", "status_code"],
                records=[AssetRecord(values={"host": "https://example.com", "status_code": 200})],
            )

    async def fake_approval(**kwargs):
        captured.update(kwargs)
        return "declined", None, None

    monkeypatch.setattr(fofamap, "_approve_and_execute_scan", fake_approval)
    monkeypatch.setattr(fofamap, "render_search_page", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(fofamap, "render_search_summary", lambda **_kwargs: None)
    monkeypatch.setattr(fofamap, "render_query_overview", lambda *_args, **_kwargs: None)
    await fofamap._run_searches(
        FakeClient(),
        ['app="nginx"'],
        {
            "query_fields": "host,status_code",
            "pages": 1,
            "size": 100,
            "max_records": 100,
            "full": False,
            "dedupe_by": None,
            "save": False,
            "output_format": "table",
            "display_rows": 100,
            "check_alive": False,
            "key_word": None,
            "include": None,
            "nuclei": True,
            "nuclei_ids": (),
            "severity": None,
            "scan_max_targets": 200,
            "outdir": None,
            "batch": True,
        },
    )
    assert captured["targets"] == ["https://example.com"]
    assert captured["template_ids"] == default_nuclei_template_ids()
    assert captured["machine"] is False


@pytest.mark.asyncio
async def test_ai_cli_harvard_scan_intent_reaches_safe_scan_and_report_bridge(monkeypatch):
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def iter_search(self, request):
            yield SearchPage(
                query=request.query,
                fields=request.fields,
                records=[
                    AssetRecord(
                        values={
                            field: {
                                "host": "https://www.harvard.edu",
                                "protocol": "https",
                                "ip": "192.0.2.10",
                                "port": 443,
                                "title": "Harvard University",
                            }.get(field, "")
                            for field in request.fields
                        }
                    )
                ],
            )

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter:
        def __init__(self, _registry):
            self.events = []

        async def generate(self, task, **_kwargs):
            from providers.base import ModelResult

            if task == "planner":
                return ModelResult(
                    text="plan",
                    structured={
                        "query": 'domain="harvard.edu"',
                        "fields": ["host", "title"],
                        "scan": {
                            "recommended": True,
                            "reason": "用户明确请求授权扫描",
                            "template_ids": ["http-missing-security-headers"],
                            "severities": ["medium", "high"],
                        },
                    },
                    model="test-model",
                    provider="test-provider",
                )
            return ModelResult(text="共发现 1 个哈佛大学网站资产。", model="test-model", provider="test-provider")

    async def fake_account(_client, _machine):
        return {"username": "test"}

    async def fake_scan_report(run, options, machine):
        captured.update({"run": run, "options": options, "machine": machine})
        return "declined", None

    monkeypatch.setattr(fofamap, "FofaClient", FakeClient)
    monkeypatch.setattr(fofamap, "_account", fake_account)
    monkeypatch.setattr(fofamap, "render_agent", lambda _run: None)
    monkeypatch.setattr(fofamap, "_agent_scan_and_report", fake_scan_report)
    monkeypatch.setattr("providers.registry.ProviderRegistry", FakeRegistry)
    monkeypatch.setattr("providers.registry.ProviderRouter", FakeRouter)
    code = await fofamap._main_async(
        cmd=None,
        ai_query="我收集一下美国哈佛大学的子域名网站，并扫描一下",
        output_format="table",
        max_records=100,
        pages=1,
        nuclei=False,
        nuclei_ids=(),
        severity=None,
        scan_max_targets=200,
        report=True,
        report_file=None,
        outdir=None,
    )
    assert code == 0
    assert captured["run"].query == 'domain="harvard.edu"'
    assert captured["run"].scan_ready is True
    assert captured["run"].scan_targets == ["https://www.harvard.edu"]
    assert captured["machine"] is False


@pytest.mark.asyncio
async def test_failed_ai_provider_stops_before_scan_and_report(monkeypatch):
    from core.agent import AgentRun, AgentState

    called = {"rendered": False, "scan_report": False}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter:
        def __init__(self, _registry):
            pass

    class FailedAgent:
        def __init__(self, _client, _router):
            pass

        async def run(self, intent, **_kwargs):
            return AgentRun(
                intent=intent,
                state=AgentState.FAILED,
                error={
                    "code": "model_auth_failed",
                    "message": "API Key 无效",
                    "hint": "运行 `fofamap init` 重新配置。",
                },
            )

    async def fake_account(_client, _machine):
        return {"username": "test"}

    def fake_render(_run):
        called["rendered"] = True

    async def forbidden_scan_report(*_args, **_kwargs):
        called["scan_report"] = True
        raise AssertionError("failed provider must not enter scan/report flow")

    monkeypatch.setattr(fofamap, "FofaClient", FakeClient)
    monkeypatch.setattr(fofamap, "_account", fake_account)
    monkeypatch.setattr(fofamap, "render_agent", fake_render)
    monkeypatch.setattr(fofamap, "_agent_scan_and_report", forbidden_scan_report)
    monkeypatch.setattr("core.agent.FofaAgent", FailedAgent)
    monkeypatch.setattr("providers.registry.ProviderRegistry", FakeRegistry)
    monkeypatch.setattr("providers.registry.ProviderRouter", FakeRouter)
    code = await fofamap._main_async(
        cmd=None,
        ai_query="查找资产",
        output_format="table",
        max_records=100,
        pages=1,
        report=True,
    )
    assert code == 2
    assert called == {"rendered": True, "scan_report": False}


def test_wizard_cancel_on_pages_returns_none(monkeypatch):
    import questionary

    class Answer:
        def __init__(self, value):
            self.value = value

        def ask(self):
            return self.value

    texts = iter(['app="nginx"', None])
    monkeypatch.setattr(questionary, "select", lambda *_args, **_kwargs: Answer("search"))
    monkeypatch.setattr(questionary, "text", lambda *_args, **_kwargs: Answer(next(texts)))
    assert fofamap._wizard({}) is None


def test_search_window_honors_start_page_and_cli_page_count(monkeypatch):
    monkeypatch.setattr(fofamap.settings.search, "start_page", 3)
    monkeypatch.setattr(fofamap.settings.search, "end_page", 5)
    assert fofamap._search_window({}) == (3, 3)
    assert fofamap._search_window({"pages": 2}) == (3, 2)


def test_default_export_path_uses_per_run_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(fofamap.settings.system, "output_dir", str(tmp_path))
    path = fofamap._default_export_path('app="nginx"', "xlsx")
    assert path.parent.parent == tmp_path
    assert path.suffix == ".xlsx"
    assert path.parent.is_dir()


@pytest.mark.asyncio
async def test_scan_report_only_does_not_execute(monkeypatch):
    monkeypatch.setattr(fofamap, "_prompt_scan_action", lambda: "report")

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("report-only must not start Nuclei")

    monkeypatch.setattr("core.scanner.NucleiScanner.run_plan", forbidden)
    status, artifact, error = await fofamap._approve_and_execute_scan(
        targets=["https://example.com"],
        template_ids=["http-missing-security-headers"],
        severities=["medium"],
        reason="explicit test",
        options={"outdir": None},
        machine=False,
        directory_name="report-only",
    )
    assert (status, artifact, error) == ("report_only", None, None)


@pytest.mark.asyncio
async def test_batch_xlsx_merge_writes_one_workbook(tmp_path, monkeypatch):
    class FakeClient:
        async def iter_search(self, request):
            yield SearchPage(
                query=request.query,
                fields=["host"],
                records=[AssetRecord(values={"host": f"https://{request.query}.example"})],
            )

    monkeypatch.setattr(fofamap.settings.system, "sheet_merge", True)
    monkeypatch.setattr(fofamap.settings.system, "export_format", "xlsx")
    monkeypatch.setattr(fofamap, "render_search_page", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(fofamap, "render_search_summary", lambda **_kwargs: None)
    monkeypatch.setattr(fofamap, "render_query_overview", lambda *_args, **_kwargs: None)
    options = {
        "query_fields": "host",
        "pages": 1,
        "size": 100,
        "max_records": 100,
        "full": False,
        "dedupe_by": None,
        "save": True,
        "output_format": "table",
        "display_rows": 100,
        "check_alive": False,
        "key_word": None,
        "include": None,
        "export_format": "xlsx",
        "outdir": str(tmp_path),
        "outfile": None,
        "nuclei": False,
    }
    await fofamap._run_searches(FakeClient(), ['app="one"', 'app="two"'], options)
    merged = list(tmp_path.glob("**/batch_merge_*.xlsx"))
    assert len(merged) == 1
    assert merged[0].stat().st_size > 0


@pytest.mark.asyncio
async def test_agent_exports_assets_into_run_directory(tmp_path, monkeypatch):
    from core.agent import AgentRun, AgentState

    monkeypatch.setattr(fofamap, "_prompt_scan_action", lambda: "report")
    run = AgentRun(
        intent='domain="example.com"',
        state=AgentState.COMPLETED,
        query='domain="example.com"',
        fields=["host", "ip"],
        assets=[{"host": "https://example.com", "ip": "192.0.2.1"}],
        result_count=1,
        scan_requested_by_user=True,
        scan_recommended=True,
        scan_template_ids=["http-missing-security-headers"],
        scan_targets=["https://example.com"],
    )
    status, error = await fofamap._agent_scan_and_report(
        run,
        {
            "save": True,
            "export_format": "csv",
            "outdir": str(tmp_path),
            "outfile": None,
            "report": True,
            "report_file": None,
            "output_format": "table",
            "nuclei": False,
            "nuclei_ids": (),
            "severity": None,
            "scan_max_targets": 200,
        },
        machine=False,
    )
    assert status == "report_only"
    assert error is None
    csv_files = list(tmp_path.glob("**/*.csv"))
    reports = list(tmp_path.glob("**/report_*.md"))
    assert csv_files and "example.com" in csv_files[0].read_text(encoding="utf-8")
    assert reports
