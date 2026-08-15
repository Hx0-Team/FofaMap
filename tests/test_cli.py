import subprocess
import sys

from click.testing import CliRunner

import fofamap
from core.models import AssetRecord, SearchPage
from utils.cli_ui import build_asset_table


def test_classic_query_without_value_prompts_instead_of_error(monkeypatch):
    captured = {}

    async def fake_main_async(**options):
        captured.update(options)
        return 0

    monkeypatch.setattr(fofamap, "_main_async", fake_main_async)
    result = CliRunner().invoke(fofamap.main, ["--query", "--no-save"], input='app="nginx"\n')
    assert result.exit_code == 0
    assert captured["query"] == 'app="nginx"'
    assert "requires an argument" not in result.output


def test_machine_fields_output_has_no_banner():
    result = CliRunner().invoke(fofamap.main, ["fields", "--output-format", "json"])
    assert result.exit_code == 0
    assert result.output.lstrip().startswith("{")
    assert "FOFA API · MCP" not in result.output


def test_use_smart_fields_defaults_on_for_ai_and_off_when_manual_list_is_set():
    assert fofamap._use_smart_fields({"ai_query": "收集中国通服"}) is True
    assert fofamap._use_smart_fields({"query": 'app="nginx"'}) is False
    assert fofamap._use_smart_fields({"ai_query": "收集资产", "query_fields": "host,ip"}) is False
    assert fofamap._use_smart_fields({"query": 'app="nginx"', "smart_fields": True}) is True
    assert fofamap._use_smart_fields({"ai_query": "收集资产", "smart_fields": False}) is False


def test_help_keeps_v2_classic_aliases():
    result = CliRunner().invoke(fofamap.main, ["--help"])
    assert result.exit_code == 0
    for option in ("--ai-query", "--query", "--host-query", "--count-query", "--icon-query", "--bat-query"):
        assert option in result.output


def test_asset_table_is_human_readable_not_raw_values_wrapper():
    page = SearchPage(
        query='app="nginx"',
        fields=["host", "ip", "port", "status_code"],
        records=[AssetRecord(values={"host": "https://example.com", "ip": "1.1.1.1", "port": 443, "status_code": 200})],
    )
    table = build_asset_table(page, terminal_width=200)
    assert [column.header for column in table.columns] == ["#", "主机", "IP", "端口", "状态码"]
    assert "values" not in str(table.rows[0])


def test_no_arguments_enters_wizard(monkeypatch):
    called = {"wizard": False, "async": False}

    def fake_wizard(options):
        called["wizard"] = True
        options["cmd"] = "fields"
        return options

    async def fake_main_async(**_):
        called["async"] = True
        return 0

    monkeypatch.setattr(fofamap, "_wizard", fake_wizard)
    monkeypatch.setattr(fofamap, "_main_async", fake_main_async)
    result = CliRunner().invoke(fofamap.main, [])
    assert result.exit_code == 0
    assert called == {"wizard": True, "async": True}


def test_classic_cli_import_does_not_boot_mcp_rest_or_model_agent():
    script = (
        "import sys; import fofamap; "
        "forbidden=[name for name in sys.modules if "
        "name == 'mcp' or name.startswith('mcp.') or name.startswith('service.') "
        "or name.startswith('providers.') or name == 'core.agent']; "
        "assert not forbidden, forbidden"
    )
    result = subprocess.run(  # noqa: S603 - sys.executable and the fixed test script are trusted
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
