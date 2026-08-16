from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import fofamap
from core.integrations import HOSTS, IntegrationError, integrate_host, normalize_host, resolve_mcp_stdio, supported_hosts


def _files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


def _expected_stdio() -> dict[str, object]:
    return {
        "command": os.path.abspath(os.path.expanduser(sys.executable)),
        "args": ["-u", str((Path(__file__).resolve().parents[1] / "mcp_server.py").resolve())],
    }


def test_support_matrix_covers_nine_requested_hosts_and_gork_alias():
    assert [host["id"] for host in supported_hosts()] == [
        "cursor",
        "codex",
        "claude",
        "opencode",
        "deepseek-harness",
        "lmstudio",
        "openclaw",
        "hermes",
        "grok",
    ]
    assert normalize_host("gork").id == "grok"
    assert normalize_host("claude-code").id == "claude"
    assert normalize_host("dsh").id == "deepseek-harness"


@pytest.mark.parametrize("host", [item.id for item in HOSTS])
def test_each_user_integration_is_installable_idempotent_and_reversible(
    tmp_path: Path, host: str, monkeypatch: pytest.MonkeyPatch
):
    project = tmp_path / "project"
    home = tmp_path / "home"
    monkeypatch.setenv("FOFA_API_KEY", "super-secret-value-that-must-not-be-copied")

    installed = integrate_host(host, scope="user", root=project, home=home)
    assert installed.target == host
    assert installed.changes
    first_files = _files(tmp_path)
    assert first_files
    assert not any(b"super-secret-value-that-must-not-be-copied" in path.read_bytes() for path in first_files)

    before_repeat = sorted(path.relative_to(tmp_path) for path in _files(tmp_path))
    repeated = integrate_host(host, scope="user", root=project, home=home)
    assert repeated.changes
    assert sorted(path.relative_to(tmp_path) for path in _files(tmp_path)) == before_repeat

    removed = integrate_host(host, scope="user", root=project, home=home, uninstall=True)
    assert removed.action == "uninstall"
    assert removed.changes


@pytest.mark.parametrize("host", [item.id for item in HOSTS])
def test_dry_run_never_writes(tmp_path: Path, host: str):
    result = integrate_host(host, root=tmp_path / "project", home=tmp_path / "home", dry_run=True)
    assert result.dry_run is True
    assert result.changes
    assert _files(tmp_path) == []


def test_json_merge_preserves_unrelated_servers_and_uninstall_removes_only_fofamap(tmp_path: Path):
    config = tmp_path / "home" / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcpServers": {"existing": {"url": "https://example.test/mcp"}}}), encoding="utf-8")

    integrate_host("cursor", home=tmp_path / "home", root=tmp_path / "project")
    installed = json.loads(config.read_text(encoding="utf-8"))
    assert installed["mcpServers"]["existing"]["url"] == "https://example.test/mcp"
    assert installed["mcpServers"]["fofamap"] == _expected_stdio()

    integrate_host("cursor", home=tmp_path / "home", root=tmp_path / "project", uninstall=True)
    removed = json.loads(config.read_text(encoding="utf-8"))
    assert removed == {"mcpServers": {"existing": {"url": "https://example.test/mcp"}}}


def test_codex_managed_toml_block_preserves_user_config(tmp_path: Path):
    config = tmp_path / "home" / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('model = "gpt-test"\n', encoding="utf-8")

    integrate_host("codex", home=tmp_path / "home", root=tmp_path / "project")
    content = config.read_text(encoding="utf-8")
    assert 'model = "gpt-test"' in content
    assert "[mcp_servers.fofamap]" in content
    assert f'command = {json.dumps(_expected_stdio()["command"])}' in content
    assert f'args = {json.dumps(_expected_stdio()["args"])}' in content

    integrate_host("codex", home=tmp_path / "home", root=tmp_path / "project", uninstall=True)
    content = config.read_text(encoding="utf-8")
    assert content == 'model = "gpt-test"\n'


def test_deepseek_harness_uses_tools_only_cordis_bridge(tmp_path: Path):
    result = integrate_host("deepseek", scope="project", home=tmp_path / "home", root=tmp_path / "project")
    patch = tmp_path / "project" / ".dsh" / "fofamap.cordis.yml"
    content = patch.read_text(encoding="utf-8")
    assert "@deepseek-ai/dsh-mcp-client" in content
    assert "serverName: fofamap" in content
    assert f'command: {json.dumps(_expected_stdio()["command"])}' in content
    assert f'args: {json.dumps(_expected_stdio()["args"])}' in content
    assert result.mcp_support == "tools-only"
    assert any("Resources" in note and "Prompts" in note for note in result.notes)


def test_lmstudio_emits_official_add_mcp_deeplink(tmp_path: Path):
    result = integrate_host("lmstudio", home=tmp_path / "home", root=tmp_path / "project")
    assert result.deeplink is not None
    assert result.deeplink.startswith("lmstudio://add_mcp?name=fofamap&config=")


def test_default_stdio_is_absolute_and_explicit_override_is_preserved():
    assert resolve_mcp_stdio() == _expected_stdio()
    assert resolve_mcp_stdio(" /custom/fofamap-mcp ") == {"command": "/custom/fofamap-mcp", "args": []}


def test_default_stdio_completes_a_real_mcp_initialize_and_tools_handshake(tmp_path: Path):
    launch = resolve_mcp_stdio()
    child_env = os.environ.copy()
    child_env["FOFAMAP_DATABASE_URL"] = f"sqlite:///{tmp_path / 'mcp.sqlite3'}"
    process = subprocess.Popen(  # noqa: S603
        [launch["command"], *launch["args"]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=child_env,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    responses: queue.Queue[str] = queue.Queue()
    reader = threading.Thread(target=lambda: [responses.put(line) for line in process.stdout], daemon=True)
    reader.start()

    def send(payload: dict[str, object]) -> None:
        process.stdin.write(json.dumps(payload) + "\n")
        process.stdin.flush()

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "fofamap-test", "version": "1"},
                },
            }
        )
        initialized = json.loads(responses.get(timeout=10))
        assert initialized["result"]["serverInfo"] == {"name": "fofamap_mcp", "version": "2.0.1"}
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = json.loads(responses.get(timeout=10))["result"]["tools"]
        assert {item["name"] for item in tools} >= {"fofa_search", "fofa_agent_run", "nuclei_plan", "nuclei_execute"}
    finally:
        process.stdin.close()
        process.wait(timeout=10)
    assert process.returncode == 0, process.stderr.read()


@pytest.mark.parametrize("host", ["openclaw", "grok"])
def test_plugin_manifests_receive_the_full_gui_safe_launch(tmp_path: Path, host: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("core.integrations.shutil.which", lambda _name: None)
    integrate_host(host, home=tmp_path / "home", root=tmp_path / "project")
    plugin_root = tmp_path / "home" / (".openclaw/extensions/fofamap" if host == "openclaw" else ".grok/plugins/fofamap")
    for name in (".mcp.json", "openclaw.plugin.json"):
        payload = json.loads((plugin_root / name).read_text(encoding="utf-8"))
        assert payload["mcpServers"]["fofamap"] == _expected_stdio()


def test_reinstall_upgrades_legacy_cursor_bare_command(tmp_path: Path):
    config = tmp_path / "home" / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"mcpServers": {"fofamap": {"command": "fofamap-mcp", "args": []}}}),
        encoding="utf-8",
    )
    integrate_host("cursor", home=tmp_path / "home", root=tmp_path / "project")
    payload = json.loads(config.read_text(encoding="utf-8"))
    assert payload["mcpServers"]["fofamap"] == _expected_stdio()


@pytest.mark.parametrize(
    ("host", "relative"),
    [
        ("claude", ".claude.json"),
        ("lmstudio", ".lmstudio/mcp.json"),
    ],
)
def test_other_json_hosts_receive_gui_safe_launch(tmp_path: Path, host: str, relative: str):
    integrate_host(host, home=tmp_path / "home", root=tmp_path / "project")
    payload = json.loads((tmp_path / "home" / relative).read_text(encoding="utf-8"))
    assert payload["mcpServers"]["fofamap"] == _expected_stdio()


def test_opencode_and_hermes_receive_command_and_arguments(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    integrate_host("opencode", home=home, root=project)
    opencode = json.loads((home / ".config/opencode/opencode.json").read_text(encoding="utf-8"))
    expected = _expected_stdio()
    assert opencode["mcp"]["fofamap"]["command"] == [expected["command"], *expected["args"]]

    integrate_host("hermes", home=home, root=project)
    hermes = yaml.safe_load((home / ".hermes/config.yaml").read_text(encoding="utf-8"))
    assert hermes["mcp_servers"]["fofamap"]["command"] == expected["command"]
    assert hermes["mcp_servers"]["fofamap"]["args"] == expected["args"]


def test_refuses_to_replace_or_remove_unmanaged_skill(tmp_path: Path):
    skill = tmp_path / "home" / ".agents" / "skills" / "fofamap"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("user-owned", encoding="utf-8")
    with pytest.raises(IntegrationError, match="拒绝覆盖"):
        integrate_host("codex", home=tmp_path / "home", root=tmp_path / "project")
    with pytest.raises(IntegrationError, match="拒绝删除"):
        integrate_host("codex", home=tmp_path / "home", root=tmp_path / "project", uninstall=True)


def test_cli_lists_integrations_without_banner():
    result = CliRunner().invoke(fofamap.main, ["integrate", "--list", "--output-format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["hosts"]) == 9
    assert "FOFA API · MCP" not in result.output


def test_cli_dry_run_all_does_not_touch_home(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    result = CliRunner().invoke(
        fofamap.main,
        ["integrate", "--agent", "all", "--dry-run", "--project-root", str(tmp_path / "project"), "--output-format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.output)["integrations"]) == 9
    assert _files(tmp_path) == []


def test_standalone_and_plugin_skills_keep_the_same_workflow_contract():
    root = Path(__file__).resolve().parents[1] / "agent-kit"
    standalone = (root / "skills" / "fofamap" / "SKILL.md").read_text(encoding="utf-8")
    bundled = (root / "plugins" / "fofamap" / "skills" / "fofamap" / "SKILL.md").read_text(encoding="utf-8")

    assert bundled == standalone
    for tool in ("fofa_account", "fofa_fields", "fofa_icon_search", "fofa_agent_run", "nuclei_execute"):
        assert f"`{tool}`" in bundled
    assert (root / "plugins" / "fofamap" / "skills" / "fofamap" / "references" / "tool-catalog.md").is_file()
