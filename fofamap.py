"""FofaMap 2.0.1 命令行：完整保留 2.0 交互模型，面向人工操作。"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Any

import rich_click as click
import yaml
from rich.live import Live

from config import config_write_path, settings
from core.client import FofaClient
from core.exporter import StreamingXlsxWorkbook, export_pages, records_to_pages
from core.fields import field_catalog
from core.models import AssetRecord, FofaError, SearchPage, SearchRequest
from utils.cli_ui import (
    build_agent_progress,
    build_nuclei_progress,
    console,
    print_banner,
    render_account,
    render_agent,
    render_error,
    render_host,
    render_nuclei_results,
    render_query_overview,
    render_scan_approval,
    render_search_page,
    render_search_summary,
    render_stats,
    section,
)
from utils.helpers import FastChecker, IconHashCalculator, insert_alive_status_field
from utils.logger import logger

click.rich_click.TEXT_MARKUP = "rich"
click.rich_click.OPTIONS_PANEL_TITLE = "选项"
click.rich_click.ARGUMENTS_PANEL_TITLE = "参数"
click.rich_click.COMMANDS_PANEL_TITLE = "命令"
click.rich_click.ERRORS_PANEL_TITLE = "错误"
click.rich_click.ABORTED_TEXT = "已中止。"
_OPTION_GROUPS = [
    {
        "name": "🤖 智能体集成",
        "options": [
            "--agent",
            "--scope",
            "--list",
            "--uninstall",
            "--dry-run",
            "--server-command",
            "--project-root",
            "--force",
        ],
    },
    {
        "name": "🔮 查询与分析",
        "options": [
            "--ai-query",
            "--query",
            "--host-query",
            "--count-query",
            "--icon-query",
            "--icon-file",
            "--bat-query",
            "--rule",
        ],
    },
    {
        "name": "⚙️ 范围、字段与过滤",
        "options": [
            "--query-fields",
            "--smart-fields",
            "--pages",
            "--size",
            "--max-records",
            "--batch-group-size",
            "--full",
            "--dedupe-by",
            "--key-word",
            "--include",
            "--check-alive",
        ],
    },
    {
        "name": "💾 显示与导出",
        "options": [
            "--outfile",
            "--outdir",
            "--export-format",
            "--save",
            "--display-rows",
            "--output-format",
            "--json",
        ],
    },
    {
        "name": "🛡️ 扫描、报告与兼容",
        "options": [
            "--nuclei",
            "--nuclei-id",
            "--severity",
            "--scan-max-targets",
            "--report",
            "--report-file",
            "--batch",
            "--update",
            "--help",
        ],
    },
]
click.rich_click.OPTION_GROUPS = {"fofamap.py": _OPTION_GROUPS, "fofamap": _OPTION_GROUPS}


_SUPPORT_LABELS = {
    "native": "原生",
    "compatibility": "兼容层",
    "tools-only": "仅工具",
    "compatible-bundle": "兼容包",
    "claude-compatible-plugin": "Claude 兼容插件",
    "native-plugin": "原生插件",
}
_SCOPE_LABELS = {"user": "用户级", "project": "项目级"}


def _support_label(value: str) -> str:
    return _SUPPORT_LABELS.get(value, value)


def _fields(value: str | None) -> list[str]:
    return [item.strip() for item in (value or settings.search.fields).split(",") if item.strip()]


def _use_smart_fields(options: dict[str, Any]) -> bool:
    if options.get("smart_fields") is True:
        return True
    if options.get("smart_fields") is False:
        return False
    if options.get("query_fields"):
        return False
    return bool(options.get("ai_query"))


def _has_task(options: dict[str, Any]) -> bool:
    return bool(
        options.get("cmd")
        or options.get("query")
        or options.get("host_query")
        or options.get("count_query")
        or options.get("ai_query")
        or options.get("icon_query")
        or options.get("icon_file")
        or options.get("bat_query")
        or options.get("init_mode")
        or options.get("update")
    )


def _wizard(options: dict[str, Any]) -> dict[str, Any] | None:
    """Restore the 2.0 arrow-key wizard while keeping 2.0.1 safety settings."""
    import questionary
    from questionary import Choice, Separator

    section("FofaMap 智能向导", "方向键选择，回车确认")
    mode = questionary.select(
        "请选择要执行的操作：",
        choices=[
            Choice("1. 🔮 AI 智能侦察（查询/反思 → 审批扫描 → 报告）", "agent"),
            Choice("2. 🔍 FOFA 标准查询", "search"),
            Choice("3. 🖥️  主机聚合画像", "host"),
            Choice("4. 📊 统计聚合分析", "stats"),
            Choice("5. 🖼️  图标哈希反查", "icon"),
            Choice("6. 📁 批量查询文件", "batch"),
            Choice("7. 📖 FOFA 规则库（app= 指纹）", "rules"),
            Separator(),
            Choice("8. 👤 查看 FOFA 账号", "account"),
            Choice("9. 📚 查看字段目录", "fields"),
            Choice("10. ⚙️  安全初始化配置", "init"),
            Choice("0. 🚪 退出", "exit"),
        ],
        qmark="›",
        pointer="❯",
    ).ask()
    if not mode or mode == "exit":
        console.print("[dim]已退出。[/]")
        return None
    if mode in {"account", "fields", "init"}:
        options["cmd"] = mode
        return options
    if mode == "rules":
        from core.rules import search_rules

        keyword = questionary.text("搜索规则库（应用 / OA / 中间件，回车列出常用）：", default="").ask()
        if keyword is None:
            return None
        matches = search_rules(keyword or "", limit=80)
        if not matches:
            console.print("[yellow]没有匹配的内置规则。完整规则列表：https://fofa.info/library[/]")
            return None
        picked = questionary.select(
            "选择一条官方 app= 规则：",
            choices=[Choice(f"{rule.category} · {rule.name}    {rule.query}", rule.query) for rule in matches],
            qmark="›",
            pointer="❯",
        ).ask()
        if not picked:
            return None
        options["query"] = picked
        mode = "search"
    else:
        prompts = {
            "agent": (
                "ai_query",
                "请描述资产检索、统计或授权扫描需求：",
                "例如：收集美国哈佛大学的子域名网站，并扫描一下",
            ),
            "search": ("query", "请输入 FOFA 查询语法：", '例如：app="nginx" && country="CN"'),
            "host": ("host_query", "请输入 IP 或域名：", "例如：8.8.8.8"),
            "stats": ("count_query", "请输入统计查询语法：", '例如：app="redis"'),
            "icon": ("icon_query", "请输入网站 URL：", "例如：https://example.com"),
            "batch": ("bat_query", "请输入批量查询 TXT 文件路径：", "每行一条 FOFA 查询语句"),
        }
        key, message, instruction = prompts[mode]
        value = questionary.text(message, instruction=instruction, validate=lambda text: bool(text.strip())).ask()
        if not value:
            return None
        options[key] = value.strip()
    if mode in {"search", "agent", "icon", "batch"}:
        pages_text = questionary.text(
            "最大查询页数：",
            default=str(settings.search.end_page),
            validate=lambda text: text.isdigit() and int(text) > 0,
        ).ask()
        if not pages_text:
            return None
        options["pages"] = int(pages_text)
        advanced = questionary.confirm("是否调整字段、历史数据和导出选项？", default=False).ask()
        if advanced is None:
            return None
        if advanced:
            field_mode = questionary.select(
                "返回字段：",
                choices=[
                    Choice("智能选择（按账号等级和任务自动挑选）", "smart"),
                    Choice("手动指定固定字段", "manual"),
                ],
                qmark="›",
                pointer="❯",
            ).ask()
            if field_mode is None:
                return None
            if field_mode == "smart":
                options["smart_fields"] = True
                console.print("[dim]将按 FOFA 账号等级和当前任务自动选择字段与字段数。[/]")
            else:
                options["smart_fields"] = False
                fields_value = questionary.text("返回字段：", default=settings.search.fields).ask()
                if fields_value is None:
                    return None
                options["query_fields"] = fields_value
            full_value = questionary.confirm("查询 FOFA 历史数据？", default=settings.search.full).ask()
            if full_value is None:
                return None
            options["full"] = full_value
            save_value = questionary.confirm("自动保存完整结果？", default=True).ask()
            if save_value is None:
                return None
            options["save"] = save_value
            if options["save"]:
                export_format = questionary.select(
                    "导出格式：", choices=["xlsx", "csv", "jsonl"], default=settings.system.export_format
                ).ask()
                if not export_format:
                    return None
                options["export_format"] = export_format
    if mode == "stats":
        stats_fields = questionary.text("统计维度：", default="country,port,org").ask()
        if not stats_fields:
            return None
        options["query_fields"] = stats_fields
    if mode in {"search", "icon", "batch"}:
        nuclei = questionary.confirm("是否同步开启 Nuclei 漏洞扫描？", default=False).ask()
        if nuclei is None:
            return None
        if nuclei:
            options["nuclei"] = True
    if mode == "agent" and options.get("smart_fields") is None:
        options["smart_fields"] = True
    return options


def _local_yaml_security_notice() -> str:
    if os.name == "nt":
        return "Windows 依赖当前用户目录 ACL，无法用 POSIX 0600 表示；建议优先使用系统钥匙串或环境变量"
    return "文件将设置为仅当前用户可读写（0600）"


def _save_setup_config(path: Path, data: dict[str, Any], *, allow_secrets: bool = False) -> None:
    """Persist setup data, requiring explicit opt-in before writing credentials."""
    secret_names = {"api_key", "key", "token", "secret", "password"}

    def contains_secret(value: Any) -> bool:
        if isinstance(value, dict):
            return any(str(name).lower() in secret_names or contains_secret(item) for name, item in value.items())
        if isinstance(value, list):
            return any(contains_secret(item) for item in value)
        return False

    if contains_secret(data) and not allow_secrets:
        raise ValueError("配置文件不得包含密钥；请使用环境变量、系统钥匙串或容器密钥")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _store_keyring(service: str, username: str, secret: str) -> bool:
    if not secret:
        return True
    try:
        import keyring

        keyring.set_password(service, username, secret)
        return True
    except Exception:
        return False


def _keyring_unavailable_reason() -> str:
    try:
        import keyring
    except ModuleNotFoundError:
        return (
            f"当前 Python 未安装 keyring：{sys.executable}。可运行 `"
            f"{sys.executable} -m pip install keyring`，或使用项目 `.venv/bin/python`。"
        )
    except Exception as exc:
        return f"无法加载系统钥匙串：{type(exc).__name__}: {exc}"
    try:
        backend = keyring.get_keyring()
        backend_name = f"{backend.__class__.__module__}.{backend.__class__.__name__}"
        return f"钥匙串后端 {backend_name} 未能保存密钥；请检查系统钥匙串权限或解锁状态。"
    except Exception as exc:
        return f"无法初始化钥匙串后端：{type(exc).__name__}: {exc}"


def _interactive_init() -> int:
    """安全初始化向导：优先系统钥匙串，明确确认后才写入 YAML。"""
    import questionary
    from questionary import Choice

    section("FofaMap 安全初始化向导", "优先系统钥匙串，可确认写入本地 YAML")
    email = questionary.text("FOFA 邮箱（当前接口可选）：", default=settings.fofa.email).ask()
    if email is None:
        return 130
    key = questionary.password("FOFA API 密钥（优先保存到系统钥匙串）：").ask()
    if key is None:
        return 130
    provider_name = questionary.select(
        "选择 AI 提供商（普通命令行查询不需要 AI）：",
        choices=[
            Choice("暂不配置 AI", ""),
            Choice("OpenAI Responses", "openai"),
            Choice("DeepSeek", "deepseek"),
            Choice("Anthropic Claude", "anthropic"),
            Choice("Ollama 本地模型", "ollama"),
            Choice("LM Studio 本地模型", "lmstudio"),
            Choice("自定义 OpenAI 兼容接口", "custom"),
        ],
    ).ask()
    if provider_name is None:
        return 130
    presets = {
        "openai": ("openai_responses", "https://api.openai.com/v1", "gpt-5.6", "OPENAI_API_KEY", "api_key"),
        "deepseek": ("openai_chat", "https://api.deepseek.com/v1", "deepseek-v4-flash", "DEEPSEEK_API_KEY", "api_key"),
        "anthropic": ("anthropic_messages", "https://api.anthropic.com", "claude-opus-5", "ANTHROPIC_API_KEY", "api_key"),
        "ollama": ("ollama_native", "http://127.0.0.1:11434", "", "", "none"),
        "lmstudio": ("openai_responses", "http://127.0.0.1:1234/v1", "", "", "none"),
        "custom": ("openai_chat", "https://api.example.com/v1", "", "CUSTOM_MODEL_API_KEY", "api_key"),
    }
    providers: dict[str, Any] = {}
    routing: dict[str, Any] = {
        "default": "",
        "planner": "",
        "query_repair": "",
        "reflector": "",
        "summarizer": "",
        "allow_cross_provider_fallback": False,
        "fallbacks": [],
    }
    provider_key = ""
    provider_key_env = ""
    if provider_name:
        protocol, default_url, default_model, provider_key_env, credential_kind = presets[provider_name]
        if provider_name == "custom":
            protocol = questionary.select(
                "接口协议：",
                choices=["openai_chat", "openai_responses", "anthropic_messages", "ollama_native"],
                default=protocol,
            ).ask()
            if protocol is None:
                return 130
        base_url = questionary.text("接口地址：", default=default_url).ask()
        model = questionary.text("模型 ID（可填任意未来模型）：", default=default_model).ask()
        if base_url is None or model is None:
            return 130
        if credential_kind != "none":
            provider_key = questionary.password(f"{provider_name} API 密钥（优先保存到系统钥匙串，可留空）：").ask() or ""
        providers[provider_name] = {
            "protocol": protocol,
            "base_url": base_url,
            "model": model,
            "api_key_env": provider_key_env,
            "credential_kind": credential_kind,
            "structured_output_mode": "prompt" if provider_name == "deepseek" else "auto",
            "max_output_tokens": 32768,
            "timeout": 120,
        }
        routing.update(
            {
                "default": provider_name,
                "planner": provider_name,
                "query_repair": provider_name,
                "reflector": provider_name,
                "summarizer": provider_name,
            }
        )
    fields = questionary.text("默认返回字段：", default=settings.search.fields).ask()
    size_text = questionary.text(
        "每页结果数：",
        default=str(settings.search.size),
        validate=lambda value: value.isdigit() and 1 <= int(value) <= 10_000,
    ).ask()
    pages_text = questionary.text(
        "默认查询页数：",
        default=str(settings.search.end_page),
        validate=lambda value: value.isdigit() and 1 <= int(value) <= 10_000,
    ).ask()
    export_format = questionary.select("默认导出格式：", choices=["xlsx", "csv", "jsonl"], default="xlsx").ask()
    if fields is None or size_text is None or pages_text is None or export_format is None:
        return 130
    full = questionary.confirm("是否默认搜索全部历史数据？", default=settings.search.full).ask()
    if full is None:
        return 130
    check_alive = questionary.confirm("是否默认开启存活检测？", default=settings.fast_check.check_alive).ask()
    if check_alive is None:
        return 130
    timeout_text = str(settings.fast_check.timeout)
    if check_alive:
        timeout_text = questionary.text(
            "存活检测超时（秒）：",
            default=str(settings.fast_check.timeout),
            validate=lambda value: value.isdigit() and 1 <= int(value) <= 60,
        ).ask()
        if timeout_text is None:
            return 130
    concurrency_text = questionary.text(
        "异步并发数：",
        default=str(settings.system.concurrency),
        validate=lambda value: value.isdigit() and 1 <= int(value) <= 100,
    ).ask()
    if concurrency_text is None:
        return 130
    sheet_merge = questionary.confirm("批量查询是否合并到同一个 Excel？", default=settings.system.sheet_merge).ask()
    if sheet_merge is None:
        return 130
    output_dir = questionary.text("默认导出目录：", default=settings.system.output_dir).ask()
    if output_dir is None:
        return 130
    config_data = {
        "fofa": {"base_url": settings.fofa.base_url, "email": email or ""},
        "search": {
            "fields": fields or settings.search.fields,
            "size": int(size_text),
            "full": bool(full),
            "start_page": 1,
            "end_page": int(pages_text),
            "max_pages": max(int(pages_text), settings.search.max_pages),
            "max_records": settings.search.max_records,
        },
        "fast_check": {
            "check_alive": bool(check_alive),
            "timeout": int(timeout_text),
        },
        "system": {
            "logger": settings.system.logger,
            "sheet_merge": bool(sheet_merge),
            "concurrency": int(concurrency_text),
            "requests_per_second": settings.system.requests_per_second,
            "export_format": export_format,
            "output_dir": output_dir or settings.system.output_dir,
            "artifact_retention_days": settings.system.artifact_retention_days,
            "allow_private_network": settings.system.allow_private_network,
        },
        "providers": providers,
        "routing": routing,
    }
    target = config_write_path()
    fofa_key_saved = _store_keyring("fofamap", email or "default", key or "")
    provider_key_saved = _store_keyring("fofamap-provider", provider_key_env, provider_key)
    failed_fofa_key = bool(key and not fofa_key_saved)
    failed_provider_key = bool(provider_key and not provider_key_saved)
    secrets_in_yaml = False
    if failed_fofa_key or failed_provider_key:
        labels = []
        if failed_fofa_key:
            labels.append("FOFA_API_KEY")
        if failed_provider_key:
            labels.append(provider_key_env)
        secrets_in_yaml = bool(
            questionary.confirm(
                f"系统钥匙串不可用：{_keyring_unavailable_reason()}\n"
                f"是否将 {', '.join(labels)} 写入本地配置 {target}？\n"
                f"默认配置路径已加入 Git 忽略规则；{_local_yaml_security_notice()}；"
                "自定义路径请自行确认忽略规则。文件中仍是明文密钥。",
                default=True,
            ).ask()
        )
        if secrets_in_yaml:
            config_data["security"] = {"local_yaml_secrets_confirmed": True}
            if failed_fofa_key:
                config_data["fofa"]["api_key"] = key
            if failed_provider_key and provider_name:
                config_data["providers"][provider_name]["api_key"] = provider_key
    _save_setup_config(target, config_data, allow_secrets=secrets_in_yaml)
    console.print(f"[bold green]✓ 配置已写入：[/][cyan]{target}[/]")
    if secrets_in_yaml:
        console.print(
            "[bold yellow]⚠ 密钥已按你的确认写入本地 YAML。请勿提交或分享该文件；"
            f"{_local_yaml_security_notice()}。若使用自定义配置路径，请确认它已被 Git 忽略。[/]"
        )
    else:
        if failed_fofa_key:
            console.print("[yellow]FOFA 密钥未保存；请在启动前设置 FOFA_API_KEY。[/]")
        if failed_provider_key:
            console.print(f"[yellow]AI 密钥未保存；请在启动前设置 {provider_key_env}。[/]")
    console.print("[dim]重新启动 FofaMap 后，新配置生效。[/]")
    return 0


def _machine_output(options: dict[str, Any]) -> bool:
    return options.get("output_format") in {"json", "jsonl"}


def _emit_json(value: Any, mode: str) -> None:
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    if mode == "jsonl" and isinstance(payload, dict) and isinstance(payload.get("records"), list):
        for record in payload["records"]:
            click.echo(json.dumps(record, ensure_ascii=False))
    else:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2 if mode == "json" else None))


def _run_slug(query: str) -> str:
    return re.sub(r"[^\w-]+", "_", query, flags=re.UNICODE).strip("_")[:36] or "fofa_result"


def _new_run_dir(query: str, outdir: str | None = None, stamp: str | None = None) -> tuple[Path, str]:
    stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    root = Path(outdir or settings.system.output_dir).expanduser()
    run_dir = root / f"{_run_slug(query)}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, stamp


def _ensure_run_dir(options: dict[str, Any], query: str) -> Path:
    existing = options.get("_run_dir")
    if existing:
        path = Path(existing)
        path.mkdir(parents=True, exist_ok=True)
        return path
    if options.get("outfile"):
        parent = Path(options["outfile"]).expanduser().parent
        run_dir = parent if str(parent) != "." else Path(options.get("outdir") or settings.system.output_dir).expanduser()
        run_dir.mkdir(parents=True, exist_ok=True)
        options["_run_dir"] = str(run_dir)
        options["_run_stamp"] = options.get("_run_stamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
        return run_dir
    label = "batch" if (options.get("bat_query") or options.get("_batch")) else query
    run_dir, stamp = _new_run_dir(label, options.get("outdir"), options.get("_run_stamp"))
    options["_run_dir"] = str(run_dir)
    options["_run_stamp"] = stamp
    return run_dir


def _default_export_path(query: str, format_name: str, outdir: str | None = None) -> Path:
    run_dir, stamp = _new_run_dir(query, outdir)
    return run_dir / f"{_run_slug(query)}_{stamp}.{format_name}"


def _query_export_path(options: dict[str, Any], query: str, index: int, total: int) -> tuple[Path, str]:
    requested = options.get("outfile")
    format_name = options.get("export_format") or settings.system.export_format
    if requested:
        path = Path(requested).expanduser()
        format_name = options.get("export_format") or path.suffix.lstrip(".") or format_name
        if total > 1 and not options.get("_merge_xlsx"):
            path = path.with_name(f"{path.stem}_{index}{path.suffix or f'.{format_name}'}")
        elif not path.suffix:
            path = path.with_suffix(f".{format_name}")
        return path, format_name
    run_dir = _ensure_run_dir(options, query)
    stamp = options.get("_run_stamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _run_slug(query)
    if total > 1:
        return run_dir / f"{slug}_{index}_{stamp}.{format_name}", format_name
    return run_dir / f"{slug}_{stamp}.{format_name}", format_name


def _search_window(options: dict[str, Any]) -> tuple[int, int]:
    """Return (start_page, max_pages). `-p` is a page count; config end_page is the last page."""
    start = settings.search.start_page
    if options.get("pages"):
        return start, int(options["pages"])
    return start, max(1, settings.search.end_page - start + 1)


def _record_url(values: dict[str, Any]) -> str | None:
    host = str(values.get("host") or "").strip()
    if host.startswith(("http://", "https://")):
        return host
    if not host:
        ip = values.get("ip")
        port = values.get("port")
        if not ip:
            return None
        host = f"{ip}:{port}" if port else str(ip)
    protocol = str(values.get("protocol") or "http").lower()
    scheme = "https" if "https" in protocol or str(values.get("port")) in {"443", "8443"} else "http"
    return f"{scheme}://{host}"


def _needs_alive_probe(asset: dict[str, Any]) -> bool:
    """Empty FOFA placeholders must not count as a completed HTTP probe."""
    if "alive_status" not in asset:
        return True
    value = asset.get("alive_status")
    return value is None or str(value).strip() == ""


def _assets_have_status_code(assets: list[dict[str, Any]], fields: list[str]) -> bool:
    return "status_code" in fields and all("status_code" in asset for asset in assets)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _apply_alive_and_local_filters(
    assets: list[dict[str, Any]],
    *,
    fields: list[str],
    options: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply include, optional HTTP alive checks, then keyword search. Same order as classic mode."""
    include = {item.strip() for item in (options.get("include") or "").split(",") if item.strip()}
    check_alive = bool(options.get("check_alive"))
    needles = [item.strip().lower() for item in (options.get("key_word") or "").split(",") if item.strip()]
    if not assets or (not include and not check_alive and not needles):
        return assets, fields
    has_status_code = _assets_have_status_code(assets, fields)
    if include and has_status_code:
        assets = [asset for asset in assets if str(asset.get("status_code")) in include]
    if (check_alive or (include and not has_status_code)) and assets:
        pending = [asset for asset in assets if _needs_alive_probe(asset)]
        if pending:
            urls = [_record_url(asset) for asset in pending]
            alive = await FastChecker.check_alive([url for url in urls if url], timeout=settings.fast_check.timeout)
            for asset, url in zip(pending, urls, strict=True):
                asset["alive_status"] = alive.get(url, "N/A") if url else "N/A"
        fields = insert_alive_status_field(fields)
        if include and not has_status_code:
            assets = [asset for asset in assets if str(asset.get("alive_status")) in include]
    if needles:
        assets = [asset for asset in assets if any(needle in str(asset).lower() for needle in needles)]
    return assets, fields


async def _apply_agent_result_filters(run: Any, options: dict[str, Any], *, machine: bool) -> None:
    """Honor --check-alive / -i / -k on AI reconnaissance results before export and scan."""
    if run.error or not run.assets:
        return
    if not options.get("check_alive") and not options.get("include") and not options.get("key_word"):
        return
    if not any(_needs_alive_probe(asset) for asset in run.assets) and not options.get("key_word"):
        return
    before = len(run.assets)
    confidence = list(run.asset_confidence)
    if len(confidence) != before:
        confidence = (confidence + [""] * before)[:before]
    identity = [id(asset) for asset in run.assets]
    status = None
    if not machine and (options.get("check_alive") or options.get("include")):
        status = console.status(f"[cyan]正在对 {before} 条 AI 资产做存活检测与过滤…[/]", spinner="dots")
        status.start()
    try:
        filtered, fields = await _apply_alive_and_local_filters(
            run.assets,
            fields=list(run.fields),
            options=options,
        )
    finally:
        if status:
            status.stop()
    kept_ids = {id(asset) for asset in filtered}
    run.assets = filtered
    run.fields = fields
    run.asset_confidence = [value for asset_id, value in zip(identity, confidence, strict=True) if asset_id in kept_ids]
    run.result_count = len(run.assets)
    run.evidence_counts = {
        strategy: sum(1 for value in run.asset_confidence if value == strategy)
        for strategy in ("precision", "balanced", "hypothesis", "recall")
        if any(value == strategy for value in run.asset_confidence)
    }
    if options.get("include") or options.get("key_word"):
        run.scan_targets = []
        for asset in run.assets:
            target = _record_url(asset)
            if target and target not in run.scan_targets:
                run.scan_targets.append(target)
    from core.agent import AgentState, AgentStep

    run.steps.append(
        AgentStep(
            state=AgentState.EVALUATE,
            detail=f"存活检测与本地过滤完成：{before} 条 → {len(run.assets)} 条",
        )
    )


async def _decorate_pages(
    pages: AsyncIterator[SearchPage],
    *,
    options: dict[str, Any],
    counters: dict[str, Any],
) -> AsyncIterator[SearchPage]:
    machine = _machine_output(options)
    async for page in pages:
        counters["pages"] += 1
        values = [record.values for record in page.records]
        values, page.fields = await _apply_alive_and_local_filters(values, fields=page.fields, options=options)
        page.records = [AssetRecord(values=item) for item in values]
        for record in page.records:
            target = _record_url(record.values)
            if target and target not in counters["targets"]:
                counters["targets"].append(target)
        counters["records"] += len(page.records)
        if machine:
            _emit_json(page, options["output_format"])
        else:
            render_search_page(page, counters["pages"], options.get("display_rows") or min(100, len(page.records)))
        yield page


async def _account(client: FofaClient, machine: bool) -> dict[str, Any]:
    if machine:
        return await client.account()
    with console.status("[cyan]正在验证 FOFA 账号与能力…[/]", spinner="dots"):
        data = await client.account()
    if not machine:
        render_account(data)
    return data


async def _run_searches(client: FofaClient, queries: list[str], options: dict[str, Any]) -> None:
    from core.scans import default_nuclei_template_ids

    if _use_smart_fields(options):
        from core.fields import account_tier, merge_return_fields

        user_info = getattr(client, "user_info", None) or {}
        tier = account_tier(user_info.get("vip_level", user_info.get("level")))
        intent = str(options.get("ai_query") or options.get("icon_query") or " ".join(queries))
        fields = merge_return_fields([], account_tier_name=tier, intent=f"{intent} {' '.join(queries)}")
    else:
        fields = _fields(options.get("query_fields"))
    start_page, pages = _search_window(options)
    size = options.get("size") or settings.search.size
    save = options.get("save", True)
    format_name = options.get("export_format") or settings.system.export_format
    merge_xlsx = bool(save and settings.system.sheet_merge and format_name == "xlsx" and len(queries) > 1)
    options["_merge_xlsx"] = merge_xlsx
    if save and not options.get("outfile"):
        options["_batch"] = len(queries) > 1
        _ensure_run_dir(options, "batch" if len(queries) > 1 else queries[0])
    workbook: StreamingXlsxWorkbook | None = None
    if merge_xlsx:
        if options.get("outfile"):
            merge_path, _ = _query_export_path({**options, "_merge_xlsx": True}, queries[0], 1, 1)
        else:
            run_dir = _ensure_run_dir(options, "batch")
            stamp = options.get("_run_stamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
            merge_path = run_dir / f"batch_merge_{stamp}.xlsx"
        workbook = StreamingXlsxWorkbook(merge_path)
    all_targets: list[str] = []
    try:
        for index, query in enumerate(queries, start=1):
            if not _machine_output(options):
                section("FOFA 资产检索", f"任务 {index}/{len(queries)}")
                render_query_overview(query, fields, pages, size, options.get("full", False))
            request = SearchRequest(
                query=query,
                fields=fields,
                size=size,
                full=options.get("full", False),
                page=start_page,
                max_pages=pages,
                max_records=options.get("max_records") or settings.search.max_records,
                dedupe_by=_fields(options.get("dedupe_by")) if options.get("dedupe_by") else [],
            )
            counters: dict[str, Any] = {"pages": 0, "records": 0, "targets": []}
            started = time.monotonic()
            decorated = _decorate_pages(client.iter_search(request), options=options, counters=counters)
            artifact: Path | None = None
            status = None if _machine_output(options) else console.status("[cyan]正在请求 FOFA 连续分页…[/]", spinner="dots")
            if status:
                status.start()
            try:
                if workbook is not None:
                    workbook.start_sheet(_run_slug(query) if len(queries) > 1 else "FOFA assets")
                    async for page in decorated:
                        workbook.write_page(page)
                    artifact = workbook.destination
                elif save:
                    artifact, _ = await export_pages(
                        decorated,
                        *_query_export_path(options, query, index, len(queries)),
                    )
                else:
                    async for _ in decorated:
                        pass
            finally:
                if status:
                    status.stop()
            all_targets.extend(url for url in counters["targets"] if url not in all_targets)
            if not _machine_output(options):
                render_search_summary(
                    records=counters["records"],
                    pages=counters["pages"],
                    artifact=str(artifact) if artifact else None,
                    elapsed=time.monotonic() - started,
                )
            if options.get("nuclei"):
                scan_dir = Path(options.get("_run_dir") or options.get("outdir") or settings.system.output_dir)
                await _approve_and_execute_scan(
                    targets=counters["targets"][: options.get("scan_max_targets") or 200],
                    template_ids=list(options.get("nuclei_ids") or default_nuclei_template_ids()),
                    severities=[item.strip() for item in (options.get("severity") or "medium,high,critical").split(",") if item.strip()],
                    reason="用户通过经典模式 -n/--nuclei 明确请求对本次 FOFA 结果执行扫描。",
                    options=options,
                    machine=_machine_output(options),
                    directory_name=str((scan_dir / f"nuclei_{index}_{datetime.now().strftime('%Y%m%d_%H%M%S')}").resolve()),
                )
    finally:
        if workbook is not None:
            workbook.close()
    run_dir_value = options.get("_run_dir")
    if save and run_dir_value and all_targets:
        targets_path = Path(run_dir_value) / "targets.txt"
        targets_path.write_text("\n".join(all_targets) + "\n", encoding="utf-8")


def _normalize_batch_query(value: str) -> str:
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return f'ip="{candidate}"'
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", candidate):
        return f'domain="{candidate.lower()}"'
    return candidate


def _load_batch(path_value: str) -> list[str]:
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise click.ClickException(f"批量查询文件不存在：{path}")
    return [
        _normalize_batch_query(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _combine_batch_queries(queries: list[str], group_size: int = 100, max_query_length: int = 4096) -> list[str]:
    """Combine homogeneous IP/domain clues into bounded OR expressions."""
    if group_size <= 1:
        return list(dict.fromkeys(queries))
    homogeneous: dict[str, list[str]] = {"ip": [], "domain": []}
    custom: list[str] = []
    pattern = re.compile(r'^(ip|domain)="([^"\\]+)"$')
    for query in dict.fromkeys(queries):
        match = pattern.fullmatch(query)
        if match:
            homogeneous[match.group(1)].append(query)
        else:
            custom.append(query)

    combined: list[str] = []
    for field in ("ip", "domain"):
        chunk: list[str] = []
        for query in homogeneous[field]:
            candidate = f"({' || '.join([*chunk, query])})"
            if chunk and (len(chunk) >= group_size or len(candidate) > max_query_length):
                combined.append(chunk[0] if len(chunk) == 1 else f"({' || '.join(chunk)})")
                chunk = []
            chunk.append(query)
        if chunk:
            combined.append(chunk[0] if len(chunk) == 1 else f"({' || '.join(chunk)})")
    return [*combined, *custom]


def _prompt_scan_action() -> Any:
    import questionary
    from questionary import Choice

    return questionary.select(
        "请选择下一步：",
        choices=[
            Choice("🚀 执行扫描", "execute"),
            Choice("✏️ 修改模板 / 严重级别", "modify"),
            Choice("📄 仅生成报告，不扫描", "report"),
            Choice("🚫 取消", "cancel"),
        ],
        qmark="›",
        pointer="❯",
    ).ask_async()


async def _prompt_scan_modify(
    template_ids: list[str],
    severities: list[str],
    *,
    all_templates: bool = False,
    all_severities: bool = False,
) -> tuple[list[str], list[str], bool, bool] | None:
    import questionary

    from core.scans import ALLOWED_SEVERITIES, nuclei_id_allowlist

    allowed_ids = sorted(nuclei_id_allowlist())
    ids_text = await questionary.text(
        "模板 ID（逗号分隔；all = 全部模板）：",
        default="all" if all_templates else ",".join(template_ids or allowed_ids[:1]),
        instruction=f" 允许：all, {', '.join(allowed_ids)}",
    ).ask_async()
    if ids_text is None:
        return None
    parsed_ids = [item.strip() for item in ids_text.split(",") if item.strip()]
    selected_all_templates = any(item.lower() == "all" for item in parsed_ids)
    if selected_all_templates:
        parsed_ids = []
    elif not parsed_ids or any(item not in nuclei_id_allowlist() for item in parsed_ids):
        console.print("[yellow]模板 ID 不在允许列表中，已保持原方案。[/]")
        return template_ids, severities, all_templates, all_severities
    sev_text = await questionary.text(
        "严重级别（逗号分隔；all = 全部级别）：",
        default="all" if all_severities else ",".join(severities or ["medium", "high", "critical"]),
        instruction=f" 允许：all, {', '.join(sorted(ALLOWED_SEVERITIES))}",
    ).ask_async()
    if sev_text is None:
        return None
    parsed_severities = [item.strip().lower() for item in sev_text.split(",") if item.strip()]
    selected_all_severities = "all" in parsed_severities
    if selected_all_severities:
        parsed_severities = []
    elif not parsed_severities or any(item not in ALLOWED_SEVERITIES for item in parsed_severities):
        console.print("[yellow]严重级别无效，已保持原方案。[/]")
        return parsed_ids, severities, selected_all_templates, all_severities
    return parsed_ids, parsed_severities, selected_all_templates, selected_all_severities


async def _approve_and_execute_scan(
    *,
    targets: list[str],
    template_ids: list[str],
    severities: list[str],
    reason: str,
    options: dict[str, Any],
    machine: bool,
    directory_name: str,
) -> tuple[str, str | None, str | None]:
    """Execute an exact typed plan only after an interactive, one-time approval."""
    if not targets:
        return "no_targets", None, None
    if machine:
        return "approval_required_interactive_cli", None, None
    if os.getenv("FOFAMAP_ENABLE_SCANNING", "").lower() == "false":
        console.print("[yellow]扫描计划已生成，但管理员通过 FOFAMAP_ENABLE_SCANNING=false 禁止了主动扫描。[/]")
        return "disabled_by_administrator", None, None
    from core.scans import align_scan_severities

    current_all_templates = any(item.strip().lower() == "all" for item in template_ids)
    current_all_severities = any(item.strip().lower() == "all" for item in severities)
    current_ids = [] if current_all_templates else list(template_ids)
    current_severities = [] if current_all_severities else align_scan_severities(current_ids, severities)
    while True:
        render_scan_approval(
            targets=targets,
            template_ids=current_ids,
            severities=current_severities,
            reason=reason,
            all_templates=current_all_templates,
            all_severities=current_all_severities,
        )
        action = await _maybe_await(_prompt_scan_action()) or "cancel"
        if action == "modify":
            modified = await _maybe_await(
                _prompt_scan_modify(
                    current_ids,
                    current_severities,
                    all_templates=current_all_templates,
                    all_severities=current_all_severities,
                )
            )
            if modified is None:
                return "declined", None, None
            current_ids, current_severities, current_all_templates, current_all_severities = modified
            if not current_all_severities:
                current_severities = align_scan_severities(current_ids, current_severities)
            continue
        if action == "report":
            return "report_only", None, None
        if action != "execute":
            return "declined", None, None
        break
    from core.scanner import NucleiScanner
    from core.scans import ScanApproval, ScanPlanRequest
    from service.store import JobStore

    try:
        store = JobStore(os.getenv("FOFAMAP_DATABASE_URL", "sqlite:///./fofamap.sqlite3"))
        approval = ScanApproval(
            store,
            secret=os.getenv("FOFAMAP_SCAN_APPROVAL_SECRET") or secrets.token_urlsafe(32),
            allow_private=settings.system.allow_private_network,
        )
        request = ScanPlanRequest(
            targets=targets,
            template_ids=current_ids,
            severities=current_severities,
            all_templates=current_all_templates,
            all_severities=current_all_severities,
        )
        job, token = approval.create(request)
        approved = approval.consume(job["id"], token)
        store.update(approved["id"], status="running")
        output = Path(directory_name)
        scan_root = (
            output
            if output.is_absolute()
            else Path(options.get("_run_dir") or options.get("outdir") or settings.system.output_dir) / directory_name
        )
        def on_progress(event) -> None:
            live.update(
                build_nuclei_progress(
                    event,
                    target_count=len(request.targets),
                    template_ids=["ALL（全部已安装模板）"] if current_all_templates else current_ids,
                )
            )

        with Live(
            build_nuclei_progress(
                None,
                target_count=len(request.targets),
                template_ids=["ALL（全部已安装模板）"] if current_all_templates else current_ids,
            ),
            console=console,
            refresh_per_second=8,
            transient=True,
        ) as live:
            result = await NucleiScanner().run_plan(request, scan_root, on_progress=on_progress)
        artifact = str(result.artifact.resolve())
        store.update(approved["id"], status="completed", artifact_path=artifact)
        render_nuclei_results(result)
        return "completed", artifact, None
    except Exception as exc:
        error = str(exc)
        console.print(f"[bold red]Nuclei 扫描未完成：[/]{error}")
        return "failed", None, error


async def _export_agent_assets(run: Any, options: dict[str, Any]) -> Path | None:
    if not options.get("save", True) or not run.assets:
        return None
    fields = list(run.fields or [])
    if not fields:
        fields = list(dict.fromkeys(key for asset in run.assets for key in asset))
    records = [AssetRecord(values={field: asset.get(field) for field in fields}) for asset in run.assets]
    query = run.query or run.intent or "agent"
    path, format_name = _query_export_path(options, query, 1, 1)
    artifact, _ = await export_pages(records_to_pages(records, fields, query), path, format_name)
    if not _machine_output(options):
        extra = "（预览截断，完整计数见报告）" if getattr(run, "assets_truncated", False) else ""
        console.print(f"[bold green]✓ 资产结果已导出：[/][cyan]{artifact}[/]{extra}")
    return artifact


async def _agent_scan_and_report(run: Any, options: dict[str, Any], machine: bool) -> tuple[str, str | None]:
    """Apply deterministic authorization, one-time approval and reporting around an AI scan recommendation."""
    from core.report import write_agent_report
    from core.scans import default_nuclei_template_ids

    if options.get("save", True) and not options.get("outfile"):
        _ensure_run_dir(options, run.query or run.intent or "agent")
    await _export_agent_assets(run, options)

    scan_status = "not_requested"
    scan_error: str | None = None
    if options.get("nuclei"):
        run.scan_requested_by_user = True
    override_ids = list(options.get("nuclei_ids") or [])
    if override_ids:
        run.scan_template_ids = list(dict.fromkeys(override_ids))
    override_severities = [item.strip().lower() for item in (options.get("severity") or "").split(",") if item.strip()]
    if override_severities:
        run.scan_severities = list(dict.fromkeys(override_severities))

    if run.error:
        scan_status = "blocked_by_agent_error"
    elif run.scan_requested_by_user and run.scan_targets:
        reason = run.scan_reason
        if not run.scan_recommended:
            scan_status = "user_requested_agent_not_recommended"
            reason = (
                "用户明确要求扫描，但 AI 未推荐该范围。仍可执行、修改或仅生成报告。"
                + (f" AI 判断：{run.scan_reason}" if run.scan_reason else "")
            )
        template_ids = list(run.scan_template_ids or default_nuclei_template_ids())
        scan_root = Path(options.get("_run_dir") or options.get("outdir") or settings.system.output_dir)
        scan_status, run.scan_artifact, scan_error = await _approve_and_execute_scan(
            targets=run.scan_targets[: options.get("scan_max_targets") or 200],
            template_ids=template_ids,
            severities=run.scan_severities,
            reason=reason,
            options=options,
            machine=machine,
            directory_name=str((scan_root / "nuclei").resolve()),
        )
    elif run.scan_recommended and not run.scan_requested_by_user:
        scan_status = "recommendation_only_no_user_authorization"
    elif run.scan_requested_by_user and not run.scan_recommended:
        scan_status = "not_recommended_by_agent"
    elif run.scan_requested_by_user and run.scan_recommended and not run.scan_ready:
        scan_status = "incomplete_or_empty_scan_plan"

    if options.get("report", True):
        report_path = options.get("report_file")
        if report_path:
            destination = Path(report_path).expanduser()
        else:
            stamp = options.get("_run_stamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
            destination = Path(options.get("_run_dir") or options.get("outdir") or settings.system.output_dir) / f"report_{stamp}.md"
        artifact = write_agent_report(run, destination, scan_status=scan_status, scan_error=scan_error)
        run.report_artifact = str(artifact)
        if not machine:
            console.print(f"[bold green]✓ AI 侦察报告已生成：[/][cyan]{artifact}[/]")
    return scan_status, scan_error


async def _main_async(**options: Any) -> int:
    action = options.get("cmd")
    machine = _machine_output(options)
    if action == "integrate":
        from core.integrations import HOSTS, IntegrationError, integrate_host, supported_hosts

        if options.get("list_integrations"):
            payload = {"hosts": supported_hosts()}
            if machine:
                _emit_json(payload, options["output_format"])
            else:
                section("智能体集成支持矩阵", "MCP 与 Skill")
                for host in payload["hosts"]:
                    console.print(
                        f"[bold cyan]{host['id']:<20}[/] MCP：[green]{_support_label(host['mcp'])}[/]  "
                        f"Skill：[green]{_support_label(host['skills'])}[/]"
                    )
                    if host["notes"]:
                        console.print(f"  [dim]{host['notes']}[/]")
            return 0
        requested = options.get("integration_agent")
        if not requested:
            raise click.UsageError("integrate 需要 --agent <name|all>，或使用 --list 查看支持矩阵。")
        targets = [host.id for host in HOSTS] if requested == "all" else [requested]
        root = Path(options["project_root"]).expanduser() if options.get("project_root") else Path.cwd()
        try:
            results = [
                integrate_host(
                    target,
                    scope=options.get("integration_scope") or "user",
                    root=root,
                    server_command=options.get("server_command") or "fofamap-mcp",
                    uninstall=bool(options.get("uninstall_integration")),
                    dry_run=bool(options.get("dry_run")),
                    force=bool(options.get("force_integration")),
                ).as_dict()
                for target in targets
            ]
        except IntegrationError as exc:
            raise click.ClickException(str(exc)) from exc
        payload = {"integrations": results}
        if machine:
            _emit_json(payload, options["output_format"])
        else:
            verb = "预览" if options.get("dry_run") else ("卸载" if options.get("uninstall_integration") else "安装")
            section(
                f"智能体集成{verb}",
                f"范围：{_SCOPE_LABELS.get(options.get('integration_scope') or 'user', options.get('integration_scope') or 'user')}",
            )
            for result in results:
                console.print(
                    f"[bold green]✓ {result['target']}[/] · MCP {_support_label(result['mcp_support'])} · "
                    f"Skill {_support_label(result['skill_support'])}"
                )
                for change in result["changes"]:
                    console.print(f"  [dim]{change}[/]")
                for note in result["notes"]:
                    console.print(f"  [yellow]{note}[/]")
                if result["deeplink"]:
                    console.print(f"  [cyan]{result['deeplink']}[/]")
        return 0
    if action == "init":
        if machine:
            _emit_json({"config": "config/settings.example.yaml", "secrets": ".env.example"}, options["output_format"])
            return 0
        # Defensive fallback for programmatic callers. The normal human CLI
        # executes this synchronously before entering asyncio (see main()).
        return await asyncio.to_thread(_interactive_init)
    if action == "fields":
        catalog = field_catalog()
        if machine:
            _emit_json(catalog, options["output_format"])
        else:
            section("FOFA 字段目录", f"版本 {catalog['version']} · {catalog.get('source', '')}")
            console.print("[bold cyan]基础返回字段[/]\n" + ", ".join(catalog["base"]))
            if catalog.get("compat"):
                console.print("\n[bold yellow]兼容返回字段（非官方附录，按需自行指定）[/]\n" + ", ".join(catalog["compat"]))
            for tier, fields in catalog["tiers"].items():
                console.print(f"\n[bold green]{tier}[/]\n" + ", ".join(fields))
            if catalog.get("memberships"):
                console.print(f"\n[bold cyan]会员等级与 API 权限[/]  [dim]{catalog.get('membership_source', '')}[/]")
                for item in catalog["memberships"]:
                    host = "是" if item["host_api"] else "否"
                    stats = "是" if item["stats_api"] else "否"
                    extra = f" · {item['notes']}" if item.get("notes") else ""
                    console.print(
                        f"  vip_level={item['vip_level']:<3} {item['name']:<8}  "
                        f"主机聚合 {host} · 统计聚合 {stats} · {item['requests_per_second']:g} req/s{extra}"
                    )
            console.print("\n[dim]查询语法请运行 `fofamap syntax`；规则库请运行 `fofamap rules`。[/]")
        return 0
    if action == "syntax":
        from core.syntax import syntax_catalog

        catalog = syntax_catalog()
        if machine:
            _emit_json(catalog, options["output_format"])
        else:
            section("FOFA 官方查询语法", catalog["source"])
            for item in catalog["operators"]:
                console.print(f"[bold cyan]{item['op']:<4}[/] {item['meaning']}")
            console.print()
            for item in catalog["query_fields"]:
                console.print(f"[bold]{item['field']:<16}[/] {item['example']:<42} [dim]{item['meaning']}[/]")
            for note in catalog["notes"]:
                console.print(f"[dim]· {note}[/]")
        return 0
    if action == "rules":
        from core.rules import rules_catalog

        catalog = rules_catalog(options.get("key_word") or options.get("rule") or "")
        if machine:
            _emit_json(catalog, options["output_format"])
        else:
            section("FOFA 规则库子集", f"{catalog['count']} 条 · {catalog['source']}")
            console.print(f"[dim]{catalog['note']}[/]")
            for category, rules in catalog["categories"].items():
                console.print(f"\n[bold green]{category}[/]")
                for rule in rules:
                    console.print(f"  [bold cyan]{rule['name']:<20}[/] {rule['query']}")
        return 0
    if action == "serve":
        from service.api import main as serve

        serve()
        return 0
    if options.get("update"):
        from core.scanner import resolve_nuclei_executable

        executable = resolve_nuclei_executable()
        if not executable:
            raise click.ClickException("未找到 Nuclei 可执行文件。请放入 PATH 或项目根目录。")
        subprocess.run([executable, "-update"], check=False)  # noqa: S603 - executable is resolved locally
        subprocess.run([executable, "-ut"], check=False)  # noqa: S603 - executable is resolved locally
        return 0

    queries: list[str] = []
    if options.get("query"):
        queries.append(options["query"])
    if options.get("bat_query"):
        batch_queries = _load_batch(options["bat_query"])
        queries.extend(_combine_batch_queries(batch_queries, options.get("batch_group_size") or 100))
    if options.get("icon_query"):
        if not machine:
            section("图标哈希计算", options["icon_query"])
        try:
            icon_query = await IconHashCalculator.get_hash(options["icon_query"])
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        if not icon_query:
            raise click.ClickException("无法获取网站图标或计算哈希。")
        if not machine:
            console.print(f"[green]✓[/] 已生成 FOFA 语句：[bold cyan]{icon_query}[/]")
        queries.append(icon_query)
    if options.get("icon_file"):
        try:
            icon_query = IconHashCalculator.from_file(options["icon_file"])
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        if not machine:
            section("本地图标哈希计算", options["icon_file"])
            console.print(f"[green]✓[/] 已生成 FOFA 语句：[bold cyan]{icon_query}[/]")
        queries.append(icon_query)

    async with FofaClient() as client:
        if action == "account":
            data = await client.account()
            _emit_json(data, options["output_format"]) if machine else render_account(data)
            return 0
        await _account(client, machine)
        if options.get("host_query"):
            data = await client.host_profile(
                str(options["host_query"]).strip().strip("'\""),
                detail=bool(options.get("host_detail", True)),
            )
            if machine:
                _emit_json(data, options["output_format"])
            else:
                section("主机聚合查询")
                render_host(data)
            return 0
        if options.get("count_query"):
            data = await client.stats(
                options["count_query"],
                _fields(options.get("query_fields") or "country,port,org"),
                size=options.get("size") or 5,
            )
            if machine:
                _emit_json(data, options["output_format"])
            else:
                section("FOFA 统计聚合")
                render_stats(data, options["count_query"])
            return 0
        if options.get("ai_query"):
            from core.agent import FofaAgent
            from providers.registry import ProviderRegistry, ProviderRouter

            registry = ProviderRegistry(settings, execution_mode="interactive")
            router = ProviderRouter(registry)
            live: Live | None = None
            live_started = False
            latest_page: SearchPage | None = None
            if not machine:
                section("AI 智能侦察", "实时展示执行阶段、查询语句和资产结果")
                live = Live("", console=console, refresh_per_second=8, transient=True)

            def on_progress(agent_run, _step) -> None:
                nonlocal live_started
                if live is None:
                    return
                live.update(build_agent_progress(agent_run, latest_page), refresh=True)
                if not live_started:
                    live.start(refresh=True)
                    live_started = True

            async def on_page(agent_run, page, _page_number) -> None:
                nonlocal latest_page
                if options.get("check_alive") or options.get("include") or options.get("key_word"):
                    values = [record.values for record in page.records]
                    values, fields = await _apply_alive_and_local_filters(
                        values,
                        fields=list(agent_run.fields or page.fields),
                        options=options,
                    )
                    agent_run.fields = fields
                    page.fields = fields
                    page.records = [AssetRecord(values=item) for item in values]
                latest_page = page
                on_progress(agent_run, None)

            need_page_observer = (not machine) or bool(
                options.get("check_alive") or options.get("include") or options.get("key_word")
            )
            try:
                run = await FofaAgent(client, router).run(
                    options["ai_query"],
                    max_records=options.get("max_records") or settings.search.max_records,
                    max_pages=_search_window(options)[1],
                    fields=None if _use_smart_fields(options) else _fields(options.get("query_fields")),
                    smart_fields=_use_smart_fields(options),
                    on_progress=on_progress if not machine else None,
                    on_page=on_page if need_page_observer else None,
                )
            finally:
                if live is not None and live_started:
                    live.stop()
                await registry.aclose()
            await _apply_agent_result_filters(run, options, machine=machine)
            if not machine:
                render_agent(run)
            if run.error:
                if machine:
                    _emit_json(run, options["output_format"])
                return 2
            await _agent_scan_and_report(run, options, machine)
            if machine:
                _emit_json(run, options["output_format"])
            return 0
        if queries:
            await _run_searches(client, queries, options)
            return 0
    raise click.UsageError("请选择向导任务，或提供 -q/-ai/-hq/-cq/-ico/-bq 参数。")


@click.command(context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 120})
@click.version_option("2.0.1", "-V", "--version", prog_name="FofaMap")
@click.argument("cmd", required=False, type=click.Choice(["account", "fields", "syntax", "rules", "serve", "init", "integrate"]))
@click.option(
    "--agent",
    "integration_agent",
    type=click.Choice(
        [
            "all",
            "cursor",
            "codex",
            "claude",
            "claude-code",
            "opencode",
            "deepseek-harness",
            "deepseek",
            "dsh",
            "lmstudio",
            "lm-studio",
            "openclaw",
            "hermes",
            "grok",
            "gork",
        ]
    ),
    help="安装目标；all 表示全部支持的智能体",
)
@click.option(
    "--scope",
    "integration_scope",
    type=click.Choice(["user", "project"]),
    default="user",
    show_default=True,
    help="用户级或项目级",
)
@click.option("--list", "list_integrations", is_flag=True, help="列出 MCP 与 Skill 支持情况")
@click.option("--uninstall", "uninstall_integration", is_flag=True, help="仅移除 FofaMap 管理的配置与文件")
@click.option("--dry-run", is_flag=True, help="只显示将发生的集成变更")
@click.option("--server-command", default="fofamap-mcp", show_default=True, help="宿主启动 MCP 服务的命令（stdio）")
@click.option("--project-root", type=click.Path(file_okay=False, path_type=Path), help="项目级安装时的项目根目录")
@click.option("--force", "force_integration", is_flag=True, help="备份后替换同名、非 FofaMap 管理的 Skill/插件")
@click.option("-init", "--init", "init_mode", is_flag=True, help="启动安全初始化向导（兼容旧用法）")
@click.option("-ai", "--ai-query", prompt="请描述 AI 侦察需求", prompt_required=False, help="AI 智能侦察（兼容 2.0）")
@click.option("-q", "--query", prompt="请输入 FOFA 查询语法", prompt_required=False, help="FOFA 标准查询（兼容 2.0）")
@click.option("-hq", "--host-query", prompt="请输入 IP 或域名", prompt_required=False, help="主机聚合画像（兼容 2.0）")
@click.option("--host-detail/--no-host-detail", default=True, help="Host 聚合是否返回端口详情（官方 detail 参数）")
@click.option("--rule", help="按 FOFA 规则库名称生成 app= 查询，例如 ThinkPHP / 致远OA")
@click.option("-cq", "--count-query", prompt="请输入统计查询语法", prompt_required=False, help="统计聚合查询（兼容 2.0）")
@click.option("-ico", "--icon-query", prompt="请输入网站 URL", prompt_required=False, help="计算网站图标哈希并反查")
@click.option("--icon-file", help="计算本地图标文件哈希并反查（最大 4 MiB）")
@click.option("-bq", "--bat-query", prompt="请输入批量查询文件", prompt_required=False, help="每行一条查询语句的 TXT 文件")
@click.option("-f", "--query-fields", help="逗号分隔的返回字段；与 --smart-fields 同时出现时以智能选择为准")
@click.option(
    "--smart-fields/--no-smart-fields",
    default=None,
    help="按账号等级和任务智能选择返回字段与字段数；AI 模式默认开启",
)
@click.option("-p", "--pages", type=click.IntRange(1, 10_000), default=None, help="最大查询页数")
@click.option("--size", type=click.IntRange(1, 10_000), default=None, help="检索每页条数；统计聚合时为每个维度 Top N（官方默认 5）")
@click.option("--max-records", type=click.IntRange(1, 1_000_000), default=None, help="本次最多返回记录数")
@click.option(
    "--batch-group-size",
    type=click.IntRange(1, 100),
    default=100,
    show_default=True,
    help="批量 IP/域名每组组合成一条 OR 查询；1 表示不组合",
)
@click.option("--full/--no-full", default=None, help="是否查询历史数据（默认跟随配置）")
@click.option("--dedupe-by", help="明确的逗号分隔去重键")
@click.option("-k", "--key-word", help="在本地结果中筛选关键词，逗号表示任一匹配；-q 与 -ai 均支持")
@click.option("-i", "--include", help="仅保留指定状态码，例如 200,403；-q 与 -ai 均支持")
@click.option(
    "--check-alive/--no-check-alive",
    default=settings.fast_check.check_alive,
    help="对结果做安全的 HTTP 存活检测；-q 与 -ai 均支持",
)
@click.option("-o", "--outfile", help="完整结果导出路径")
@click.option("--outdir", help="默认导出目录")
@click.option("--export-format", type=click.Choice(["xlsx", "csv", "jsonl"]), help="导出文件格式")
@click.option("--save/--no-save", default=True, help="自动保存完整结果（默认开启）")
@click.option("--display-rows", type=click.IntRange(1, 500), default=100, help="每页终端展示行数（默认完整展示 100 条）")
@click.option("--output-format", type=click.Choice(["table", "json", "jsonl"]), default="table", help="终端输出格式")
@click.option("--json", "json_output", is_flag=True, help="等价于 --output-format json")
@click.option("-n", "--nuclei", is_flag=True, help="查询后生成精确 Nuclei 计划并请求执行审批")
@click.option(
    "--nuclei-id",
    "nuclei_ids",
    multiple=True,
    help="覆盖 AI 方案的 Nuclei 模板 ID，可重复；输入 all 使用全部已安装模板",
)
@click.option("--severity", help="Nuclei 严重级别，例如 medium,high,critical；输入 all 使用全部级别")
@click.option("--scan-max-targets", type=click.IntRange(1, 10_000), default=200, help="单次审批最多扫描目标数")
@click.option("--report/--no-report", default=True, help="AI 模式自动生成 Markdown 报告")
@click.option("--report-file", help="AI Markdown 报告路径")
@click.option("-batch", "--batch", is_flag=True, help="兼容 2.0 无人值守标记（不会跳过扫描审批）")
@click.option("-up", "--update", is_flag=True, help="更新 Nuclei 与模板")
def main(**options: Any) -> None:
    """FOFA 资产检索、导出、MCP 与多模型智能体。无参数启动交互式向导。"""
    if options.pop("json_output"):
        options["output_format"] = "json"
    if options.pop("init_mode"):
        options["cmd"] = "init"
    mapped_from_rule = False
    if options.get("rule") and not options.get("query") and options.get("cmd") != "rules":
        from core.rules import resolve_rule_query

        try:
            options["query"] = resolve_rule_query(options["rule"]).query
            mapped_from_rule = True
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    if options.get("full") is None:
        options["full"] = settings.search.full
    logger.set_enabled(settings.system.logger)
    machine = _machine_output(options)
    if not machine:
        print_banner()
        if mapped_from_rule:
            console.print(f"[green]✓[/] 规则库已映射为：[bold cyan]{options['query']}[/]")
    if not _has_task(options):
        wizard_options = _wizard(options)
        if wizard_options is None:
            return
        options = wizard_options
    try:
        # questionary/prompt_toolkit manages its own event loop. Running the
        # init wizard inside asyncio.run() causes a nested-loop RuntimeError.
        if options.get("cmd") == "init" and not machine:
            code = _interactive_init()
        else:
            code = asyncio.run(_main_async(**options))
    except FofaError as exc:
        if machine:
            _emit_json({"error": exc.as_dict()}, options["output_format"])
        else:
            render_error(exc.code.value, exc.message, exc.alternatives)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        if not machine:
            console.print("\n[yellow]操作已取消。[/]")
        raise SystemExit(130) from None
    raise SystemExit(code)


if __name__ == "__main__":
    main()
