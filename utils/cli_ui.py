"""Human-first Rich terminal presentation for FofaMap's classic and wizard modes."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from rich import box
from rich.console import Console, Group
from rich.markdown import Heading, Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import config_write_path
from core.models import AssetRecord, SearchPage
from utils.helpers import insert_alive_status_field

if TYPE_CHECKING:
    from core.agent import AgentRun
    from core.scanner import NucleiProgressEvent, NucleiScanResult

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}

console = Console(highlight=False)


class _LeftAlignedHeading(Heading):
    LEVEL_ALIGN = {f"h{level}": "left" for level in range(1, 7)}

    def __rich_console__(self, console, options):
        text = self.text.copy()
        text.justify = "left"
        if self.tag == "h2":
            text.stylize("bold cyan")
            yield Text()
        elif self.tag == "h1":
            text.stylize("bold cyan")
        elif self.tag == "h3":
            text.stylize("bold")
        yield text


class LeftAlignedMarkdown(Markdown):
    """Rich Markdown with left-aligned headings and extra space before h2."""

    elements = {**Markdown.elements, "heading_open": _LeftAlignedHeading}


_SECTION_TITLES = {
    "结论": "结论",
    "高置信": "高置信资产",
    "高置信资产": "高置信资产",
    "噪声": "噪声与误报",
    "噪声与误报": "噪声与误报",
    "暴露面": "暴露面",
    "风险与暴露面": "风险与暴露面",
    "证据边界与噪声": "证据边界与噪声",
    "覆盖缺口": "覆盖缺口",
    "处置优先级": "处置优先级",
    "缺口": "下一步",
    "下一步": "下一步",
    "缺口与下一步": "下一步",
}


def normalize_summary_markdown(text: str) -> str:
    """Turn numbered walls of text into scannable `##` sections for the terminal."""
    if not text or not str(text).strip():
        return text
    body = str(text).replace("\r\n", "\n").strip()
    body = re.sub(
        r"^(?:#{1,6}\s*)?(?:\*\*)?(?:[一二三四五1-5][\.、]|[1-5]\.\s*)\s*"
        r"(结论|高置信资产|高置信|噪声与误报|噪声|风险与暴露面|暴露面|证据边界与噪声|"
        r"覆盖缺口|处置优先级|缺口与下一步|下一步|缺口)\s*(?:\*\*)?\s*$",
        lambda match: f"## {_SECTION_TITLES.get(match.group(1), match.group(1))}",
        body,
        flags=re.MULTILINE,
    )
    body = re.sub(r"\n{3,}", "\n\n", body)
    body = re.sub(r"([^\n])\n(## )", r"\1\n\n\2", body)
    return body.strip() + "\n"


def _summary_panel(markdown: str) -> Panel:
    rendered = LeftAlignedMarkdown(
        normalize_summary_markdown(markdown),
        code_theme="monokai",
        inline_code_theme="monokai",
        hyperlinks=False,
    )
    return Panel(
        rendered,
        title="[bold]AI 总结[/]",
        border_style="magenta",
        padding=(1, 3),
        expand=True,
    )


def print_banner() -> None:
    logo = Text()
    logo.append("  ______      ____        __  ___            \n", style="bold cyan")
    logo.append(" / ____/___  / __/___ _  /  |/  /___ _____  \n", style="bold cyan")
    logo.append("/ /_  / __ \\/ /_/ __ `/ / /|_/ / __ `/ __ \\ \n", style="bold cyan")
    logo.append("/ __/ / /_/ / __/ /_/ / / /  / / /_/ / /_/ /\n", style="bold cyan")
    logo.append("/_/    \\____/_/  \\__,_/ /_/  /_/\\__,_/ .___/ \n", style="bold cyan")
    logo.append("                                      /_/", style="bold cyan")
    subtitle = Text("  v2.0.1  [ AI Powered & Interactive Wizard ] — By Hx0 Team", style="bold bright_white")
    console.print(Panel(Group(logo, subtitle), border_style="cyan", padding=(0, 1), expand=False))


def section(title: str, subtitle: str | None = None) -> None:
    label = Text(f" {title} ", style="bold black on cyan")
    if subtitle:
        label.append(f"  {subtitle}", style="dim")
    console.print()
    console.print(label)


def render_account(data: dict[str, Any]) -> None:
    from core.membership import format_quota, membership_from_account

    name = data.get("username") or data.get("name") or data.get("email") or "FOFA 用户"
    membership = membership_from_account(data)
    vip_raw = data.get("vip_level") if data.get("vip_level") is not None else data.get("level") or data.get("vip") or "-"
    if membership:
        tier_label = f"{membership.name}（vip_level={membership.vip_level}）"
        capability = (
            f"主机聚合 {'是' if membership.host_api else '否'} · "
            f"统计聚合 {'是' if membership.stats_api else '否'} · "
            f"{membership.requests_per_second:g} req/s"
        )
    else:
        tier_label = str(vip_raw)
        capability = "未知（未识别的 vip_level）"
    remain = format_quota(data, membership)
    email = str(data.get("email") or "")
    if "@" in email:
        local, domain = email.split("@", 1)
        email = f"{local[:2]}***@{domain}"
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column(style="white")
    grid.add_row("账号", str(name))
    if email:
        grid.add_row("邮箱", email)
    grid.add_row("会员等级", tier_label)
    grid.add_row("接口权限", capability)
    grid.add_row("可用额度", remain)
    console.print(Panel(grid, title="[bold green]✓ FOFA 登录成功[/]", border_style="green", expand=False))


def render_query_overview(query: str, fields: list[str], pages: int, size: int, full: bool) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(style="white")
    grid.add_row("查询语句", query)
    grid.add_row("返回字段", ", ".join(fields))
    grid.add_row("查询预算", f"最多 {pages} 页 × {size} 条")
    grid.add_row("历史数据", "是" if full else "否")
    console.print(Panel(grid, title="[bold]检索任务[/]", border_style="blue"))


def _cell(value: Any, limit: int = 72) -> str:
    text = "" if value is None else str(value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _visible_fields(fields: list[str], terminal_width: int) -> list[str]:
    priority = ["host", "ip", "port", "protocol", "alive_status", "evidence", "status_code", "title", "country", "domain"]
    preferred = [field for field in priority if field in fields]
    preferred.extend(field for field in fields if field not in preferred)
    limit = 5 if terminal_width < 100 else 7 if terminal_width < 140 else 9
    return preferred[:limit]


def build_asset_table(page: SearchPage, display_rows: int = 100, terminal_width: int | None = None) -> Table:
    visible_fields = _visible_fields(page.fields, terminal_width or console.width)
    table = Table(
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        row_styles=["", "dim"],
        show_lines=False,
        expand=True,
    )
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    widths = {
        "host": 30,
        "ip": 18,
        "port": 7,
        "protocol": 10,
        "status_code": 8,
        "title": 36,
        "country": 9,
        "domain": 24,
        "alive_status": 12,
        "evidence": 8,
    }
    minimums = {
        "host": 22,
        "ip": 15,
        "port": 5,
        "protocol": 6,
        "status_code": 6,
        "title": 18,
        "country": 4,
        "domain": 14,
        "alive_status": 7,
        "evidence": 4,
    }
    labels = {
        "host": "主机",
        "ip": "IP",
        "port": "端口",
        "protocol": "协议",
        "status_code": "状态码",
        "title": "标题",
        "country": "国家",
        "domain": "域名",
        "alive_status": "存活",
        "lastupdatetime": "更新时间",
        "product.version": "版本",
        "evidence": "归属证据",
    }
    for field in visible_fields:
        justify = "right" if field in {"port", "status_code"} else "left"
        table.add_column(
            labels.get(field, field),
            justify=justify,
            overflow="ellipsis",
            no_wrap=True,
            min_width=minimums.get(field, 8),
            max_width=widths.get(field, 18),
            ratio=2 if field in {"host", "title"} else 1,
        )
    for index, record in enumerate(page.records[:display_rows], start=1):
        table.add_row(str(index), *[_cell(record.values.get(field)) for field in visible_fields])
    return table


def render_search_page(page: SearchPage, page_number: int, display_rows: int = 100) -> None:
    count = len(page.records)
    title = f"第 {page_number} 页 · {count} 条"
    if page.total is not None:
        title += f" · FOFA 总量 {page.total:,}"
    console.print(Panel(build_asset_table(page, display_rows), title=f"[bold green]{title}[/]", border_style="green"))
    hidden = [field for field in page.fields if field not in _visible_fields(page.fields, console.width)]
    if hidden:
        console.print(f"[dim]为适配当前终端宽度，表格隐藏字段：{', '.join(hidden)}；导出文件仍保留全部字段。[/]")
    if count > display_rows:
        console.print(f"[dim]本页仅展示前 {display_rows} 条，其余 {count - display_rows} 条仍会写入导出文件。[/]")


def render_search_summary(*, records: int, pages: int, artifact: str | None, elapsed: float) -> None:
    parts = ["[bold green]✓ 检索完成[/]", f"共 [bold]{records:,}[/] 条", f"{pages} 页", f"耗时 {elapsed:.2f}s"]
    if artifact:
        parts.append(f"已保存至 [cyan]{artifact}[/]")
    console.print(Panel("  ·  ".join(parts), border_style="green"))


def render_host(data: dict[str, Any]) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan")
    grid.add_column()
    for label, key in (
        ("主机", "host"),
        ("IP", "ip"),
        ("国家/地区", "country_name"),
        ("组织", "org"),
        ("ASN", "asn"),
        ("更新时间", "update_time"),
    ):
        grid.add_row(label, _cell(data.get(key, "-")))
    items: list[Any] = [Panel(grid, title="[bold]主机资产画像[/]", border_style="cyan")]
    ports = data.get("ports") or []
    if ports:
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=True)
        table.add_column("端口", justify="right")
        table.add_column("协议")
        table.add_column("产品")
        table.add_column("更新时间")
        for port in sorted(ports, key=lambda item: item.get("port") or 0):
            products = ", ".join(str(product.get("product") or product.get("name") or "") for product in (port.get("products") or []))
            table.add_row(
                _cell(port.get("port")),
                _cell(port.get("protocol")),
                _cell(products),
                _cell(port.get("update_time")),
            )
        items.append(Panel(table, title=f"[bold green]开放端口 · {len(ports)}[/]", border_style="green"))
    console.print(Group(*items))


def render_stats(data: dict[str, Any], query: str) -> None:
    console.print(Panel(f"[bold]查询：[/]{query}\n[bold]统计总量：[/]{data.get('size', 0):,}", border_style="cyan"))
    for field, rows in (data.get("aggs") or {}).items():
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column(field.upper(), min_width=24)
        table.add_column("数量", justify="right")
        for index, item in enumerate((rows or [])[:20], start=1):
            table.add_row(str(index), _cell(item.get("name")), f"{item.get('count', 0):,}")
        console.print(Panel(table, title=f"[bold green]{field} Top {min(len(rows or []), 20)}[/]", border_style="green"))


_AGENT_STATE_LABELS = {
    "intent_parsing": "需求解析",
    "query_validation": "语法校验",
    "execute": "资产查询",
    "evaluate": "结果评估",
    "reflect": "动态反思",
    "query_repair": "查询修复",
    "summarize": "生成总结",
    "completed": "完成",
    "failed": "失败",
}


def _agent_asset_page(run: AgentRun, *, tail: int | None = None) -> SearchPage:
    start = max(0, len(run.assets) - tail) if tail else 0
    assets = run.assets[start:]
    fields = run.fields or list(dict.fromkeys(key for asset in assets for key in asset))
    records = []
    confidence_labels = {"precision": "高", "balanced": "中", "hypothesis": "待验证", "recall": "候选"}
    for offset, asset in enumerate(assets):
        values = dict(asset)
        confidence_index = start + offset
        if confidence_index < len(run.asset_confidence):
            values["evidence"] = confidence_labels.get(run.asset_confidence[confidence_index], "候选")
        records.append(AssetRecord(values=values))
    if any("alive_status" in asset for asset in assets):
        fields = insert_alive_status_field(fields)
    if run.asset_confidence and "evidence" not in fields:
        fields = [*fields, "evidence"]
    return SearchPage(
        query=run.query or "",
        fields=fields,
        records=records,
    )


def _agent_query_table(run: AgentRun, *, compact: bool = False) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=True)
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("来源", no_wrap=True)
    table.add_column("策略", no_wrap=True)
    table.add_column("查询目的", max_width=30)
    table.add_column("FOFA 语句", ratio=3)
    if not compact:
        table.add_column("FOFA总量", justify="right", no_wrap=True)
        table.add_column("取样", justify="right", no_wrap=True)
        table.add_column("新增", justify="right", no_wrap=True)
    for index, item in enumerate(run.queries, start=1):
        source = {
            "planner": "首轮规划",
            "entity_resolution": "官网线索",
        }.get(item.source, f"动态反思 R{item.source.rsplit('_', 1)[-1]}")
        strategy = {
            "precision": "精准",
            "balanced": "均衡",
            "hypothesis": "待验证",
            "recall": "召回",
            "correction": "修正",
        }.get(item.strategy, item.strategy)
        values = [str(index), source, strategy, _cell(item.purpose, 30), _cell(item.query, 140)]
        if not compact:
            available = str(item.available_count) if item.available_count is not None else "-"
            values.extend([available, str(item.result_count), str(item.new_assets)])
        table.add_row(*values)
    return table


def _website_candidate_table(run: AgentRun) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=True)
    table.add_column("状态", no_wrap=True)
    table.add_column("域名", no_wrap=True)
    table.add_column("首选 URL", ratio=2)
    table.add_column("证据", ratio=2)
    status_labels = {"corroborated": "交叉印证", "observed": "FOFA 已观测", "candidate": "待验证"}
    evidence_labels = {
        "entity_resolution": "实体解析",
        "name_in_title": "标题同名",
        "icp_observed": "备案线索",
        "certificate_observed": "证书线索",
        "fofa_precision": "精准查询",
        "fofa_balanced": "均衡查询",
        "fofa_hypothesis": "域名假设",
        "fofa_recall": "召回查询",
    }
    for item in run.website_candidates:
        table.add_row(
            status_labels.get(item.status, item.status),
            item.domain,
            _cell(item.url, 80),
            "、".join(evidence_labels.get(value, value) for value in item.evidence),
        )
    return table


def build_agent_progress(run: AgentRun, latest_page: SearchPage | None = None) -> Group:
    """Build the transient live view shown while the Agent is still running."""
    grid = Table(box=box.SIMPLE, header_style="bold cyan", expand=True)
    grid.add_column("阶段", no_wrap=True)
    grid.add_column("实时进度", ratio=3)
    for step in run.steps[-8:]:
        grid.add_row(_AGENT_STATE_LABELS.get(step.state.value, step.state.value), step.detail)
    items: list[Any] = [Panel(grid, title="[bold cyan]智能体实时执行中[/]", border_style="cyan")]
    if run.queries:
        items.append(
            Panel(
                _agent_query_table(run, compact=True),
                title=f"[bold blue]查询策略 · {len(run.queries)} 个 · 当前去重资产 {run.result_count:,} 条[/]",
                border_style="blue",
            )
        )
    elif run.query:
        items.append(Panel(f"[bold]FOFA 语句[/]  {run.query}\n[bold]当前已接收[/]  {run.result_count:,} 条", border_style="blue"))
    if latest_page and latest_page.records:
        page = latest_page.model_copy(update={"records": latest_page.records[-8:]})
        items.append(
            Panel(
                build_asset_table(page, display_rows=8),
                title=f"[bold green]本页最新资产 · 累计 {run.result_count:,} 条[/]",
                border_style="green",
            )
        )
    elif run.assets:
        page = _agent_asset_page(run, tail=8)
        items.append(
            Panel(
                build_asset_table(page, display_rows=8),
                title=f"[bold green]最新资产 · 累计 {run.result_count:,} 条[/]",
                border_style="green",
            )
        )
    return Group(*items)


def render_agent(run: AgentRun) -> None:
    state_style = "green" if run.error is None else "red"
    grid = Table(box=box.SIMPLE, header_style="bold cyan", expand=True)
    grid.add_column("步骤", no_wrap=True)
    grid.add_column("状态")
    grid.add_column("说明", ratio=3)
    for index, step in enumerate(run.steps, start=1):
        grid.add_row(str(index), _AGENT_STATE_LABELS.get(step.state.value, step.state.value), step.detail)
    console.print(
        Panel(
            grid,
            title=f"[bold {state_style}]智能体 · {_AGENT_STATE_LABELS.get(run.state.value, run.state.value)}[/]",
            border_style=state_style,
        )
    )
    if run.action.value == "host_query" and run.result_data:
        render_host(run.result_data)
    elif run.action.value == "stat_query" and run.result_data:
        render_stats(run.result_data, run.query or "")
    if run.queries and run.action.value != "stat_query":
        console.print(
            Panel(
                _agent_query_table(run),
                title=f"[bold cyan]FOFA 多维查询策略 · {len(run.queries)} 个 · 去重结果 {run.result_count:,} 条[/]",
                border_style="cyan",
            )
        )
    elif run.query:
        console.print(Panel(f"[bold]FOFA 语句[/]\n{run.query}\n\n[bold]结果数[/]  {run.result_count:,}", border_style="cyan"))
    if run.website_candidates:
        console.print(
            Panel(
                _website_candidate_table(run),
                title=f"[bold magenta]网站候选清单 · {len(run.website_candidates)} 个[/]",
                subtitle="交叉印证仍不等同于法律或组织归属确认",
                border_style="magenta",
            )
        )
    if run.assets:
        page = _agent_asset_page(run)
        shown = len(run.assets)
        title = f"查询到的资产候选 · 展示 {shown:,} / {run.result_count:,} 条"
        console.print(Panel(build_asset_table(page, display_rows=shown), title=f"[bold green]{title}[/]", border_style="green"))
        if run.evidence_counts.get("recall"):
            console.print(
                f"[yellow]其中 {run.evidence_counts['recall']:,} 条仅由召回型语句命中，表示名称/内容相关候选，"
                "不等同于已确认归属。[/]"
            )
        if run.evidence_counts.get("hypothesis"):
            console.print(
                f"[yellow]其中 {run.evidence_counts['hypothesis']:,} 条来自官网域名假设验证，"
                "仅说明候选域名在 FOFA 中存在；归属仍需结合官网内容、备案或权威来源复核。[/]"
            )
        if run.assets_truncated:
            console.print(f"[dim]终端结果为前 {shown:,} 条预览；本次查询实际返回 {run.result_count:,} 条。[/]")
    if run.summary:
        console.print(_summary_panel(run.summary))
    if run.error:
        render_error(
            run.error.get("code", "agent_error"),
            run.error.get("message", "智能体执行失败"),
            hint=run.error.get("hint"),
        )
        return
    decision = Table.grid(padding=(0, 2))
    decision.add_column(style="bold cyan")
    decision.add_column()
    decision.add_row("用户要求扫描", "是" if run.scan_requested_by_user else "否")
    decision.add_row("AI 建议扫描", "是" if run.scan_recommended else "否")
    decision.add_row("判断理由", run.scan_reason or "-")
    decision.add_row("候选目标", f"{len(run.scan_targets):,}")
    decision.add_row(f"模板 ID（{len(run.scan_template_ids)}）", ", ".join(run.scan_template_ids) or "-")
    decision.add_row("严重级别", ", ".join(run.scan_severities))
    console.print(Panel(decision, title="[bold]扫描决策（尚未执行）[/]", border_style="yellow"))


def render_scan_approval(
    *,
    targets: list[str],
    template_ids: list[str],
    severities: list[str],
    reason: str,
    all_templates: bool = False,
    all_severities: bool = False,
) -> None:
    preview = "\n".join(f"  • {_cell(target, 100)}" for target in targets[:8])
    if len(targets) > 8:
        preview += f"\n  … 以及另外 {len(targets) - 8:,} 个目标"
    template_scope = "ALL（全部已安装模板）" if all_templates else ", ".join(template_ids)
    severity_scope = "ALL（全部严重级别）" if all_severities else ", ".join(severities)
    scope_warning = (
        "\n[bold red]范围警告：ALL 会运行当前 Nuclei 安装可加载的完整模板集合；"
        "耗时、请求量和潜在影响都会显著增加。[/]\n"
        if all_templates
        else ""
    )
    body = (
        f"[bold]AI 判断：[/]{reason or '-'}\n"
        f"[bold]目标数量：[/]{len(targets):,}\n"
        f"[bold]模板范围：[/]{template_scope}\n"
        f"[bold]严重级别：[/]{severity_scope}\n"
        f"{scope_warning}\n"
        f"[bold]目标预览[/]\n{preview}"
    )
    console.print(
        Panel(
            body,
            title="[bold yellow]⚠ Nuclei 执行审批[/]",
            subtitle="确认令牌仅绑定以上目标、模板范围、级别范围与有效期",
            border_style="yellow",
        )
    )


_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "unknown": "white",
}


def _severity_label(name: str) -> str:
    return SEVERITY_LABELS.get(name, name)


def build_nuclei_progress(
    event: NucleiProgressEvent | None,
    *,
    target_count: int,
    template_ids: list[str] | None = None,
) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    loaded = event.loaded_targets if event and event.loaded_targets is not None else target_count
    grid.add_row("扫描目标", f"{loaded:,} 个")
    if event and event.loaded_templates is not None:
        grid.add_row("已加载模板", f"{event.loaded_templates:,} 个")
    elif template_ids:
        grid.add_row("模板 ID", ", ".join(template_ids))
    grid.add_row("已发现命中", f"{event.findings if event else 0:,} 条")
    grid.add_row("最新日志", _cell(event.line if event else "正在启动 Nuclei…", 100))
    return Panel(grid, title="[bold yellow]Nuclei 扫描进行中[/]", border_style="yellow")


def render_nuclei_results(result: NucleiScanResult, *, preview: int = 20) -> None:
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold cyan", no_wrap=True)
    summary.add_column()
    summary.add_row("扫描目标", f"{(result.loaded_targets or result.target_count):,} 个")
    summary.add_row("命中条数", f"{len(result.findings):,} 条")
    summary.add_row("涉及站点", f"{result.host_count:,} 个")
    summary.add_row("耗时", f"{result.duration_seconds:.1f}s")
    if result.severity_counts:
        summary.add_row(
            "严重级别",
            "  ".join(
                f"[{_SEVERITY_STYLE.get(name, 'white')}]{_severity_label(name)} {count:,}[/]"
                for name, count in result.severity_counts.items()
            ),
        )
    title = "[bold green]✓ Nuclei 扫描完成[/]" if result.findings else "[bold green]✓ Nuclei 扫描完成 · 未发现命中[/]"
    console.print(Panel(summary, title=title, subtitle=result.headline(), border_style="green"))

    grouped = result.grouped()
    if grouped:
        table = Table(
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            row_styles=["", "dim"],
            expand=True,
            show_lines=False,
        )
        table.add_column("级别", no_wrap=True)
        table.add_column("站点", overflow="fold", min_width=24)
        table.add_column("检测项", overflow="fold")
        table.add_column("命中详情", overflow="fold", ratio=2)
        for hit in grouped[:preview]:
            style = _SEVERITY_STYLE.get(hit.severity, "white")
            details = ", ".join(hit.details) if hit.details else f"{hit.count} 条命中"
            table.add_row(
                f"[{style}]{_severity_label(hit.severity)}[/]",
                hit.target,
                hit.name or hit.template_id,
                _cell(details, 80),
            )
        extra = f" · 仅展示前 {preview:,} 个站点" if len(grouped) > preview else ""
        console.print(Panel(table, title=f"[bold]命中站点汇总 · {len(grouped):,} 个{extra}[/]", border_style="cyan"))
    if result.summary_path:
        console.print(f"[bold green]✓ 可读摘要：[/][cyan]{result.summary_path}[/]")
    console.print(f"[dim]原始 JSONL：{result.artifact}[/]")


def render_error(
    code: str,
    message: str,
    alternatives: list[str] | None = None,
    *,
    hint: str | None = None,
) -> None:
    config_path = config_write_path()
    hints = {
        "auth_failed": "请检查 FOFA_API_KEY；若该密钥曾提交到 Git，请先轮换。",
        "quota_exhausted": "FOFA 查询额度不足，请检查账号用量或降低查询预算。",
        "permission_denied": "当前账号无权使用请求字段。FofaMap 不会静默降级，请确认替代字段后重试。",
        "rate_limited": "触发 FOFA 限速；客户端已完成安全重试，请稍后再试或降低速率。",
        "invalid_query": "请检查 FOFA 查询语法、引号与括号。",
        "transport_error": "网络或 FOFA 服务暂时不可用，请检查连接后重试。",
        "model_provider_not_configured": (
            f"运行 `fofamap init`（也兼容 `python fofamap.py -init`）配置 AI 提供商。配置文件位置：{config_path}"
        ),
        "model_auth_failed": (
            f"AI API 密钥无效、过期或未配置。运行 `fofamap init` 重新填写，或检查环境变量/系统钥匙串。配置文件：{config_path}"
        ),
        "model_not_found": "检查模型 ID、接口地址和协议；Ollama/LM Studio 还需确认服务已启动且模型已安装。",
        "model_transport_error": "检查网络、代理和接口地址；使用 Ollama/LM Studio 时确认本地服务端口可访问。",
        "model_rate_limited": "模型额度或速率已用尽，请检查供应商账户或 Token Plan 配额后重试。",
        "model_request_error": "检查模型能力、上下文限制、接口协议与请求参数。",
        "model_response_error": "模型未返回有效结构化结果，请更换支持结构化输出的模型或检查接口协议。",
        "model_structured_output_error": "模型未返回有效结构化结果，请更换支持结构化输出的模型或检查接口协议。",
        "model_credential_not_allowed": "服务端智能体使用标准 API 密钥；订阅模型应由官方宿主通过 MCP 调用。",
    }
    lines = [f"[bold red]{message}[/]"]
    default_hint = hints.get(code)
    selected_hint = " ".join(dict.fromkeys(part for part in (hint, default_hint) if part)) or None
    if selected_hint:
        lines.append(f"\n[yellow]如何修复：[/]{selected_hint}")
    if alternatives:
        lines.append(f"\n[yellow]可用替代字段：[/]{', '.join(alternatives)}")
    console.print(Panel("".join(lines), title=f"[bold red]错误 · {code}[/]", border_style="red"))
