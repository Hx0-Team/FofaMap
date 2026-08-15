"""Deterministic Markdown reports for CLI Agent runs and approved scans."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from core.agent import AgentRun
from core.scanner import format_nuclei_summary_markdown, load_nuclei_result
from utils.cli_ui import normalize_summary_markdown


def _safe(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def write_agent_report(
    run: AgentRun,
    destination: Path,
    *,
    scan_status: str = "not_requested",
    scan_error: str | None = None,
) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# FofaMap AI 资产侦察报告",
        "",
        f"- 生成时间：{datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- Run ID：`{run.id}`",
        f"- 状态：`{run.state.value}`",
        f"- 动作：`{run.action.value}`",
        f"- 用户需求：{_safe(run.intent)}",
        f"- FOFA 查询：`{_safe(run.query)}`",
        f"- 结果数量：{run.result_count:,}",
        "",
        "## 执行过程",
        "",
        "| # | 阶段 | 说明 |",
        "|---:|---|---|",
    ]
    for index, step in enumerate(run.steps, start=1):
        lines.append(f"| {index} | {_safe(step.state.value)} | {_safe(step.detail)} |")
    if run.queries:
        lines.extend(
            [
                "",
                "## 多维查询策略",
                "",
                "| # | 来源 | 策略 | 查询目的 | FOFA 查询 | FOFA 总量 | 取样 | 去重新增 |",
                "|---:|---|---|---|---|---:|---:|---:|",
            ]
        )
        for index, item in enumerate(run.queries, start=1):
            source = {
                "planner": "首轮规划",
                "entity_resolution": "官网线索",
            }.get(item.source, f"动态反思 R{item.source.rsplit('_', 1)[-1]}")
            lines.append(
                f"| {index} | {source} | {_safe(item.strategy)} | {_safe(item.purpose)} | `{_safe(item.query)}` | "
                f"{item.available_count if item.available_count is not None else '-'} | {item.result_count:,} | "
                f"{item.new_assets:,} |"
            )
    if run.website_candidates:
        lines.extend(
            [
                "",
                "## 网站候选清单",
                "",
                "| 状态 | 域名 | 首选 URL | 证据 |",
                "|---|---|---|---|",
            ]
        )
        status_labels = {"corroborated": "交叉印证", "observed": "FOFA 已观测", "candidate": "待验证"}
        for item in run.website_candidates:
            lines.append(
                f"| {status_labels.get(item.status, item.status)} | `{_safe(item.domain)}` | "
                f"{_safe(item.url)} | {_safe(', '.join(item.evidence))} |"
            )
        lines.extend(["", "> 交叉印证表示 FOFA 中存在多种一致线索，仍不等同于法律或组织归属确认。"])
    if run.action.value == "host_query" and run.result_data:
        ports = run.result_data.get("ports") or []
        lines.extend(
            [
                "",
                "## 主机聚合画像",
                "",
                f"- Host：{_safe(run.result_data.get('host') or run.target)}",
                f"- IP：{_safe(run.result_data.get('ip'))}",
                f"- 组织：{_safe(run.result_data.get('org'))}",
                f"- 国家/地区：{_safe(run.result_data.get('country_name'))}",
                f"- 更新时间：{_safe(run.result_data.get('update_time'))}",
                "",
                "| 端口 | 协议 | 产品 | 更新时间 |",
                "|---:|---|---|---|",
            ]
        )
        for port in ports:
            products = ", ".join(
                str(product.get("product") or product.get("name") or "") for product in (port.get("products") or [])
            )
            lines.append(
                f"| {_safe(port.get('port'))} | {_safe(port.get('protocol'))} | {_safe(products)} | "
                f"{_safe(port.get('update_time'))} |"
            )
    elif run.action.value == "stat_query" and run.result_data:
        lines.extend(["", "## 统计聚合结果", "", f"- 统计总量：{run.result_count:,}"])
        for field, rows in (run.result_data.get("aggs") or {}).items():
            lines.extend(["", f"### {_safe(field)}", "", "| # | 值 | 数量 |", "|---:|---|---:|"])
            for index, item in enumerate((rows or [])[:20], start=1):
                lines.append(f"| {index} | {_safe(item.get('name'))} | {int(item.get('count') or 0):,} |")
    else:
        lines.extend(["", "## 查询到的资产候选", ""])
    if run.action.value not in {"host_query", "stat_query"} and run.assets:
        asset_fields = (run.fields or list(dict.fromkeys(key for asset in run.assets for key in asset)))[:8]
        if run.asset_confidence:
            asset_fields = [*asset_fields, "归属证据"]
        lines.extend(
            [
                "| # | " + " | ".join(_safe(field) for field in asset_fields) + " |",
                "|---:|" + "|".join("---" for _ in asset_fields) + "|",
            ]
        )
        confidence_labels = {"precision": "高", "balanced": "中", "hypothesis": "待验证", "recall": "候选"}
        for index, asset in enumerate(run.assets, start=1):
            values = [
                confidence_labels.get(run.asset_confidence[index - 1], "候选")
                if field == "归属证据" and index <= len(run.asset_confidence)
                else asset.get(field)
                for field in asset_fields
            ]
            lines.append(f"| {index} | " + " | ".join(_safe(value) for value in values) + " |")
        if run.evidence_counts.get("recall"):
            lines.extend(
                [
                    "",
                    f"> {run.evidence_counts['recall']:,} 条仅由召回型语句命中，属于名称/内容相关候选，不等同于已确认归属。",
                ]
            )
        if run.evidence_counts.get("hypothesis"):
            lines.extend(
                [
                    "",
                    f"> {run.evidence_counts['hypothesis']:,} 条来自官网域名假设验证；仅证明候选域名在 FOFA 中存在，"
                    "仍需结合官网内容、备案或权威来源复核归属。",
                ]
            )
        if run.assets_truncated:
            lines.extend(["", f"> 仅展示前 {len(run.assets):,} 条；本次查询实际返回 {run.result_count:,} 条。"])
    elif run.action.value not in {"host_query", "stat_query"}:
        lines.append("未返回可展示资产。")
    lines.extend(["", "## AI 总结", "", normalize_summary_markdown(run.summary) if run.summary else "未生成总结。", "", "## 扫描决策", ""])
    lines.extend(
        [
            f"- 用户是否明确要求扫描：{'是' if run.scan_requested_by_user else '否'}",
            f"- AI 是否建议扫描：{'是' if run.scan_recommended else '否'}",
            f"- 判断理由：{_safe(run.scan_reason) or '-'}",
            f"- 目标数量：{len(run.scan_targets):,}",
            f"- 模板 ID：{', '.join(run.scan_template_ids) or '-'}",
            f"- 严重级别：{', '.join(run.scan_severities)}",
            f"- 执行状态：`{scan_status}`",
            f"- 扫描产物：{run.scan_artifact or '-'}",
        ]
    )
    if scan_error:
        lines.append(f"- 扫描错误：{_safe(scan_error)}")
    scan_section = _nuclei_report_section(run.scan_artifact, target_count=len(run.scan_targets))
    if scan_section:
        lines.extend(["", *scan_section])
    lines.extend(
        [
            "",
            "## 模型路由与用量",
            "",
            "| 任务 | 提供商 | 模型 | 回退 | 输入 | 输出 |",
            "|---|---|---|---|---:|---:|",
        ]
    )
    for event in run.route_events:
        lines.append(
            "| {task} | {provider} | {model} | {fallback} | {input} | {output} |".format(
                task=_safe(event.get("task")),
                provider=_safe(event.get("provider")),
                model=_safe(event.get("model")),
                fallback="是" if event.get("fallback") else "否",
                input=event.get("input_tokens") or "-",
                output=event.get("output_tokens") or "-",
            )
        )
    lines.extend(
        [
            "",
            "> FOFA 指纹代表资产暴露信息，不等同于已确认漏洞。Nuclei 结果也应由授权人员复核。",
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")
    run.report_artifact = str(destination.resolve())
    return destination


def _nuclei_report_section(artifact: str | None, *, target_count: int) -> list[str]:
    if not artifact:
        return []
    path = Path(artifact)
    if path.suffix != ".jsonl" or not path.is_file():
        return []
    try:
        result = load_nuclei_result(path, target_count=target_count)
    except OSError:
        return []
    markdown = format_nuclei_summary_markdown(result)
    body = markdown.splitlines()
    if body and body[0].startswith("# "):
        body[0] = "## Nuclei 扫描结果"
    return body
