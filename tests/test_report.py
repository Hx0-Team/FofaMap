from pathlib import Path

from core.agent import AgentAction, AgentRun, AgentState, AgentStep
from core.report import write_agent_report


def test_agent_markdown_report_contains_query_scan_decision_and_usage(tmp_path: Path):
    run = AgentRun(
        intent="收集授权资产并扫描",
        state=AgentState.COMPLETED,
        query='domain="example.edu"',
        fields=["host", "ip", "title"],
        result_count=12,
        assets=[{"host": "https://example.edu", "ip": "203.0.113.10", "title": "Example University"}],
        summary="发现 12 个公开资产。",
        scan_requested_by_user=True,
        scan_recommended=True,
        scan_reason="存在 HTTP 资产",
        scan_template_ids=["http-missing-security-headers"],
        scan_targets=["https://example.edu"],
        steps=[AgentStep(state=AgentState.EXECUTE, detail="FOFA query completed")],
        route_events=[{"task": "planner", "provider": "openai", "model": "gpt-5.6", "fallback": False}],
    )
    path = write_agent_report(run, tmp_path / "report.md", scan_status="declined")
    content = path.read_text(encoding="utf-8")
    assert 'domain="example.edu"' in content
    assert "http-missing-security-headers" in content
    assert "declined" in content
    assert "gpt-5.6" in content
    assert "## 查询到的资产" in content
    assert "https://example.edu" in content
    assert content.index("## 查询到的资产") < content.index("## AI 总结")
    assert "## Nuclei 扫描结果" not in content


def test_agent_markdown_report_includes_nuclei_summary(tmp_path: Path):
    jsonl = tmp_path / "nuclei.jsonl"
    jsonl.write_text(
        '{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers",'
        '"severity":"info"},"matched-at":"https://www.example.edu","matcher-name":"x-frame-options"}\n',
        encoding="utf-8",
    )
    run = AgentRun(
        intent="收集授权资产并扫描",
        state=AgentState.COMPLETED,
        query='domain="example.edu"',
        result_count=1,
        assets=[{"host": "https://www.example.edu"}],
        summary="发现公开资产。",
        scan_requested_by_user=True,
        scan_recommended=True,
        scan_reason="存在 HTTP 资产",
        scan_template_ids=["http-missing-security-headers"],
        scan_targets=["https://www.example.edu"],
        scan_artifact=str(jsonl),
        steps=[AgentStep(state=AgentState.EXECUTE, detail="FOFA query completed")],
    )
    content = write_agent_report(run, tmp_path / "report.md", scan_status="completed").read_text(encoding="utf-8")
    assert "## Nuclei 扫描结果" in content
    assert "命中 1 条" in content
    assert "https://www.example.edu" in content
    assert "x-frame-options" in content


def test_routed_host_report_contains_structured_host_appendix(tmp_path: Path):
    run = AgentRun(
        intent="分析 8.8.8.8",
        action=AgentAction.HOST,
        target="8.8.8.8",
        state=AgentState.COMPLETED,
        result_count=1,
        result_data={
            "host": "8.8.8.8",
            "ip": "8.8.8.8",
            "org": "Example DNS",
            "ports": [{"port": 53, "protocol": "udp", "products": [{"product": "DNS"}]}],
        },
        summary="观察到 DNS 服务。",
    )

    content = write_agent_report(run, tmp_path / "host.md").read_text(encoding="utf-8")

    assert "`host_query`" in content
    assert "## 主机聚合画像" in content
    assert "| 53 | udp | DNS |" in content
    assert "## 查询到的资产候选" not in content


def test_routed_stats_report_contains_aggregate_tables(tmp_path: Path):
    run = AgentRun(
        intent="统计 Redis 国家分布",
        action=AgentAction.STATS,
        state=AgentState.COMPLETED,
        query='app="Redis"',
        result_count=1234,
        result_data={"size": 1234, "aggs": {"country": [{"name": "US", "count": 700}]}},
        summary="美国样本最多。",
    )

    content = write_agent_report(run, tmp_path / "stats.md").read_text(encoding="utf-8")

    assert "`stat_query`" in content
    assert "## 统计聚合结果" in content
    assert "| 1 | US | 700 |" in content
