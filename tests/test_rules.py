from core.agent import AgentQuery, _deterministic_fallback_plan, _merge_library_queries
from core.rules import (
    LIBRARY_RULES,
    library_size,
    match_intent_rules,
    resolve_rule_query,
    rules_catalog,
    rules_hint_for_prompt,
    search_rules,
)
from core.syntax import syntax_catalog


def test_library_resolves_official_app_query():
    assert resolve_rule_query("ThinkPHP").query == 'app="ThinkPHP"'
    assert resolve_rule_query("致远OA").query.startswith("app=")
    assert any(rule.name == "Redis" for rule in search_rules("redis"))


def test_library_has_high_value_coverage_and_unique_names():
    assert library_size() >= 180
    names = [rule.name for rule in LIBRARY_RULES]
    assert len(names) == len(set(names))
    catalog = rules_catalog()
    assert catalog["total"] == library_size()
    assert catalog["count"] == library_size()
    assert len(catalog["rules"]) == library_size()
    assert "OA" in catalog["categories"]
    assert catalog["count"] > 50


def test_rules_catalog_filters_by_keyword():
    catalog = rules_catalog("OA")
    assert catalog["source"] == "https://fofa.info/library"
    assert catalog["count"] >= 8
    assert "OA" in catalog["categories"]
    assert any(item["name"] == "致远OA" for item in catalog["rules"])


def test_match_intent_uses_official_app_query_for_named_product():
    matched = match_intent_rules("帮我找一下致远OA的暴露面")
    assert matched[0].name == "致远OA"
    assert matched[0].query == 'app="致远互联-OA"'
    hint = rules_hint_for_prompt("找一下蓝凌OA")
    assert 'app="蓝凌软件"' in hint
    assert match_intent_rules("帮我收集安徽省邮电职业技术学院的全网资产") == []


def test_match_intent_expands_oa_category_without_a_specific_product():
    names = {rule.name for rule in match_intent_rules("找一下国内的OA系统")}
    assert "致远OA" in names
    assert "泛微OA" in names


def test_fallback_and_merge_prefer_library_fingerprints():
    plan = _deterministic_fallback_plan("找一下致远OA")
    assert plan["queries"][0]["query"] == 'app="致远互联-OA"'
    assert plan["queries"][0]["strategy"] == "precision"
    merged = _merge_library_queries(
        "找一下 Jenkins",
        [AgentQuery(query='title="Jenkins"', purpose="名称召回", strategy="recall", source="planner")],
        limit=5,
    )
    assert merged[0].source == "library"
    assert merged[0].query == 'app="Jenkins"'
    assert merged[1].query == 'title="Jenkins"'


def test_syntax_catalog_covers_official_operators_and_app_field():
    catalog = syntax_catalog()
    assert catalog["source"] == "https://fofa.info/api/introd"
    assert {item["op"] for item in catalog["operators"]} >= {"=", "==", "!=", "&&", "||"}
    fields = {item["field"] for item in catalog["query_fields"]}
    assert {"app", "fid", "icon_hash", "status_code", "is_honeypot"} <= fields
