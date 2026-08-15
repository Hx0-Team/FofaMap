from io import StringIO

from rich.console import Console

from core.fields import account_tier, field_catalog, fofa_request_fields, merge_return_fields, suggest_fields
from core.membership import (
    capability_error,
    capped_requests_per_second,
    format_quota,
    host_fallback_query,
    membership_for,
)
from utils import cli_ui


def test_account_tier_maps_official_vip_levels_exactly():
    assert account_tier(0) is None
    assert account_tier(1) == "personal"
    assert account_tier(2) == "professional"
    assert account_tier(5) == "enterprise"
    assert account_tier(11) == "personal"
    assert account_tier(12) == "professional"
    assert account_tier(13) == "business"
    assert account_tier(22) == "personal"
    assert account_tier(14) is None
    assert account_tier("unknown") is None


def test_education_account_is_not_treated_as_business():
    membership = membership_for(22)
    assert membership is not None
    assert membership.name == "教育账户"
    assert membership.field_tier == "personal"
    assert membership.host_api is True
    assert membership.stats_api is False
    assert membership.requests_per_second == 1.0


def test_registered_user_has_no_host_or_stats_api():
    membership = membership_for(0)
    assert membership is not None
    assert membership.host_api is False
    assert membership.stats_api is False
    assert capability_error({"vip_level": 0}, "host")
    assert capability_error({"vip_level": 11}, "stats")
    assert capability_error({"vip_level": 2}, "stats") is None
    assert capability_error({"vip_level": 13}, "host") is None
    assert capability_error({}, "stats") is None


def test_rate_limit_is_capped_to_official_concurrency():
    assert capped_requests_per_second(2.0, 11) == 1.0
    assert capped_requests_per_second(2.0, 13) == 2.0
    assert capped_requests_per_second(2.0, 5) == 2.0
    assert capped_requests_per_second(10.0, 5) == 5.0
    assert capped_requests_per_second(100.0, None) == 100.0


def test_daily_pack_quota_renders_minus_one_as_3000_requests():
    text = format_quota({"vip_level": 1, "remain_api_query": -1, "remain_api_data": -1, "fofa_point": 12})
    assert "每日 3000 次" in text
    assert "F点：12" in text
    interface = format_quota({"vip_level": 12, "remain_api_query": 80, "remain_api_data": 40})
    assert "查询：80" in interface
    assert "数据：40" in interface


def test_host_fallback_query_uses_ip_or_host_clause():
    assert host_fallback_query("8.8.8.8") == 'ip="8.8.8.8"'
    assert host_fallback_query("2001:db8::1") == 'ip="2001:db8::1"'
    assert host_fallback_query("baidu.com") == 'host="baidu.com"'


def test_field_catalog_includes_official_membership_table():
    catalog = field_catalog()
    assert catalog["membership_source"] == "https://fofa.info/api"
    by_level = {item["vip_level"]: item for item in catalog["memberships"]}
    assert by_level[22]["stats_api"] is False
    assert by_level[22]["field_tier"] == "personal"
    assert by_level[0]["host_api"] is False
    assert by_level[5]["requests_per_second"] == 5.0


def test_suggest_fields_for_org_discovery_stays_within_membership():
    personal = suggest_fields("帮我收集一下中国通服的全网资产", account_tier_name="personal")
    business = suggest_fields("帮我收集一下中国通服的全网资产", account_tier_name="business")
    assert personal[0:5] == ["host", "protocol", "ip", "port", "title"]
    assert "org" in personal
    assert "domain" in personal
    assert "body" not in personal
    assert "icon_hash" not in personal
    assert "product" in business
    assert "lastupdatetime" in business
    assert len(personal) <= 8
    assert len(business) <= 14
    assert len(business) >= len(personal)


def test_merge_return_fields_drops_heavy_fields_unless_requested():
    merged = merge_return_fields(["host", "body", "product"], account_tier_name="professional", intent="收集哈佛大学资产")
    assert "host" in merged
    assert "body" not in merged
    content = suggest_fields("看一下网站正文和 banner", account_tier_name="business")
    assert "body" in content or "header" in content or "banner" in content


def test_render_account_shows_chinese_membership_and_api_caps(monkeypatch):
    stream = StringIO()
    monkeypatch.setattr(cli_ui, "console", Console(file=stream, width=120, color_system=None))
    cli_ui.render_account({"username": "hx0", "vip_level": 22, "remain_api_query": -1, "remain_api_data": -1})
    output = stream.getvalue()
    assert "教育账户" in output
    assert "vip_level=22" in output
    assert "主机聚合 是" in output
    assert "统计聚合 否" in output
    assert "每日 3000 次" in output


def test_local_alive_status_is_never_sent_to_fofa():
    assert fofa_request_fields(["host", "alive_status", "protocol", "evidence", "ip"]) == [
        "host",
        "protocol",
        "ip",
    ]
