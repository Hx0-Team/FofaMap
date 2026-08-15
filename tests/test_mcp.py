import pytest
from mcp import Client

from mcp_server import mcp


@pytest.mark.asyncio
async def test_mcp_v2_structured_schema_and_annotations():
    async with Client(mcp) as client:
        tools = await client.list_tools()
        by_name = {tool.name: tool for tool in tools.tools}
        assert "fofa_search" in by_name
        assert "fofa_syntax" in by_name
        assert "fofa_rules" in by_name
        assert "fofa_fields" in by_name
        assert "fofa_account" in by_name
        assert "fofa_icon_search" in by_name
        assert by_name["fofa_search"].output_schema["type"] == "object"
        assert by_name["fofa_search"].annotations.read_only_hint is True
        assert by_name["nuclei_execute"].annotations.destructive_hint is True
        result = await client.call_tool("fofa_validate_query", {"query": 'app="nginx"'})
        assert result.structured_content["data"]["valid"] is True
        assert result.content
        syntax = await client.call_tool("fofa_syntax", {})
        assert syntax.structured_content["data"]["source"] == "https://fofa.info/api/introd"
        fields = await client.call_tool("fofa_fields", {})
        assert fields.structured_content["data"]["memberships"]
        rules = await client.call_tool("fofa_rules", {"keyword": "ThinkPHP"})
        assert rules.structured_content["data"]["count"] >= 1
