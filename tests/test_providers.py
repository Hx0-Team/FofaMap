import json

import httpx
import pytest

from config import Config, ProviderProfile
from providers.base import ModelResult, ProviderError
from providers.http import HttpModelProvider, assistant_message_text
from providers.registry import ProviderRegistry, ProviderRouter


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("protocol", "response", "expected_path"),
    [
        ("openai_responses", {"id": "r1", "output_text": '{"query":"x"}', "usage": {"input_tokens": 2, "output_tokens": 3}}, "/responses"),
        (
            "openai_chat",
            {"choices": [{"message": {"content": '{"query":"x"}'}}], "usage": {"prompt_tokens": 2, "completion_tokens": 3}},
            "/chat/completions",
        ),
        (
            "anthropic_messages",
            {"content": [{"type": "text", "text": '{"query":"x"}'}], "usage": {"input_tokens": 2, "output_tokens": 3}},
            "/v1/messages",
        ),
        ("ollama_native", {"message": {"content": '{"query":"x"}'}, "prompt_eval_count": 2, "eval_count": 3}, "/api/chat"),
    ],
)
async def test_all_protocols_return_common_result(protocol, response, expected_path):
    seen = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        return httpx.Response(200, json=response)

    profile = ProviderProfile(
        protocol=protocol, base_url="https://model.test", model="arbitrary-future-model", api_key_env="", credential_kind="none"
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        provider = HttpModelProvider("test", profile, client=http)
        result = await provider.generate(system="s", prompt="p", schema={"type": "object"})
    assert result.structured == {"query": "x"}
    assert result.model == "arbitrary-future-model"
    assert seen == [expected_path]


@pytest.mark.asyncio
async def test_ollama_model_discovery():
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"models": [{"name": "qwen:latest"}]}))
    profile = ProviderProfile(protocol="ollama_native", base_url="http://ollama.test", credential_kind="none")
    async with httpx.AsyncClient(transport=transport) as http:
        models = await HttpModelProvider("ollama", profile, client=http).discover_models()
    assert models == ["qwen:latest"]


def test_assistant_message_text_ignores_hidden_reasoning():
    assert assistant_message_text({"content": "", "reasoning_content": "long hidden chain of thought"}) == ""
    assert assistant_message_text({"content": None, "reasoning_content": "hidden"}) == ""
    assert assistant_message_text({"content": [{"type": "text", "text": "## 结论\nOK"}]}) == "## 结论\nOK"
    assert assistant_message_text({"content": "<think>plan</think>\n## 结论\n正文"}) == "## 结论\n正文"


@pytest.mark.asyncio
async def test_deepseek_chat_disables_thinking_by_default():
    seen: list[dict] = []

    def handler(request: httpx.Request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-v4-flash",
        api_key_env="",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        provider = HttpModelProvider("deepseek", profile, client=http)
        result = await provider.generate(system="s", prompt="p")
    assert result.text == "ok"
    assert seen[0]["thinking"] == {"type": "disabled"}
    assert "reasoning_effort" not in seen[0]
    assert seen[0]["max_tokens"] == 32768


@pytest.mark.asyncio
async def test_non_deepseek_chat_does_not_send_thinking():
    seen: list[dict] = []

    def handler(request: httpx.Request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="gpt-test",
        api_key_env="",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        provider = HttpModelProvider("test", profile, client=http)
        await provider.generate(system="s", prompt="p")
    assert "thinking" not in seen[0]


@pytest.mark.asyncio
async def test_empty_reasoning_content_is_not_used_as_chat_answer():
    def handler(_request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "", "reasoning_content": "spent the whole budget thinking"}}],
                "usage": {"prompt_tokens": 3000, "completion_tokens": 4096},
            },
        )

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-v4-flash",
        api_key_env="",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        provider = HttpModelProvider("deepseek", profile, client=http)
        result = await provider.generate(system="s", prompt="p")
    assert result.text == ""
    assert result.output_tokens == 4096


def test_legacy_runtime_key_is_used_but_excluded_from_serialization():
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://provider.test/v1",
        api_key_env="MODEL_API_KEY",
        runtime_api_key="legacy-only-in-memory",
    )
    provider = HttpModelProvider("legacy", profile)
    assert provider._api_key() == "legacy-only-in-memory"
    assert "runtime_api_key" not in profile.model_dump()


def test_explicit_yaml_profile_key_is_used_but_excluded_from_serialization():
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://provider.test/v1",
        api_key_env="MODEL_API_KEY",
        api_key="confirmed-local-key",
    )
    provider = HttpModelProvider("local", profile)
    assert provider._api_key() == "confirmed-local-key"
    assert "api_key" not in profile.model_dump()


@pytest.mark.asyncio
async def test_structured_output_gets_at_most_two_repairs():
    responses = iter(["not json", "still not json", '{"query":"fixed"}'])

    def handler(_: httpx.Request):
        return httpx.Response(200, json={"choices": [{"message": {"content": next(responses)}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test",
        model="json-challenged-model",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        provider = HttpModelProvider("test", profile, client=http)
        result = await provider.generate(system="s", prompt="p", schema={"type": "object"})
    assert result.structured == {"query": "fixed"}


@pytest.mark.asyncio
async def test_structured_output_accepts_json_wrapped_in_reasoning_or_prose():
    response = '<think>Need a query, not {"final": true} yet.</think>\nResult:\n```json\n{"query":"fixed"}\n```'
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json={"choices": [{"message": {"content": response}}]})
    )
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test",
        model="reasoning-model",
        credential_kind="none",
        structured_output_mode="prompt",
    )
    async with httpx.AsyncClient(transport=transport) as http:
        result = await HttpModelProvider("test", profile, client=http).generate(
            system="s",
            prompt="p",
            schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        )
    assert result.structured == {"query": "fixed"}


@pytest.mark.asyncio
async def test_openai_compatible_falls_back_when_native_response_format_is_unavailable():
    bodies = []

    def handler(request: httpx.Request):
        bodies.append(__import__("json").loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(
                400,
                json={"error": {"message": "This response_format type is unavailable now", "type": "invalid_request_error"}},
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"query":"app=\\"nginx\\""}'}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="compatible-model",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await HttpModelProvider("compatible", profile, client=http).generate(
            system="s",
            prompt="p",
            schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
    assert result.structured == {"query": 'app="nginx"'}
    assert "response_format" in bodies[0]
    assert "response_format" not in bodies[1]
    assert "Return only JSON matching this JSON Schema" in bodies[1]["messages"][1]["content"]


@pytest.mark.asyncio
async def test_prompt_structured_mode_skips_unsupported_native_format_on_first_request():
    bodies = []

    def handler(request: httpx.Request):
        bodies.append(__import__("json").loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"query":"x"}'}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="prompt-json-model",
        credential_kind="none",
        structured_output_mode="prompt",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await HttpModelProvider("prompt", profile, client=http).generate(
            system="s",
            prompt="p",
            schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
    assert result.structured == {"query": "x"}
    assert len(bodies) == 1
    assert "response_format" not in bodies[0]
    assert "Return only JSON matching this JSON Schema" in bodies[0]["messages"][1]["content"]


@pytest.mark.asyncio
async def test_prompt_mode_repairs_json_that_parses_but_fails_schema_validation():
    responses = iter(['{"wrong":true}', '{"query":"fixed"}'])

    def handler(_: httpx.Request):
        return httpx.Response(200, json={"choices": [{"message": {"content": next(responses)}}]})

    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="prompt-json-model",
        credential_kind="none",
        structured_output_mode="prompt",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await HttpModelProvider("prompt", profile, client=http).generate(
            system="s",
            prompt="p",
            schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        )
    assert result.structured == {"query": "fixed"}


@pytest.mark.asyncio
async def test_interactive_subscription_credential_is_rejected_by_service():
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test",
        model="plan-model",
        api_key_env="SUBSCRIPTION_KEY",
        credential_kind="interactive_only",
    )
    provider = HttpModelProvider("coding-plan", profile, execution_mode="service")
    with pytest.raises(ProviderError) as captured:
        await provider.generate(system="s", prompt="p")
    assert captured.value.code == "model_credential_not_allowed"
    assert "MCP" in captured.value.hint


@pytest.mark.asyncio
async def test_incorrect_model_api_key_has_actionable_error():
    transport = httpx.MockTransport(lambda _: httpx.Response(401, json={"error": {"message": "invalid api key"}}))
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="test-model",
        api_key_env="TEST_MODEL_API_KEY",
        runtime_api_key="incorrect-key",
    )
    async with httpx.AsyncClient(transport=transport) as http:
        provider = HttpModelProvider("test", profile, client=http)
        with pytest.raises(ProviderError) as captured:
            await provider.generate(system="s", prompt="p")
    assert captured.value.code == "model_auth_failed"
    assert captured.value.status_code == 401
    assert "fofamap init" in captured.value.hint


@pytest.mark.asyncio
async def test_invalid_model_or_endpoint_has_actionable_error():
    transport = httpx.MockTransport(lambda _: httpx.Response(400, json={"error": {"message": "invalid model: model not found"}}))
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="https://model.test/v1",
        model="missing-model",
        credential_kind="none",
    )
    async with httpx.AsyncClient(transport=transport) as http:
        provider = HttpModelProvider("test", profile, client=http)
        with pytest.raises(ProviderError) as captured:
            await provider.generate(system="s", prompt="p")
    assert captured.value.code == "model_not_found"
    assert "模型 ID" in captured.value.hint


@pytest.mark.asyncio
async def test_invalid_base_url_has_actionable_transport_error():
    profile = ProviderProfile(
        protocol="openai_chat",
        base_url="://bad-model-url",
        model="test-model",
        credential_kind="none",
    )
    provider = HttpModelProvider("test", profile)
    with pytest.raises(ProviderError) as captured:
        await provider.generate(system="s", prompt="p")
    await provider.aclose()
    assert captured.value.code == "model_transport_error"
    assert "接口地址" in captured.value.hint


@pytest.mark.asyncio
async def test_unconfigured_planner_points_to_init_wizard():
    router = ProviderRouter(ProviderRegistry(Config()))
    with pytest.raises(ProviderError) as captured:
        await router.generate("planner", system="s", prompt="p")
    assert captured.value.code == "model_provider_not_configured"
    assert "fofamap init" in captured.value.hint


def test_reflector_route_falls_back_to_query_repair_profile():
    config = Config.model_validate({"routing": {"default": "default", "query_repair": "repair-model"}})
    router = ProviderRouter(ProviderRegistry(config))

    assert router._profile_for_task("reflector") == "repair-model"


class _RoutedProvider:
    def __init__(self, name, result=None, error=None):
        self.name = name
        self.result = result
        self.error = error

    async def generate(self, **_):
        if self.error:
            raise self.error
        return self.result


@pytest.mark.asyncio
async def test_explicit_cross_provider_fallback_is_recorded():
    config = Config.model_validate(
        {
            "routing": {
                "default": "primary",
                "allow_cross_provider_fallback": True,
                "fallbacks": ["backup"],
            }
        }
    )
    registry = ProviderRegistry(config)
    registry.providers = {
        "primary": _RoutedProvider("primary", error=ProviderError("rate limited", retryable=True)),
        "backup": _RoutedProvider(
            "backup",
            result=ModelResult(text="ok", model="backup-model", provider="backup"),
        ),
    }
    router = ProviderRouter(registry)
    result = await router.generate("summarizer", system="s", prompt="p")
    assert result.text == "ok"
    assert router.events[0].fallback is True
    assert router.events[0].provider == "backup"
