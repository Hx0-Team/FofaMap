"""HTTP adapters for Responses, OpenAI-compatible Chat, Anthropic and Ollama."""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from jsonschema import Draft202012Validator

from config import ProviderProfile
from providers.base import ModelCapabilities, ModelResult, ProviderError


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("type") in {None, "text", "output_text"}:
                parts.append(str(item.get("text") or item.get("content") or ""))
        return "".join(parts).strip()
    return ""


def _strip_think_blocks(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()


def assistant_message_text(message: Any) -> str:
    """User-facing assistant text. Hidden reasoning is never treated as the answer."""
    if not isinstance(message, dict):
        return ""
    text = _strip_think_blocks(_content_to_text(message.get("content")))
    return text


class HttpModelProvider:
    def __init__(
        self, name: str, profile: ProviderProfile, *, client: httpx.AsyncClient | None = None, execution_mode: str = "service"
    ) -> None:
        self.name = name
        self.profile = profile
        self._client = client
        self._owns_client = client is None
        self.execution_mode = execution_mode

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.profile.timeout, verify=True, follow_redirects=False)
        return self._client

    def _api_key(self) -> str:
        if self.profile.credential_kind in {"subscription", "interactive_only"} and self.execution_mode != "interactive":
            raise ProviderError(
                "订阅或编程套餐凭证只能在厂商允许的交互环境中使用。",
                code="model_credential_not_allowed",
                hint="服务端智能体请改用标准按量 API 密钥；订阅模型请由 Codex/Cursor/Claude Code 通过 MCP 调用。",
            )
        key = os.getenv(self.profile.api_key_env, "") if self.profile.api_key_env else ""
        if not key and self.profile.api_key_env:
            try:
                import keyring

                key = keyring.get_password("fofamap-provider", self.profile.api_key_env) or ""
            except Exception:
                key = ""
        if not key:
            key = self.profile.runtime_api_key
        if not key:
            key = self.profile.api_key
        if self.profile.credential_kind != "none" and self.profile.api_key_env and not key:
            raise ProviderError(
                f"AI 提供商 {self.name!r} 缺少 API 密钥（{self.profile.api_key_env} 未设置）。",
                code="model_auth_failed",
                hint=f"运行 `fofamap init` 重新保存密钥，或设置环境变量 {self.profile.api_key_env}。",
            )
        return key

    def _headers(self) -> dict[str, str]:
        key = self._api_key()
        if self.profile.protocol == "anthropic_messages":
            return {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        headers = {"content-type": "application/json"}
        if key:
            headers["authorization"] = f"Bearer {key}"
        return headers

    async def _json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        client = await self._get_client()
        try:
            response = await client.request(
                method,
                f"{self.profile.base_url.rstrip('/')}{path}",
                headers=self._headers(),
                **kwargs,
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise ProviderError(
                f"无法连接 AI 提供商 {self.name!r}：{exc}",
                retryable=True,
                code="model_transport_error",
                hint="运行 `fofamap init` 检查接口地址，并确认网络、代理和本地模型服务是否可用。",
            ) from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError(
                f"AI 提供商 {self.name!r} 返回了非 JSON 响应（HTTP {response.status_code}）。",
                code="model_response_error",
                hint="检查接口地址与协议是否匹配，例如 Responses、Chat Completions、Anthropic 或 Ollama。",
                status_code=response.status_code,
            ) from exc
        if response.is_error:
            message = data.get("error", data)
            message_text = str(message).lower()
            if response.status_code in {401, 403} or any(
                marker in message_text for marker in ("api key", "apikey", "unauthorized", "authentication failed")
            ):
                code = "model_auth_failed"
                hint = "API 密钥无效、过期或无权限。运行 `fofamap init` 重新填写，或更新对应环境变量/系统钥匙串。"
            elif response.status_code == 404 or (
                "model" in message_text and any(marker in message_text for marker in ("not found", "does not exist", "invalid model"))
            ):
                code = "model_not_found"
                hint = "运行 `fofamap init` 检查模型 ID、接口地址和协议；本地模型还需确认服务已经启动。"
            elif response.status_code == 429:
                code = "model_rate_limited"
                hint = "模型额度或速率已用尽，请检查供应商账户、套餐配额，或稍后重试。"
            elif response.status_code >= 500:
                code = "model_transport_error"
                hint = "模型服务暂时不可用，请稍后重试；持续失败时检查接口地址和供应商状态。"
            else:
                code = "model_request_error"
                hint = "检查模型 ID、上下文限制、结构化输出能力和提供商协议配置。"
            raise ProviderError(
                f"AI 提供商 {self.name!r} 请求失败（HTTP {response.status_code}）：{message}",
                retryable=response.status_code in {429, 500, 502, 503, 504},
                code=code,
                hint=hint,
                status_code=response.status_code,
            )
        return data

    async def discover_models(self) -> list[str]:
        if self.profile.protocol == "ollama_native":
            data = await self._json("GET", "/api/tags")
            return [item.get("name") or item.get("model") for item in data.get("models", []) if item.get("name") or item.get("model")]
        data = await self._json("GET", "/models")
        return [item["id"] for item in data.get("data", []) if item.get("id")]

    async def capabilities(self, model: str | None = None) -> ModelCapabilities:
        protocol = self.profile.protocol
        return ModelCapabilities(
            tool_calling=True if protocol in {"openai_responses", "openai_chat", "anthropic_messages", "ollama_native"} else None,
            structured_output=True,
            streaming=True,
            reasoning_effort=protocol == "openai_responses",
            max_output_tokens=self.profile.max_output_tokens,
        )

    @staticmethod
    def _decode_json(text: str) -> dict[str, Any] | list[Any] | None:
        candidate = text.strip()
        if candidate.startswith("```"):
            candidate = candidate.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, (dict, list)) else None
        except json.JSONDecodeError:
            pass

        # Prompt-structured and reasoning models sometimes wrap an otherwise
        # valid JSON value in prose, <think> blocks or a Markdown fence. Decode
        # the last complete top-level object/array instead of rejecting it.
        decoder = json.JSONDecoder()
        decoded: list[tuple[int, int, dict[str, Any] | list[Any]]] = []
        for match in re.finditer(r"[\[{]", candidate):
            try:
                value, consumed = decoder.raw_decode(candidate[match.start() :])
            except json.JSONDecodeError:
                continue
            if isinstance(value, (dict, list)):
                decoded.append((match.start() + consumed, -match.start(), value))
        return max(decoded, key=lambda item: (item[0], item[1]))[2] if decoded else None

    def _uses_deepseek_thinking(self) -> bool:
        haystack = f"{self.name} {self.profile.base_url} {self.profile.model}".lower()
        return "deepseek" in haystack

    def _chat_thinking_payload(self, *, omit_thinking: bool) -> dict[str, Any]:
        if omit_thinking or not self._uses_deepseek_thinking():
            return {}
        effort = (self.profile.reasoning_effort or "").strip().lower()
        if effort in {"", "none", "off", "disabled"}:
            # DeepSeek V4 Flash thinks by default; reasoning tokens share max_tokens
            # with content and can return HTTP 200 with an empty final answer.
            return {"thinking": {"type": "disabled"}}
        payload: dict[str, Any] = {"thinking": {"type": "enabled"}}
        if effort in {"low", "high", "max"}:
            payload["reasoning_effort"] = effort
        return payload

    async def generate(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict[str, Any] | None = None,
        model: str | None = None,
    ) -> ModelResult:
        repair_prompt = prompt
        native_structured = bool(schema) and self.profile.structured_output_mode != "prompt"
        repair_attempts = 0
        omit_thinking = False
        while True:
            try:
                return await self._generate_once(
                    system=system,
                    prompt=repair_prompt,
                    schema=schema,
                    model=model,
                    native_structured=native_structured,
                    omit_thinking=omit_thinking,
                )
            except ProviderError as exc:
                message = str(exc).lower()
                if (
                    not omit_thinking
                    and exc.code == "model_request_error"
                    and "thinking" in message
                ):
                    omit_thinking = True
                    continue
                native_schema_unavailable = exc.code == "model_request_error" and any(
                    marker in message for marker in ("response_format", "json_schema", "text.format")
                ) and any(marker in message for marker in ("unavailable", "not support", "unsupported", "unknown", "invalid"))
                if (
                    schema
                    and native_structured
                    and native_schema_unavailable
                    and self.profile.structured_output_mode != "native"
                ):
                    # OpenAI-compatible does not mean every provider implements
                    # native response_format/json_schema. Keep the schema in the
                    # prompt and validate/repair the returned JSON locally.
                    native_structured = False
                    continue
                if not schema or exc.code != "model_structured_output_error" or repair_attempts >= 2:
                    raise
                repair_attempts += 1
                repair_prompt = (
                    prompt
                    + "\nYour previous response was not valid JSON for the required schema. "
                    + "Return only one corrected JSON value with no Markdown fence."
                )

    async def _generate_once(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict[str, Any] | None = None,
        model: str | None = None,
        native_structured: bool = True,
        omit_thinking: bool = False,
    ) -> ModelResult:
        selected_model = model or self.profile.model
        if not selected_model:
            models = await self.discover_models()
            if not models:
                raise ProviderError(
                    f"AI 提供商 {self.name!r} 没有发现可用模型。",
                    code="model_not_found",
                    hint="运行 `fofamap init` 填写明确的模型 ID，或启动 Ollama/LM Studio 并安装模型。",
                )
            selected_model = models[0]
        protocol = self.profile.protocol
        schema_suffix = ""
        if schema:
            schema_suffix = "\nReturn only JSON matching this JSON Schema:\n" + json.dumps(schema, ensure_ascii=False)

        if protocol == "openai_responses":
            body: dict[str, Any] = {
                "model": selected_model,
                "instructions": system,
                "input": prompt if native_structured else prompt + schema_suffix,
                "max_output_tokens": self.profile.max_output_tokens,
            }
            if self.profile.reasoning_effort:
                body["reasoning"] = {"effort": self.profile.reasoning_effort}
            if schema and native_structured:
                body["text"] = {"format": {"type": "json_schema", "name": "fofamap_output", "strict": True, "schema": schema}}
            data = await self._json("POST", "/responses", json=body)
            text = data.get("output_text", "")
            if not text:
                text = "".join(
                    part.get("text", "")
                    for item in data.get("output", [])
                    for part in item.get("content", [])
                    if part.get("type") in {"output_text", "text"}
                )
            usage = data.get("usage") or {}
        elif protocol == "anthropic_messages":
            body = {
                "model": selected_model,
                "system": system,
                "messages": [{"role": "user", "content": prompt + schema_suffix}],
                "max_tokens": self.profile.max_output_tokens,
            }
            data = await self._json("POST", "/v1/messages", json=body)
            text = "".join(item.get("text", "") for item in data.get("content", []) if item.get("type") == "text")
            usage = data.get("usage") or {}
        elif protocol == "ollama_native":
            body = {
                "model": selected_model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt + schema_suffix}],
                "stream": False,
            }
            if schema and native_structured:
                body["format"] = schema
            data = await self._json("POST", "/api/chat", json=body)
            text = assistant_message_text(data.get("message") or {})
            usage = {"input_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count")}
        else:
            body = {
                "model": selected_model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt + schema_suffix}],
                "max_tokens": self.profile.max_output_tokens,
            }
            body.update(self._chat_thinking_payload(omit_thinking=omit_thinking))
            if schema and native_structured:
                body["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": "fofamap_output", "strict": True, "schema": schema},
                }
            data = await self._json("POST", "/chat/completions", json=body)
            text = assistant_message_text((data.get("choices") or [{}])[0].get("message") or {})
            usage = data.get("usage") or {}

        structured = self._decode_json(text) if schema else None
        schema_error = None
        if schema and structured is not None:
            validation_errors = list(Draft202012Validator(schema).iter_errors(structured))
            if validation_errors:
                schema_error = validation_errors[0].message
        if schema and (structured is None or schema_error):
            raise ProviderError(
                f"模型 {self.name}/{selected_model} 未返回符合 Schema 的结构化 JSON。"
                + (f" 首个校验错误：{schema_error}" if schema_error else ""),
                code="model_structured_output_error",
                hint="该模型可能不支持可靠的结构化输出；请在 `fofamap init` 中更换模型或接口协议。",
            )
        return ModelResult(
            text=text,
            structured=structured,
            model=selected_model,
            provider=self.name,
            input_tokens=usage.get("input_tokens") or usage.get("prompt_tokens"),
            output_tokens=usage.get("output_tokens") or usage.get("completion_tokens"),
            raw_id=data.get("id"),
        )
