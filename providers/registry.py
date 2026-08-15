"""Provider presets and explicit, auditable task routing."""

from __future__ import annotations

from typing import Any

from config import Config
from providers.base import ModelResult, ProviderError, RouteEvent
from providers.http import HttpModelProvider

MODEL_PRESETS: dict[str, dict[str, Any]] = {
    "openai": {
        "protocol": "openai_responses",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-5.6", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
    },
    "deepseek": {"protocol": "openai_chat", "base_url": "https://api.deepseek.com/v1", "models": ["deepseek-v4-flash", "deepseek-v4-pro"]},
    "zhipu": {"protocol": "openai_chat", "base_url": "https://open.bigmodel.cn/api/paas/v4", "models": ["glm-5.2"]},
    "anthropic": {
        "protocol": "anthropic_messages",
        "base_url": "https://api.anthropic.com",
        "models": ["claude-fable-5", "claude-opus-5", "claude-sonnet-5"],
    },
    "xai": {"protocol": "openai_chat", "base_url": "https://api.x.ai/v1", "models": ["grok-4.6"]},
    "minimax": {"protocol": "openai_chat", "base_url": "https://api.minimax.io/v1", "models": ["MiniMax-M3"]},
    "mimo": {"protocol": "openai_chat", "base_url": "https://api.xiaomimimo.com/v1", "models": ["mimo-v2.5", "mimo-v2.5-pro"]},
    "ollama": {"protocol": "ollama_native", "base_url": "http://127.0.0.1:11434", "models": []},
    "lmstudio": {"protocol": "openai_responses", "base_url": "http://127.0.0.1:1234/v1", "models": []},
}


class ProviderRegistry:
    def __init__(self, config: Config, *, execution_mode: str = "service") -> None:
        self.config = config
        self.execution_mode = execution_mode
        self.providers = {
            name: HttpModelProvider(name, profile, execution_mode=execution_mode) for name, profile in config.providers.items()
        }

    def get(self, name: str) -> HttpModelProvider:
        if name not in self.providers:
            raise ProviderError(
                f"AI 提供商 {name!r} 尚未配置。",
                code="model_provider_not_configured",
                hint="运行 `fofamap init` 重新配置 AI 提供商、模型 ID 和 API 密钥。",
            )
        return self.providers[name]

    async def aclose(self) -> None:
        for provider in self.providers.values():
            await provider.aclose()


class ProviderRouter:
    def __init__(self, registry: ProviderRegistry) -> None:
        self.registry = registry
        self.events: list[RouteEvent] = []

    def _profile_for_task(self, task: str) -> str:
        routing = self.registry.config.routing
        configured = getattr(routing, task, "")
        if task == "reflector" and not configured:
            configured = routing.query_repair
        return configured or routing.default

    async def generate(self, task: str, *, system: str, prompt: str, schema: dict[str, Any] | None = None) -> ModelResult:
        primary = self._profile_for_task(task)
        if not primary:
            raise ProviderError(
                f"任务 {task!r} 没有配置可用的 AI 提供商。",
                code="model_provider_not_configured",
                hint="运行 `fofamap init`，选择 AI 提供商并配置默认模型。",
            )
        candidates = [primary]
        routing = self.registry.config.routing
        if routing.allow_cross_provider_fallback:
            candidates.extend(name for name in routing.fallbacks if name != primary)
        last_error: Exception | None = None
        for index, name in enumerate(candidates):
            provider = self.registry.get(name)
            try:
                result = await provider.generate(system=system, prompt=prompt, schema=schema)
                self.events.append(
                    RouteEvent(
                        task=task,
                        provider=name,
                        model=result.model,
                        reason="configured task route" if index == 0 else f"fallback after: {last_error}",
                        fallback=index > 0,
                        input_tokens=result.input_tokens,
                        output_tokens=result.output_tokens,
                    )
                )
                return result
            except ProviderError as exc:
                last_error = exc
                if index == 0 and (not routing.allow_cross_provider_fallback or not exc.retryable):
                    raise
        raise last_error or ProviderError("all configured providers failed")
