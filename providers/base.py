"""Vendor-neutral model provider contracts."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel


class ModelCapabilities(BaseModel):
    tool_calling: bool | None = None
    structured_output: bool | None = None
    vision: bool | None = None
    streaming: bool | None = None
    reasoning_effort: bool | None = None
    context_window: int | None = None
    max_output_tokens: int | None = None


class ModelResult(BaseModel):
    text: str
    structured: dict[str, Any] | list[Any] | None = None
    model: str
    provider: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    raw_id: str | None = None


class ProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        code: str = "model_provider_error",
        hint: str | None = None,
        status_code: int | None = None,
    ):
        super().__init__(message)
        self.retryable = retryable
        self.code = code
        self.hint = hint
        self.status_code = status_code


class ModelProvider(Protocol):
    name: str

    async def discover_models(self) -> list[str]: ...

    async def capabilities(self, model: str | None = None) -> ModelCapabilities: ...

    async def generate(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict[str, Any] | None = None,
        model: str | None = None,
    ) -> ModelResult: ...


class RouteEvent(BaseModel):
    task: str
    provider: str
    model: str
    reason: str
    fallback: bool = False
    input_tokens: int | None = None
    output_tokens: int | None = None
    estimated_cost: float | None = None
