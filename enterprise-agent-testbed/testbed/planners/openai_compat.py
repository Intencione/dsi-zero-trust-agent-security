"""LLM planner for any OpenAI-compatible Chat Completions endpoint with tool calling.

Works with OpenAI and with OpenAI-compatible providers by setting OPENAI_BASE_URL,
e.g. DeepSeek, Qwen/DashScope compatible mode, Moonshot/Kimi, Zhipu, or a local
Ollama server (http://localhost:11434/v1).

Provider quirks handled here:
* Thinking/reasoning models (DeepSeek, Kimi, ...) return `reasoning_content`; with
  tool calls it must be sent back on later requests, so it is kept in the history.
* Provider-specific parameters go through --extra-body, e.g.
  '{"thinking": {"type": "disabled"}}' (DeepSeek) or '{"enable_thinking": false}' (Qwen),
  or '{"max_completion_tokens": 4000}' for OpenAI reasoning models.
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

from .base import Planner, PlannerTurn, PlannerUnavailable, ProposedCall

PASSTHROUGH_FIELDS = ("reasoning_content",)


class OpenAICompatPlanner(Planner):
    kind = "llm"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 temperature: float | None = None, max_tokens: int | None = None,
                 extra_body: dict[str, Any] | None = None, timeout: float = 180.0, max_retries: int = 3):
        try:
            import openai
        except ImportError as e:  # pragma: no cover
            raise SystemExit("The 'openai' package is required: pip install -r requirements.txt") from e
        self._sdk_version = getattr(openai, "__version__", "unknown")
        self.model = model
        # Resolve explicitly: an empty OPENAI_BASE_URL would otherwise break the SDK.
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key or key.endswith("..."):
            raise SystemExit("Set a real OPENAI_API_KEY (shell or .env) to use --planner openai.")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.extra_body = extra_body or {}
        self.timeout = timeout
        self.max_retries = max_retries
        self.client = openai.OpenAI(api_key=key, base_url=self.base_url, timeout=timeout, max_retries=max_retries)
        self.messages: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self._resolved: set[str] = set()
        self._fingerprints: set[str] = set()

    def describe(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "provider": "openai-compatible",
            "base_url_host": urlparse(str(self.client.base_url)).netloc,  # what the SDK actually uses
            "model": self.model,
            "temperature": self.temperature if self.temperature is not None else "provider default",
            "max_tokens": self.max_tokens if self.max_tokens is not None else "provider default",
            "extra_body": self.extra_body,
            "timeout_s": self.timeout,
            "max_retries": self.max_retries,
            "sdk": f"openai-python {self._sdk_version}",
        }

    def _kwargs(self, messages: list[dict[str, Any]], with_tools: bool) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages}
        if with_tools:
            kwargs["tools"] = self.tools
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        if self.extra_body:
            kwargs["extra_body"] = self.extra_body
        return kwargs

    def _note(self, resp: Any) -> None:
        if getattr(resp, "model", None):
            self._resolved.add(resp.model)
        if getattr(resp, "system_fingerprint", None):
            self._fingerprints.add(resp.system_fingerprint)

    def preflight(self) -> dict[str, Any]:
        try:
            resp = self.client.chat.completions.create(
                **self._kwargs([{"role": "user", "content": "Reply with the single word OK."}], with_tools=False))
        except Exception as e:
            raise PlannerUnavailable(f"{type(e).__name__}: {e}") from e
        self._note(resp)
        return {"preflight_ok": True, "resolved_model": getattr(resp, "model", None)}

    def observed(self) -> dict[str, Any]:
        return {"resolved_models": sorted(self._resolved), "system_fingerprints": sorted(self._fingerprints)}

    def start(self, system_prompt: str, user_prompt: str, tools: list[dict[str, Any]], task_id: str) -> None:
        self.messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
        self.tools = [
            {"type": "function",
             "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools
        ]

    def next_turn(self) -> PlannerTurn:
        resp = self.client.chat.completions.create(**self._kwargs(self.messages, with_tools=True))
        self._note(resp)
        choice = resp.choices[0]
        msg = choice.message
        tool_calls = list(msg.tool_calls or [])
        assistant: dict[str, Any] = {"role": "assistant", "content": msg.content}
        extra = getattr(msg, "model_extra", None) or {}
        for f in PASSTHROUGH_FIELDS:  # e.g. DeepSeek/Kimi thinking: must be echoed back with tool calls
            if extra.get(f) is not None:
                assistant[f] = extra[f]
        if tool_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls
            ]
        self.messages.append(assistant)
        usage = {}
        if getattr(resp, "usage", None):
            usage = {"input_tokens": resp.usage.prompt_tokens or 0, "output_tokens": resp.usage.completion_tokens or 0}
        calls = [ProposedCall(tc.id, tc.function.name, tc.function.arguments) for tc in tool_calls]
        return PlannerTurn(tool_calls=calls, text=msg.content, usage=usage, finish_reason=choice.finish_reason,
                           truncated=choice.finish_reason == "length")

    def observe(self, results: list[tuple[ProposedCall, dict[str, Any]]]) -> None:
        for call, result in results:
            self.messages.append({"role": "tool", "tool_call_id": call.id,
                                  "content": json.dumps(result, ensure_ascii=False)})

    def transcript(self) -> list[Any]:
        return self.messages
