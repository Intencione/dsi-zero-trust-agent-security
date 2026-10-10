"""LLM planner for the Anthropic Messages API with tool use."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

from .base import Planner, PlannerTurn, PlannerUnavailable, ProposedCall


class AnthropicPlanner(Planner):
    kind = "llm"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 temperature: float | None = None, max_tokens: int | None = None,
                 extra_body: dict[str, Any] | None = None, timeout: float = 180.0, max_retries: int = 3):
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise SystemExit("The 'anthropic' package is required: pip install -r requirements.txt") from e
        self._sdk_version = getattr(anthropic, "__version__", "unknown")
        self.model = model
        self.base_url = base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key or key.endswith("..."):
            raise SystemExit("Set a real ANTHROPIC_API_KEY (shell or .env) to use --planner anthropic.")
        self.temperature = temperature
        self.max_tokens = max_tokens or 4096
        self.extra_body = extra_body or {}
        self.timeout = timeout
        self.max_retries = max_retries
        self.client = anthropic.Anthropic(api_key=key, base_url=self.base_url, timeout=timeout, max_retries=max_retries)
        self.system = ""
        self.messages: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self._resolved: set[str] = set()

    def describe(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "provider": "anthropic",
            "base_url_host": urlparse(str(self.client.base_url)).netloc,  # what the SDK actually uses
            "model": self.model,
            "temperature": self.temperature if self.temperature is not None else "provider default",
            "max_tokens": self.max_tokens,
            "extra_body": self.extra_body,
            "timeout_s": self.timeout,
            "max_retries": self.max_retries,
            "sdk": f"anthropic-python {self._sdk_version}",
        }

    def _create(self, **kwargs: Any) -> Any:
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.extra_body:
            kwargs["extra_body"] = self.extra_body
        resp = self.client.messages.create(model=self.model, **kwargs)
        if getattr(resp, "model", None):
            self._resolved.add(resp.model)
        return resp

    def preflight(self) -> dict[str, Any]:
        try:
            resp = self._create(max_tokens=16, messages=[{"role": "user", "content": "Reply with the single word OK."}])
        except Exception as e:
            raise PlannerUnavailable(f"{type(e).__name__}: {e}") from e
        return {"preflight_ok": True, "resolved_model": getattr(resp, "model", None)}

    def observed(self) -> dict[str, Any]:
        return {"resolved_models": sorted(self._resolved)}

    def start(self, system_prompt: str, user_prompt: str, tools: list[dict[str, Any]], task_id: str) -> None:
        self.system = system_prompt
        self.messages = [{"role": "user", "content": user_prompt}]
        self.tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                      for t in tools]

    def next_turn(self) -> PlannerTurn:
        resp = self._create(max_tokens=self.max_tokens, system=self.system, messages=self.messages, tools=self.tools)
        content: list[dict[str, Any]] = []
        calls: list[ProposedCall] = []
        texts: list[str] = []
        for block in resp.content:
            if block.type == "text":
                content.append({"type": "text", "text": block.text})
                texts.append(block.text)
            elif block.type == "tool_use":
                content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                calls.append(ProposedCall(block.id, block.name, block.input))
            else:  # keep other block types (e.g. thinking) so the conversation stays valid
                content.append(block.model_dump(exclude_none=True))
        self.messages.append({"role": "assistant", "content": content})
        usage = {}
        if getattr(resp, "usage", None):
            usage = {"input_tokens": resp.usage.input_tokens or 0, "output_tokens": resp.usage.output_tokens or 0}
        return PlannerTurn(tool_calls=calls, text="\n".join(texts) if texts else None, usage=usage,
                           finish_reason=resp.stop_reason, truncated=resp.stop_reason == "max_tokens")

    def observe(self, results: list[tuple[ProposedCall, dict[str, Any]]]) -> None:
        blocks = [{"type": "tool_result", "tool_use_id": call.id,
                   "content": json.dumps(result, ensure_ascii=False),
                   "is_error": result.get("status") != "ok"}
                  for call, result in results]
        self.messages.append({"role": "user", "content": blocks})

    def transcript(self) -> list[Any]:
        return [{"role": "system", "content": self.system}] + self.messages
