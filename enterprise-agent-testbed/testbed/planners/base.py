"""Planner interface. A planner PROPOSES tool calls; it never executes them."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProposedCall:
    id: str                 # provider tool-call id (or synthetic for scripted)
    name: str
    arguments: Any          # dict, or raw JSON string as returned by the model


@dataclass
class PlannerTurn:
    tool_calls: list[ProposedCall]
    text: str | None = None                     # visible assistant text (final answer when tool_calls is empty)
    usage: dict[str, Any] = field(default_factory=dict)
    finish_reason: str | None = None            # provider's stop/finish reason
    truncated: bool = False                     # output was cut off by a token limit


class PlannerUnavailable(RuntimeError):
    """Raised by preflight when the model endpoint cannot be used (auth, model name, network)."""


class Planner(ABC):
    kind: str = "abstract"   # "llm" or "scripted"

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Provider/model/configuration for the run manifest (no secrets)."""

    def preflight(self) -> dict[str, Any]:
        """Check the endpoint once before a run. Returns facts for the manifest (e.g. resolved model)."""
        return {}

    def observed(self) -> dict[str, Any]:
        """Facts observed during calls (e.g. resolved model versions) for the manifest."""
        return {}

    @abstractmethod
    def start(self, system_prompt: str, user_prompt: str, tools: list[dict[str, Any]], task_id: str) -> None:
        """Begin a fresh conversation for one task trial."""

    @abstractmethod
    def next_turn(self) -> PlannerTurn:
        """Ask the planner for its next proposal."""

    @abstractmethod
    def observe(self, results: list[tuple[ProposedCall, dict[str, Any]]]) -> None:
        """Feed tool results (as produced by the application) back to the planner."""

    def transcript(self) -> list[Any]:
        return []
