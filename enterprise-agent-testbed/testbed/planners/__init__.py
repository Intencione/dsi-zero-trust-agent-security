from __future__ import annotations

from typing import Any

from .base import Planner, PlannerTurn, ProposedCall


def make_planner(kind: str, **kwargs: Any) -> Planner:
    """kind: 'scripted' | 'openai' | 'anthropic'."""
    if kind == "scripted":
        from .scripted import ScriptedPlanner
        return ScriptedPlanner()
    if kind == "openai":
        from .openai_compat import OpenAICompatPlanner
        return OpenAICompatPlanner(**kwargs)
    if kind == "anthropic":
        from .anthropic_planner import AnthropicPlanner
        return AnthropicPlanner(**kwargs)
    raise ValueError(f"Unknown planner '{kind}'")


__all__ = ["Planner", "PlannerTurn", "ProposedCall", "make_planner"]
