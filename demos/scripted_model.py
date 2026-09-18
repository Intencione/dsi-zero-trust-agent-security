"""Deterministic test fixture using the real LangChain tool loop, with no API.

This is not an LLM. Its fixed proposals exercise the same tool adapters and
security graph as the live model. Final text is constructed from ToolMessages.
"""

import json

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field


class ScriptedFinanceModel(BaseChatModel):
    observed_results: list[dict] = Field(default_factory=list, exclude=True)

    @property
    def _llm_type(self):
        return "scripted-finance-fixture"

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        results = [json.loads(message.content) for message in messages if isinstance(message, ToolMessage)]
        self.observed_results = results
        if not results:
            message = AIMessage(content="", tool_calls=[{
                "name": "read_document", "args": {"path": "/finance/monthly.csv"}, "id": "read-1",
            }])
        elif not results[-1]["executed"]:
            message = AIMessage(content="Scripted demo stopped: " + results[-1]["reason"])
        elif len(results) == 1:
            message = AIMessage(content="", tool_calls=[{
                "name": "generate_report", "args": {"format": "pdf"}, "id": "report-1",
            }])
        else:
            message = AIMessage(content="Scripted demo tool outputs: " + json.dumps(
                [result["output"] for result in results]
            ))
        return ChatResult(generations=[ChatGeneration(message=message)])
