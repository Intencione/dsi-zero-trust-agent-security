"""Only business arguments are model-controlled; the host supplies task bindings."""

from dataclasses import dataclass
from typing import Callable

from langchain.tools import tool
from pydantic import BaseModel, ConfigDict

from secure_runtime import ToolCall


@dataclass(frozen=True)
class TaskBinding:
    task_id: str
    instruction_id: str
    resource_id: str
    target_machine_id: str


class StrictArguments(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class ReadArguments(StrictArguments):
    path: str


class ReportArguments(StrictArguments):
    format: str


class EmailArguments(StrictArguments):
    recipient: str
    body: str


def build_tools(binding: TaskBinding, dispatch: Callable[[ToolCall], dict]):
    def propose(name, arguments):
        return dispatch(ToolCall(
            task_id=binding.task_id, instruction_id=binding.instruction_id,
            resource_id=binding.resource_id, target_machine_id=binding.target_machine_id,
            tool_name=name, arguments=tuple(arguments.items()),
        ))

    @tool(args_schema=ReadArguments)
    def read_document(path: str):
        """Request an enterprise document at the exact specified path."""
        return propose("read_document", {"path": path})

    @tool(args_schema=ReportArguments)
    def generate_report(format: str):
        """Request a financial report. This task permits the exact format pdf."""
        return propose("generate_report", {"format": format})

    @tool(args_schema=EmailArguments)
    def send_email(recipient: str, body: str):
        """Request an email; availability does not imply this task permits sending."""
        return propose("send_email", {"recipient": recipient, "body": body})

    return [read_document, generate_report, send_email]
