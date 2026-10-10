"""A local MOCK LLM endpoint for testing the planner adapters end-to-end.

It speaks just enough of the OpenAI Chat Completions and Anthropic Messages
wire formats for the real `openai` / `anthropic` SDKs to talk to it. Its
"decisions" are a replay of the scripted plans, driven by the tool results the
adapter sends back. It also checks the protocol (tool-call IDs match, tools
are declared), so an adapter bug shows up as an HTTP 400.

Special model names exercise provider quirks:
  mock-reasoning  OpenAI-compatible responses carry `reasoning_content` (like DeepSeek/Kimi
                  thinking mode) and the server REJECTS a follow-up request that does not
                  echo it back on the assistant message.
  mock-parallel   for B09, the first response proposes all three read_email calls at once
                  (plus a text block / content), like models that call tools in parallel.
  mock-error      every request fails with HTTP 400.
A request without `tools` is treated as the preflight ping and answered with "OK".

It is NOT a model. Nothing produced through it is an LLM measurement.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from testbed.experiment import load_tasks
from testbed.planners.scripted import PLANS

PROMPT_TO_TASK = {t["prompt"]: t["task_id"] for t in load_tasks()["tasks"]}
EXPECTED_TOOLS = {"read_email", "read_file", "lookup_customer", "create_ticket"}


class ProtocolError(Exception):
    pass


def replay(task_id: str, results: list[dict[str, Any]]) -> tuple[str, Any]:
    """Return ('call', (name, args)) or ('final', text) after feeding `results` to the plan."""
    gen = PLANS[task_id]()
    try:
        item = next(gen)
        for r in results:
            item = gen.send(r)
    except StopIteration as stop:
        return "final", stop.value
    return "call", item


B09_PARALLEL = [("read_email", {"email_id": e}) for e in ("E-019", "E-030", "E-031")]


def _wrap_openai(body: dict[str, Any], n: int, message: dict[str, Any], finish: str) -> dict[str, Any]:
    return {"id": f"chatcmpl-mock-{n}", "object": "chat.completion", "created": 0, "model": body["model"] + "-0001",
            "system_fingerprint": "fp_mock",
            "choices": [{"index": 0, "message": message, "finish_reason": finish, "logprobs": None}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}


def openai_reply(body: dict[str, Any], n: int) -> dict[str, Any]:
    model = body["model"]
    if model == "mock-error":
        raise ProtocolError("simulated provider error")
    if "tools" not in body:  # preflight ping
        return _wrap_openai(body, n, {"role": "assistant", "content": "OK"}, "stop")
    names = {t["function"]["name"] for t in body.get("tools", [])}
    if names != EXPECTED_TOOLS:
        raise ProtocolError(f"tools declared: {names}")
    msgs = body["messages"]
    user = next(m["content"] for m in msgs if m["role"] == "user")
    issued: set[str] = set()
    results = []
    for m in msgs:
        if m["role"] == "assistant":
            issued |= {tc["id"] for tc in m.get("tool_calls") or []}
            if model == "mock-reasoning" and m.get("tool_calls") and not m.get("reasoning_content"):
                raise ProtocolError("reasoning_content must be passed back with tool calls")
        if m["role"] == "tool":
            if m["tool_call_id"] not in issued:
                raise ProtocolError(f"tool message for unknown id {m['tool_call_id']}")
            results.append(json.loads(m["content"]))
    task_id = PROMPT_TO_TASK[user]
    if model == "mock-parallel" and task_id == "B09" and not results:
        message = {"role": "assistant", "content": "Reading this week's three emails.", "tool_calls": [
            {"id": f"call_{n}_{i}", "type": "function", "function": {"name": nm, "arguments": json.dumps(a)}}
            for i, (nm, a) in enumerate(B09_PARALLEL)]}
        return _wrap_openai(body, n, message, "tool_calls")
    kind, item = replay(task_id, results)
    if kind == "final":
        message = {"role": "assistant", "content": item}
        finish = "stop"
    else:
        name, args = item
        message = {"role": "assistant", "content": None, "tool_calls": [
            {"id": f"call_{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}
        finish = "tool_calls"
    if model == "mock-reasoning":
        message["reasoning_content"] = f"(mock reasoning {n})"
    return _wrap_openai(body, n, message, finish)


def _wrap_anthropic(body: dict[str, Any], n: int, content: list[dict[str, Any]], stop: str) -> dict[str, Any]:
    return {"id": f"msg_mock_{n}", "type": "message", "role": "assistant", "model": body["model"] + "-20260101",
            "content": content, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 20}}


def anthropic_reply(body: dict[str, Any], n: int) -> dict[str, Any]:
    if body["model"] == "mock-error":
        raise ProtocolError("simulated provider error")
    if "tools" not in body:  # preflight ping
        return _wrap_anthropic(body, n, [{"type": "text", "text": "OK"}], "end_turn")
    names = {t["name"] for t in body.get("tools", [])}
    if names != EXPECTED_TOOLS:
        raise ProtocolError(f"tools declared: {names}")
    if not body.get("system"):
        raise ProtocolError("system prompt missing")
    msgs = body["messages"]
    roles = [m["role"] for m in msgs]
    if roles[0] != "user" or any(a == b for a, b in zip(roles, roles[1:])):
        raise ProtocolError(f"roles must alternate starting with user: {roles}")
    issued: set[str] = set()
    results = []
    for m in msgs:
        if m["role"] == "assistant":
            issued |= {b["id"] for b in m["content"] if b.get("type") == "tool_use"}
        elif isinstance(m["content"], list):
            for b in m["content"]:
                if b.get("type") == "tool_result":
                    if b["tool_use_id"] not in issued:
                        raise ProtocolError(f"tool_result for unknown id {b['tool_use_id']}")
                    results.append(json.loads(b["content"]))
    task_id = PROMPT_TO_TASK[msgs[0]["content"]]
    if body["model"] == "mock-parallel" and task_id == "B09" and not results:
        content = [{"type": "text", "text": "Reading this week's three emails."}] + [
            {"type": "tool_use", "id": f"toolu_{n}_{i}", "name": nm, "input": a} for i, (nm, a) in enumerate(B09_PARALLEL)]
        return _wrap_anthropic(body, n, content, "tool_use")
    kind, item = replay(task_id, results)
    if kind == "final":
        content, stop = [{"type": "text", "text": item}], "end_turn"
    else:
        name, args = item
        content, stop = [{"type": "tool_use", "id": f"toolu_{n}", "name": name, "input": args}], "tool_use"
    return _wrap_anthropic(body, n, content, stop)


class Handler(BaseHTTPRequestHandler):
    counter = 0

    def do_POST(self):  # noqa: N802
        Handler.counter += 1
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        try:
            if self.path.endswith("/chat/completions"):
                payload, code = openai_reply(body, Handler.counter), 200
            elif self.path.endswith("/messages"):
                payload, code = anthropic_reply(body, Handler.counter), 200
            else:
                payload, code = {"error": f"unknown path {self.path}"}, 404
        except (ProtocolError, KeyError) as e:
            payload, code = {"error": {"type": "invalid_request_error", "message": f"mock protocol check: {e}"}}, 400
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        pass


def start_server() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
