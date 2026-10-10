"""End-to-end test of the OpenAI-compatible and Anthropic planner adapters,
using the real SDKs against a local MOCK endpoint (tests/mock_llm_server.py).

This proves the adapters encode tools, parse tool calls and return tool results
correctly, including provider quirks. It is NOT an LLM measurement - the mock
replays the scripted plans.
"""
from __future__ import annotations

import pytest

from testbed.agent import run_agent
from testbed.evaluator import evaluate
from testbed.experiment import load_tasks, run_baseline
from testbed.planners.base import PlannerUnavailable

TASKS = {t["task_id"]: t for t in load_tasks()["tasks"]}


@pytest.fixture(scope="module")
def mock_url():
    from tests.mock_llm_server import start_server
    srv, url = start_server()
    yield url
    srv.shutdown()


def _planner(kind, url, model="mock-model"):
    if kind == "openai":
        pytest.importorskip("openai")
        from testbed.planners.openai_compat import OpenAICompatPlanner
        return OpenAICompatPlanner(model=model, base_url=url + "/v1", api_key="test-key", max_retries=0)
    pytest.importorskip("anthropic")
    from testbed.planners.anthropic_planner import AnthropicPlanner
    return AnthropicPlanner(model=model, base_url=url, api_key="test-key", max_retries=0)


def _run(env, planner, task_id):
    task = TASKS[task_id]
    agent = run_agent(planner, env["runner"](task["actor_id"], task_id), task["prompt"], task_id)
    ev = evaluate(task, agent, env["store"].list_tickets(), env["audit"].events_for(task_id, 1))
    return agent, ev


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("task_id", sorted(TASKS))
def test_adapter_end_to_end(env, mock_url, kind, task_id):
    planner = _planner(kind, mock_url)
    agent, ev = _run(env, planner, task_id)
    assert agent.stop_reason == "final_answer", agent.error
    assert ev["success"], ev["failed_checks"]
    assert agent.usage["input_tokens"] > 0
    desc = planner.describe()
    assert desc["kind"] == "llm" and desc["base_url_host"].startswith("127.0.0.1")
    assert planner.observed()["resolved_models"]  # resolved model version is captured


def test_reasoning_content_is_passed_back(env, mock_url):
    """DeepSeek/Kimi thinking mode: the server rejects follow-ups that drop reasoning_content."""
    planner = _planner("openai", mock_url, model="mock-reasoning")
    agent, ev = _run(env, planner, "B10")
    assert agent.stop_reason == "final_answer", agent.error
    assert ev["success"], ev["failed_checks"]
    assert any(m.get("reasoning_content") for m in planner.transcript() if m["role"] == "assistant")


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_parallel_tool_calls_and_interleaved_text(env, mock_url, kind):
    planner = _planner(kind, mock_url, model="mock-parallel")
    agent, ev = _run(env, planner, "B09")
    assert ev["success"], ev["failed_checks"]
    assert [c["turn"] for c in agent.tool_calls] == [1, 1, 1]  # three calls proposed in one turn
    assert "Reading this week's three emails." in agent.visible_text


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_provider_error_is_planner_error_not_crash(env, mock_url, kind):
    agent, ev = _run(env, _planner(kind, mock_url, model="mock-error"), "B01")
    assert agent.stop_reason == "planner_error" and not ev["success"]


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
def test_preflight(mock_url, kind):
    assert _planner(kind, mock_url).preflight()["preflight_ok"]
    with pytest.raises(PlannerUnavailable):
        _planner(kind, mock_url, model="mock-error").preflight()


def test_run_baseline_writes_complete_evidence(tmp_path, mock_url):
    out = run_baseline(lambda: _planner("openai", mock_url), task_ids=["B06", "B09"], results_dir=tmp_path,
                       run_id="R-test")
    import json
    man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    res = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert man["completed"] and man["planner_preflight"]["preflight_ok"]
    assert man["planner_observed"]["resolved_models"] == ["mock-model-0001"]
    assert man["system_prompt_sha256"] and man["measures_llm_behaviour"] is True
    assert [r["success"] for r in res["results"]] == [True, True]
    assert (out / "final_state" / "B06_t1_tickets.json").exists() and (out / "transcripts" / "B09_t1.json").exists()
    with pytest.raises(FileExistsError):  # an explicit run id never overwrites evidence
        run_baseline(lambda: _planner("openai", mock_url), task_ids=["B01"], results_dir=tmp_path, run_id="R-test")


def test_preflight_failure_records_no_run(tmp_path, mock_url):
    with pytest.raises(SystemExit):
        run_baseline(lambda: _planner("openai", mock_url, model="mock-error"), task_ids=["B01"], results_dir=tmp_path)
    assert not any(tmp_path.iterdir())
