import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from langchain_core.messages import ToolMessage
from pydantic import ValidationError

from agent.models import build_agent
from demos.finance_agent import build_finance_demo
from demos.scripted_model import ScriptedFinanceModel


class AgentIntegrationTests(unittest.TestCase):
    def demo(self, scenario="none"):
        return build_finance_demo(scenario=scenario, review=lambda details: True, log=lambda message: None)

    @staticmethod
    def invoke(demo, model):
        return build_agent(model, demo.tools).invoke({"messages": [{
            "role": "user", "content": "Read /finance/monthly.csv and generate a PDF report. Do not send it."
        }]})

    def test_mock_outputs_reach_the_next_model_turn(self):
        demo = self.demo()
        model = ScriptedFinanceModel()
        result = self.invoke(demo, model)
        messages = [message for message in result["messages"] if isinstance(message, ToolMessage)]
        self.assertEqual(len(messages), 2)
        self.assertEqual(model.observed_results, [json.loads(message.content) for message in messages])
        self.assertEqual(model.observed_results[0]["output"]["content"], {
            "revenue": 120000, "expenses": 80000, "profit": 40000,
        })
        self.assertEqual(model.observed_results[1]["output"]["report"], "Monthly financial report")
        self.assertIn("40000", result["messages"][-1].text)
        self.assertEqual(len(demo.setup.effects), 2)
        for message in messages:
            self.assertNotIn("permit_id", message.content)
            self.assertNotIn("approval_id", message.content)
            self.assertNotIn(demo.setup.agent_token, message.content)
            self.assertNotIn(demo.setup.user_token, message.content)

    def test_incident_during_approval_block_reaches_model(self):
        demo = self.demo("approval-incident")
        model = ScriptedFinanceModel()
        self.invoke(demo, model)
        self.assertEqual(model.observed_results[0]["status"], "blocked")
        self.assertEqual(demo.setup.effects, [])
        self.assertIs(demo.simulator.service.policy, demo.setup.runtime.policy)

    def test_after_read_incident_preserves_read_output_and_blocks_report(self):
        demo = self.demo("after-read")
        model = ScriptedFinanceModel()
        self.invoke(demo, model)
        self.assertEqual(model.observed_results[0]["output"]["content"]["profit"], 40000)
        self.assertEqual(model.observed_results[1]["status"], "blocked")
        self.assertEqual([call.tool_name for call in demo.setup.effects], ["read_document"])

    def test_available_email_tool_is_outside_task_grant(self):
        demo = self.demo()
        email = next(tool for tool in demo.tools if tool.name == "send_email")
        result = email.invoke({"recipient": "colleague@example.test", "body": "report"})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("scope", result["reason"])
        self.assertEqual(demo.setup.effects, [])

    def test_unauthorized_arguments_are_not_normalized(self):
        demo = self.demo()
        tools = {tool.name: tool for tool in demo.tools}
        for name, arguments in (
            ("read_document", {"path": "/finance/../finance/monthly.csv"}),
            ("read_document", {"path": "/finance/monthly.csv "}),
            ("generate_report", {"format": "PDF"}),
            ("generate_report", {"format": "docx"}),
        ):
            with self.subTest(arguments=arguments):
                result = tools[name].invoke(arguments)
                self.assertEqual(result["decision"], "BLOCK")
                self.assertIn("scope", result["reason"])
        self.assertEqual(demo.setup.effects, [])

    def test_model_cannot_supply_trusted_fields_or_coerce_arguments(self):
        demo = self.demo()
        read = next(tool for tool in demo.tools if tool.name == "read_document")
        for extra in ("task_id", "instruction_id", "target_machine_id", "dsi", "approved", "permit_id"):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                read.invoke({"path": "/finance/monthly.csv", extra: "forged"})
        with self.assertRaises(ValidationError):
            read.invoke({"path": 123})
        self.assertEqual({tool.name for tool in demo.tools}, {"read_document", "generate_report", "send_email"})
        self.assertEqual(demo.setup.effects, [])

    def test_entry_points_are_import_safe_without_credentials(self):
        env = dict(os.environ)
        env.pop("OPENAI_API_KEY", None)
        result = subprocess.run([
            sys.executable, "-B", "-c",
            "import llm_graph_demo, llm_secure_demo, demos.finance_agent; print('imported')",
        ], cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "imported\n")

    def test_cli_displays_exact_approval_and_resumes_with_terminal_answer(self):
        result = subprocess.run([
            sys.executable, "-B", "llm_graph_demo.py", "--offline",
        ], cwd=Path(__file__).resolve().parents[1], input="y\n", capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HUMAN APPROVAL REQUIRED", result.stdout)
        self.assertIn('"environment_type": "production"', result.stdout)
        self.assertIn("/finance/monthly.csv", result.stdout)
        self.assertIn("[approval] REEVALUATE", result.stdout)
        self.assertIn("[prepare] BLOCK", result.stdout)
        self.assertNotIn("[execute]", result.stdout)
