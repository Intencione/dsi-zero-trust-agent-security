from dataclasses import replace
import unittest
from unittest.mock import patch

from agent_demo import Decision, READ_INTERNAL_DOCUMENT
from demos.finance_agent import DemoDriver, build_finance_demo
from secure_agent_demo import make_demo
from telemetry.dsi_service import DSIService
from telemetry.simulator import SecurityEventSimulator


class WorkflowTests(unittest.TestCase):
    def demo(self, **kwargs):
        return build_finance_demo(log=lambda message: None, review=lambda details: True, **kwargs)

    @staticmethod
    def decisions(demo):
        return [(entry["stage"], entry["decision"]) for entry in demo.setup.runtime.audit]

    def test_scoped_action_allows_and_executes(self):
        demo = self.demo(scenario="after-read")
        call = demo.setup.read_call()
        output = demo.workflow.start(call, demo.driver.plan_context)
        self.assertTrue(output["result"]["executed"])
        self.assertEqual(output["result"]["output"]["content"]["profit"], 40000)
        self.assertEqual(self.decisions(demo), [("prepare", "ALLOW"), ("execute", "ALLOW")])
        self.assertEqual(demo.dsi_service.status()["level"], "NORMAL")

    def test_unchanged_approval_inspects_exact_call_and_executes(self):
        demo = self.demo(scenario="none")
        call = demo.setup.read_call()
        output = demo.workflow.start(call, demo.driver.plan_context)
        details = output["__interrupt__"][0].value
        self.assertEqual(details["call"]["arguments"], call.arguments)
        self.assertEqual(details["call"]["target_machine_id"], call.target_machine_id)
        self.assertIn("purpose", details)
        self.assertIn("environment", details)
        self.assertEqual(demo.setup.effects, [])
        resumed = demo.workflow.resume(call.request_id, approved=True)
        self.assertTrue(resumed["result"]["executed"])
        self.assertEqual(demo.setup.effects, [call])
        self.assertEqual(demo.dsi_service.status()["level"], "NORMAL")

    def test_incident_while_pending_cannot_be_overridden_by_approval(self):
        demo = self.demo(scenario="none")
        call = demo.setup.read_call()
        paused = demo.workflow.start(call, demo.driver.plan_context)
        self.assertTrue(paused["__interrupt__"])
        demo.simulator.trigger_incident()
        result = demo.workflow.resume(call.request_id, approved=True)
        self.assertEqual(self.decisions(demo), [
            ("prepare", Decision.APPROVAL.value), ("approval", "REEVALUATE"), ("prepare", "BLOCK"),
        ])
        self.assertEqual(result["plan_context"].security_epoch, demo.dsi_service.status()["security_epoch"])
        self.assertEqual(result["result"]["status"], "blocked")
        self.assertEqual(demo.setup.effects, [])

    def test_expired_approval_requires_another_human_decision(self):
        now = [1000]
        demo = self.demo(scenario="none", clock=lambda: now[0])
        reviews = []

        def review(details):
            reviews.append(details)
            if len(reviews) == 1:
                now[0] += 60
            return True

        demo.driver.review = review
        result = demo.driver(demo.setup.read_call())
        self.assertTrue(result["executed"])
        self.assertEqual(len(reviews), 2)
        self.assertGreater(reviews[1]["expires_at"], reviews[0]["expires_at"])
        self.assertEqual(self.decisions(demo), [
            ("prepare", Decision.APPROVAL.value), ("approval", "REEVALUATE"),
            ("prepare", Decision.APPROVAL.value), ("approval", "ALLOW"), ("execute", "ALLOW"),
        ])
        self.assertEqual(len(demo.setup.effects), 1)

    def test_environment_change_during_approval_is_revalidated(self):
        demo = self.demo(scenario="none")

        def review(details):
            policy = demo.setup.runtime.policy
            policy.update_environment(replace(policy.environment, source_risk=90))
            return True

        demo.driver.review = review
        result = demo.driver(demo.setup.read_call())
        self.assertEqual(result["status"], "blocked")
        self.assertIn(("approval", "REEVALUATE"), self.decisions(demo))
        self.assertEqual(demo.setup.effects, [])

    def test_invalid_resume_value_does_not_approve(self):
        demo = self.demo(scenario="none")
        call = demo.setup.read_call()
        demo.workflow.start(call, demo.driver.plan_context)
        with self.assertRaises(TypeError):
            demo.workflow.resume(call.request_id, approved="yes")
        self.assertEqual(demo.setup.effects, [])
        result = demo.workflow.resume(call.request_id, approved=False)
        self.assertEqual(result["result"]["status"], "blocked")

    def test_revoked_approver_reaches_runtime_revalidation_on_resume(self):
        demo = self.demo(scenario="none")
        call = demo.setup.read_call()
        demo.workflow.start(call, demo.driver.plan_context)
        demo.setup.runtime.identities.revoke(demo.setup.user_token)
        result = demo.workflow.resume(call.request_id, approved=True)
        self.assertEqual(result["result"]["status"], "blocked")
        self.assertIn(("approval", "BLOCK"), self.decisions(demo))
        self.assertEqual(demo.setup.effects, [])

    def test_change_before_dispatch_refreshes_and_blocks(self):
        demo = self.demo(scenario="after-read")
        runtime = demo.setup.runtime
        execute = runtime.execute

        def incident_before_dispatch(*args):
            demo.simulator.trigger_incident()
            return execute(*args)

        with patch.object(runtime, "execute", side_effect=incident_before_dispatch):
            result = demo.driver(demo.setup.read_call())
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(self.decisions(demo), [
            ("prepare", "ALLOW"), ("execute", "REEVALUATE"), ("prepare", "BLOCK"),
        ])
        self.assertEqual(demo.setup.effects, [])

    def test_handler_failure_is_terminal_and_cannot_be_replayed(self):
        demo = self.demo(scenario="after-read")
        attempts = []

        def failure(call):
            attempts.append(call)
            raise OSError("simulated failure")

        demo.setup.runtime.register_tool("read_document", READ_INTERNAL_DOCUMENT, {"path": "string"}, failure)
        call = demo.setup.read_call()
        result = demo.driver(call)
        self.assertFalse(result["executed"])
        self.assertEqual(result["error"], "OSError")
        self.assertEqual(demo.driver(call)["status"], "blocked")
        self.assertEqual(attempts, [call])

    def test_successful_request_cannot_execute_twice_through_graph(self):
        demo = self.demo(scenario="none")
        call = demo.setup.read_call()
        self.assertTrue(demo.driver(call)["executed"])
        self.assertEqual(demo.driver(call)["status"], "blocked")
        self.assertEqual(demo.setup.effects, [call])

    def test_composition_rejects_a_second_independent_policy(self):
        demo = self.demo(scenario="none")
        other = SecurityEventSimulator(DSIService(make_demo().runtime.policy))
        with self.assertRaisesRegex(ValueError, "same PolicyEngine"):
            DemoDriver(demo.workflow, other, lambda details: True, "none", print)
