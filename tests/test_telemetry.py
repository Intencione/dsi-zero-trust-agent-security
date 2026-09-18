import unittest

from agent_demo import Decision
from secure_agent_demo import make_demo
from telemetry.dsi_service import DSIService
from telemetry.simulator import SecurityEventSimulator


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.demo = make_demo()
        self.runtime = self.demo.runtime
        self.service = DSIService(self.runtime.policy)
        self.simulator = SecurityEventSimulator(self.service)

    def test_same_policy_and_dsi_drive_stale_and_fresh_decisions(self):
        policy = self.runtime.policy
        dsi = policy.dsi
        context = policy.capture_context()
        self.assertIs(self.simulator.service, self.service)
        self.assertIs(self.service.policy, policy)
        status = self.simulator.trigger_incident()
        self.assertIs(self.service.policy.dsi, dsi)
        self.assertEqual(status["level"], "CRISIS")
        self.assertEqual(status["security_epoch"], context.security_epoch + 1)
        call = self.demo.read_call()
        stale = self.runtime.prepare(self.demo.agent_token, call, context)
        fresh = self.runtime.prepare(self.demo.agent_token, call, policy.capture_context())
        self.assertEqual(stale.decision, Decision.REEVALUATE)
        self.assertEqual(fresh.decision, Decision.BLOCK)
        self.assertEqual(self.demo.effects, [])

    def test_simulator_emits_incident_once_even_after_recovery(self):
        self.simulator.trigger_incident()
        recovered = self.service.ingest_signals()
        self.assertEqual(recovered["level"], "NORMAL")
        self.assertEqual(self.simulator.trigger_incident(), recovered)

    def test_admin_emergency_updates_runtime_state(self):
        status = self.service.set_emergency(True)
        self.assertTrue(self.runtime.policy.dsi.admin_emergency)
        self.assertEqual(status["level"], "CRISIS")
        self.assertEqual(self.service.set_emergency(False)["score"], 0)

    def test_score_change_within_epoch_invalidates_existing_permit(self):
        context = self.runtime.policy.capture_context()
        call = self.demo.read_call()
        permit = self.runtime.prepare(self.demo.agent_token, call, context).permit_id
        status = self.service.ingest_signals(network_anomaly=10)
        self.assertEqual(status["security_epoch"], context.security_epoch)
        result = self.runtime.execute(self.demo.agent_token, call, permit)
        self.assertEqual(result.decision, Decision.REEVALUATE)
        self.assertEqual(self.demo.effects, [])
