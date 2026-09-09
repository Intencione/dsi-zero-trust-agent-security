"""Policy behavior checks; no live tools, credentials, or network access."""

from dataclasses import FrozenInstanceError, replace
from contextlib import redirect_stdout
from io import StringIO
import unittest

from agent_demo import (
    CREATE_PUBLIC_CONTENT, DELETE_FILE, DEMO_ENVIRONMENT,
    GENERATE_FINANCIAL_REPORT, ISOLATE_HOST, READ_INTERNAL_DOCUMENT,
    READ_SECURITY_LOGS, TRANSFER_FILE, Decision, DynamicSecurityIndicator,
    EnvironmentType, NetworkAccess, PolicyEngine,
    cybersecurity_agent, execute_action, finance_agent, marketing_agent,
)


class EnvironmentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.dsi = DynamicSecurityIndicator()
        self.policy = PolicyEngine(self.dsi, DEMO_ENVIRONMENT)

    def decision(self, agent=finance_agent, action=READ_INTERNAL_DOCUMENT):
        return self.policy.evaluate(agent, action, self.policy.capture_context())[0]

    def change_environment(self, **changes):
        self.policy.update_environment(replace(DEMO_ENVIRONMENT, **changes))

    def test_same_action_in_test_and_production(self):
        self.assertEqual(self.decision(), Decision.ALLOW)
        self.change_environment(environment_type=EnvironmentType.PRODUCTION)
        self.assertEqual(self.decision(), Decision.APPROVAL)

    def test_environment_approval_factors_independently(self):
        for changes in (
            {"source_risk": 50}, {"target_risk": 50},
            {"target_criticality": 75}, {"resource_sensitivity": 75},
            {"privileged_execution": True}, {"sandboxed": False},
        ):
            with self.subTest(changes=changes):
                self.change_environment(**changes)
                self.assertEqual(self.decision(), Decision.APPROVAL)

    def test_risk_boundaries(self):
        for field in ("source_risk", "target_risk"):
            for risk, expected in (
                (49, Decision.ALLOW), (50, Decision.APPROVAL),
                (74, Decision.APPROVAL), (75, Decision.BLOCK),
            ):
                with self.subTest(field=field, risk=risk):
                    self.change_environment(**{field: risk})
                    self.assertEqual(self.decision(), expected)

    def test_local_machine_denials_even_with_zero_enterprise_dsi(self):
        for changes in (
            {"source_risk": 90}, {"source_quarantined": True},
            {"target_risk": 90}, {"target_quarantined": True},
        ):
            with self.subTest(changes=changes):
                self.change_environment(**changes)
                self.assertEqual(self.dsi.score, 0)
                self.assertEqual(self.decision(), Decision.BLOCK)

    def test_source_denial_applies_to_crisis_responders(self):
        self.dsi.set_emergency_mode(True)
        for changes in ({"source_risk": 90}, {"source_quarantined": True}):
            self.change_environment(**changes)
            for action in (READ_SECURITY_LOGS, ISOLATE_HOST):
                with self.subTest(changes=changes, action=action.name):
                    self.assertEqual(
                        self.decision(cybersecurity_agent, action), Decision.BLOCK
                    )

    def test_incident_response_exception_is_scoped_to_actions_and_permissions(self):
        for crisis in (False, True):
            self.dsi.set_emergency_mode(crisis)
            self.change_environment(target_risk=90, target_quarantined=True)
            with self.subTest(crisis=crisis):
                self.assertEqual(
                    self.decision(cybersecurity_agent, READ_SECURITY_LOGS), Decision.ALLOW
                )
                self.assertEqual(
                    self.decision(cybersecurity_agent, READ_INTERNAL_DOCUMENT), Decision.BLOCK
                )
                unauthorized = replace(cybersecurity_agent, permissions=[])
                self.assertEqual(
                    self.decision(unauthorized, READ_SECURITY_LOGS), Decision.BLOCK
                )

    def test_crisis_exception_preserves_environment_approval(self):
        self.dsi.set_emergency_mode(True)
        self.change_environment(target_risk=90, privileged_execution=True)
        self.assertEqual(
            self.decision(cybersecurity_agent, ISOLATE_HOST), Decision.APPROVAL
        )

    def test_network_and_sensitive_transfer(self):
        self.change_environment(network_access=NetworkAccess.ISOLATED)
        self.assertEqual(self.decision(), Decision.BLOCK)
        self.change_environment(resource_sensitivity=90)
        self.assertEqual(self.decision(action=TRANSFER_FILE), Decision.APPROVAL)
        self.change_environment(
            resource_sensitivity=90, network_access=NetworkAccess.INTERNET_ENABLED
        )
        self.assertEqual(self.decision(action=TRANSFER_FILE), Decision.BLOCK)

    def test_environment_change_invalidates_old_plan_and_fresh_plan_blocks(self):
        context = self.policy.capture_context()
        self.change_environment(source_risk=90)
        self.assertEqual(context.security_epoch, self.dsi.epoch)
        self.assertEqual(
            self.policy.evaluate(finance_agent, READ_INTERNAL_DOCUMENT, context)[0],
            Decision.REEVALUATE,
        )
        self.assertEqual(self.decision(), Decision.BLOCK)

    def test_environment_returning_to_old_values_does_not_revive_old_plan(self):
        context = self.policy.capture_context()
        self.change_environment(source_risk=90)
        self.policy.update_environment(DEMO_ENVIRONMENT)
        self.assertEqual(
            self.policy.evaluate(finance_agent, READ_INTERNAL_DOCUMENT, context)[0],
            Decision.REEVALUATE,
        )
        self.assertEqual(self.decision(), Decision.ALLOW)

    def test_identical_environment_update_does_not_invalidate_plan(self):
        context = self.policy.capture_context()
        self.policy.update_environment(replace(DEMO_ENVIRONMENT))
        self.assertEqual(context, self.policy.capture_context())
        self.assertEqual(self.decision(), Decision.ALLOW)

    def test_scope_change_invalidates_plan(self):
        for field in ("source_machine_id", "target_machine_id", "resource_id"):
            with self.subTest(field=field):
                self.policy.update_environment(DEMO_ENVIRONMENT)
                context = self.policy.capture_context()
                self.change_environment(**{field: "another-scope"})
                self.assertEqual(
                    self.policy.evaluate(finance_agent, READ_INTERNAL_DOCUMENT, context)[0],
                    Decision.REEVALUATE,
                )

    def test_global_epoch_and_original_incident_block(self):
        context = self.policy.capture_context()
        self.dsi.calculate(90, 75, 85, 80)
        self.assertEqual(
            self.policy.evaluate(finance_agent, TRANSFER_FILE, context)[0],
            Decision.REEVALUATE,
        )
        self.assertEqual(self.decision(action=TRANSFER_FILE), Decision.BLOCK)
        self.change_environment(privileged_execution=True)
        self.assertEqual(self.decision(action=TRANSFER_FILE), Decision.BLOCK)

    def test_original_crisis_department_rules(self):
        self.assertEqual(self.decision(action=GENERATE_FINANCIAL_REPORT), Decision.ALLOW)
        self.dsi.set_emergency_mode(True)
        self.assertEqual(self.decision(action=GENERATE_FINANCIAL_REPORT), Decision.BLOCK)
        self.assertEqual(self.decision(marketing_agent, CREATE_PUBLIC_CONTENT), Decision.APPROVAL)
        self.assertEqual(self.decision(marketing_agent, TRANSFER_FILE), Decision.BLOCK)
        self.assertEqual(self.decision(cybersecurity_agent, ISOLATE_HOST), Decision.ALLOW)

    def test_destructive_approval_never_overrides_environment_denial(self):
        operator = replace(finance_agent, permissions=[DELETE_FILE.name])
        self.assertEqual(self.decision(operator, DELETE_FILE), Decision.APPROVAL)
        self.change_environment(source_quarantined=True)
        self.assertEqual(self.decision(operator, DELETE_FILE), Decision.BLOCK)
        self.policy.update_environment(DEMO_ENVIRONMENT)
        self.dsi.calculate(30, 30, 30, 30)
        self.assertEqual(self.decision(operator, DELETE_FILE), Decision.BLOCK)

    def test_missing_context_requires_reevaluation(self):
        self.assertEqual(
            self.policy.evaluate(finance_agent, READ_INTERNAL_DOCUMENT, None)[0],
            Decision.REEVALUATE,
        )

    def test_runtime_logs_missing_context_without_crashing(self):
        output = StringIO()
        with redirect_stdout(output):
            decision = execute_action(
                finance_agent, READ_INTERNAL_DOCUMENT, self.policy, None
            )
        self.assertEqual(decision, Decision.REEVALUATE)
        self.assertIn("[AUDIT]", output.getvalue())
        self.assertIn("CurrentEnvironment=", output.getvalue())

    def test_environment_validation_and_immutability(self):
        for changes in (
            {"source_risk": -1}, {"target_risk": 101}, {"target_risk": float("nan")},
            {"target_criticality": True}, {"resource_sensitivity": "90"},
            {"source_machine_id": ""}, {"environment_type": "production"},
            {"network_access": None}, {"source_quarantined": "false"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(DEMO_ENVIRONMENT, **changes)
        with self.assertRaises(FrozenInstanceError):
            DEMO_ENVIRONMENT.source_risk = 90
        with self.assertRaises(ValueError):
            PolicyEngine(self.dsi, None)


if __name__ == "__main__":
    unittest.main()
