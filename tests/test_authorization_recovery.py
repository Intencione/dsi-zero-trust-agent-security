"""Independent runtime/graph instances, shared SQLite, deterministic clocks."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from agent_demo import Decision, EnvironmentType
from secure_agent_demo import make_demo
from secure_runtime import SecureRuntime
from authorization.runtime import PersistentSecureRuntime, Lifecycle, AuthorizationUnavailable, DispatchCommitFailure
from authorization.store import SQLiteAuthorizationStore
from agent.persistent_workflow import PersistentSecurityWorkflow


class Crash(BaseException):
    pass


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'runtime.sqlite'
        self.now = [1000.0]
        self.setup = make_demo(lambda: self.now[0])
        self.host = self.setup.runtime
        self.call = self.setup.read_call()
        self.store = SQLiteAuthorizationStore(self.path)
        self.addCleanup(lambda: self.store.close())
        self.runtime = PersistentSecureRuntime(self.host, self.store)
        self.workflow = self.graph()

    def graph(self, approver=None):
        return PersistentSecurityWorkflow(self.runtime, self.setup.agent_token,
                                          approver or self.setup.user_token)

    def restart(self):
        self.store.close()
        self.store = SQLiteAuthorizationStore(self.path)
        # New runtime, policy, identity provider and provenance registry. A trusted
        # host rehydrates its external identity/provenance authority, not checkpoints.
        host = SecureRuntime(copy.deepcopy(self.host.policy),
                             copy.deepcopy(self.host.identities),
                             copy.deepcopy(self.host.inputs), clock=lambda: self.now[0])
        host.identities.clock = lambda: self.now[0]
        host.inputs.identities = host.identities
        host._tools = self.host._tools.copy()
        self.runtime = PersistentSecureRuntime(host, self.store)
        self.host = host
        self.workflow = self.graph()

    def production(self):
        self.host.policy.update_environment(replace(self.host.policy.environment,
                                                   environment_type=EnvironmentType.PRODUCTION))

    def prepare(self):
        return self.runtime.prepare(self.setup.agent_token, self.call, self.runtime.policy.capture_context())

    def execute(self, permit, call=None):
        return self.runtime.execute(self.setup.agent_token, call or self.call, permit)

    def state(self):
        return self.runtime.request_status(self.setup.agent_token, self.call.request_id)

    def test_pending_survives_and_approves(self):
        self.production()
        result = self.prepare()
        self.restart()
        self.assertIn('__interrupt__', self.workflow.restore(self.call.request_id))
        result = self.runtime.resolve_approval(self.setup.user_token, result.approval_id, approved=True)
        self.assertTrue(self.execute(result.permit_id).executed)

    def test_security_epoch_changed_offline(self):
        self.production()
        pending = self.prepare()
        self.host.policy.dsi.set_emergency_mode(True)
        self.restart()
        result = self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=True)
        self.assertEqual(result.decision, Decision.REEVALUATE)
        self.assertFalse(self.setup.effects)

    def test_environment_epoch_changed_offline(self):
        self.production()
        pending = self.prepare()
        self.host.policy.update_environment(replace(self.host.policy.environment, source_risk=60))
        self.restart()
        result = self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=True)
        self.assertEqual(result.decision, Decision.REEVALUATE)

    def test_changed_arguments_after_restart(self):
        permit = self.prepare().permit_id
        self.restart()
        result = self.execute(permit, replace(self.call, arguments=(('path', '/secret'),)))
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertFalse(self.setup.effects)

    def test_rejected_approval_remains_rejected(self):
        self.production()
        pending = self.prepare()
        self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=False)
        self.restart()
        self.assertEqual(self.prepare().decision, Decision.BLOCK)
        self.assertEqual(self.runtime.recover(self.setup.agent_token, self.call.request_id).decision, Decision.BLOCK)

    def test_consumed_permit_stays_consumed(self):
        permit = self.prepare().permit_id
        self.assertTrue(self.execute(permit).executed)
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.BLOCK)
        self.assertEqual(len(self.setup.effects), 1)

    def test_unused_expired_permit(self):
        permit = self.prepare().permit_id
        self.now[0] += 61
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.REEVALUATE)
        self.assertFalse(self.setup.effects)

    def test_completed_graph_returns_result_without_rerun(self):
        first = self.workflow.start(self.call, self.runtime.policy.capture_context())
        self.restart()
        second = self.workflow.restore(self.call.request_id)
        self.assertEqual(first['result'], second['result'])
        self.assertEqual(len(self.setup.effects), 1)

    def test_crash_before_dispatch_unused_permit_safe(self):
        self.prepare()
        self.restart()
        self.assertTrue(self.runtime.recover(self.setup.agent_token, self.call.request_id).executed)
        self.assertEqual(len(self.setup.effects), 1)

    def test_crash_after_dispatch_before_side_effect_unknown(self):
        self.runtime.register_idempotent_adapter('read_document', lambda call, key: self.crash())
        permit = self.prepare().permit_id
        with self.assertRaises(Crash):
            self.execute(permit)
        self.restart()
        self.assertEqual(self.state()['state'], Lifecycle.UNKNOWN_OUTCOME.value)
        self.assertEqual(self.runtime.recover(self.setup.agent_token, self.call.request_id).error, 'UNKNOWN_OUTCOME')
        self.assertFalse(self.setup.effects)

    @staticmethod
    def crash():
        raise Crash()

    def test_crash_after_side_effect_unknown_no_retry(self):
        def effect(call, key):
            self.setup.effects.append(call)
            raise Crash()
        self.runtime.register_idempotent_adapter('read_document', effect)
        permit = self.prepare().permit_id
        with self.assertRaises(Crash):
            self.execute(permit)
        self.restart()
        self.workflow.restore(self.call.request_id)
        self.assertEqual(self.state()['state'], 'UNKNOWN_OUTCOME')
        self.assertEqual(len(self.setup.effects), 1)

    def test_idempotency_identity_stable_and_forwarded(self):
        self.prepare()
        expected = self.state()['execution_id']
        self.restart()
        keys = []
        self.runtime.register_idempotent_adapter('read_document', lambda call, key: keys.append(key))
        self.runtime.recover(self.setup.agent_token, self.call.request_id)
        self.assertEqual(keys, [expected])
        self.assertEqual(self.state()['execution_id'], expected)

    def test_audit_survives(self):
        self.execute(self.prepare().permit_id)
        before = copy.deepcopy(self.runtime.audit)
        self.restart()
        self.assertEqual(self.runtime.audit, before)
        self.assertTrue(any(e['stage'] == 'dispatch' for e in before))

    def test_agent_cannot_approve(self):
        self.production()
        self.prepare()
        output = self.graph(self.setup.agent_token).resume(self.call.request_id, approved=True)
        self.assertFalse(self.setup.effects)
        self.assertEqual(self.state()['state'], 'APPROVAL_PENDING')

    def test_expired_approval_revalidated_on_resume(self):
        self.production()
        self.workflow.start(self.call, self.runtime.policy.capture_context())
        self.now[0] += 61
        self.restart()
        output = self.workflow.resume(self.call.request_id, approved=True)
        self.assertEqual(output['result']['decision'], Decision.REEVALUATE.value)
        self.assertFalse(self.setup.effects)

    def test_checkpoint_alone_cannot_create_authority(self):
        with self.assertRaises(ValueError):
            self.workflow.graph.invoke({'request_id': 'invented', 'decision': 'ALLOW',
                'permit_id': 'forged', 'approved': True, 'state': 'EXECUTED'},
                {'configurable': {'thread_id': 'invented'}})
        self.assertFalse(self.runtime._permits)
        self.assertFalse(self.setup.effects)

    def test_tampered_pending_graph_cannot_self_approve_or_complete(self):
        self.production()
        self.workflow.start(self.call, self.runtime.policy.capture_context())
        self.workflow.graph.update_state({'configurable': {'thread_id': self.call.request_id}},
            {'request_id': self.call.request_id, 'approved': True, 'permit_id': 'forged',
             'decision': 'ALLOW', 'result': {'executed': True}, 'telemetry': {'severity': 0},
             'authorization': {'state': 'EXECUTED'}})
        self.restart()
        self.assertIn('__interrupt__', self.workflow.restore(self.call.request_id))
        self.assertEqual(self.state()['state'], 'APPROVAL_PENDING')
        self.assertFalse(self.setup.effects)

    def test_checkpoint_request_swap_rejected(self):
        self.prepare()
        with self.assertRaises(ValueError):
            self.workflow.graph.invoke({'request_id': 'other'},
                {'configurable': {'thread_id': self.call.request_id}})
        self.assertFalse(self.setup.effects)

    def test_no_authority_or_session_secrets_in_checkpoint(self):
        self.production()
        self.workflow.start(self.call, self.runtime.policy.capture_context())
        raw = self.store.checkpoint_load(json.dumps([self.call.request_id, '']))
        for secret in (self.setup.agent_token, self.setup.user_token, *self.runtime._pending.keys()):
            self.assertNotIn(secret, raw)
        self.assertNotIn('plan_context', raw)
        self.assertNotIn('permit_id', raw)

    def test_commit_failure_before_dispatch_prevents_effect(self):
        permit = self.prepare().permit_id
        self.store.save = lambda value: (_ for _ in ()).throw(OSError('disk full'))
        with self.assertRaises(DispatchCommitFailure):
            self.execute(permit)
        self.assertFalse(self.setup.effects)
        with self.assertRaises(AuthorizationUnavailable):
            self.runtime.recover(self.setup.agent_token, self.call.request_id)

    def test_result_commit_failure_recovers_unknown(self):
        permit = self.prepare().permit_id
        save = self.store.save
        def commit(value):
            if self.setup.effects:
                raise OSError('disk full after effect')
            save(value)
        self.store.save = commit
        with self.assertRaises(AuthorizationUnavailable):
            self.execute(permit)
        self.restart()
        self.assertEqual(self.state()['state'], 'UNKNOWN_OUTCOME')
        self.assertEqual(len(self.setup.effects), 1)

    def test_new_runtime_uses_live_identity_revocation(self):
        permit = self.prepare().permit_id
        self.host.identities.revoke(self.setup.agent_token)
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.BLOCK)
        self.assertFalse(self.setup.effects)

    def test_duplicate_prepare_never_mints_replacement(self):
        self.prepare()
        self.restart()
        before = set(self.runtime._permits)
        self.assertEqual(self.prepare().decision, Decision.BLOCK)
        self.assertEqual(before, set(self.runtime._permits))

    def test_one_writer_only(self):
        with self.assertRaises(BlockingIOError):
            SQLiteAuthorizationStore(self.path)

    def test_missing_snapshot_refuses_recovery(self):
        self.store._db.execute('DELETE FROM authorization')
        with self.assertRaises(ValueError):
            self.restart()

    def test_clock_rollback_refuses_recovery(self):
        self.prepare()
        self.now[0] -= 1
        with self.assertRaises(AuthorizationUnavailable):
            self.restart()

    def test_after_approval_before_execution_recovers_unused_permit(self):
        self.production()
        pending = self.prepare()
        approved = self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=True)
        self.restart()
        self.assertTrue(self.execute(approved.permit_id).executed)

    def test_crash_during_preparation_does_not_mint_on_recovery(self):
        from unittest.mock import patch
        with patch.object(SecureRuntime, 'prepare', side_effect=Crash()):
            with self.assertRaises(Crash):
                self.prepare()
        self.restart()
        result = self.runtime.recover(self.setup.agent_token, self.call.request_id)
        self.assertEqual(result.decision, Decision.REEVALUATE)
        self.assertFalse(self.runtime._permits)
        self.assertFalse(self.setup.effects)

    def test_ordinary_adapter_error_is_unknown_not_retryable(self):
        def fail(call, key):
            self.setup.effects.append(call)
            raise OSError('remote outcome uncertain')
        self.runtime.register_idempotent_adapter('read_document', fail)
        result = self.execute(self.prepare().permit_id)
        self.assertEqual(result.error, 'UNKNOWN_OUTCOME')
        self.restart()
        self.workflow.restore(self.call.request_id)
        self.assertEqual(len(self.setup.effects), 1)

    def test_task_revocation_is_durable(self):
        permit = self.prepare().permit_id
        self.runtime.revoke_task(self.setup.user_token, self.call.task_id)
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.BLOCK)

    def test_foreign_session_cannot_restore_result(self):
        self.execute(self.prepare().permit_id)
        other = self.host.identities.issue_agent_session('FinanceAssistant', self.setup.user_token,
                                                       self.host.policy.environment.source_machine_id)
        self.restart()
        with self.assertRaises(ValueError):
            self.runtime.recover(other, self.call.request_id)

    def test_new_authority_has_no_plaintext_session_tokens(self):
        self.production()
        self.prepare()
        raw = self.store.load()
        self.assertNotIn(self.setup.agent_token, raw)
        self.assertNotIn(self.setup.user_token, raw)

    def test_telemetry_and_authorization_share_database_and_policy_on_restart(self):
        from telemetry.reliability import ReliableDSIService
        from telemetry.sources import TrustedSource
        from telemetry.simulator import SecurityEventSimulator
        from agent_demo import PolicyEngine, DynamicSecurityIndicator, DEMO_ENVIRONMENT
        key = b't' * 32
        source = TrustedSource('security', key, reporting_interval=10, grace_period=5)
        service = ReliableDSIService.open_sqlite(self.runtime.policy, self.path,
            sources=[source], clock=lambda: self.now[0])
        simulator = SecurityEventSimulator(service, source_id='security', key=key)
        simulator.heartbeat()
        self.production()
        pending = self.prepare()
        environment = self.runtime.policy.environment
        environment_epoch = self.runtime.policy.environment_epoch
        service.close()
        self.store.close()
        self.now[0] += 16
        policy = PolicyEngine(DynamicSecurityIndicator(), DEMO_ENVIRONMENT)
        policy.update_environment(environment)
        self.assertEqual(policy.environment_epoch, environment_epoch)
        service = ReliableDSIService.open_sqlite(policy, self.path,
            sources=[source], clock=lambda: self.now[0])
        self.addCleanup(service.close)
        self.store = SQLiteAuthorizationStore(self.path)
        host = SecureRuntime(policy, self.host.identities, self.host.inputs, clock=lambda: self.now[0])
        host._tools = self.host._tools.copy()
        self.runtime = PersistentSecureRuntime(host, self.store)
        self.assertIs(service.policy, self.runtime.policy)
        self.assertIs(service.policy.dsi, self.runtime.policy.dsi)
        result = self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=True)
        self.assertEqual(result.decision, Decision.REEVALUATE)
        self.assertGreaterEqual(policy.dsi.score, 95)
        self.assertFalse(self.setup.effects)

    def test_corrupt_snapshot_fails_closed(self):
        self.store._db.execute("UPDATE authorization SET data='not-json'")
        with self.assertRaises(ValueError):
            self.restart()

    def test_permit_is_hashed_at_rest_and_hash_is_not_a_bearer(self):
        permit = self.prepare().permit_id
        self.assertNotIn(permit, self.store.load())
        saved_hash = next(iter(self.runtime._permits))
        self.restart()
        self.assertEqual(self.execute(saved_hash).decision, Decision.BLOCK)
        self.assertTrue(self.execute(permit).executed)

    def test_approver_revoked_after_approval_blocks_recovered_permit(self):
        self.production()
        pending = self.prepare()
        permit = self.runtime.resolve_approval(self.setup.user_token, pending.approval_id, approved=True).permit_id
        self.host.identities.set_active('Charlie', False)
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.BLOCK)
        self.assertFalse(self.setup.effects)

    def test_graph_cannot_clear_security_state(self):
        self.production()
        self.workflow.start(self.call, self.runtime.policy.capture_context())
        self.runtime.policy.dsi.set_emergency_mode(True)
        self.workflow.graph.invoke({'request_id': self.call.request_id,
            'telemetry': {'score': 0}, 'environment': {'source_risk': 0},
            'security_epoch': 1, 'approved': True},
            {'configurable': {'thread_id': self.call.request_id}})
        self.assertGreaterEqual(self.runtime.policy.dsi.score, 95)
        self.assertFalse(self.setup.effects)

    def test_changed_tool_binding_blocks_recovered_permit(self):
        permit = self.prepare().permit_id
        tool = self.host._tools['read_document']
        self.host.register_tool(tool.name, tool.action, dict(tool.schema), tool.handler)
        self.restart()
        self.assertEqual(self.execute(permit).decision, Decision.REEVALUATE)
        self.assertFalse(self.setup.effects)

    def test_distinct_exact_call_has_distinct_execution_identity(self):
        self.prepare()
        first = self.state()['execution_id']
        other = replace(self.call, request_id='another-request')
        self.runtime.prepare(self.setup.agent_token, other, self.runtime.policy.capture_context())
        self.assertNotEqual(first, self.runtime.request_status(self.setup.agent_token, other.request_id)['execution_id'])
