"""Deterministic local restart demonstration. No remote tools or live model calls."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from agent_demo import EnvironmentType
from secure_agent_demo import make_demo
from secure_runtime import SecureRuntime
from authorization.store import SQLiteAuthorizationStore
from authorization.runtime import PersistentSecureRuntime
from agent.persistent_workflow import PersistentSecurityWorkflow


def main():
    now = [1000.0]
    setup = make_demo(lambda: now[0])
    host = setup.runtime
    host.policy.update_environment(replace(host.policy.environment,
                                           environment_type=EnvironmentType.PRODUCTION))
    call = setup.read_call()
    with TemporaryDirectory(prefix='dsi-restart-') as directory:
        path = Path(directory) / 'security.sqlite'
        store = SQLiteAuthorizationStore(path)
        runtime = PersistentSecureRuntime(host, store)
        workflow = PersistentSecurityWorkflow(runtime, setup.agent_token, setup.user_token)
        workflow.start(call, runtime.policy.capture_context())
        print('Before restart:', runtime.request_status(setup.agent_token, call.request_id)['state'])
        store.close()

        # The trusted host supplies the same live IdP/provenance service and
        # verified policy; these are not sourced from the graph checkpoint.
        fresh_host = SecureRuntime(host.policy, host.identities, host.inputs, clock=lambda: now[0])
        fresh_host._tools = host._tools.copy()
        store = SQLiteAuthorizationStore(path)
        runtime = PersistentSecureRuntime(fresh_host, store)
        workflow = PersistentSecurityWorkflow(runtime, setup.agent_token, setup.user_token)
        print('Restored review:', bool(workflow.restore(call.request_id).get('__interrupt__')))
        print('Human response:', workflow.resume(call.request_id, approved=True)['result']['status'])
        print('Restored completed result:', workflow.restore(call.request_id)['result']['status'])
        print('Actual mock tool calls:', len(setup.effects))
        store.close()


if __name__ == '__main__':
    main()
