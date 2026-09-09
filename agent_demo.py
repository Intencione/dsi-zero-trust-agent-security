from dataclasses import dataclass, replace
from enum import Enum
from datetime import datetime


# ============================================================
# Security States and Decisions
# ============================================================

class SecurityLevel(Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    SEVERE = "SEVERE"
    CRISIS = "CRISIS"


class Decision(Enum):
    ALLOW = "ALLOW"
    APPROVAL = "REQUIRE HUMAN APPROVAL"
    BLOCK = "BLOCK"
    REEVALUATE = "REEVALUATE"


# ============================================================
# Dynamic Security Indicator (DSI)
# ============================================================

class DynamicSecurityIndicator:
    """
    Represents the current organization-wide security condition.

    The score ranges from 0 to 100 and is calculated from
    multiple simulated enterprise security signals.

    A change in security level increments the Security Epoch,
    invalidating authorizations issued under a previous epoch.
    """

    def __init__(self):
        self.score = 0.0
        self.epoch = 1
        self.admin_emergency = False

    def calculate(
        self,
        network_anomaly=0,
        unknown_operations=0,
        destructive_activity=0,
        other_alerts=0
    ):
        """
        Each signal is expected to be between 0 and 100.

        DSI weights:
        - Network anomaly:        30%
        - Unknown operations:     20%
        - Destructive activity:   30%
        - Other alerts:           20%
        """

        previous_level = self.get_level()

        new_score = (
            network_anomaly * 0.30
            + unknown_operations * 0.20
            + destructive_activity * 0.30
            + other_alerts * 0.20
        )

        if self.admin_emergency:
            new_score = max(new_score, 95)

        self.score = min(100, max(0, new_score))

        new_level = self.get_level()

        # A material change in enterprise security condition
        # invalidates previous authorization.
        if previous_level != new_level:
            self.epoch += 1

        return self.score

    def set_emergency_mode(self, enabled: bool):
        """
        Allows a human administrator to manually activate
        or deactivate enterprise crisis mode.
        """

        previous_level = self.get_level()
        self.admin_emergency = enabled

        if enabled:
            self.score = max(self.score, 95)
        else:
            # For this early prototype, disabling emergency mode
            # resets the DSI to a normal state.
            self.score = 0

        new_level = self.get_level()

        if previous_level != new_level:
            self.epoch += 1

    def get_level(self):
        if self.score >= 90:
            return SecurityLevel.CRISIS
        elif self.score >= 75:
            return SecurityLevel.SEVERE
        elif self.score >= 50:
            return SecurityLevel.HIGH
        elif self.score >= 25:
            return SecurityLevel.ELEVATED
        else:
            return SecurityLevel.NORMAL

    def display(self):
        print("\n=== ENTERPRISE SECURITY STATUS ===")
        print(f"DSI Score: {self.score:.1f}")
        print(f"Security Level: {self.get_level().value}")
        print(f"Security Epoch: {self.epoch}")
        print(f"Admin Emergency Mode: {self.admin_emergency}")


# ============================================================
# Agent Identity
# ============================================================

@dataclass
class AgentIdentity:
    name: str
    human_user: str
    department: str
    permissions: list[str]


# ============================================================
# Action Definition
# ============================================================

@dataclass
class Action:
    name: str
    sensitivity: int
    proactive: bool = True
    requires_intranet: bool = False
    file_transfer: bool = False
    destructive: bool = False


# ============================================================
# Machine, Resource, and Execution Environment
# ============================================================

class EnvironmentType(Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class NetworkAccess(Enum):
    ISOLATED = "isolated"
    INTERNAL_ONLY = "internal_only"
    INTERNET_ENABLED = "internet_enabled"


@dataclass(frozen=True)
class EnvironmentContext:
    """Simulated trusted configuration for one source/target/resource scope.

    Sensitivity describes potential impact; risk describes current danger.
    These values must come from infrastructure/inventory in a real system,
    not from an LLM's self-reported description of its tool call.
    """

    source_machine_id: str
    target_machine_id: str
    resource_id: str
    environment_type: EnvironmentType
    source_risk: int
    source_quarantined: bool
    target_risk: int
    target_quarantined: bool
    target_criticality: int
    resource_sensitivity: int
    sandboxed: bool
    privileged_execution: bool
    network_access: NetworkAccess

    def __post_init__(self):
        for name in ("source_machine_id", "target_machine_id", "resource_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty identifier")
        for name in (
            "source_risk", "target_risk", "target_criticality",
            "resource_sensitivity",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 100:
                raise ValueError(f"{name} must be an integer from 0 to 100")
        for name in (
            "source_quarantined", "target_quarantined", "sandboxed",
            "privileged_execution",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if not isinstance(self.environment_type, EnvironmentType):
            raise ValueError("environment_type must be an EnvironmentType")
        if not isinstance(self.network_access, NetworkAccess):
            raise ValueError("network_access must be a NetworkAccess")


@dataclass(frozen=True)
class PlanContext:
    security_epoch: int
    environment_epoch: int
    environment: EnvironmentContext


DEMO_ENVIRONMENT = EnvironmentContext(
    source_machine_id="agent-runner-01",
    target_machine_id="test-server-01",
    resource_id="demo-workspace",
    environment_type=EnvironmentType.TEST,
    source_risk=5,
    source_quarantined=False,
    target_risk=5,
    target_quarantined=False,
    target_criticality=25,
    resource_sensitivity=30,
    sandboxed=True,
    privileged_execution=False,
    network_access=NetworkAccess.INTERNAL_ONLY,
)


# ============================================================
# Example Enterprise Actions
# ============================================================

READ_PUBLIC_INFO = Action(
    name="read_public_information",
    sensitivity=10,
    proactive=True
)

CREATE_PUBLIC_CONTENT = Action(
    name="create_public_content",
    sensitivity=15,
    proactive=True
)

READ_INTERNAL_DOCUMENT = Action(
    name="read_internal_document",
    sensitivity=50,
    proactive=True,
    requires_intranet=True
)

SEND_EMAIL = Action(
    name="send_email",
    sensitivity=40,
    proactive=True
)

TRANSFER_FILE = Action(
    name="transfer_file",
    sensitivity=75,
    proactive=True,
    requires_intranet=True,
    file_transfer=True
)

GENERATE_FINANCIAL_REPORT = Action(
    name="generate_financial_report",
    sensitivity=45,
    proactive=True,
    requires_intranet=True
)

EXECUTE_PAYMENT = Action(
    name="execute_payment",
    sensitivity=95,
    proactive=True,
    requires_intranet=True
)

DELETE_FILE = Action(
    name="delete_file",
    sensitivity=100,
    proactive=True,
    destructive=True
)

READ_SECURITY_LOGS = Action(
    name="read_security_logs",
    sensitivity=60,
    proactive=False,
    requires_intranet=True
)

ISOLATE_HOST = Action(
    name="isolate_compromised_host",
    sensitivity=85,
    proactive=False,
    requires_intranet=True
)


# ============================================================
# Policy Engine
# ============================================================

class PolicyEngine:
    """
    Evaluates whether an AI agent should be allowed to perform
    an action under the current enterprise security condition.
    """

    def __init__(self, dsi: DynamicSecurityIndicator, environment: EnvironmentContext):
        if not isinstance(environment, EnvironmentContext):
            raise ValueError("An explicit EnvironmentContext is required")
        self.dsi = dsi
        self._environment = environment
        self._environment_epoch = 1

    @property
    def environment(self):
        return self._environment

    @property
    def environment_epoch(self):
        return self._environment_epoch

    def update_environment(self, environment: EnvironmentContext):
        """Simulate an inventory/telemetry update, not an agent decision."""
        if not isinstance(environment, EnvironmentContext):
            raise ValueError("An explicit EnvironmentContext is required")
        if environment != self._environment:
            self._environment = environment
            self._environment_epoch += 1

    def capture_context(self):
        return PlanContext(self.dsi.epoch, self.environment_epoch, self.environment)

    def evaluate(self, agent, action, plan_context):
        # ----------------------------------------------------
        # 1. Continuous re-evaluation
        # ----------------------------------------------------

        if not isinstance(plan_context, PlanContext):
            return Decision.REEVALUATE, "A current plan context is required."

        if plan_context.security_epoch != self.dsi.epoch:
            return (
                Decision.REEVALUATE,
                "Security environment changed. "
                "Previous authorization is stale."
            )

        if (
            plan_context.environment_epoch != self.environment_epoch
            or plan_context.environment != self.environment
        ):
            return (
                Decision.REEVALUATE,
                "Machine, resource, or execution environment changed. "
                "Previous authorization is stale.",
            )

        # ----------------------------------------------------
        # 2. Delegated authorization
        # ----------------------------------------------------

        if action.name not in agent.permissions:
            return (
                Decision.BLOCK,
                "Action is outside the agent's delegated authority."
            )

        level = self.dsi.get_level()
        dsi_score = self.dsi.score
        environment = self.environment
        incident_response = (
            agent.department == "cybersecurity"
            and action.name in {"read_security_logs", "isolate_compromised_host"}
        )
        approval_reasons = []

        # Environment denials precede all approval/allow paths. A dangerous
        # source is never exempt, including for incident-response agents.
        if environment.source_quarantined or environment.source_risk >= 75:
            return Decision.BLOCK, "Source machine is quarantined or high risk."

        if (
            environment.target_quarantined or environment.target_risk >= 75
        ) and not incident_response:
            return Decision.BLOCK, "Target machine is quarantined or high risk."

        if (
            action.requires_intranet
            and environment.network_access == NetworkAccess.ISOLATED
        ):
            return Decision.BLOCK, "Isolated execution has no intranet access."

        if (
            action.file_transfer
            and environment.resource_sensitivity >= 75
            and environment.network_access == NetworkAccess.INTERNET_ENABLED
        ):
            return (
                Decision.BLOCK,
                "Sensitive file transfer is blocked in internet-enabled execution.",
            )

        # Illustrative approval floors; these are not calibrated risk weights.
        high_impact = (
            action.sensitivity >= 50 or action.destructive or action.file_transfer
        )
        if environment.source_risk >= 50:
            approval_reasons.append("source machine risk is elevated")
        if environment.target_risk >= 50 and not incident_response:
            approval_reasons.append("target machine risk is elevated")
        if environment.environment_type == EnvironmentType.PRODUCTION and high_impact:
            approval_reasons.append("high-impact operation in production")
        if environment.target_criticality >= 75 and high_impact:
            approval_reasons.append("target machine is business-critical")
        if environment.resource_sensitivity >= 75:
            approval_reasons.append("resource is highly sensitive")
        if environment.privileged_execution:
            approval_reasons.append("execution uses administrator privileges")
        if not environment.sandboxed and high_impact:
            approval_reasons.append("high-impact execution is not sandboxed")

        # ----------------------------------------------------
        # 3. Immediate destructive-action protection
        # ----------------------------------------------------

        if action.destructive:
            if level == SecurityLevel.NORMAL:
                approval_reasons.append("action is destructive")
            else:
                return (
                    Decision.BLOCK,
                    "Destructive actions are blocked under elevated "
                    "security conditions."
                )

        # ----------------------------------------------------
        # 4. Department-aware crisis policies
        # ----------------------------------------------------

        if level == SecurityLevel.CRISIS:

            # Finance has little operational necessity during
            # active cyber incident response.
            if agent.department == "finance" and action.proactive:
                return (
                    Decision.BLOCK,
                    "Finance proactive operations are suspended "
                    "during enterprise crisis mode."
                )

            # Marketing may continue low-risk public work,
            # but loses access to sensitive internal resources.
            if agent.department == "marketing":
                if action.requires_intranet:
                    return (
                        Decision.BLOCK,
                        "Marketing intranet access is suspended "
                        "during crisis mode."
                    )

                if action.file_transfer:
                    return (
                        Decision.BLOCK,
                        "Marketing file transfers are suspended "
                        "during crisis mode."
                    )

            # Cybersecurity agents remain operational because
            # they are directly involved in incident response.
            if incident_response:
                if approval_reasons:
                    return Decision.APPROVAL, "; ".join(approval_reasons) + "."
                return (
                    Decision.ALLOW,
                    "Cybersecurity incident-response action "
                    "remains authorized during crisis mode.",
                )

        # ----------------------------------------------------
        # 5. Dynamic risk calculation
        # ----------------------------------------------------

        # DSI intentionally has a high weight because
        # enterprise-wide threat conditions should strongly
        # influence agent authorization.
        final_risk = (
            dsi_score * 0.60
            + action.sensitivity * 0.40
        )

        # ----------------------------------------------------
        # 6. Final decision
        # ----------------------------------------------------

        if final_risk >= 80:
            return (
                Decision.BLOCK,
                f"Dynamic risk score is too high ({final_risk:.1f})."
            )

        if final_risk >= 60:
            approval_reasons.append(f"elevated dynamic risk ({final_risk:.1f})")

        if approval_reasons:
            return (
                Decision.APPROVAL,
                "Human approval is required: " + "; ".join(approval_reasons) + "."
            )

        else:
            return (
                Decision.ALLOW,
                f"Dynamic risk is acceptable ({final_risk:.1f})."
            )


# ============================================================
# Audit Logging
# ============================================================

def log_event(agent, action, decision, reason, policy, plan_context):
    timestamp = datetime.now().isoformat(timespec="seconds")
    dsi = policy.dsi

    print(
        f"[AUDIT] {timestamp} | "
        f"Agent={agent.name} | "
        f"Department={agent.department} | "
        f"User={agent.human_user} | "
        f"Action={action.name} | "
        f"DSI={dsi.score:.1f} | "
        f"Level={dsi.get_level().value} | "
        f"Epoch={dsi.epoch} | "
        f"EnvironmentEpoch={policy.environment_epoch} | "
        f"PlanContext={plan_context} | "
        f"CurrentEnvironment={policy.environment} | "
        f"Decision={decision.value} | "
        f"Reason={reason}"
    )


# ============================================================
# Runtime Execution
# ============================================================

def execute_action(agent, action, policy, plan_context):
    print("\n--------------------------------------------------")
    print(f"Agent: {agent.name}")
    print(f"Department: {agent.department}")
    print(f"Human User: {agent.human_user}")
    print(f"Requested Action: {action.name}")
    print(f"Action Sensitivity: {action.sensitivity}")
    print(f"Plan Security Epoch: {getattr(plan_context, 'security_epoch', 'missing')}")
    print(f"Current Security Epoch: {policy.dsi.epoch}")
    print(f"Plan Environment Epoch: {getattr(plan_context, 'environment_epoch', 'missing')}")
    print(f"Current Environment Epoch: {policy.environment_epoch}")
    print(f"Environment: {policy.environment}")

    decision, reason = policy.evaluate(
        agent,
        action,
        plan_context
    )

    print(f"Decision: {decision.value}")
    print(f"Reason: {reason}")

    log_event(
        agent,
        action,
        decision,
        reason,
        policy,
        plan_context,
    )

    return decision


# ============================================================
# Agent Definitions
# ============================================================

finance_agent = AgentIdentity(
    name="FinanceAssistant",
    human_user="Charlie",
    department="finance",
    permissions=[
        "read_internal_document",
        "send_email",
        "transfer_file",
        "generate_financial_report",
        "execute_payment"
    ]
)

marketing_agent = AgentIdentity(
    name="MarketingAssistant",
    human_user="Charlie",
    department="marketing",
    permissions=[
        "read_public_information",
        "create_public_content",
        "read_internal_document",
        "send_email",
        "transfer_file"
    ]
)

cybersecurity_agent = AgentIdentity(
    name="CybersecurityAssistant",
    human_user="Charlie",
    department="cybersecurity",
    permissions=[
        "read_security_logs",
        "isolate_compromised_host",
        "read_internal_document"
    ]
)


# ============================================================
# Demo Scenarios
# ============================================================

def scenario_normal(dsi, policy):
    print("\n\n==================================================")
    print("SCENARIO 1: NORMAL ENTERPRISE OPERATION")
    print("==================================================")

    dsi.calculate(
        network_anomaly=5,
        unknown_operations=5,
        destructive_activity=0,
        other_alerts=5
    )

    dsi.display()

    plan_context = policy.capture_context()

    execute_action(
        finance_agent,
        GENERATE_FINANCIAL_REPORT,
        policy,
        plan_context
    )


def scenario_security_incident(dsi, policy):
    print("\n\n==================================================")
    print("SCENARIO 2: SECURITY CONDITION CHANGES")
    print("==================================================")

    # Agent creates a plan while the environment is normal.
    original_plan_context = policy.capture_context()

    print(
        f"\nFinance Agent created a plan under "
        f"Security Epoch {original_plan_context.security_epoch}."
    )

    # Enterprise suddenly detects suspicious activity.
    dsi.calculate(
        network_anomaly=90,
        unknown_operations=75,
        destructive_activity=85,
        other_alerts=80
    )

    dsi.display()

    # Attempt to execute an action under the old authorization.
    execute_action(
        finance_agent,
        TRANSFER_FILE,
        policy,
        original_plan_context
    )

    print("\nAgent re-evaluates the action under the new epoch.")

    new_plan_context = policy.capture_context()

    execute_action(
        finance_agent,
        TRANSFER_FILE,
        policy,
        new_plan_context
    )


def scenario_crisis_mode(dsi, policy):
    print("\n\n==================================================")
    print("SCENARIO 3: ADMINISTRATOR ACTIVATES CRISIS MODE")
    print("==================================================")

    dsi.set_emergency_mode(True)

    dsi.display()

    plan_context = policy.capture_context()

    print("\n--- Finance Agent ---")

    execute_action(
        finance_agent,
        GENERATE_FINANCIAL_REPORT,
        policy,
        plan_context
    )

    print("\n--- Marketing Agent: Public Work ---")

    execute_action(
        marketing_agent,
        CREATE_PUBLIC_CONTENT,
        policy,
        plan_context
    )

    print("\n--- Marketing Agent: Internal File Access ---")

    execute_action(
        marketing_agent,
        TRANSFER_FILE,
        policy,
        plan_context
    )

    print("\n--- Cybersecurity Agent ---")

    execute_action(
        cybersecurity_agent,
        READ_SECURITY_LOGS,
        policy,
        plan_context
    )

    execute_action(
        cybersecurity_agent,
        ISOLATE_HOST,
        policy,
        plan_context
    )


def scenario_machine_environments():
    print("\n\n==================================================")
    print("SCENARIO 4: MACHINE AND EXECUTION ENVIRONMENT")
    print("==================================================")

    # Keep enterprise DSI normal to demonstrate independent local controls.
    policy = PolicyEngine(DynamicSecurityIndicator(), DEMO_ENVIRONMENT)
    policy.dsi.display()

    print("\n--- Read internal document in test environment: ALLOW ---")
    execute_action(
        finance_agent, READ_INTERNAL_DOCUMENT, policy, policy.capture_context()
    )

    print("\n--- Same operation in production: HUMAN APPROVAL ---")
    policy.update_environment(replace(
        DEMO_ENVIRONMENT, environment_type=EnvironmentType.PRODUCTION
    ))
    execute_action(
        finance_agent, READ_INTERNAL_DOCUMENT, policy, policy.capture_context()
    )

    old_context = policy.capture_context()
    policy.update_environment(replace(policy.environment, source_risk=90))
    print("\n--- Source becomes high risk; old context: REEVALUATE ---")
    execute_action(finance_agent, READ_INTERNAL_DOCUMENT, policy, old_context)
    print("\n--- Re-evaluated under the new environment: BLOCK ---")
    execute_action(
        finance_agent, READ_INTERNAL_DOCUMENT, policy, policy.capture_context()
    )

    print("\n--- High-risk target; business operation: BLOCK ---")
    policy.update_environment(replace(DEMO_ENVIRONMENT, target_risk=90))
    execute_action(
        finance_agent, READ_INTERNAL_DOCUMENT, policy, policy.capture_context()
    )
    print("\n--- Healthy source reads incident logs on high-risk target: ALLOW ---")
    execute_action(
        cybersecurity_agent, READ_SECURITY_LOGS, policy, policy.capture_context()
    )

    print("\n--- Sensitive file transfer with internet access: BLOCK ---")
    policy.update_environment(replace(
        DEMO_ENVIRONMENT,
        resource_sensitivity=90,
        network_access=NetworkAccess.INTERNET_ENABLED,
    ))
    execute_action(finance_agent, TRANSFER_FILE, policy, policy.capture_context())


# ============================================================
# Main
# ============================================================

def main():
    dsi = DynamicSecurityIndicator()
    policy = PolicyEngine(dsi, DEMO_ENVIRONMENT)

    scenario_normal(dsi, policy)
    scenario_security_incident(dsi, policy)
    scenario_crisis_mode(dsi, policy)
    scenario_machine_environments()


if __name__ == "__main__":
    main()
