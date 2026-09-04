from dataclasses import dataclass
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

    def __init__(self, dsi: DynamicSecurityIndicator):
        self.dsi = dsi

    def evaluate(self, agent, action, plan_epoch):
        # ----------------------------------------------------
        # 1. Continuous re-evaluation
        # ----------------------------------------------------

        if plan_epoch != self.dsi.epoch:
            return (
                Decision.REEVALUATE,
                "Security environment changed. "
                "Previous authorization is stale."
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

        # ----------------------------------------------------
        # 3. Immediate destructive-action protection
        # ----------------------------------------------------

        if action.destructive:
            if level == SecurityLevel.NORMAL:
                return (
                    Decision.APPROVAL,
                    "Destructive action requires human approval."
                )
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
            if agent.department == "cybersecurity":
                if action.name in {
                    "read_security_logs",
                    "isolate_compromised_host"
                }:
                    return (
                        Decision.ALLOW,
                        "Cybersecurity incident-response action "
                        "remains authorized during crisis mode."
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

        elif final_risk >= 60:
            return (
                Decision.APPROVAL,
                f"Elevated dynamic risk ({final_risk:.1f}). "
                "Human approval is required."
            )

        else:
            return (
                Decision.ALLOW,
                f"Dynamic risk is acceptable ({final_risk:.1f})."
            )


# ============================================================
# Audit Logging
# ============================================================

def log_event(agent, action, decision, reason, dsi):
    timestamp = datetime.now().isoformat(timespec="seconds")

    print(
        f"[AUDIT] {timestamp} | "
        f"Agent={agent.name} | "
        f"Department={agent.department} | "
        f"User={agent.human_user} | "
        f"Action={action.name} | "
        f"DSI={dsi.score:.1f} | "
        f"Level={dsi.get_level().value} | "
        f"Epoch={dsi.epoch} | "
        f"Decision={decision.value} | "
        f"Reason={reason}"
    )


# ============================================================
# Runtime Execution
# ============================================================

def execute_action(agent, action, policy, plan_epoch):
    print("\n--------------------------------------------------")
    print(f"Agent: {agent.name}")
    print(f"Department: {agent.department}")
    print(f"Human User: {agent.human_user}")
    print(f"Requested Action: {action.name}")
    print(f"Action Sensitivity: {action.sensitivity}")
    print(f"Plan Epoch: {plan_epoch}")
    print(f"Current Security Epoch: {policy.dsi.epoch}")

    decision, reason = policy.evaluate(
        agent,
        action,
        plan_epoch
    )

    print(f"Decision: {decision.value}")
    print(f"Reason: {reason}")

    log_event(
        agent,
        action,
        decision,
        reason,
        policy.dsi
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

    plan_epoch = dsi.epoch

    execute_action(
        finance_agent,
        GENERATE_FINANCIAL_REPORT,
        policy,
        plan_epoch
    )


def scenario_security_incident(dsi, policy):
    print("\n\n==================================================")
    print("SCENARIO 2: SECURITY CONDITION CHANGES")
    print("==================================================")

    # Agent creates a plan while the environment is normal.
    original_plan_epoch = dsi.epoch

    print(
        f"\nFinance Agent created a plan under "
        f"Security Epoch {original_plan_epoch}."
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
        original_plan_epoch
    )

    print("\nAgent re-evaluates the action under the new epoch.")

    new_plan_epoch = dsi.epoch

    execute_action(
        finance_agent,
        TRANSFER_FILE,
        policy,
        new_plan_epoch
    )


def scenario_crisis_mode(dsi, policy):
    print("\n\n==================================================")
    print("SCENARIO 3: ADMINISTRATOR ACTIVATES CRISIS MODE")
    print("==================================================")

    dsi.set_emergency_mode(True)

    dsi.display()

    plan_epoch = dsi.epoch

    print("\n--- Finance Agent ---")

    execute_action(
        finance_agent,
        GENERATE_FINANCIAL_REPORT,
        policy,
        plan_epoch
    )

    print("\n--- Marketing Agent: Public Work ---")

    execute_action(
        marketing_agent,
        CREATE_PUBLIC_CONTENT,
        policy,
        plan_epoch
    )

    print("\n--- Marketing Agent: Internal File Access ---")

    execute_action(
        marketing_agent,
        TRANSFER_FILE,
        policy,
        plan_epoch
    )

    print("\n--- Cybersecurity Agent ---")

    execute_action(
        cybersecurity_agent,
        READ_SECURITY_LOGS,
        policy,
        plan_epoch
    )

    execute_action(
        cybersecurity_agent,
        ISOLATE_HOST,
        policy,
        plan_epoch
    )


# ============================================================
# Main
# ============================================================

def main():
    dsi = DynamicSecurityIndicator()
    policy = PolicyEngine(dsi)

    scenario_normal(dsi, policy)
    scenario_security_incident(dsi, policy)
    scenario_crisis_mode(dsi, policy)


if __name__ == "__main__":
    main()