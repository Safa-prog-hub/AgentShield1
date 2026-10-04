ALLOWED_ACTIONS = {
    "LOW": ["ALLOW", "MONITOR"],
    "MEDIUM": ["MONITOR", "BLOCK"],
    "HIGH": ["BLOCK", "ISOLATE"],
    "CRITICAL": ["ISOLATE", "BLOCK"]
}


def apply_policy(severity, decision, threat=None, incident=None):
    """
    Validate a proposed response against the security policy.

    The policy considers:
    - severity
    - proposed decision
    - threat type
    - incident recurrence
    """

    event_count = 1

    if incident:
        event_count = int(
            incident.get("event_count", 1)
        )

    allowed = ALLOWED_ACTIONS.get(
        severity,
        ["MONITOR"]
    )

    # Repeated medium-risk activity can be blocked.
    if (
        severity == "MEDIUM"
        and event_count >= 20
        and decision == "BLOCK"
    ):
        return {
            "policy_status": "APPROVED",
            "action": "BLOCK",
            "policy_reason": "Repeated medium-risk activity"
        }

    if decision in allowed:
        return {
            "policy_status": "APPROVED",
            "action": decision,
            "policy_reason": f"{severity} severity policy"
        }

    return {
        "policy_status": "DENIED",
        "action": "MONITOR",
        "policy_reason": "Requested action not permitted by policy"
    }