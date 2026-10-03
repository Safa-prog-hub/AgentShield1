ALLOWED_ACTIONS = {
    "LOW": ["ALLOW", "MONITOR"],
    "MEDIUM": ["MONITOR"],
    "HIGH": ["BLOCK"],
    "CRITICAL": ["ISOLATE", "BLOCK"]
}


def apply_policy(severity, decision):
    """
    Check whether the proposed decision is permitted
    by the security policy.
    """

    allowed = ALLOWED_ACTIONS.get(severity, [])

    if decision in allowed:
        return {
            "policy_status": "APPROVED",
            "action": decision
        }

    return {
        "policy_status": "DENIED",
        "action": "MONITOR"
    }