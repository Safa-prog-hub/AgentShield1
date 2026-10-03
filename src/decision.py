def make_decision(severity):
    """
    Determine the recommended response based on risk severity.
    """

    decisions = {
        "CRITICAL": "ISOLATE",
        "HIGH": "BLOCK",
        "MEDIUM": "MONITOR",
        "LOW": "ALLOW"
    }

    return decisions.get(severity, "MONITOR")