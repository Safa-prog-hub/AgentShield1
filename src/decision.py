def make_decision(severity, threat=None, incident=None):
    """
    Determine the recommended response using:
    - Risk severity
    - Threat type
    - Incident recurrence
    """

    event_count = 1

    if incident:
        event_count = int(
            incident.get("event_count", 1)
        )

    # Critical threats require isolation.
    if severity == "CRITICAL":
        return "ISOLATE"

    # Repeated high-severity activity should be blocked.
    if severity == "HIGH":
        return "BLOCK"

    # Repeated medium-severity attacks become blocking candidates.
    if severity == "MEDIUM" and event_count >= 20:
        return "BLOCK"

    # Normal medium-risk activity is monitored.
    if severity == "MEDIUM":
        return "MONITOR"

    # Low-risk events are allowed.
    if severity == "LOW":
        return "ALLOW"

    return "MONITOR"