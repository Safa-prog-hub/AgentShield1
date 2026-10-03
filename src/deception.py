def select_deception(threat, severity, source_ip):
    """
    Select an adaptive deception action based on
    the detected threat and severity.
    """

    if threat == "PortScan":
        return {
            "deception_type": "PORT_HONEYPOT",
            "target": source_ip,
            "action": "REDIRECT_TO_HONEYPOT",
            "message": "Suspicious scanning source selected for port honeypot deception"
        }

    if threat == "SSH_BRUTE_FORCE":
        return {
            "deception_type": "SSH_HONEYPOT",
            "target": source_ip,
            "action": "REDIRECT_TO_HONEYPOT",
            "message": "SSH brute-force source selected for SSH honeypot deception"
        }

    if severity == "CRITICAL":
        return {
            "deception_type": "HIGH_INTERACTION_HONEYPOT",
            "target": source_ip,
            "action": "REDIRECT_TO_HONEYPOT",
            "message": "Critical threat selected for high-interaction deception"
        }

    if severity == "HIGH":
        return {
            "deception_type": "LOW_INTERACTION_HONEYPOT",
            "target": source_ip,
            "action": "REDIRECT_TO_HONEYPOT",
            "message": "High-severity threat selected for deception"
        }

    return {
        "deception_type": "NONE",
        "target": source_ip,
        "action": "NO_DECEPTION",
        "message": "No deception required"
    }