def execute_response(action, source_ip):
    """
    Execute a controlled lab response.

    The current prototype simulates the response instead
    of modifying the real system firewall.
    """

    if action == "BLOCK":
        return {
            "response_status": "EXECUTED",
            "action": "BLOCK",
            "target": source_ip,
            "message": f"Simulated blocking of source IP {source_ip}"
        }

    if action == "ISOLATE":
        return {
            "response_status": "EXECUTED",
            "action": "ISOLATE",
            "target": source_ip,
            "message": f"Simulated isolation of source IP {source_ip}"
        }

    if action == "MONITOR":
        return {
            "response_status": "EXECUTED",
            "action": "MONITOR",
            "target": source_ip,
            "message": f"Continued monitoring of source IP {source_ip}"
        }

    return {
        "response_status": "NO_ACTION",
        "action": "ALLOW",
        "target": source_ip,
        "message": "No response action required"
    }