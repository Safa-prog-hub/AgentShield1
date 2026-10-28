
import subprocess

IPTABLES = "/usr/sbin/iptables"


def verify_response(response_result):
    """
    Independently verify whether a response was applied.

    BLOCK: Check whether the source IP DROP rule exists.
    ISOLATE: Report as simulated, not verified.
    MONITOR: Report as monitoring, not a firewall change.
    """

    action = response_result.get("action")
    target = response_result.get("target")

    if response_result.get("response_status") != "EXECUTED":
        return {
            "verification_status": "FAILED",
            "verified_action": None,
            "target": target,
            "message": "Response command did not report successful execution"
        }

    if action == "BLOCK":
        try:
            check_rule = subprocess.run(
                [
                    IPTABLES,
                    "-C", "INPUT",
                    "-s", str(target),
                    "-j", "DROP"
                ],
                capture_output=True,
                text=True,
                timeout=5
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "verification_status": "FAILED",
                "verified_action": None,
                "target": target,
                "message": f"Could not verify firewall rule: {exc}"
            }

        if check_rule.returncode == 0:
            return {
                "verification_status": "VERIFIED",
                "verified_action": "BLOCK",
                "target": target,
                "message": "Firewall INPUT DROP rule confirmed"
            }

        return {
            "verification_status": "FAILED",
            "verified_action": None,
            "target": target,
            "message": "Firewall INPUT DROP rule was not found"
        }

    if action == "ISOLATE":
        return {
            "verification_status": "SIMULATED",
            "verified_action": None,
            "target": target,
            "message": "Isolation is simulated; no actual isolation was verified"
        }

    if action == "MONITOR":
        return {
            "verification_status": "MONITORING",
            "verified_action": "MONITOR",
            "target": target,
            "message": "Monitoring continues; no firewall change was required"
        }

    return {
        "verification_status": "NOT_APPLICABLE",
        "verified_action": None,
        "target": target,
        "message": "No response action was applied"
    }
