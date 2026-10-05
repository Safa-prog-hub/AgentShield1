import subprocess
import ipaddress


IPTABLES = "/usr/sbin/iptables"


def execute_response(action, source_ip):
    """
    Execute a controlled lab response.

    BLOCK:
        Adds a real iptables DROP rule for the source IP.

    ISOLATE:
        Currently simulated.

    MONITOR:
        Continues monitoring without changing firewall rules.
    """

    # ---------------------------------------------------------
    # BLOCK SOURCE IP
    # ---------------------------------------------------------
    if action == "BLOCK":

        # Validate source IP before using it in an iptables command.
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return {
                "response_status": "FAILED",
                "action": "BLOCK",
                "target": source_ip,
                "message": f"Invalid source IP: {source_ip}"
            }

        # Check whether the DROP rule already exists.
        check_rule = subprocess.run(
            [
                IPTABLES,
                "-C", "INPUT",
                "-s", source_ip,
                "-j", "DROP"
            ],
            capture_output=True,
            text=True
        )

        # Rule does not exist → add it.
        if check_rule.returncode != 0:

            add_rule = subprocess.run(
                [
                    IPTABLES,
                    "-I", "INPUT", "1",
                    "-s", source_ip,
                    "-j", "DROP"
                ],
                capture_output=True,
                text=True
            )

            if add_rule.returncode != 0:
                return {
                    "response_status": "FAILED",
                    "action": "BLOCK",
                    "target": source_ip,
                    "message": (
                        f"Failed to block source IP {source_ip}: "
                        f"{add_rule.stderr.strip()}"
                    )
                }

            return {
                "response_status": "EXECUTED",
                "action": "BLOCK",
                "target": source_ip,
                "message": (
                    f"Source IP {source_ip} blocked using "
                    f"iptables INPUT DROP rule"
                )
            }

        # Rule already exists.
        return {
            "response_status": "EXECUTED",
            "action": "BLOCK",
            "target": source_ip,
            "message": (
                f"Source IP {source_ip} is already blocked "
                f"by iptables"
            )
        }

    # ---------------------------------------------------------
    # ISOLATE
    # ---------------------------------------------------------
    if action == "ISOLATE":
        return {
            "response_status": "EXECUTED",
            "action": "ISOLATE",
            "target": source_ip,
            "message": f"Simulated isolation of source IP {source_ip}"
        }

    # ---------------------------------------------------------
    # MONITOR
    # ---------------------------------------------------------
    if action == "MONITOR":
        return {
            "response_status": "EXECUTED",
            "action": "MONITOR",
            "target": source_ip,
            "message": f"Continued monitoring of source IP {source_ip}"
        }

    # ---------------------------------------------------------
    # NO ACTION
    # ---------------------------------------------------------
    return {
        "response_status": "NO_ACTION",
        "action": "ALLOW",
        "target": source_ip,
        "message": "No response action required"
    }