
import json
import os
import re
import time
import threading
import subprocess
from collections import defaultdict, deque

from detector import load_model, detect_threat
from behavior_detector import detect_port_scan
from ssh_bruteforce_detector import detect_ssh_bruteforce


INPUT_FILE = "output/normalized_events.jsonl"
OUTPUT_FILE = "output/live_detection_results.jsonl"

# Real SSH authentication log
AUTH_LOG = "/var/log/auth.log"

# Protected AgentShield server
TARGET_IP = os.getenv(
    "AGENTSHIELD_SSH_TARGET",
    "172.26.45.187"
)

# SSH brute-force settings
WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 3
ALERT_COOLDOWN = 30

failed_attempts = defaultdict(deque)
last_alert = {}


def enable_ssh_honeypot_redirect(source_ip):
    """
    Automatically redirect future SSH connections from a detected
    attacker IP to Cowrie running on port 2222.

    The redirect is applied only after AgentShield detects
    SSH brute-force activity.
    """

    cowrie_port = "2222"

    # Check whether the rule already exists
    check_rule = [
        "iptables",
        "-t",
        "nat",
        "-C",
        "PREROUTING",
        "-s",
        source_ip,
        "-p",
        "tcp",
        "--dport",
        "22",
        "-j",
        "REDIRECT",
        "--to-ports",
        cowrie_port
    ]

    # Rule to add
    add_rule = [
        "iptables",
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-s",
        source_ip,
        "-p",
        "tcp",
        "--dport",
        "22",
        "-j",
        "REDIRECT",
        "--to-ports",
        cowrie_port
    ]

    try:
        # Check if redirect is already active
        check = subprocess.run(
            check_rule,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if check.returncode == 0:
            print(
                f"[DECEPTION] SSH honeypot redirect already active "
                f"for {source_ip}"
            )
            return True

        # Add redirect rule
        result = subprocess.run(
            add_rule,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode == 0:
            print(
                f"[DECEPTION] SSH connection from {source_ip} "
                f"will now be redirected to Cowrie :2222"
            )
            print(
                f"[DECEPTION] Target: {TARGET_IP}:22 "
                f"-> Cowrie :2222"
            )
            return True

        print(
            "[DECEPTION ERROR] Failed to add iptables rule:"
        )
        print(
            result.stderr.strip()
        )

        return False

    except Exception as error:
        print(
            "[DECEPTION ERROR]:",
            error
        )
        return False


def follow_file(file_path):
    """
    Continuously monitor a JSONL file for new events.
    """

    with open(file_path, "r") as file:
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line


def parse_auth_log_line(line):
    """
    Extract failed SSH authentication information
    from /var/log/auth.log.

    Example:

    Failed password for invalid user wronguser
    from 172.26.32.1 port 13703 ssh2
    """

    pattern = (
        r"sshd(?:-session)?\[\d+\]: "
        r"Failed password for "
        r"(?:invalid user )?"
        r"(\S+) "
        r"from "
        r"(\S+) "
        r"port "
        r"(\d+)"
    )

    match = re.search(pattern, line)

    if not match:
        return None

    return {
        "username": match.group(1),
        "source_ip": match.group(2),
        "source_port": int(match.group(3))
    }


def ssh_detection_loop(output):
    """
    Monitor /var/log/auth.log for real SSH authentication
    failures and convert brute-force detections into the
    unified AgentShield output format.
    """

    print("\n[SSH] Waiting for /var/log/auth.log...")

    while not os.path.exists(AUTH_LOG):
        time.sleep(1)

    if not os.access(AUTH_LOG, os.R_OK):
        print(
            "[SSH] ERROR: Cannot read /var/log/auth.log"
        )
        return

    print(
        "[SSH] Authentication log accessible."
    )

    print(
        "[SSH] Monitoring real SSH authentication failures...\n"
    )

    with open(AUTH_LOG, "r") as file:

        # Start from current end.
        # Old attacks should not be detected again.
        file.seek(0, os.SEEK_END)

        while True:

            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()

            if not line:
                continue

            parsed = parse_auth_log_line(line)

            if parsed is None:
                continue

            source_ip = parsed["source_ip"]
            source_port = parsed["source_port"]
            username = parsed["username"]

            now = time.time()

            # Record failed authentication
            failed_attempts[source_ip].append(now)

            # Remove failures older than 60 seconds
            cutoff = now - WINDOW_SECONDS

            history = failed_attempts[source_ip]

            while history and history[0] < cutoff:
                history.popleft()

            attempt_count = len(history)

            # Need at least 3 failures
            if attempt_count < FAILURE_THRESHOLD:
                continue

            # Avoid repeated alerts from the same attacker
            previous_alert = last_alert.get(
                source_ip,
                0
            )

            if now - previous_alert < ALERT_COOLDOWN:
                continue

            # Create common AgentShield event
            event = {
                "timestamp": time.strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
                "source_ip": source_ip,
                "destination_ip": TARGET_IP,
                "destination_port": 22,
                "source_port": source_port,
                "auth_success": False,
                "auth_attempts": attempt_count
            }

            detected, confidence = detect_ssh_bruteforce(
                event
            )

            if not detected:
                continue

            last_alert[source_ip] = now

            # Unified AgentShield detection result
            result = {
                "event_id": (
                    f"SSH-{int(time.time() * 1000)}"
                ),
                "timestamp": event["timestamp"],
                "source_ip": source_ip,
                "destination_ip": TARGET_IP,
                "source_port": source_port,
                "destination_port": 22,
                "protocol": "TCP",
                "threat": "SSH_BRUTE_FORCE",
                "confidence": round(
                    confidence,
                    4
                ),
                "detection_source": "SSH auth.log",
                "auth_attempts": attempt_count,
                "username": username
            }

            # Send detection to AgentShield pipeline
            output.write(
                json.dumps(result) + "\n"
            )

            output.flush()

            print(
                "--------------------------------------"
            )

            print(
                f"Event ID: "
                f"{result['event_id']}"
            )

            print(
                f"Source: "
                f"{result['source_ip']}"
            )

            print(
                f"Destination: "
                f"{result['destination_ip']}:"
                f"{result['destination_port']}"
            )

            print(
                f"Username: "
                f"{result['username']}"
            )

            print(
                f"Authentication failures: "
                f"{result['auth_attempts']}"
            )

            print(
                f"Threat: "
                f"{result['threat']}"
            )

            print(
                f"Confidence: "
                f"{result['confidence']:.2%}"
            )

            print(
                f"Detection source: "
                f"{result['detection_source']}"
            )

            print(
                "🚨 SSH BRUTE-FORCE DETECTED 🚨"
            )

            print(
                "Event written to "
                "live_detection_results.jsonl"
            )

            # -------------------------------------------------
            # AgentShield Autonomous Deception Response
            # -------------------------------------------------
            #
            # IMPORTANT:
            # This happens only AFTER the SSH brute-force
            # detection threshold has been reached.
            #
            # The current failed SSH connection is NOT changed.
            # The NEXT new SSH connection from the attacker
            # will be redirected to Cowrie.
            # -------------------------------------------------

            deception_enabled = enable_ssh_honeypot_redirect(
                source_ip
            )

            if deception_enabled:
                print(
                    "🪤 DECEPTION ACTIVATED"
                )
                print(
                    f"Future SSH connections from "
                    f"{source_ip} will be redirected "
                    f"to Cowrie."
                )
            else:
                print(
                    "⚠️ DECEPTION ACTIVATION FAILED"
                )

            print(
                "--------------------------------------"
            )


def network_detection_loop(model, output):
    """
    Existing AgentShield network detection pipeline.
    """

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    print(
        f"Monitoring: {INPUT_FILE}"
    )

    print(
        "Waiting for new Zeek network events...\n"
    )

    for line in follow_file(INPUT_FILE):

        line = line.strip()

        if not line:
            continue

        try:

            event = json.loads(line)

            result = detect_threat(
                model,
                event
            )

            scan_detected, scan_confidence = detect_port_scan(
                event
            )

            if scan_detected:

                result["threat"] = "PortScan"

                result["confidence"] = round(
                    scan_confidence,
                    4
                )

            output.write(
                json.dumps(result) + "\n"
            )

            output.flush()

            print(
                "--------------------------------------"
            )

            print(
                f"Event ID: "
                f"{result['event_id']}"
            )

            print(
                f"Source: "
                f"{result['source_ip']}"
            )

            print(
                f"Destination: "
                f"{result['destination_ip']}:"
                f"{result['destination_port']}"
            )

            print(
                f"Threat: "
                f"{result['threat']}"
            )

            print(
                f"Confidence: "
                f"{result['confidence']:.2%}"
            )

        except Exception as error:

            print(
                "Detection error:",
                error
            )


def main():

    print(
        "\n======================================"
    )

    print(
        " AgentShield Live Threat Detection"
    )

    print(
        "======================================"
    )

    model = load_model()

    with open(
        OUTPUT_FILE,
        "a"
    ) as output:

        # Start SSH detection in parallel
        ssh_thread = threading.Thread(
            target=ssh_detection_loop,
            args=(output,),
            daemon=True
        )

        ssh_thread.start()

        # Keep existing network detection running
        network_detection_loop(
            model,
            output
        )


if __name__ == "__main__":
    main()

