import os
import re
import time
from collections import defaultdict, deque

from ssh_bruteforce_detector import detect_ssh_bruteforce


AUTH_LOG = "/var/log/auth.log"

# SSH brute-force detection settings
WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 3
ALERT_COOLDOWN = 30

# Target server IP for the AgentShield lab
TARGET_IP = os.getenv(
    "AGENTSHIELD_SSH_TARGET",
    "172.26.45.187"
)

# Store failed authentication timestamps per source IP
failed_attempts = defaultdict(deque)

# Prevent printing the same alert continuously
last_alert = {}


def parse_auth_log_line(line):
    """
    Parse failed SSH authentication messages from /var/log/auth.log.

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

    username = match.group(1)
    source_ip = match.group(2)
    source_port = int(match.group(3))

    return {
        "username": username,
        "source_ip": source_ip,
        "source_port": source_port
    }


def cleanup_old_attempts(source_ip, now):
    """
    Remove authentication failures older than the detection window.
    """

    history = failed_attempts[source_ip]

    cutoff = now - WINDOW_SECONDS

    while history and history[0] < cutoff:
        history.popleft()


def create_event(source_ip, source_port, attempt_count):
    """
    Convert auth.log information into the common
    AgentShield SSH event structure.
    """

    return {
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


def main():

    print("\n======================================")
    print(" AgentShield SSH Brute-Force Detector")
    print("======================================")
    print(f"Monitoring: {AUTH_LOG}")
    print(f"Target IP: {TARGET_IP}\n")

    if not os.path.exists(AUTH_LOG):
        print("ERROR: /var/log/auth.log not found.")
        return

    # Check whether the file is readable
    if not os.access(AUTH_LOG, os.R_OK):
        print("ERROR: Cannot read /var/log/auth.log")
        print("Make sure the current user has adm permissions.")
        return

    print("Authentication log accessible.")
    print("Monitoring new SSH authentication failures...\n")

    with open(AUTH_LOG, "r") as file:

        # Start from current end.
        # We don't want old authentication failures
        # to trigger a detection when the program starts.
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

            # Record this failed authentication
            failed_attempts[source_ip].append(now)

            # Remove failures outside the 60-second window
            cleanup_old_attempts(source_ip, now)

            attempt_count = len(
                failed_attempts[source_ip]
            )

            print("--------------------------------------")
            print(f"Source IP: {source_ip}")
            print(f"Username: {username}")
            print(f"Source Port: {source_port}")
            print(
                f"Failed attempts in last "
                f"{WINDOW_SECONDS}s: {attempt_count}"
            )

            # Not enough failures yet
            if attempt_count < FAILURE_THRESHOLD:
                print("Brute Force: False")
                continue

            # Prevent repeated alerts every few seconds
            previous_alert = last_alert.get(
                source_ip,
                0
            )

            if now - previous_alert < ALERT_COOLDOWN:
                print(
                    "Brute Force: True "
                    "(alert cooldown active)"
                )
                continue

            event = create_event(
                source_ip,
                source_port,
                attempt_count
            )

            detected, confidence = detect_ssh_bruteforce(
                event
            )

            print(f"Brute Force: {detected}")
            print(f"Confidence: {confidence:.2%}")

            if detected:

                last_alert[source_ip] = now

                print("--------------------------------------")
                print("🚨 SSH BRUTE-FORCE DETECTED 🚨")
                print(f"Source: {source_ip}")
                print(f"Target: {TARGET_IP}:22")
                print(f"Username: {username}")
                print(
                    f"Authentication failures: "
                    f"{attempt_count}"
                )
                print(
                    f"Confidence: "
                    f"{confidence:.2%}"
                )
                print("--------------------------------------")


if __name__ == "__main__":
    main()