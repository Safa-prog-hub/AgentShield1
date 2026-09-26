import os
import time

from ssh_log_parser import parse_ssh_line
from ssh_bruteforce_detector import detect_ssh_bruteforce


SSH_LOG = os.path.expanduser(
    "~/AgentShield/zeek-native/ssh.log"
)


def load_fields(file):
    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        line = line.rstrip("\n")

        if line.startswith("#fields"):
            return line.split("\t")[1:]


def follow_file(file):
    while True:
        line = file.readline()

        if not line:
            time.sleep(0.5)
            continue

        yield line


def main():
    print("\n======================================")
    print(" AgentShield SSH Brute-Force Detector")
    print("======================================")
    print(f"Monitoring: {SSH_LOG}\n")

    while not os.path.exists(SSH_LOG):
        print("Waiting for Zeek ssh.log...")
        time.sleep(1)

    with open(SSH_LOG, "r") as file:

        fields = load_fields(file)

        print("Zeek SSH fields loaded.")
        print("Monitoring new SSH events...\n")

        # Start from the current end of the file.
        file.seek(0, os.SEEK_END)

        for line in follow_file(file):

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            event = parse_ssh_line(line, fields)

            if event is None:
                print("Skipped malformed SSH event.")
                continue

            # Ignore successful authentication.
            if event["auth_success"] is True:
                continue

            # Ignore records where Zeek did not record an authentication attempt.
            try:
                auth_attempts = int(event["auth_attempts"])
            except (ValueError, TypeError):
                auth_attempts = 0

            if auth_attempts <= 0:
                continue

            detected, confidence = detect_ssh_bruteforce(event)

            print("--------------------------------------")
            print(f"Source IP: {event['source_ip']}")
            print(f"Destination: {event['destination_ip']}:{event['destination_port']}")
            print(f"Authentication attempts: {auth_attempts}")
            print(f"Brute Force: {detected}")
            print(f"Confidence: {confidence:.2%}")

            if detected:
                print("🚨 SSH BRUTE-FORCE DETECTED 🚨")


if __name__ == "__main__":
    main()
