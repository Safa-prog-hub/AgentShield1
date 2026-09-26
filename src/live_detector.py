import json
import os
import time
import threading

from detector import load_model, detect_threat
from behavior_detector import detect_port_scan
from ssh_log_parser import parse_ssh_line
from ssh_bruteforce_detector import detect_ssh_bruteforce


INPUT_FILE = "output/normalized_events.jsonl"
OUTPUT_FILE = "output/live_detection_results.jsonl"

SSH_LOG = os.path.expanduser(
    "~/AgentShield/zeek-native/ssh.log"
)


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


def load_ssh_fields(file):

    while True:

        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        line = line.rstrip("\n")

        if line.startswith("#fields"):
            return line.split("\t")[1:]


def ssh_detection_loop(output):

    """
    Monitor Zeek ssh.log and convert SSH brute-force
    detections into the unified AgentShield output format.
    """

    print("\n[SSH] Waiting for Zeek ssh.log...")

    while not os.path.exists(SSH_LOG):
        time.sleep(1)

    with open(SSH_LOG, "r") as file:

        fields = load_ssh_fields(file)

        print("[SSH] Zeek SSH fields loaded.")
        print("[SSH] Monitoring SSH events...\n")

        # Start from new SSH events only.
        file.seek(0, os.SEEK_END)

        while True:

            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:

                event = parse_ssh_line(
                    line,
                    fields
                )

                if event is None:
                    continue

                # Ignore successful authentication.
                if event["auth_success"] is True:
                    continue

                # Ignore incomplete SSH records.
                try:
                    auth_attempts = int(
                        event["auth_attempts"]
                    )
                except (ValueError, TypeError):
                    auth_attempts = 0

                if auth_attempts <= 0:
                    continue

                detected, confidence = detect_ssh_bruteforce(
                    event
                )

                if not detected:
                    continue

                result = {
                    "event_id": f"SSH-{int(time.time() * 1000)}",
                    "timestamp": event["timestamp"],
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "source_port": None,
                    "destination_port": int(
                        event["destination_port"]
                    ),
                    "protocol": "TCP",
                    "threat": "SSH_BRUTE_FORCE",
                    "confidence": round(
                        confidence,
                        4
                    ),
                    "detection_source": "Zeek SSH",
                    "auth_attempts": auth_attempts
                }

                output.write(
                    json.dumps(result) + "\n"
                )

                output.flush()

                print(
                    "--------------------------------------"
                )

                print(
                    f"Event ID: {result['event_id']}"
                )

                print(
                    f"Source: {result['source_ip']}"
                )

                print(
                    f"Destination: "
                    f"{result['destination_ip']}:"
                    f"{result['destination_port']}"
                )

                print(
                    f"Threat: {result['threat']}"
                )

                print(
                    f"Confidence: "
                    f"{result['confidence']:.2%}"
                )

                print(
                    "🚨 SSH BRUTE-FORCE DETECTED 🚨"
                )

            except Exception as error:

                print(
                    "[SSH] Detection error:",
                    error
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

    print("\n======================================")
    print(" AgentShield Live Threat Detection")
    print("======================================")

    model = load_model()

    with open(
        OUTPUT_FILE,
        "a"
    ) as output:

        # Start SSH detection in parallel.
        ssh_thread = threading.Thread(
            target=ssh_detection_loop,
            args=(output,),
            daemon=True
        )

        ssh_thread.start()

        # Keep existing network detection running.
        network_detection_loop(
            model,
            output
        )


if __name__ == "__main__":
    main()