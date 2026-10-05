import json
import os
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from member2_pipeline import (
    INPUT_FILE,
    OUTPUT_FILE,
    INCIDENT_FILE,
    process_event,
    load_incidents,
    save_incident
)
from incident_correlation import correlate_event


def follow_file(file_path):
    """
    Follow a JSONL file and yield only NEW lines.
    Existing historical events are ignored.
    """

    with open(file_path, "r") as input_file:
        input_file.seek(0, os.SEEK_END)

        while True:
            line = input_file.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line


def print_result(result):
    print("--------------------------------------")
    print(f"Event ID       : {result['event_id']}")
    print(f"Incident ID    : {result['incident_id']}")
    print(f"Source IP      : {result['source_ip']}")
    print(f"Threat         : {result['threat']}")
    print(f"Confidence     : {result['confidence']:.2%}")

    print(f"Behavior Score : {result['behavior_score']}")
    print(f"Unique Ports   : {result['unique_ports']}")
    print(f"Connections    : {result['total_connections']}")
    print(f"Scan Rate      : {result['scan_rate']}")

    print(f"Risk Score     : {result['risk_score']:.2%}")
    print(f"Severity       : {result['severity']}")

    print(f"Decision       : {result['decision']}")

    print(f"Policy         : {result['policy_status']}")
    print(f"Policy Reason  : {result['policy_reason']}")

    print(f"Action         : {result['action']}")
    print(f"Response       : {result['response_status']}")

    print(f"Verification   : {result['verification_status']}")

    print(f"Deception      : {result['deception_type']}")
    print(f"Deception Act. : {result['deception_action']}")

    print(f"Recovery       : {result['recovery_status']}")
    print(f"Recovery Act.  : {result['recovery_action']}")

    print(f"Cowrie Evidence: {result['cowrie_evidence_found']}")
    print(f"Cowrie Events  : {result['cowrie_event_count']}")
    print(f"Cowrie Commands: {result['cowrie_commands']}")

    print("--------------------------------------")
    print()


def main():

    print("\n======================================")
    print(" AgentShield Member-2 LIVE Worker")
    print("======================================")
    print()
    print(f"Monitoring: {INPUT_FILE}")
    print("Waiting for NEW detection events...")
    print()

    incidents = load_incidents()

    with open(OUTPUT_FILE, "a") as output_file:

        for line in follow_file(INPUT_FILE):

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print("Skipping invalid JSON event")
                continue

            threat = event.get("threat", "BENIGN")

            # Ignore benign events
            if threat == "BENIGN":
                continue

            print(f"[NEW EVENT] {event.get('event_id')} | {threat}")

            # Incident correlation
            incident = correlate_event(
                event,
                incidents
            )

            # Member-2 processing
            result = process_event(
                event,
                incident
            )

            # Save result
            output_file.write(
                json.dumps(result)
                + "\n"
            )

            output_file.flush()

            # Save new incident
            if incident["event_count"] == 1:

                save_incident(
                    incident
                )

            print_result(result)


if __name__ == "__main__":
    main()