import json
import os

from risk import calculate_risk
from decision import make_decision
from policy import apply_policy
from response import execute_response
from verification import verify_response
from incident_correlation import correlate_event
from deception import select_deception
from recovery import recover_system
from cowrie_evidence import get_cowrie_evidence


INPUT_FILE = "output/live_detection_results.jsonl"
OUTPUT_FILE = "output/member2_results.jsonl"
STATE_FILE = "output/member2_state.txt"
INCIDENT_FILE = "output/incidents.jsonl"


def process_event(event, incident):
    """
    Process one Member-1 detection through the
    Member-2 analysis, response, deception,
    verification, recovery and Cowrie evidence pipeline.
    """

    threat = event.get("threat", "BENIGN")
    confidence = float(event.get("confidence", 0.0))
    source_ip = event.get("source_ip")

    # 1. Risk Analysis
    risk_score, severity = calculate_risk(
        threat,
        confidence
    )

    # 2. Decision
    decision = make_decision(
        severity
    )

    # 3. Policy
    policy_result = apply_policy(
        severity,
        decision
    )

    # 4. Response
    response_result = execute_response(
        policy_result["action"],
        source_ip
    )

    # 5. Verification
    verification_result = verify_response(
        response_result
    )

    # 6. Adaptive Deception
    deception_result = select_deception(
        threat,
        severity,
        source_ip
    )

    # 7. Recovery
    recovery_result = recover_system(
        response_result["action"],
        source_ip
    )

    # 8. Cowrie Evidence
    cowrie_evidence = get_cowrie_evidence(
        source_ip
    )

    return {
        "event_id": event.get("event_id"),
        "incident_id": incident["incident_id"],
        "timestamp": event.get("timestamp"),
        "source_ip": source_ip,
        "destination_ip": event.get("destination_ip"),
        "threat": threat,
        "confidence": confidence,
        "risk_score": risk_score,
        "severity": severity,
        "decision": decision,
        "policy_status": policy_result["policy_status"],
        "action": response_result["action"],
        "response_status": response_result["response_status"],
        "verification_status": verification_result[
            "verification_status"
        ],
        "deception_type": deception_result[
            "deception_type"
        ],
        "deception_action": deception_result[
            "action"
        ],
        "recovery_status": recovery_result[
            "recovery_status"
        ],
        "recovery_action": recovery_result[
            "action"
        ],
        "cowrie_evidence_found": cowrie_evidence[
            "evidence_found"
        ],
        "cowrie_event_count": cowrie_evidence[
            "event_count"
        ],
        "cowrie_commands": cowrie_evidence[
            "commands"
        ]
    }


def load_state():
    """
    Load the number of input lines already processed.
    """

    if not os.path.exists(STATE_FILE):
        return 0

    with open(STATE_FILE, "r") as state_file:
        content = state_file.read().strip()

    if not content:
        return 0

    return int(content)


def save_state(line_number):
    """
    Save the number of input lines already processed.
    """

    with open(STATE_FILE, "w") as state_file:
        state_file.write(str(line_number))


def load_incidents():
    """
    Load existing incidents from the incident file.
    """

    incidents = []

    if not os.path.exists(INCIDENT_FILE):
        return incidents

    with open(INCIDENT_FILE, "r") as incident_file:

        for line in incident_file:

            if not line.strip():
                continue

            incidents.append(
                json.loads(line)
            )

    return incidents


def save_incident(incident):
    """
    Append an incident record to the incident log.
    """

    with open(INCIDENT_FILE, "a") as incident_file:
        incident_file.write(
            json.dumps(incident) + "\n"
        )


def main():

    print("\n======================================")
    print(" AgentShield Member-2 Pipeline")
    print("======================================\n")

    processed_lines = load_state()
    incidents = load_incidents()

    print(
        f"Previously processed input lines: "
        f"{processed_lines}"
    )

    current_line = 0
    new_events = 0

    with open(INPUT_FILE, "r") as input_file, \
            open(OUTPUT_FILE, "a") as output_file:

        for line in input_file:

            current_line += 1

            # Skip previously processed events
            if current_line <= processed_lines:
                continue

            if not line.strip():
                continue

            event = json.loads(line)

            # Ignore benign events
            if event.get("threat") == "BENIGN":
                continue

            # Correlate event into an incident
            incident = correlate_event(
                event,
                incidents
            )

            result = process_event(
                event,
                incident
            )

            output_file.write(
                json.dumps(result) + "\n"
            )

            output_file.flush()

            # Save/update incident
            if incident["event_count"] == 1:

                save_incident(
                    incident
                )

            else:

                # Rewrite incident file with updated state
                with open(
                    INCIDENT_FILE,
                    "w"
                ) as incident_file:

                    for existing_incident in incidents:

                        incident_file.write(
                            json.dumps(
                                existing_incident
                            ) + "\n"
                        )

            new_events += 1

            print("--------------------------------------")
            print(
                f"Event ID       : "
                f"{result['event_id']}"
            )
            print(
                f"Incident ID    : "
                f"{result['incident_id']}"
            )
            print(
                f"Source IP      : "
                f"{result['source_ip']}"
            )
            print(
                f"Threat         : "
                f"{result['threat']}"
            )
            print(
                f"Confidence     : "
                f"{result['confidence']:.2%}"
            )
            print(
                f"Risk Score     : "
                f"{result['risk_score']:.2%}"
            )
            print(
                f"Severity       : "
                f"{result['severity']}"
            )
            print(
                f"Decision       : "
                f"{result['decision']}"
            )
            print(
                f"Policy         : "
                f"{result['policy_status']}"
            )
            print(
                f"Action         : "
                f"{result['action']}"
            )
            print(
                f"Response       : "
                f"{result['response_status']}"
            )
            print(
                f"Verification   : "
                f"{result['verification_status']}"
            )
            print(
                f"Deception      : "
                f"{result['deception_type']}"
            )
            print(
                f"Deception Act. : "
                f"{result['deception_action']}"
            )
            print(
                f"Recovery       : "
                f"{result['recovery_status']}"
            )
            print(
                f"Recovery Act.  : "
                f"{result['recovery_action']}"
            )
            print(
                f"Cowrie Evidence: "
                f"{result['cowrie_evidence_found']}"
            )
            print(
                f"Cowrie Events  : "
                f"{result['cowrie_event_count']}"
            )
            print(
                f"Cowrie Commands: "
                f"{result['cowrie_commands']}"
            )
            print("--------------------------------------")

    save_state(
        current_line
    )

    print(
        f"\nNew events processed: "
        f"{new_events}"
    )

    print(
        f"Input lines processed up to: "
        f"{current_line}"
    )

    print(
        f"Total incidents tracked: "
        f"{len(incidents)}"
    )

    print(
        "Member-2 pipeline completed.\n"
    )


if __name__ == "__main__":
    main()