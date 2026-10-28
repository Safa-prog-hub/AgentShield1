
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
from behavior_detector import analyze_port_scan_behavior


INPUT_FILE = os.getenv(
    "AGENTSHIELD_INPUT",
    "output/live_detection_results.jsonl"
)

OUTPUT_FILE = os.getenv(
    "AGENTSHIELD_OUTPUT",
    "output/member2_results.jsonl"
)

STATE_FILE = os.getenv(
    "AGENTSHIELD_STATE",
    "output/member2_state.txt"
)

INCIDENT_FILE = os.getenv(
    "AGENTSHIELD_INCIDENTS",
    "output/incidents.jsonl"
)


def process_event(event, incident):
    """
    Process a detection through risk analysis, policy,
    response, verification, deception, recovery and evidence.
    """

    threat = event.get("threat", "BENIGN")
    confidence = float(event.get("confidence", 0.0))
    source_ip = event.get("source_ip")

    # 1. Behavioral analysis
    behavior = None

    if threat == "PortScan":
        behavior = analyze_port_scan_behavior(
            event,
            record_event=False
        )

        incoming_behavior_score = event.get("behavior_score")

        if incoming_behavior_score is not None:
            behavior = dict(behavior or {})
            behavior["behavior_score"] = max(
                0.0,
                min(1.0, float(incoming_behavior_score))
            )

    # 2. Risk analysis
    risk_score, severity = calculate_risk(
        threat,
        confidence,
        incident,
        behavior
    )

    # 3. Decision
    decision = make_decision(
        severity,
        threat,
        incident
    )

    # 4. Policy
    policy_result = apply_policy(
        severity,
        decision,
        threat,
        incident
    )

    # 5. Response
    response_result = execute_response(
        policy_result["action"],
        source_ip
    )

    # 6. Verification
    verification_result = verify_response(
        response_result
    )

    # 7. Adaptive deception
    deception_result = select_deception(
        threat,
        severity,
        source_ip
    )

    # 8. Recovery reporting
    # Recovery receives the verification result.
    # The recovery module must distinguish simulated recovery
    # from actual system restoration.
    recovery_result = recover_system(
        response_result["action"],
        source_ip,
        verification_result["verification_status"]
    )

    # 9. Cowrie evidence
    cowrie_evidence = get_cowrie_evidence(
        source_ip
    )

    # 10. Final incident result
    return {
        "event_id": event.get("event_id"),
        "incident_id": incident["incident_id"],
        "timestamp": event.get("timestamp"),
        "source_ip": source_ip,
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "threat": threat,
        "confidence": confidence,

        # Risk
        "risk_score": risk_score,
        "severity": severity,

        # Behavioral evidence
        "behavior_score": (
            behavior.get("behavior_score")
            if behavior else None
        ),
        "unique_ports": (
            behavior.get("unique_ports")
            if behavior else None
        ),
        "total_connections": (
            behavior.get("total_connections")
            if behavior else None
        ),
        "scan_rate": (
            behavior.get("scan_rate")
            if behavior else None
        ),

        # Decision
        "decision": decision,

        # Policy
        "policy_status": policy_result["policy_status"],
        "policy_reason": policy_result.get("policy_reason"),

        # Response
        "action": response_result["action"],
        "response_status": response_result["response_status"],
        "response_message": response_result.get("message"),

        # Verification
        "verification_status": verification_result[
            "verification_status"
        ],
        "verification_message": verification_result.get(
            "message",
            "No verification message available"
        ),

        # Deception
        "deception_type": deception_result.get(
            "deception_type",
            "NONE"
        ),
        "deception_action": deception_result.get(
            "action",
            "NONE"
        ),

        # Recovery
        "recovery_status": recovery_result["recovery_status"],
        "recovery_action": recovery_result["action"],
        "recovery_message": recovery_result.get("message"),

        # Cowrie evidence
        "cowrie_evidence_found": cowrie_evidence.get(
            "evidence_found",
            False
        ),
        "cowrie_event_count": cowrie_evidence.get(
            "event_count",
            0
        ),
        "cowrie_commands": cowrie_evidence.get(
            "commands",
            []
        )
    }


def load_state():
    """Load the number of input lines already processed."""

    if not os.path.exists(STATE_FILE):
        return 0

    with open(STATE_FILE, "r") as state_file:
        content = state_file.read().strip()

    return int(content) if content else 0


def save_state(line_number):
    """Save the number of input lines already processed."""

    with open(STATE_FILE, "w") as state_file:
        state_file.write(str(line_number))


def load_incidents():
    """Load existing incidents from the incident file."""

    incidents = []

    if not os.path.exists(INCIDENT_FILE):
        return incidents

    with open(INCIDENT_FILE, "r") as incident_file:
        for line in incident_file:
            if line.strip():
                incidents.append(json.loads(line))

    return incidents


def save_incident(incident):
    """Append a new incident record."""

    with open(INCIDENT_FILE, "a") as incident_file:
        incident_file.write(json.dumps(incident) + "\n")


def main():
    print("\n======================================")
    print(" AgentShield Member-2 Pipeline")
    print("======================================\n")

    processed_lines = load_state()
    incidents = load_incidents()

    print(f"Previously processed input lines: {processed_lines}")

    current_line = 0
    new_events = 0

    os.makedirs(os.path.dirname(OUTPUT_FILE) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(INCIDENT_FILE) or ".", exist_ok=True)

    with open(INPUT_FILE, "r") as input_file, \
            open(OUTPUT_FILE, "a") as output_file:

        for line in input_file:
            current_line += 1

            # Skip previously processed input lines.
            if current_line <= processed_lines:
                continue

            if not line.strip():
                continue

            event = json.loads(line)

            # Ignore benign detections.
            if event.get("threat") == "BENIGN":
                continue

            # Correlate the event with an incident.
            incident = correlate_event(event, incidents)

            # Process the event.
            result = process_event(event, incident)

            # Append result without overwriting history.
            output_file.write(json.dumps(result) + "\n")
            output_file.flush()

            # Save new or updated incident state.
            if incident["event_count"] == 1:
                save_incident(incident)
            else:
                with open(INCIDENT_FILE, "w") as incident_file:
                    for existing_incident in incidents:
                        incident_file.write(
                            json.dumps(existing_incident) + "\n"
                        )

            new_events += 1

            print("--------------------------------------")
            print(f"Event ID        : {result['event_id']}")
            print(f"Incident ID     : {result['incident_id']}")
            print(f"Source IP       : {result['source_ip']}")
            print(f"Threat          : {result['threat']}")
            print(f"Confidence      : {result['confidence']:.2%}")
            print(f"Behavior Score  : {result['behavior_score']}")
            print(f"Unique Ports    : {result['unique_ports']}")
            print(f"Connections     : {result['total_connections']}")
            print(f"Scan Rate       : {result['scan_rate']}")
            print(f"Risk Score      : {result['risk_score']:.2%}")
            print(f"Severity        : {result['severity']}")
            print(f"Decision        : {result['decision']}")
            print(f"Policy          : {result['policy_status']}")
            print(f"Policy Reason   : {result['policy_reason']}")
            print(f"Action          : {result['action']}")
            print(f"Response        : {result['response_status']}")
            print(f"Response Detail : {result['response_message']}")
            print(f"Verification    : {result['verification_status']}")
            print(f"Verify Detail   : {result['verification_message']}")
            print(f"Deception       : {result['deception_type']}")
            print(f"Deception Act.  : {result['deception_action']}")
            print(f"Recovery        : {result['recovery_status']}")
            print(f"Recovery Act.   : {result['recovery_action']}")
            print(f"Recovery Detail : {result['recovery_message']}")
            print(f"Cowrie Evidence : {result['cowrie_evidence_found']}")
            print(f"Cowrie Events   : {result['cowrie_event_count']}")
            print(f"Cowrie Commands : {result['cowrie_commands']}")
            print("--------------------------------------")

    save_state(current_line)

    print(f"\nNew events processed: {new_events}")
    print(f"Input lines processed up to: {current_line}")
    print(f"Total incidents tracked: {len(incidents)}")
    print("Member-2 pipeline completed.\n")


if __name__ == "__main__":
    main()
