import json
import os


COWRIE_EVIDENCE_FILE = "output/deception_events.jsonl"


def get_cowrie_evidence(source_ip):
    """
    Retrieve Cowrie interaction evidence
    for a specific source IP.
    """

    if not os.path.exists(COWRIE_EVIDENCE_FILE):
        return {
            "evidence_found": False,
            "event_count": 0,
            "commands": [],
            "last_event": None
        }

    matches = []

    with open(COWRIE_EVIDENCE_FILE, "r") as evidence_file:

        for line in evidence_file:

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("source_ip") == source_ip:
                matches.append(event)

    commands = [
        event.get("command")
        for event in matches
        if event.get("command")
    ]

    return {
        "evidence_found": len(matches) > 0,
        "event_count": len(matches),
        "commands": commands,
        "last_event": matches[-1] if matches else None
    }


if __name__ == "__main__":

    result = get_cowrie_evidence(
        "172.26.32.1"
    )

    print("\n=== Cowrie Evidence Lookup ===")
    print(result)