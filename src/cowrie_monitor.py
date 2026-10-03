import json
import os

COWRIE_LOG = "/mnt/d/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_FILE = "output/deception_events.jsonl"


def read_cowrie_events():
    """
    Read attacker interaction events from Cowrie JSON logs.
    """

    if not os.path.exists(COWRIE_LOG):
        print("Cowrie JSON log not found.")
        return []

    events = []

    with open(COWRIE_LOG, "r") as log_file:

        for line in log_file:

            if not line.strip():
                continue

            try:
                entry = json.loads(line)

            except json.JSONDecodeError:
                continue

            event_id = entry.get("eventid")

            if event_id in {
                "cowrie.session.connect",
                "cowrie.login.success",
                "cowrie.command.input"
            }:

                event = {
                    "event_id": event_id,
                    "timestamp": entry.get("timestamp"),
                    "source_ip": entry.get("src_ip"),
                    "username": entry.get("username"),
                    "command": entry.get("input")
                }

                events.append(event)

    return events


def save_deception_events(events):
    """
    Save Cowrie interaction evidence
    in AgentShield JSONL format.
    """

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w"
    ) as output_file:

        for event in events:

            output_file.write(
                json.dumps(event) + "\n"
            )


if __name__ == "__main__":

    events = read_cowrie_events()

    save_deception_events(events)

    print("\n=== AgentShield Deception Evidence ===")

    for event in events[-10:]:
        print(event)

    print(
        f"\nTotal Cowrie events captured: "
        f"{len(events)}"
    )

    print(
        f"Evidence saved to: "
        f"{OUTPUT_FILE}"
    )