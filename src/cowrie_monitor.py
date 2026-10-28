
import json
import os

COWRIE_LOG = "/mnt/d/cowrie/var/log/cowrie/cowrie.json"
OUTPUT_FILE = "output/deception_events.jsonl"

TRACKED_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
}


def read_cowrie_events():
    """Read selected attacker interaction events from Cowrie JSON logs."""

    if not os.path.exists(COWRIE_LOG):
        print(f"Cowrie JSON log not found: {COWRIE_LOG}")
        return []

    events = []

    with open(COWRIE_LOG, "r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = entry.get("eventid")
            if event_id not in TRACKED_EVENTS:
                continue

            events.append({
                "event_id": event_id,
                "timestamp": entry.get("timestamp"),
                "source_ip": entry.get("src_ip"),
                "session_id": entry.get("session"),
                "username": entry.get("username"),
                "command": entry.get("input"),
            })

    return events


def save_deception_events(events):
    """Append Cowrie evidence as JSONL without overwriting existing records."""

    output_dir = os.path.dirname(OUTPUT_FILE)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Append mode preserves earlier evidence.
    # Avoid duplicate records when the complete Cowrie log is re-read.
    existing_keys = set()

    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as output_file:
            for line in output_file:
                try:
                    old_event = json.loads(line)
                    key = (
                        old_event.get("session_id"),
                        old_event.get("event_id"),
                        old_event.get("timestamp"),
                        old_event.get("command"),
                    )
                    existing_keys.add(key)
                except json.JSONDecodeError:
                    continue

    written = 0

    with open(OUTPUT_FILE, "a", encoding="utf-8") as output_file:
        for event in events:
            key = (
                event.get("session_id"),
                event.get("event_id"),
                event.get("timestamp"),
                event.get("command"),
            )

            if key in existing_keys:
                continue

            output_file.write(json.dumps(event) + "\n")
            existing_keys.add(key)
            written += 1

    return written


if __name__ == "__main__":
    events = read_cowrie_events()
    written = save_deception_events(events)

    print("\n=== AgentShield Deception Evidence ===")
    for event in events[-10:]:
        print(event)

    print(f"\nCowrie events read: {len(events)}")
    print(f"New evidence records saved: {written}")
    print(f"Evidence file: {OUTPUT_FILE}")
