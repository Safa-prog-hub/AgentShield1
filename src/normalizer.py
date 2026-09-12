import json
import uuid
from datetime import datetime


def normalize_zeek_event(event):

    def to_int(value):
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0

    def to_float(value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    timestamp = event.get("ts", "0")

    try:
        timestamp = datetime.fromtimestamp(
            float(timestamp)
        ).isoformat()
    except (ValueError, TypeError):
        timestamp = str(timestamp)

    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "timestamp": timestamp,
        "source_ip": event.get("id.orig_h"),
        "destination_ip": event.get("id.resp_h"),
        "source_port": to_int(event.get("id.orig_p")),
        "destination_port": to_int(event.get("id.resp_p")),
        "protocol": str(
            event.get("proto", "unknown")
        ).upper(),
        "duration": to_float(
            event.get("duration")
        ),
        "source_packets": to_int(
            event.get("orig_pkts")
        ),
        "destination_packets": to_int(
            event.get("resp_pkts")
        ),
        "source_bytes": to_int(
            event.get("orig_bytes")
        ),
        "destination_bytes": to_int(
            event.get("resp_bytes")
        ),
        "event_type": "NETWORK",
        "threat": None,
        "confidence": None
    }


def save_event(
    event,
    filename="output/normalized_events.jsonl"
):
    with open(filename, "a") as file:
        file.write(
            json.dumps(event) + "\n"
        )
