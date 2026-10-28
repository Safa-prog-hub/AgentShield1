
import json
import os
from datetime import datetime, timezone, timedelta

COWRIE_EVIDENCE_FILE = "output/deception_events.jsonl"


def _parse_timestamp(value):
    """Convert an ISO timestamp to a timezone-aware datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def get_cowrie_evidence(
    source_ip,
    since=None,
    until=None,
    window_minutes=None
):
    """
    Retrieve Cowrie evidence for a source IP.

    Optional:
      since / until: ISO timestamps defining the incident window.
      window_minutes: recent lookback period ending at the current time.

    Existing return fields are preserved for pipeline compatibility.
    """

    empty_result = {
        "evidence_found": False,
        "event_count": 0,
        "commands": [],
        "last_event": None,
        "session_ids": [],
        "time_filtered": bool(
            since is not None
            or until is not None
            or window_minutes is not None
        ),
    }

    if not os.path.exists(COWRIE_EVIDENCE_FILE):
        return empty_result

    since_dt = _parse_timestamp(since)
    until_dt = _parse_timestamp(until)

    if window_minutes is not None:
        until_dt = datetime.now(timezone.utc)
        since_dt = until_dt - timedelta(minutes=window_minutes)

    matches = []

    with open(
        COWRIE_EVIDENCE_FILE,
        "r",
        encoding="utf-8"
    ) as evidence_file:
        for line in evidence_file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("source_ip") != source_ip:
                continue

            event_time = _parse_timestamp(event.get("timestamp"))

            # If a time filter is requested, ignore events whose
            # timestamps cannot be reliably compared.
            if since_dt is not None or until_dt is not None:
                if event_time is None:
                    continue

                if since_dt is not None and event_time < since_dt:
                    continue

                if until_dt is not None and event_time > until_dt:
                    continue

            matches.append(event)

    # Sort chronologically instead of relying on file order.
    matches.sort(
        key=lambda event: (
            _parse_timestamp(event.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc)
        )
    )

    commands = [
        event.get("command")
        for event in matches
        if event.get("command")
    ]

    session_ids = list(dict.fromkeys(
        event.get("session_id")
        for event in matches
        if event.get("session_id")
    ))

    return {
        "evidence_found": bool(matches),
        "event_count": len(matches),
        "commands": commands,
        "last_event": matches[-1] if matches else None,
        "session_ids": session_ids,
        "time_filtered": bool(
            since is not None
            or until is not None
            or window_minutes is not None
        ),
    }


if __name__ == "__main__":
    result = get_cowrie_evidence("172.26.32.1")

    print("\n=== Cowrie Evidence Lookup ===")
    print(json.dumps(result, indent=2))
