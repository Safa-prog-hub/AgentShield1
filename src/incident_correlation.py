from datetime import datetime


CORRELATION_WINDOW_SECONDS = 60


def correlate_event(event, incidents):
    """
    Correlate a detection event with an existing incident.

    Events are grouped when they have the same source IP,
    same threat type, and occur within the correlation window.
    """

    source_ip = event.get("source_ip")
    threat = event.get("threat")

    try:
        event_time = datetime.fromisoformat(
            event["timestamp"]
        )
    except (KeyError, ValueError):
        return None

    for incident in incidents:

        if incident["source_ip"] != source_ip:
            continue

        if incident["primary_threat"] != threat:
            continue

        try:
            last_time = datetime.fromisoformat(
                incident["last_seen"]
            )
        except ValueError:
            continue

        time_difference = abs(
            event_time - last_time
        ).total_seconds()

        if 0 <= time_difference <= CORRELATION_WINDOW_SECONDS:
            incident["event_count"] += 1

            if event_time < datetime.fromisoformat(incident["first_seen"]):
                incident["first_seen"] = event["timestamp"]

            if event_time > datetime.fromisoformat(incident["last_seen"]):
                incident["last_seen"] = event["timestamp"]

            incident["event_ids"].append(
                event.get("event_id")
            )

            return incident

    # No matching incident found → create a new incident.
    incident = {
        "incident_id": f"INC-{len(incidents) + 1:04d}",
        "source_ip": source_ip,
        "primary_threat": threat,
        "first_seen": event["timestamp"],
        "last_seen": event["timestamp"],
        "event_count": 1,
        "event_ids": [
            event.get("event_id")
        ]
    }

    incidents.append(incident)

    return incident