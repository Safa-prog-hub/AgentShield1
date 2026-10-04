from datetime import datetime


CORRELATION_WINDOW_SECONDS = 60


def correlate_event(event, incidents):
    """
    Correlate a detection event with an existing incident.

    Events are grouped when they have:
    - the same source IP
    - the same threat type
    - activity within the correlation window

    The incident also maintains:
    - event count
    - first seen
    - last seen
    - event IDs
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

        if incident.get("source_ip") != source_ip:
            continue

        if incident.get("primary_threat") != threat:
            continue

        try:
            last_time = datetime.fromisoformat(
                incident["last_seen"]
            )
        except (KeyError, ValueError):
            continue

        time_difference = abs(
            (event_time - last_time).total_seconds()
        )

        if time_difference <= CORRELATION_WINDOW_SECONDS:

            incident["event_count"] = (
                int(incident.get("event_count", 0)) + 1
            )

            try:
                first_time = datetime.fromisoformat(
                    incident["first_seen"]
                )

                if event_time < first_time:
                    incident["first_seen"] = event["timestamp"]

            except (KeyError, ValueError):
                incident["first_seen"] = event["timestamp"]

            if event_time > last_time:
                incident["last_seen"] = event["timestamp"]

            event_id = event.get("event_id")

            if event_id:
                incident.setdefault(
                    "event_ids",
                    []
                ).append(event_id)

            return incident

    # --------------------------------------------------------
    # Create new incident
    # --------------------------------------------------------

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