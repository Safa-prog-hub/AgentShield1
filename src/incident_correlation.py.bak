from datetime import datetime


CORRELATION_WINDOW_SECONDS = 60


def parse_timestamp(timestamp):
    """
    Convert supported AgentShield timestamps into datetime.

    Supports:
    1. ISO format:
       2026-10-04T18:30:00

    2. ISO format with timezone:
       2026-10-04T18:30:00+00:00

    3. Unix / Zeek epoch timestamp:
       1791116933.997188
    """

    if timestamp is None:
        return None

    # Try ISO timestamp first
    try:
        return datetime.fromisoformat(
            str(timestamp)
        )
    except (ValueError, TypeError):
        pass

    # Try Unix / Zeek timestamp
    try:
        return datetime.fromtimestamp(
            float(timestamp)
        )
    except (ValueError, TypeError, OSError):
        return None


def correlate_event(event, incidents):
    """
    Correlate a detection event with an existing incident.

    Events are grouped when they have:
    - the same source IP
    - the same threat type
    - activity within the correlation window

    The incident maintains:
    - event count
    - first seen
    - last seen
    - event IDs
    """

    source_ip = event.get("source_ip")
    threat = event.get("threat")
    timestamp = event.get("timestamp")

    event_time = parse_timestamp(timestamp)

    # If timestamp is invalid, do not silently return None.
    # Create a new incident so the Member-2 pipeline
    # can continue processing the security event.
    if event_time is None:

        incident = {
            "incident_id": (
                f"INC-{len(incidents) + 1:04d}"
            ),
            "source_ip": source_ip,
            "primary_threat": threat,
            "first_seen": str(timestamp),
            "last_seen": str(timestamp),
            "event_count": 1,
            "event_ids": [
                event.get("event_id")
            ]
        }

        incidents.append(incident)

        return incident

    # --------------------------------------------------------
    # Search existing incidents
    # --------------------------------------------------------

    for incident in incidents:

        if incident.get("source_ip") != source_ip:
            continue

        if incident.get("primary_threat") != threat:
            continue

        last_time = parse_timestamp(
            incident.get("last_seen")
        )

        if last_time is None:
            continue

        time_difference = abs(
            (
                event_time - last_time
            ).total_seconds()
        )

        if time_difference <= CORRELATION_WINDOW_SECONDS:

            incident["event_count"] = (
                int(
                    incident.get(
                        "event_count",
                        0
                    )
                ) + 1
            )

            first_time = parse_timestamp(
                incident.get("first_seen")
            )

            if (
                first_time is None
                or event_time < first_time
            ):
                incident["first_seen"] = str(
                    timestamp
                )

            if event_time > last_time:
                incident["last_seen"] = str(
                    timestamp
                )

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
        "incident_id": (
            f"INC-{len(incidents) + 1:04d}"
        ),
        "source_ip": source_ip,
        "primary_threat": threat,
        "first_seen": str(timestamp),
        "last_seen": str(timestamp),
        "event_count": 1,
        "event_ids": [
            event.get("event_id")
        ]
    }

    incidents.append(incident)

    return incident