import time
from collections import defaultdict, deque


WINDOW_SECONDS = 10
UNIQUE_PORT_THRESHOLD = 20

connection_history = defaultdict(deque)


def analyze_port_scan_behavior(event, record_event=True):
    """
    Analyze port-scanning behavior.

    record_event=True:
        Add the current event to behavioral history.

    record_event=False:
        Analyze existing history without adding the
        current event again.

    This prevents Member-2 from double-counting an
    event already processed by Member-1.
    """

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")

    if not source_ip or not destination_ip:
        return {
            "is_suspicious": False,
            "unique_ports": 0,
            "total_connections": 0,
            "scan_rate": 0.0,
            "behavior_score": 0.0
        }

    try:
        destination_port = int(destination_port)
    except (ValueError, TypeError):
        return {
            "is_suspicious": False,
            "unique_ports": 0,
            "total_connections": 0,
            "scan_rate": 0.0,
            "behavior_score": 0.0
        }

    now = time.time()

    key = (
        source_ip,
        destination_ip
    )

    history = connection_history[key]

    # Only Member-1 detection records the event.
    if record_event:
        history.append(
            (
                now,
                destination_port
            )
        )

    cutoff = now - WINDOW_SECONDS

    while history and history[0][0] < cutoff:
        history.popleft()

    total_connections = len(history)

    unique_ports = len({
        port
        for timestamp, port in history
    })

    scan_rate = (
        total_connections / WINDOW_SECONDS
    )

    port_score = min(
        1.0,
        unique_ports /
        (UNIQUE_PORT_THRESHOLD * 2)
    )

    connection_score = min(
        1.0,
        total_connections / 40
    )

    rate_score = min(
        1.0,
        scan_rate / 4
    )

    behavior_score = (
        (port_score * 0.50)
        + (connection_score * 0.30)
        + (rate_score * 0.20)
    )

    is_suspicious = (
        unique_ports >= UNIQUE_PORT_THRESHOLD
    )

    return {
        "is_suspicious": is_suspicious,
        "unique_ports": unique_ports,
        "total_connections": total_connections,
        "scan_rate": round(
            scan_rate,
            4
        ),
        "behavior_score": round(
            behavior_score,
            4
        )
    }


def detect_port_scan(event):
    """
    Member-1 interface.

    Member-1 records the event in behavioral history
    and uses the result for detection.
    """

    result = analyze_port_scan_behavior(
        event,
        record_event=True
    )

    if result["is_suspicious"]:
        return (
            True,
            result["behavior_score"]
        )

    return False, 0.0