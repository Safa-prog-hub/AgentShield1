import time
from collections import defaultdict, deque


# ============================================================
# CONFIGURATION
# ============================================================

WINDOW_SECONDS = 10
UNIQUE_PORT_THRESHOLD = 20


# ============================================================
# PORT SCAN TRACKING
# ============================================================

# Key:
# (source_ip, destination_ip)
#
# Value:
# deque containing:
# (timestamp, destination_port)

connection_history = defaultdict(deque)


# ============================================================
# DETECT PORT SCAN
# ============================================================

def detect_port_scan(event):
    """
    Detect port-scanning behavior using a sliding time window.

    A source is considered suspicious when it contacts
    many unique destination ports on the same destination
    within a short period.
    """

    source_ip = event.get("source_ip")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")

    if not source_ip or not destination_ip:
        return False, 0.0

    try:
        destination_port = int(destination_port)
    except (ValueError, TypeError):
        return False, 0.0

    now = time.time()

    key = (
        source_ip,
        destination_ip
    )

    history = connection_history[key]

    # Add current connection
    history.append(
        (
            now,
            destination_port
        )
    )

    # Remove events outside the time window
    cutoff = now - WINDOW_SECONDS

    while history and history[0][0] < cutoff:
        history.popleft()

    # Count unique destination ports
    unique_ports = {
        port
        for timestamp, port in history
    }

    # Detect scan
    if len(unique_ports) >= UNIQUE_PORT_THRESHOLD:

        confidence = min(
            1.0,
            len(unique_ports) /
            (UNIQUE_PORT_THRESHOLD * 2)
        )

        return True, confidence

    return False, 0.0
