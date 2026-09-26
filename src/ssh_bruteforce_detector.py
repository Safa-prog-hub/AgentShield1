import time
from collections import defaultdict, deque


WINDOW_SECONDS = 60
FAILURE_THRESHOLD = 3
ATTEMPT_THRESHOLD = 3

failed_connections = defaultdict(deque)


def detect_ssh_bruteforce(event):

    source_ip = event.get("source_ip")
    auth_success = event.get("auth_success")
    auth_attempts = event.get("auth_attempts")

    if not source_ip:
        return False, 0.0

    # Only explicitly failed authentication is considered.
    if auth_success is not False:
        return False, 0.0

    try:
        auth_attempts = int(auth_attempts)
    except (ValueError, TypeError):
        return False, 0.0

    # Ignore incomplete SSH records.
    if auth_attempts <= 0:
        return False, 0.0

    # --------------------------------------------------
    # Case 1:
    # A single SSH connection already contains
    # multiple failed authentication attempts.
    # --------------------------------------------------
    if auth_attempts >= ATTEMPT_THRESHOLD:

        confidence = min(
            1.0,
            0.5 + (auth_attempts - ATTEMPT_THRESHOLD) * 0.1
        )

        return True, confidence

    # --------------------------------------------------
    # Case 2:
    # Multiple failed SSH connections from same source.
    # --------------------------------------------------
    now = time.time()

    history = failed_connections[source_ip]
    history.append(now)

    cutoff = now - WINDOW_SECONDS

    while history and history[0] < cutoff:
        history.popleft()

    failure_count = len(history)

    if failure_count >= FAILURE_THRESHOLD:

        confidence = min(
            1.0,
            failure_count / (FAILURE_THRESHOLD * 2)
        )

        return True, confidence

    return False, 0.0