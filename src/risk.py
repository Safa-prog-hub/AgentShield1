from datetime import datetime


def calculate_risk(
    threat,
    confidence,
    incident=None,
    behavior=None
):
    """
    Calculate contextual risk using:

    - Threat type
    - ML detection confidence
    - Incident recurrence
    - Incident duration
    - Behavioral evidence
    """

    threat_weights = {
        "SSH_BRUTE_FORCE": 0.85,
        "PortScan": 0.60,
        "DDoS": 0.95,
        "Bot": 0.80,
        "DoS slowloris": 0.85,
        "FTP-Patator": 0.80,
        "Web Attack – Brute Force": 0.85,
        "BENIGN": 0.05
    }

    threat_weight = threat_weights.get(
        threat,
        0.50
    )

    confidence = max(
        0.0,
        min(1.0, float(confidence))
    )

    # ========================================================
    # 1. BASE RISK
    # ========================================================

    base_risk = (
        threat_weight * confidence
    )

    # ========================================================
    # 2. INCIDENT CONTEXT
    # ========================================================

    event_count = 1
    duration_seconds = 0

    if incident:

        event_count = max(
            1,
            int(
                incident.get(
                    "event_count",
                    1
                )
            )
        )

        try:
            first_seen = datetime.fromisoformat(
                incident["first_seen"]
            )

            last_seen = datetime.fromisoformat(
                incident["last_seen"]
            )

            duration_seconds = max(
                0,
                (
                    last_seen - first_seen
                ).total_seconds()
            )

        except (
            KeyError,
            ValueError,
            TypeError
        ):
            duration_seconds = 0

    # ========================================================
    # 3. RECURRENCE FACTOR
    # ========================================================

    if event_count >= 100:
        recurrence_factor = 1.30

    elif event_count >= 50:
        recurrence_factor = 1.20

    elif event_count >= 20:
        recurrence_factor = 1.15

    elif event_count >= 5:
        recurrence_factor = 1.10

    else:
        recurrence_factor = 1.00

    # ========================================================
    # 4. DURATION FACTOR
    # ========================================================

    if duration_seconds >= 300:
        duration_factor = 1.15

    elif duration_seconds >= 60:
        duration_factor = 1.10

    else:
        duration_factor = 1.00

    # ========================================================
    # 5. BEHAVIOR FACTOR
    # ========================================================

    behavior_factor = 1.00

    if behavior:

        behavior_score = max(
            0.0,
            min(
                1.0,
                float(
                    behavior.get(
                        "behavior_score",
                        0.0
                    )
                )
            )
        )

        # Behavioral evidence contributes
        # up to a 20% risk increase.
        behavior_factor = (
            1.00 + (0.20 * behavior_score)
        )

    # ========================================================
    # 6. FINAL CONTEXTUAL RISK
    # ========================================================

    risk_score = (
        base_risk
        * recurrence_factor
        * duration_factor
        * behavior_factor
    )

    risk_score = min(
        1.0,
        risk_score
    )

    # ========================================================
    # 7. SEVERITY
    # ========================================================

    if risk_score >= 0.75:
        severity = "CRITICAL"

    elif risk_score >= 0.50:
        severity = "HIGH"

    elif risk_score >= 0.25:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return round(
        risk_score,
        4
    ), severity