def calculate_risk(threat, confidence):
    """
    Calculate a risk score and severity from detected threat
    and model confidence.
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

    threat_weight = threat_weights.get(threat, 0.50)

    risk_score = threat_weight * float(confidence)

    if risk_score >= 0.75:
        severity = "CRITICAL"
    elif risk_score >= 0.50:
        severity = "HIGH"
    elif risk_score >= 0.25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return round(risk_score, 4), severity