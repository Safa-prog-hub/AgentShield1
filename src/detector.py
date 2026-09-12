import os
import joblib
import pandas as pd

from live_feature_adapter import (
    build_live_features,
    features_to_list,
    FEATURE_NAMES
)


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "models/agentshield_rf.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    model = joblib.load(
        MODEL_PATH
    )

    print(
        f"Random Forest loaded: {MODEL_PATH}"
    )

    return model


# ============================================================
# DETECT THREAT
# ============================================================

def detect_threat(model, event):

    # Convert normalized event
    # into 78 model features
    features = build_live_features(
        event
    )

    feature_values = features_to_list(
        features
    )

    # Create DataFrame using
    # exactly the same feature names
    # and order used during training.
    X = pd.DataFrame(
        [feature_values],
        columns=FEATURE_NAMES
    )

    # Prediction
    prediction = model.predict(X)[0]

    # Prediction probabilities
    probabilities = model.predict_proba(X)[0]

    # Highest probability
    confidence = float(
        max(probabilities)
    )

    result = {

        "event_id":
            event.get("event_id"),

        "timestamp":
            event.get("timestamp"),

        "source_ip":
            event.get("source_ip"),

        "destination_ip":
            event.get("destination_ip"),

        "destination_port":
            event.get("destination_port"),

        "threat":
            str(prediction),

        "confidence":
            round(confidence, 4)
    }

    return result


# ============================================================
# TEST DETECTOR
# ============================================================

if __name__ == "__main__":

    print("\n======================================")
    print(" AgentShield Threat Detection Agent")
    print("======================================\n")

    model = load_model()

    # Example normalized Zeek event
    sample_event = {

        "event_id":
            "EVT-DEMO001",

        "timestamp":
            "2026-09-12T13:00:00",

        "source_ip":
            "192.168.1.50",

        "destination_ip":
            "10.0.0.10",

        "source_port":
            45122,

        "destination_port":
            22,

        "protocol":
            "TCP",

        "duration":
            1.5,

        "source_packets":
            10,

        "destination_packets":
            5,

        "source_bytes":
            1000,

        "destination_bytes":
            500,

        "event_type":
            "NETWORK"
    }

    result = detect_threat(
        model,
        sample_event
    )

    print("Detection Result")
    print("----------------")

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )

    print(
        "\nThreat detection completed."
    )
