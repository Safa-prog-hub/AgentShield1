import math


def safe_number(value):
    try:
        number = float(value)

        if math.isnan(number) or math.isinf(number):
            return 0.0

        return number

    except (ValueError, TypeError):
        return 0.0


def extract_features(event):
    """
    Convert a normalized AgentShield event
    into numerical features for threat detection.
    """

    source_packets = safe_number(
        event.get("source_packets")
    )

    destination_packets = safe_number(
        event.get("destination_packets")
    )

    source_bytes = safe_number(
        event.get("source_bytes")
    )

    destination_bytes = safe_number(
        event.get("destination_bytes")
    )

    duration = safe_number(
        event.get("duration")
    )

    total_packets = (
        source_packets +
        destination_packets
    )

    total_bytes = (
        source_bytes +
        destination_bytes
    )

    packets_per_second = (
        total_packets / duration
        if duration > 0
        else 0.0
    )

    bytes_per_second = (
        total_bytes / duration
        if duration > 0
        else 0.0
    )

    return {
        "source_port": safe_number(
            event.get("source_port")
        ),

        "destination_port": safe_number(
            event.get("destination_port")
        ),

        "duration": duration,

        "source_packets": source_packets,

        "destination_packets": destination_packets,

        "source_bytes": source_bytes,

        "destination_bytes": destination_bytes,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "packets_per_second": packets_per_second,

        "bytes_per_second": bytes_per_second
    }


if __name__ == "__main__":

    sample_event = {
        "source_port": 5353,
        "destination_port": 5353,
        "duration": 0.79535,
        "source_packets": 6,
        "destination_packets": 0,
        "source_bytes": 1391,
        "destination_bytes": 0
    }

    features = extract_features(sample_event)

    print("Extracted Features:")
    print("--------------------")

    for name, value in features.items():
        print(f"{name}: {value}")
