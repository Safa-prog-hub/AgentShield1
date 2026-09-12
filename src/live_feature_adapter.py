import math


FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]


def safe_number(value):
    try:
        number = float(value)

        if math.isnan(number) or math.isinf(number):
            return 0.0

        return number

    except (ValueError, TypeError):
        return 0.0


def build_live_features(event):
    """
    Convert a normalized Zeek event into the
    78-feature structure expected by the
    trained Random Forest model.

    Features unavailable from a single Zeek
    conn.log record are initialized to 0.
    """

    duration = safe_number(
        event.get("duration")
    )

    fwd_packets = safe_number(
        event.get("source_packets")
    )

    bwd_packets = safe_number(
        event.get("destination_packets")
    )

    fwd_bytes = safe_number(
        event.get("source_bytes")
    )

    bwd_bytes = safe_number(
        event.get("destination_bytes")
    )

    total_packets = (
        fwd_packets + bwd_packets
    )

    total_bytes = (
        fwd_bytes + bwd_bytes
    )

    flow_bytes_per_second = (
        total_bytes / duration
        if duration > 0
        else 0.0
    )

    flow_packets_per_second = (
        total_packets / duration
        if duration > 0
        else 0.0
    )

    fwd_packets_per_second = (
        fwd_packets / duration
        if duration > 0
        else 0.0
    )

    bwd_packets_per_second = (
        bwd_packets / duration
        if duration > 0
        else 0.0
    )

    # Approximate average packet sizes.
    fwd_avg_size = (
        fwd_bytes / fwd_packets
        if fwd_packets > 0
        else 0.0
    )

    bwd_avg_size = (
        bwd_bytes / bwd_packets
        if bwd_packets > 0
        else 0.0
    )

    all_packet_sizes = []

    if fwd_packets > 0:
        all_packet_sizes.append(
            fwd_avg_size
        )

    if bwd_packets > 0:
        all_packet_sizes.append(
            bwd_avg_size
        )

    min_packet_size = (
        min(all_packet_sizes)
        if all_packet_sizes
        else 0.0
    )

    max_packet_size = (
        max(all_packet_sizes)
        if all_packet_sizes
        else 0.0
    )

    average_packet_size = (
        total_bytes / total_packets
        if total_packets > 0
        else 0.0
    )

    features = {

        "Destination Port":
            safe_number(
                event.get("destination_port")
            ),

        "Flow Duration":
            duration,

        "Total Fwd Packets":
            fwd_packets,

        "Total Backward Packets":
            bwd_packets,

        "Total Length of Fwd Packets":
            fwd_bytes,

        "Total Length of Bwd Packets":
            bwd_bytes,

        "Fwd Packet Length Max":
            fwd_avg_size,

        "Fwd Packet Length Min":
            fwd_avg_size,

        "Fwd Packet Length Mean":
            fwd_avg_size,

        "Fwd Packet Length Std":
            0.0,

        "Bwd Packet Length Max":
            bwd_avg_size,

        "Bwd Packet Length Min":
            bwd_avg_size,

        "Bwd Packet Length Mean":
            bwd_avg_size,

        "Bwd Packet Length Std":
            0.0,

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Flow IAT Mean": 0.0,
        "Flow IAT Std": 0.0,
        "Flow IAT Max": 0.0,
        "Flow IAT Min": 0.0,

        "Fwd IAT Total": 0.0,
        "Fwd IAT Mean": 0.0,
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": 0.0,
        "Fwd IAT Min": 0.0,

        "Bwd IAT Total": 0.0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0.0,
        "Bwd IAT Min": 0.0,

        "Fwd PSH Flags": 0.0,
        "Bwd PSH Flags": 0.0,

        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,

        "Fwd Header Length": 0.0,
        "Bwd Header Length": 0.0,

        "Fwd Packets/s":
            fwd_packets_per_second,

        "Bwd Packets/s":
            bwd_packets_per_second,

        "Min Packet Length":
            min_packet_size,

        "Max Packet Length":
            max_packet_size,

        "Packet Length Mean":
            average_packet_size,

        "Packet Length Std": 0.0,

        "Packet Length Variance": 0.0,

        "FIN Flag Count": 0.0,
        "SYN Flag Count": 0.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,

        "Down/Up Ratio":
            (
                bwd_packets / fwd_packets
                if fwd_packets > 0
                else 0.0
            ),

        "Average Packet Size":
            average_packet_size,

        "Avg Fwd Segment Size":
            fwd_avg_size,

        "Avg Bwd Segment Size":
            bwd_avg_size,

        "Fwd Header Length.1": 0.0,

        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,

        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,

        "Subflow Fwd Packets":
            fwd_packets,

        "Subflow Fwd Bytes":
            fwd_bytes,

        "Subflow Bwd Packets":
            bwd_packets,

        "Subflow Bwd Bytes":
            bwd_bytes,

        "Init_Win_bytes_forward": 0.0,
        "Init_Win_bytes_backward": 0.0,

        "act_data_pkt_fwd":
            fwd_packets,

        "min_seg_size_forward": 0.0,

        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,

        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0
    }

    return features


def features_to_list(features):
    """
    Return features in exactly the same
    order used by the trained model.
    """

    return [
        features[name]
        for name in FEATURE_NAMES
    ]
