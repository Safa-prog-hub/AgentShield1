import json
import os
import time

from detector import load_model, detect_threat


INPUT_FILE = "output/normalized_events.jsonl"
OUTPUT_FILE = "output/live_detection_results.jsonl"


def follow_file(file_path):
    """
    Continuously monitor a JSONL file for new events.
    """

    with open(file_path, "r") as file:

        # Start from the current end of file.
        file.seek(0, os.SEEK_END)

        while True:

            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line


def main():

    print("\n======================================")
    print(" AgentShield Live Threat Detection")
    print("======================================")

    if not os.path.exists(INPUT_FILE):

        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    model = load_model()

    print(
        f"Monitoring: {INPUT_FILE}"
    )

    print(
        "Waiting for new Zeek events...\n"
    )

    with open(
        OUTPUT_FILE,
        "a"
    ) as output:

        for line in follow_file(
            INPUT_FILE
        ):

            line = line.strip()

            if not line:
                continue

            try:

                event = json.loads(line)

                result = detect_threat(
                    model,
                    event
                )

                output.write(
                    json.dumps(result) + "\n"
                )

                output.flush()

                print(
                    "--------------------------------------"
                )

                print(
                    f"Event ID: "
                    f"{result['event_id']}"
                )

                print(
                    f"Source: "
                    f"{result['source_ip']}"
                )

                print(
                    f"Destination: "
                    f"{result['destination_ip']}:"
                    f"{result['destination_port']}"
                )

                print(
                    f"Threat: "
                    f"{result['threat']}"
                )

                print(
                    f"Confidence: "
                    f"{result['confidence']:.2%}"
                )

            except Exception as error:

                print(
                    "Detection error:",
                    error
                )


if __name__ == "__main__":

    main()
