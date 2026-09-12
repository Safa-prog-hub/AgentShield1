import json
import os

from detector import load_model, detect_threat


INPUT_FILE = "output/normalized_events.jsonl"
OUTPUT_FILE = "output/detection_results.jsonl"


def process_events():

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    model = load_model()

    total = 0

    with open(INPUT_FILE, "r") as infile, \
         open(OUTPUT_FILE, "w") as outfile:

        for line in infile:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                result = detect_threat(
                    model,
                    event
                )

                outfile.write(
                    json.dumps(result) + "\n"
                )

                total += 1

                print(
                    f"[{total}] "
                    f"{result['source_ip']} → "
                    f"{result['destination_ip']}:"
                    f"{result['destination_port']} | "
                    f"{result['threat']} | "
                    f"{result['confidence']:.2%}"
                )

            except Exception as error:

                print(
                    "Error processing event:",
                    error
                )

    print("\n======================================")
    print(" Detection Completed")
    print("======================================")
    print(f"Events processed: {total}")
    print(f"Results saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    process_events()
