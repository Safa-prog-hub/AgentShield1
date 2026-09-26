import json
import os
import time

from normalizer import normalize_zeek_event, save_event


ZEEK_LOG = os.path.expanduser(
    "~/AgentShield/zeek-native/conn.log"
)


def parse_event(line, fields):
    values = line.split("\t")

    if len(values) != len(fields):
        return None

    return dict(zip(fields, values))


def main():

    print("\n======================================")
    print(" AgentShield Live Zeek Collector")
    print("======================================")

    print(f"Monitoring: {ZEEK_LOG}\n")

    while not os.path.exists(ZEEK_LOG):
        print("Waiting for Zeek conn.log...")
        time.sleep(1)

    fields = None

    with open(ZEEK_LOG, "r") as file:

        # Read the header first
        for line in file:

            line = line.rstrip("\n")

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                break

        if fields is None:
            raise RuntimeError(
                "Could not find #fields in conn.log"
            )

        # Start from the current end
        file.seek(0, os.SEEK_END)

        print("Zeek fields loaded.")
        print("Waiting for new Zeek events...\n")

        while True:

            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            line = line.rstrip("\n")

            if not line or line.startswith("#"):
                continue

            event = parse_event(line, fields)

            if event is None:
                print(
                    "Skipped malformed Zeek event:",
                    line
                )
                continue

            try:

                normalized = normalize_zeek_event(event)

                save_event(normalized)

                print(
                    json.dumps(
                        normalized,
                        indent=2
                    )
                )

            except Exception as error:

                print(
                    "Error processing event:",
                    error
                )


if __name__ == "__main__":
    main()
