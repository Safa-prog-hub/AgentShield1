def parse_ssh_line(line, fields):
    values = line.rstrip("\n").split("\t")

    if len(values) != len(fields):
        return None

    event = dict(zip(fields, values))

    return {
        "timestamp": event.get("ts"),
        "source_ip": event.get("id.orig_h"),
        "destination_ip": event.get("id.resp_h"),
        "destination_port": event.get("id.resp_p"),
        "auth_success": event.get("auth_success") == "T",
        "auth_attempts": event.get("auth_attempts"),
    }
