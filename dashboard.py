import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import Counter
from html import escape

BASE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(BASE, "output")

INCIDENT_FILE = os.path.join(OUTPUT, "incidents.jsonl")
RESULT_FILE = os.path.join(OUTPUT, "member2_results.jsonl")

COWRIE_LOG = "/mnt/d/cowrie/var/log/cowrie/cowrie.log"


def format_timestamp(value):
    """Convert ISO timestamps to a consistent readable local format."""
    if not value or value == "-":
        return "-"
    try:
        from datetime import datetime
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is not None:
            from datetime import timezone
            dt = dt.astimezone()
        return dt.strftime("%d-%m-%Y %H:%M:%S")
    except Exception:
        return str(value)


def get_blocked_ips():
    """Read active IPv4 INPUT DROP rules from iptables."""
    import subprocess
    blocked = []
    try:
        result = subprocess.run(
            ["/usr/sbin/iptables", "-S", "INPUT"],
            capture_output=True,
            text=True,
            timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "-s" in parts and "-j" in parts:
                try:
                    src = parts[parts.index("-s") + 1]
                    target = parts[parts.index("-j") + 1]
                    if target == "DROP" and src != "0.0.0.0/0":
                        blocked.append({"ip": src, "rule": line})
                except (ValueError, IndexError):
                    continue
    except Exception:
        pass
    return blocked

def read_jsonl(path, max_lines=10000):
    records = []
    if not os.path.exists(path):
        return records

    try:
        with open(path, "rb") as f:
            lines = f.readlines()[-max_lines:]

        for line in lines:
            try:
                records.append(json.loads(line.decode("utf-8")))
            except Exception:
                continue
    except Exception:
        pass

    return records

def build_page():
    incidents = read_jsonl(INCIDENT_FILE)
    results = read_jsonl(RESULT_FILE)

    latest_by_incident = {}

    for r in results:
        iid = r.get("incident_id")
        if iid:
            latest_by_incident[iid] = r

    rows = []

    for inc in incidents:
        iid = inc.get("incident_id", "-")
        result = latest_by_incident.get(iid, {})

        rows.append({
            "incident_id": iid,
            "source_ip": inc.get("source_ip", "-"),
            "threat": inc.get("primary_threat", "-"),
            "events": inc.get("event_count", 0),
            "first_seen": inc.get("first_seen", "-"),
            "last_seen": inc.get("last_seen", "-"),
            "confidence": result.get("confidence"),
            "risk": result.get("risk_score"),
            "severity": result.get("severity", "UNKNOWN"),
            "decision": result.get("decision", "-"),
            "response": result.get("response_status", "-"),
            "verification": result.get("verification_status", "-"),
            "deception": result.get("deception_type", "-")
        })

    rows.sort(key=lambda x: x["last_seen"], reverse=True)

    total = len(rows)
    critical = sum(1 for r in rows if r["severity"] == "CRITICAL")
    high = sum(1 for r in rows if r["severity"] == "HIGH")
    blocked = sum(1 for r in rows if r["decision"] == "BLOCK")
    deception = sum(
        1 for r in rows
        if r["deception"] not in ("-", "", None)
    )
    verified = sum(
        1 for r in rows
        if r["verification"] == "VERIFIED"
    )

    threats = Counter(r["threat"] for r in rows)
    actions = Counter(r["decision"] for r in rows)

    threat_html = ""
    for name, count in threats.most_common():
        threat_html += f"""
        <div class="bar-row">
            <span>{escape(str(name))}</span>
            <div class="bar">
                <div style="width:{min(count * 18, 100)}%"></div>
            </div>
            <b>{count}</b>
        </div>
        """

    action_html = ""
    for name, count in actions.most_common():
        action_html += f"""
        <div class="bar-row">
            <span>{escape(str(name))}</span>
            <div class="bar action-bar">
                <div style="width:{min(count * 18, 100)}%"></div>
            </div>
            <b>{count}</b>
        </div>
        """

    table_html = ""

    for r in rows[:30]:
        severity = r["severity"]

        if severity == "CRITICAL":
            sev_class = "critical"
        elif severity == "HIGH":
            sev_class = "high"
        elif severity == "MEDIUM":
            sev_class = "medium"
        else:
            sev_class = "low"

        confidence = r["confidence"]
        confidence_text = "-"
        if isinstance(confidence, (int, float)):
            confidence_text = f"{confidence * 100:.1f}%"

        risk = r["risk"]
        risk_text = "-"
        if isinstance(risk, (int, float)):
            risk_text = f"{risk * 100:.1f}%"

        table_html += f"""
        <tr>
            <td><b>{escape(str(r["incident_id"]))}</b></td>
            <td>{escape(format_timestamp(r["last_seen"]))}</td>
            <td>{escape(str(r["threat"]))}</td>
            <td>{escape(str(r["source_ip"]))}</td>
            <td>{r["events"]}</td>
            <td>{confidence_text}</td>
            <td>{risk_text}</td>
            <td><span class="badge {sev_class}">
                {escape(str(severity))}
            </span></td>
            <td><b>{escape(str(r["decision"]))}</b></td>
            <td>{escape(str(r["response"]))}</td>
            <td>{escape(str(r["verification"]))}</td>
            <td>{escape(str(r["deception"]))}</td>
        </tr>
        """

    if not table_html:
        table_html = """
        <tr>
            <td colspan="12" class="empty">
                Waiting for security incidents...
            </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">

<title>AgentShield SOC Dashboard</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #0b1120;
    color: #e5e7eb;
    font-family: Arial, Helvetica, sans-serif;
}}

.header {{
    background: #111827;
    border-bottom: 1px solid #263244;
    padding: 22px 30px;
}}

.header h1 {{
    margin: 0;
    font-size: 28px;
}}

.header p {{
    margin: 7px 0 0;
    color: #94a3b8;
}}

.status {{
    float: right;
    color: #22c55e;
    font-weight: bold;
}}

.container {{
    padding: 25px 30px;
}}

.nav {{
    background: #0f172a;
    border-bottom: 1px solid #263244;
    padding: 0 30px;
    display: flex;
    gap: 8px;
}}

.nav a {{
    color: #94a3b8;
    text-decoration: none;
    padding: 14px 18px;
    font-size: 14px;
    font-weight: bold;
    border-bottom: 2px solid transparent;
}}

.nav a:hover {{
    color: #e5e7eb;
    background: #172033;
}}

.nav a.active {{
    color: #60a5fa;
    border-bottom-color: #3b82f6;
}}

.log-table {{
    margin-top: 15px;
}}

.log-success {{
    color: #22c55e;
    font-weight: bold;
}}

.log-command {{
    color: #60a5fa;
    font-family: monospace;
    font-weight: bold;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}

.card {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 18px;
}}

.card-title {{
    color: #94a3b8;
    font-size: 13px;
}}

.card-value {{
    margin-top: 8px;
    font-size: 29px;
    font-weight: bold;
}}

.grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 25px;
}}

.panel {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 20px;
}}

.panel h2 {{
    margin-top: 0;
    font-size: 18px;
}}

.bar-row {{
    display: grid;
    grid-template-columns: 160px 1fr 35px;
    align-items: center;
    gap: 10px;
    margin: 13px 0;
    font-size: 13px;
}}

.bar {{
    height: 10px;
    background: #1e293b;
    border-radius: 10px;
    overflow: hidden;
}}

.bar div {{
    height: 100%;
    background: #3b82f6;
}}

.action-bar div {{
    background: #22c55e;
}}

.table-panel {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 20px;
    overflow-x: auto;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

th {{
    color: #94a3b8;
    text-align: left;
    padding: 12px 10px;
    border-bottom: 1px solid #263244;
}}

td {{
    padding: 13px 10px;
    border-bottom: 1px solid #1f2937;
    white-space: nowrap;
}}

tr:hover {{
    background: #172033;
}}

.badge {{
    padding: 5px 9px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: bold;
}}

.critical {{
    background: #7f1d1d;
    color: #fecaca;
}}

.high {{
    background: #78350f;
    color: #fed7aa;
}}

.medium {{
    background: #713f12;
    color: #fef08a;
}}

.low {{
    background: #14532d;
    color: #bbf7d0;
}}

.empty {{
    text-align: center;
    padding: 40px;
    color: #64748b;
}}

.footer {{
    color: #64748b;
    text-align: center;
    padding: 25px;
    font-size: 12px;
}}

@media(max-width: 1000px) {{
    .cards {{
        grid-template-columns: repeat(3, 1fr);
    }}

    .grid {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>

<body>

<div class="header">
    <span class="status">● LIVE</span>
    <h1>🛡 AgentShield SOC</h1>
    <p>Autonomous Cyber Defense & Incident Management Dashboard</p>
</div>

<div class="nav">
    <a href="/" class="active">Overview</a>
    <a href="/incidents">Incidents</a>
    <a href="/deception">🪤 Deception Logs</a>
    <a href="/blocked">🚫 Blocked IPs</a>
</div>

<div class="container">

<div class="cards">

    <div class="card">
        <div class="card-title">TOTAL INCIDENTS</div>
        <div class="card-value">{total}</div>
    </div>

    <div class="card">
        <div class="card-title">CRITICAL</div>
        <div class="card-value">{critical}</div>
    </div>

    <div class="card">
        <div class="card-title">HIGH</div>
        <div class="card-value">{high}</div>
    </div>

    <div class="card">
        <div class="card-title">BLOCKED</div>
        <div class="card-value">{blocked}</div>
    </div>

    <div class="card">
        <div class="card-title">DECEPTION</div>
        <div class="card-value">{deception}</div>
    </div>

    <div class="card">
        <div class="card-title">VERIFIED</div>
        <div class="card-value">{verified}</div>
    </div>

</div>

<div class="grid">

<div class="panel">
    <h2>Threat Distribution</h2>
    {threat_html or "<p>No threats detected.</p>"}
</div>

<div class="panel">
    <h2>Response Actions</h2>
    {action_html or "<p>No response actions.</p>"}
</div>

</div>

<div class="table-panel">

<h2>Live Incident Correlation</h2>

<table>
<thead>
<tr>
    <th>Incident</th>
    <th>Timestamp</th>
    <th>Threat</th>
    <th>Source IP</th>
    <th>Events</th>
    <th>Confidence</th>
    <th>Risk</th>
    <th>Severity</th>
    <th>Decision</th>
    <th>Response</th>
    <th>Verification</th>
    <th>Deception</th>
</tr>
</thead>

<tbody>
{table_html}
</tbody>
</table>

</div>

<div class="footer">
    AgentShield • Detect → Analyze → Decide → Act → Verify → Learn/Adapt
    • Auto-refresh: 3 seconds
</div>

</div>

</body>
</html>
"""



def build_deception_page():
    logs = read_jsonl(os.path.join(OUTPUT, "deception_events.jsonl"))

    cowrie_lines = []

    if os.path.exists(COWRIE_LOG):
        try:
            with open(COWRIE_LOG, "r", encoding="utf-8", errors="ignore") as f:
                cowrie_lines = f.readlines()[-500:]
        except Exception:
            pass

    sessions = []
    current_sessions = {}

    import re

    for line in cowrie_lines:

        # New Cowrie SSH connection
        m = re.search(
            r"^(\S+) \[ssh,([^,]+),([^\]]+)\] New connection: .*"
            r"\(([^:]+):2222\)",
            line
        )

        if m:
            timestamp = m.group(1)
            session_id = m.group(2)
            source_ip = m.group(3)

            current_sessions[session_id] = {
                "timestamp": timestamp,
                "session_id": session_id,
                "source_ip": source_ip,
                "target": "172.26.45.187:2222",
                "username": "-",
                "login": "-",
                "commands": []
            }

            continue

        # Successful Cowrie login
        m = re.search(
            r"^(\S+) \[ssh,([^,]+),([^\]]+)\] "
            r"login attempt \[([^/]+)/([^\]]+)\] succeeded",
            line
        )

        if m:
            timestamp = m.group(1)
            session_id = m.group(2)
            username = m.group(4)

            session = current_sessions.get(session_id)

            if session:
                session["username"] = username
                session["login"] = "SUCCESS"

            continue

        # Captured command
        m = re.search(
            r"^(\S+) \[ssh,([^,]+),([^\]]+)\] CMD: (.*)$",
            line
        )

        if m:
            timestamp = m.group(1)
            session_id = m.group(2)
            command = m.group(4).strip()

            session = current_sessions.get(session_id)

            if session:
                session["commands"].append({
                    "timestamp": timestamp,
                    "command": command
                })

            continue

        # Connection lost
        m = re.search(
            r"^(\S+) \[ssh,([^,]+),([^\]]+)\] Connection lost",
            line
        )

        if m:
            timestamp = m.group(1)
            session_id = m.group(2)

            session = current_sessions.get(session_id)

            if session:
                session["status"] = "CLOSED"
                sessions.append(session)
                del current_sessions[session_id]

    for session in current_sessions.values():
        sessions.append(session)

    sessions.reverse()

    session_rows = ""

    for session in sessions[:30]:

        commands = session.get("commands", [])

        command_text = "<br>".join(
            f'<span class="log-command">{escape(str(c["command"]))}</span>'
            for c in commands
        )

        if not command_text:
            command_text = "-"

        session_rows += f"""
        <tr>
            <td>{escape(format_timestamp(session.get("timestamp", "-")))}</td>
            <td><b>{escape(str(session.get("source_ip", "-")))}</b></td>
            <td>{escape(str(session.get("session_id", "-")))}</td>
            <td>{escape(str(session.get("target", "-")))}</td>
            <td>{escape(str(session.get("username", "-")))}</td>
            <td>
                <span class="log-success">
                    {escape(str(session.get("login", "-")))}
                </span>
            </td>
            <td>{command_text}</td>
            <td>{escape(str(session.get("status", "ACTIVE")))}</td>
        </tr>
        """

    if not session_rows:
        session_rows = """
        <tr>
            <td colspan="8" class="empty">
                No Cowrie deception sessions recorded yet.
            </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">

<title>AgentShield - Deception Logs</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #0b1120;
    color: #e5e7eb;
    font-family: Arial, Helvetica, sans-serif;
}}

.header {{
    background: #111827;
    border-bottom: 1px solid #263244;
    padding: 22px 30px;
}}

.header h1 {{
    margin: 0;
    font-size: 28px;
}}

.header p {{
    margin: 7px 0 0;
    color: #94a3b8;
}}

.status {{
    float: right;
    color: #22c55e;
    font-weight: bold;
}}

.nav {{
    background: #0f172a;
    border-bottom: 1px solid #263244;
    padding: 0 30px;
    display: flex;
    gap: 8px;
}}

.nav a {{
    color: #94a3b8;
    text-decoration: none;
    padding: 14px 18px;
    font-size: 14px;
    font-weight: bold;
}}

.nav a:hover {{
    color: #e5e7eb;
    background: #172033;
}}

.nav a.active {{
    color: #60a5fa;
    border-bottom: 2px solid #3b82f6;
}}

.container {{
    padding: 25px 30px;
}}

.panel {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 20px;
}}

.panel h2 {{
    margin-top: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

th {{
    color: #94a3b8;
    text-align: left;
    padding: 12px 10px;
    border-bottom: 1px solid #263244;
}}

td {{
    padding: 13px 10px;
    border-bottom: 1px solid #1f2937;
    white-space: nowrap;
    vertical-align: top;
}}

tr:hover {{
    background: #172033;
}}

.log-success {{
    color: #22c55e;
    font-weight: bold;
}}

.log-command {{
    color: #60a5fa;
    font-family: monospace;
    font-weight: bold;
}}

.info {{
    background: #0f172a;
    border: 1px solid #263244;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
    color: #94a3b8;
}}

.info b {{
    color: #e5e7eb;
}}

.empty {{
    text-align: center;
    padding: 40px;
    color: #64748b;
}}
</style>
</head>

<body>

<div class="header">
    <span class="status">● LIVE</span>
    <h1>🛡 AgentShield SOC</h1>
    <p>Deception & Honeypot Activity Monitor</p>
</div>

<div class="nav">
    <a href="/">Overview</a>
    <a href="/incidents">Incidents</a>
    <a href="/deception" class="active">🪤 Deception Logs</a>
    <a href="/blocked">🚫 Blocked IPs</a>
</div>

<div class="container">

<div class="info">
    <b>🪤 Autonomous Deception</b><br>
    Detected attackers are redirected to the Cowrie SSH honeypot.
    This page displays real Cowrie sessions and captured attacker
    activity from the deception environment.
</div>

<div class="panel">

<h2>Deception Sessions</h2>

<table>
<thead>
<tr>
    <th>Timestamp</th>
    <th>Attacker IP</th>
    <th>Session ID</th>
    <th>Honeypot Target</th>
    <th>Username</th>
    <th>Login</th>
    <th>Captured Commands</th>
    <th>Status</th>
</tr>
</thead>

<tbody>
{session_rows}
</tbody>

</table>

</div>

</div>

</body>
</html>
"""


def build_blocked_page():
    blocked = get_blocked_ips()

    rows = ""
    for item in blocked:
        rows += f"""
        <tr>
            <td><b>{escape(str(item["ip"]))}</b></td>
            <td><span class="badge">ACTIVE BLOCK</span></td>
            <td>{escape(str(item["rule"]))}</td>
            <td>iptables INPUT DROP</td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="4" class="empty">No IP addresses are currently blocked by AgentShield.</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>AgentShield - Blocked IPs</title>
<style>
* {{ box-sizing: border-box; }}
body {{ margin:0; background:#0b1120; color:#e5e7eb; font-family:Arial,Helvetica,sans-serif; }}
.header {{ background:#111827; border-bottom:1px solid #263244; padding:22px 30px; }}
.header h1 {{ margin:0; font-size:28px; }}
.header p {{ margin:7px 0 0; color:#94a3b8; }}
.status {{ float:right; color:#22c55e; font-weight:bold; }}
.nav {{ background:#0f172a; border-bottom:1px solid #263244; padding:0 30px; display:flex; gap:8px; }}
.nav a {{ color:#94a3b8; text-decoration:none; padding:14px 18px; font-size:14px; font-weight:bold; border-bottom:2px solid transparent; }}
.nav a:hover {{ color:#e5e7eb; background:#172033; }}
.nav a.active {{ color:#60a5fa; border-bottom-color:#3b82f6; }}
.container {{ padding:25px 30px; }}
.panel {{ background:#111827; border:1px solid #263244; border-radius:10px; padding:20px; }}
.panel h2 {{ margin-top:0; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ color:#94a3b8; text-align:left; padding:12px 10px; border-bottom:1px solid #263244; }}
td {{ padding:13px 10px; border-bottom:1px solid #1f2937; vertical-align:top; }}
tr:hover {{ background:#172033; }}
.badge {{ background:#7f1d1d; color:#fecaca; padding:5px 9px; border-radius:6px; font-size:11px; font-weight:bold; }}
.info {{ background:#0f172a; border:1px solid #263244; border-radius:8px; padding:16px; margin-bottom:20px; color:#94a3b8; }}
.info b {{ color:#e5e7eb; }}
.empty {{ text-align:center; padding:40px; color:#64748b; }}
</style>
</head>
<body>
<div class="header">
<span class="status">● LIVE</span>
<h1>🛡 AgentShield SOC</h1>
<p>Active Firewall Block Management</p>
</div>
<div class="nav">
<a href="/">Overview</a>
<a href="/incidents">Incidents</a>
<a href="/deception">🪤 Deception Logs</a>
<a href="/blocked" class="active">🚫 Blocked IPs</a>
</div>
<div class="container">
<div class="info"><b>🚫 Active Blocks</b><br>
This page reads the current iptables INPUT DROP rules, so it shows IP addresses that are actually blocked right now. It is not based only on historical incidents.
</div>
<div class="panel">
<h2>Currently Blocked IPs ({len(blocked)})</h2>
<table>
<thead><tr><th>Source IP</th><th>Status</th><th>Firewall Rule</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</div>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/deception":
            content = build_deception_page().encode("utf-8")

        elif self.path == "/blocked":
            content = build_blocked_page().encode("utf-8")

        elif self.path == "/incidents":
            content = build_page().encode("utf-8")

        elif self.path == "/" or self.path.startswith("/?"):
            content = build_page().encode("utf-8")

        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()

        try:
            self.wfile.write(content)
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), DashboardHandler)

    print()
    print("==============================================")
    print("        AgentShield SOC Dashboard")
    print("==============================================")
    print()
    print("Dashboard running at:")
    print("http://localhost:8000")
    print()
    print("Reading:")
    print("output/incidents.jsonl")
    print("output/member2_results.jsonl")
    print("Active firewall rules: /usr/sbin/iptables -S INPUT")
    print()
    print("Auto-refresh: 3 seconds")
    print("Press Ctrl+C to stop")
    print()

    server.serve_forever()
