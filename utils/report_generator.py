from html import escape


def print_alert(alert):
    print("=" * 80)
    print(f"SEVERITY        : {alert.get('severity')}")
    print(f"RISK SCORE      : {alert.get('risk_score')}/100")
    print(f"ALERT TYPE      : {alert.get('type')}")
    print(f"MITRE ATT&CK    : {alert.get('mitre_id')} - {alert.get('mitre_technique')}")

    if alert.get("username"):
        print(f"USERNAME        : {alert.get('username')}")

    if alert.get("source_ip"):
        print(f"SOURCE IP       : {alert.get('source_ip')}")

    if alert.get("process"):
        print(f"PROCESS         : {alert.get('process')}")

    print(f"DESCRIPTION     : {alert.get('description', 'Suspicious activity detected.')}")
    print(f"RECOMMENDATION  : {alert.get('recommendation', 'Investigate the event.')}")
    print("=" * 80)


def save_text_report(alerts, path):
    with open(path, "w", encoding="utf-8") as report:
        report.write("SOC Threat Hunter\n")
        report.write("=" * 35 + "\n\n")

        for alert in alerts:
            report.write(f"Severity: {alert.get('severity')}\n")
            report.write(f"Risk Score: {alert.get('risk_score')}/100\n")
            report.write(f"Alert Type: {alert.get('type')}\n")
            report.write(f"MITRE ATT&CK: {alert.get('mitre_id')} - {alert.get('mitre_technique')}\n")

            if alert.get("username"):
                report.write(f"Username: {alert.get('username')}\n")

            if alert.get("source_ip"):
                report.write(f"Source IP: {alert.get('source_ip')}\n")

            if alert.get("process"):
                report.write(f"Process: {alert.get('process')}\n")

            report.write(f"Description: {alert.get('description', 'Suspicious activity detected.')}\n")
            report.write(f"Recommendation: {alert.get('recommendation', 'Investigate the event.')}\n")
            report.write("-" * 35 + "\n\n")


def save_html_report(alerts, path):
    rows = ""

    for alert in alerts:
        rows += f"""
        <tr>
            <td>{escape(str(alert.get('severity')))}</td>
            <td>{escape(str(alert.get('risk_score')))}</td>
            <td>{escape(str(alert.get('type')))}</td>
            <td>{escape(str(alert.get('mitre_id')))} - {escape(str(alert.get('mitre_technique')))}</td>
            <td>{escape(str(alert.get('username', '')))}</td>
            <td>{escape(str(alert.get('source_ip', '')))}</td>
            <td>{escape(str(alert.get('description', '')))}</td>
            <td>{escape(str(alert.get('recommendation', '')))}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Threat Hunter</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f6f8;
        }}
        h1 {{
            color: #1f2937;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        th, td {{
            border: 1px solid #d1d5db;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #111827;
            color: white;
        }}
        tr:nth-child(even) {{
            background: #f9fafb;
        }}
    </style>
</head>
<body>
    <h1>SOC Threat Hunter</h1>
    <p>This report was generated automatically by the SOC Threat Hunter tool.</p>

    <table>
        <tr>
            <th>Severity</th>
            <th>Risk Score</th>
            <th>Alert Type</th>
            <th>MITRE ATT&CK</th>
            <th>Username</th>
            <th>Source IP</th>
            <th>Description</th>
            <th>Recommendation</th>
        </tr>
        {rows}
    </table>
</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as report:
        report.write(html)
