def detect_powershell(events):
    alerts = []

    suspicious_keywords = [
        "-enc",
        "-encodedcommand",
        "iex",
        "downloadstring",
        "invoke-webrequest",
        "bypass",
        "hidden"
    ]

    for event in events:
        if event.get("event_id") != "4688":
            continue

        process = event.get("process_name", "").lower()

        for keyword in suspicious_keywords:
            if keyword in process:
                alerts.append({
                    "severity": "HIGH",
                    "risk_score": 85,
                    "type": "Suspicious PowerShell Execution",
                    "mitre_id": "T1059.001",
                    "mitre_technique": "PowerShell",
                    "process": process,
                    "username": event.get("username"),
                    "source_ip": event.get("source_ip"),
                    "description": f"Suspicious PowerShell keyword detected: {keyword}",
                    "recommendation": "Review command line, parent process, user context, endpoint activity, and possible script execution."
                })
                break

    return alerts
