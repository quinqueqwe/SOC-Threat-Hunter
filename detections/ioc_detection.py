def load_iocs(path):
    with open(path, encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip() and not line.startswith("#")]


def detect_iocs(events, ioc_path):
    iocs = load_iocs(ioc_path)
    alerts = []

    for event in events:
        source_ip = event.get("source_ip", "")

        if source_ip in iocs:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 98,
                "type": "Known IOC Detected",
                "mitre_id": "T1071",
                "mitre_technique": "Application Layer Protocol",
                "source_ip": source_ip,
                "username": event.get("username"),
                "description": f"Source IP {source_ip} matched an IOC list.",
                "recommendation": "Check threat intelligence sources, block the IP if confirmed malicious, and investigate related host activity."
            })

    return alerts
