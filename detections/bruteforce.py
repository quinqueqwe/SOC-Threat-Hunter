from collections import defaultdict


def detect_bruteforce(events):
    failed_logins = defaultdict(int)

    for event in events:
        if event.get("event_id") == "4625":
            key = (event.get("username"), event.get("source_ip"))
            failed_logins[key] += 1

    alerts = []

    for (username, source_ip), attempts in failed_logins.items():
        if attempts >= 5:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 90,
                "type": "Possible Brute Force Attack",
                "mitre_id": "T1110",
                "mitre_technique": "Brute Force",
                "username": username,
                "source_ip": source_ip,
                "description": f"{attempts} failed login attempts detected for user '{username}' from {source_ip}.",
                "recommendation": "Investigate authentication logs, check source IP reputation, review successful logins, and consider account lockout or IP blocking."
            })

    return alerts
