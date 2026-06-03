def detect_admin_group_addition(events):
    alerts = []

    for event in events:
        if event.get("event_id") == "4732":
            alerts.append({
                "severity": "HIGH",
                "risk_score": 95,
                "type": "User Added to Administrators Group",
                "mitre_id": "T1098",
                "mitre_technique": "Account Manipulation",
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "description": f"User '{event.get('username')}' was added to a privileged local group.",
                "recommendation": "Confirm if the privilege change was approved. Investigate for possible privilege escalation."
            })

    return alerts
