def detect_user_creation(events):
    alerts = []

    for event in events:
        if event.get("event_id") == "4720":
            alerts.append({
                "severity": "HIGH",
                "risk_score": 80,
                "type": "New User Account Created",
                "mitre_id": "T1136",
                "mitre_technique": "Create Account",
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "description": f"New user account '{event.get('username')}' was created.",
                "recommendation": "Verify whether the account creation was authorized and review related account activity."
            })

    return alerts
