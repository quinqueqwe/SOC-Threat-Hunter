# SOC Threat Hunter 

SOC Threat Hunter is a Python-based threat hunting toolkit for detecting suspicious Windows security events.

This project simulates SOC Analyst L1 workflows by analyzing Windows-style event logs, generating alerts, assigning risk scores, 
mapping detections to MITRE ATT&CK, and producing text and HTML investigation reports.


## Project Goals

- Practice Windows Event Log analysis
- Build basic threat detection logic
- Simulate SOC alert triage
- Add risk scoring similar to SIEM alerts
- Map detections to MITRE ATT&CK techniques
- Generate investigation reports


## Detection Capabilities

| Detection | Windows Event ID | MITRE ATT&CK | Risk Score |
|---|---:|---|---:|
| Failed login brute-force activity | 4625 | T1110 - Brute Force | 90 |
| Suspicious PowerShell execution | 4688 | T1059.001 - PowerShell | 85 |
| New user account creation | 4720 | T1136 - Create Account | 80 |
| User added to administrators group | 4732 | T1098 - Account Manipulation | 95 |
| Known IOC source IP detected | Any | T1071 - Application Layer Protocol | 98 |


## Project Structure

```text
soc-threat-hunter-v2/
├── detections/
│   ├── admin_group.py
│   ├── bruteforce.py
│   ├── ioc_detection.py
│   ├── powershell.py
│   └── user_creation.py
├── ioc/
│   └── ioc_list.txt
├── logs/
│   └── sample_logs.csv
├── notes/
│   └── DEVELOPER_NOTES.md
├── reports/
│   └── investigation_001.md
├── screenshots/
│   └── .gitkeep
├── utils/
│   ├── log_loader.py
│   └── report_generator.py
├── main.py
└── README.md
```


## How to Run

```bash
python main.py
```


## Generated Reports

After running the tool, the following reports are created:

```text
reports/threat_report.txt
reports/threat_report.html
```

Open `reports/threat_report.html` in a browser to view the HTML report.


## Skills Demonstrated

- Python scripting
- Windows Event ID analysis
- Log parsing
- Threat hunting
- Alert triage
- Risk scoring
- MITRE ATT&CK mapping
- IOC detection
- Incident reporting
- Blue Team fundamentals


## Future Improvements

- Add JSON log support
- Add Sysmon event detection
- Add Sigma rule examples
- Add Wazuh log support
- Add Streamlit dashboard
- Add unit tests

## Screenshots

### Project Structure

![Project Structure](screenshots/project_structure.png)

### Threat Hunting Execution

![Threat Hunting Execution](screenshots/terminal_execution.png)

### HTML Report

![HTML Report](screenshots/html_report.png)

### Brute Force Detection

![Brute Force Detection](screenshots/bruteforce_alert.png)

### Suspicious PowerShell Detection

![PowerShell Detection](screenshots/powershell_alert.png)

### IOC Detection

![IOC Detection](screenshots/ioc_detection.png)
