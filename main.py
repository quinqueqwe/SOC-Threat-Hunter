from detections.bruteforce import detect_bruteforce
from detections.powershell import detect_powershell
from detections.user_creation import detect_user_creation
from detections.admin_group import detect_admin_group_addition
from detections.ioc_detection import detect_iocs

from utils.log_loader import load_logs
from utils.report_generator import print_alert, save_text_report, save_html_report


def main():
    events = load_logs("logs/sample_logs.csv")

    alerts = []
    alerts.extend(detect_bruteforce(events))
    alerts.extend(detect_powershell(events))
    alerts.extend(detect_user_creation(events))
    alerts.extend(detect_admin_group_addition(events))
    alerts.extend(detect_iocs(events, "ioc/ioc_list.txt"))

    print("\nSOC Threat Hunter\n")

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print_alert(alert)

    save_text_report(alerts, "reports/threat_report.txt")
    save_html_report(alerts, "reports/threat_report.html")

    print("\nReports saved:")
    print("- reports/threat_report.txt")
    print("- reports/threat_report.html")


if __name__ == "__main__":
    main()
