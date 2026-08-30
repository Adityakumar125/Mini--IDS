import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from data.ids_data import record_alert


def generate_alert(alert):

    # --------------------------------------------------
    # Validate alert
    # --------------------------------------------------

    if not alert:
        return

    # --------------------------------------------------
    # Store alert in SQLite
    # --------------------------------------------------

    alert_id = record_alert(alert)

    # --------------------------------------------------
    # Console output
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("🚨 SECURITY ALERT")
    print("=" * 60)

    print(
        f"Alert ID  : {alert_id}"
    )

    print(
        f"Time      : {alert.get('timestamp', '-')}"
    )

    print(
        f"Type      : {alert.get('type', 'UNKNOWN')}"
    )

    print(
        f"Severity  : {alert.get('severity', 'MEDIUM')}"
    )

    print(
        f"Source IP : {alert.get('source_ip', '-')}"
    )

    print(
        f"Message   : {alert.get('message', '-')}"
    )

    print("=" * 60)