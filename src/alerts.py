import sys
import os
from datetime import datetime


# ============================================================
# PROJECT ROOT
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(
        0,
        BASE_DIR
    )


# ============================================================
# DATABASE
# ============================================================

from data.ids_data import record_alert


# ============================================================
# GENERATE ALERT
# ============================================================

def generate_alert(alert):

    if not alert:
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Save alert to database

    record_alert(alert)

    # Console output

    print("\n" + "=" * 60)
    print("🚨 SECURITY ALERT")
    print("=" * 60)

    print(
        f"Time      : {timestamp}"
    )

    print(
        f"Type      : "
        f"{alert.get('type', 'UNKNOWN')}"
    )

    print(
        f"Severity  : "
        f"{alert.get('severity', 'MEDIUM')}"
    )

    print(
        f"Source IP : "
        f"{alert.get('source_ip', '-')}"
    )

    print(
        f"Message   : "
        f"{alert.get('message', '-')}"
    )

    print("=" * 60)