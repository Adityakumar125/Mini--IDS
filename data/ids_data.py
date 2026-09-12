import time
import os
import sqlite3
import threading

from datetime import datetime


# ============================================================
# DATABASE LOCATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

DB_PATH = os.path.join(
    DATA_DIR,
    "ids.db"
)

os.makedirs(
    DATA_DIR,
    exist_ok=True
)


# ============================================================
# THREAD LOCK
# ============================================================

lock = threading.Lock()


# ============================================================
# LIVE PACKET RATE
# ============================================================

_last_packet_count = 0
_last_packet_time = time.time()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    return sqlite3.connect(
        DB_PATH,
        timeout=10
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():

    with get_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (

                id INTEGER
                    PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT
                    NOT NULL,

                protocol TEXT
                    DEFAULT 'OTHER',

                source_ip TEXT,

                destination_ip TEXT,

                source_port INTEGER,

                destination_port INTEGER,

                packet_size INTEGER
                    DEFAULT 0
            )
        """)
                # ====================================================
        # PACKET TABLE MIGRATION
        # ====================================================

        existing_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(packets)"
            ).fetchall()
        }

        new_columns = {

            "protocol":
                "TEXT DEFAULT 'OTHER'",

            "source_ip":
                "TEXT",

            "destination_ip":
                "TEXT",

            "source_port":
                "INTEGER",

            "destination_port":
                "INTEGER",

            "packet_size":
                "INTEGER DEFAULT 0"
        }

        for column, definition in new_columns.items():

            if column not in existing_columns:

                conn.execute(
                    f"""
                    ALTER TABLE packets
                    ADD COLUMN {column}
                    {definition}
                    """
                )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts(

                id INTEGER
                    PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT
                    NOT NULL,

                type TEXT
                    NOT NULL,

                severity TEXT
                    NOT NULL,

                source_ip TEXT,

                message TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings(

                key TEXT
                    PRIMARY KEY,

                value TEXT
                    NOT NULL
            )
        """)

        # Default monitoring state

        conn.execute("""
            INSERT OR IGNORE INTO settings
            (key, value)
            VALUES
            ('monitoring_active', '1')
        """)

        conn.commit()


# ============================================================
# RECORD PACKET
# ============================================================

def record_packet(
    protocol="OTHER",
    source_ip=None,
    destination_ip=None,
    source_port=None,
    destination_port=None,
    packet_size=0
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with lock:

        with get_connection() as conn:

            conn.execute(
                """
                INSERT INTO packets
                (
                    timestamp,
                    protocol,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    packet_size
                )

                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    protocol,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    packet_size
                )
            )

            conn.commit()


    
# ============================================================
# DEVICE TRACKING
# ============================================================

def init_devices_table():

    with get_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (

                id INTEGER
                    PRIMARY KEY AUTOINCREMENT,

                ip_address TEXT
                    UNIQUE
                    NOT NULL,

                first_seen TEXT
                    NOT NULL,

                last_seen TEXT
                    NOT NULL,

                packet_count INTEGER
                    DEFAULT 0
            )
        """)

        conn.commit()


# ============================================================
# RECORD DEVICE
# ============================================================

def record_device(ip_address):

    if not ip_address:
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with lock:

        with get_connection() as conn:

            existing = conn.execute(
                """
                SELECT id
                FROM devices
                WHERE ip_address = ?
                """,
                (ip_address,)
            ).fetchone()

            if existing:

                conn.execute(
                    """
                    UPDATE devices

                    SET
                        last_seen = ?,
                        packet_count = packet_count + 1

                    WHERE ip_address = ?
                    """,
                    (
                        timestamp,
                        ip_address
                    )
                )

            else:

                conn.execute(
                    """
                    INSERT INTO devices
                    (
                        ip_address,
                        first_seen,
                        last_seen,
                        packet_count
                    )

                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        ip_address,
                        timestamp,
                        timestamp,
                        1
                    )
                )

            conn.commit()


# ============================================================
# GET CONNECTED DEVICES
# ============================================================

def get_connected_devices():

    with lock:

        with get_connection() as conn:

            rows = conn.execute(
                """
                SELECT
                    ip_address,
                    first_seen,
                    last_seen,
                    packet_count
                FROM devices
                ORDER BY last_seen DESC
                """
            ).fetchall()

    devices = []

    for row in rows:

        ip_address = row[0]

        # ----------------------------------------------------
        # CLASSIFY DEVICE
        # ----------------------------------------------------

        if (
            ip_address.startswith("10.")
            or ip_address.startswith("192.168.")
            or (
                ip_address.startswith("172.")
                and 16 <= int(
                    ip_address.split(".")[1]
                ) <= 31
            )
        ):

            device_type = "LOCAL"

        elif ip_address.startswith("fe80:"):

            device_type = "LOCAL"

        else:

            device_type = "EXTERNAL"

        # ----------------------------------------------------
        # DEVICE INFORMATION
        # ----------------------------------------------------

        devices.append({

            "ip_address": ip_address,

            "first_seen": row[1],

            "last_seen": row[2],

            "packet_count": row[3],

            "device_type": device_type

        })

    return devices
# ============================================================
# CLEAR DEVICES
# ============================================================

def clear_devices():

    with lock:

        with get_connection() as conn:

            conn.execute(
                "DELETE FROM devices"
            )

            conn.commit()


# ============================================================

# ============================================================
# RECORD ALERT
# ============================================================

def record_alert(alert):

    if not alert:
        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with lock:

        with get_connection() as conn:

            conn.execute(
                """
                INSERT INTO alerts
                (
                    timestamp,
                    type,
                    severity,
                    source_ip,
                    message
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    timestamp,

                    alert.get(
                        "type",
                        "UNKNOWN"
                    ),

                    alert.get(
                        "severity",
                        "MEDIUM"
                    ),

                    alert.get(
                        "source_ip"
                    ),

                    alert.get(
                        "message",
                        ""
                    )
                )
            )

            conn.commit()


# ============================================================
# GET PACKETS PER SECOND
# ============================================================

def get_packet_rate():

    global _last_packet_count
    global _last_packet_time

    current_time = time.time()

    with lock:

        with get_connection() as conn:

            current_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM packets
                """
            ).fetchone()[0]

    elapsed = (
        current_time
        - _last_packet_time
    )

    if elapsed <= 0:
        return 0

    packet_difference = (
        current_count
        - _last_packet_count
    )

    packet_rate = (
        packet_difference
        / elapsed
    )

    _last_packet_count = current_count
    _last_packet_time = current_time

    return round(
        max(packet_rate, 0),
        2
    )


# ============================================================
# GET STATISTICS
# ============================================================

def get_stats():

    with lock:

        with get_connection() as conn:

            # ------------------------------------------------
            # TOTAL PACKETS
            # ------------------------------------------------

            packets = conn.execute(
                """
                SELECT COUNT(*)
                FROM packets
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # TOTAL ALERTS
            # ------------------------------------------------

            alerts = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # HIGH
            # ------------------------------------------------

            high = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'HIGH'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # MEDIUM
            # ------------------------------------------------

            medium = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'MEDIUM'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # LOW
            # ------------------------------------------------

            low = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'LOW'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # ATTACK TYPES
            # ------------------------------------------------

            type_rows = conn.execute(
                """
                SELECT
                    type,
                    COUNT(*)
                FROM alerts
                GROUP BY type
                ORDER BY COUNT(*) DESC
                """
            ).fetchall()

            # ------------------------------------------------
            # RECENT ALERTS
            # ------------------------------------------------

            rows = conn.execute(
                """
                SELECT
                    timestamp,
                    type,
                    severity,
                    source_ip,
                    message
                FROM alerts
                ORDER BY id DESC
                LIMIT 20
                """
            ).fetchall()

    # ========================================================
    # ATTACK TYPE DICTIONARY
    # ========================================================

    alert_types = {
        row[0]: row[1]
        for row in type_rows
    }

    # ========================================================
    # RECENT ALERT DICTIONARIES
    # ========================================================

    recent_alerts = []

    for row in rows:

        recent_alerts.append({

            "timestamp": row[0],

            "type": row[1],

            "severity": row[2],

            "source_ip": row[3],

            "message": row[4]
        })

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "packets": packets,

        "alerts": alerts,

        "high": high,

        "medium": medium,

        "low": low,

        "alert_types": alert_types,

        "recent_alerts": recent_alerts
    }


# ============================================================
# ALERT HISTORY
# ============================================================

def get_alert_history(limit=20):

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 20

    limit = max(
        1,
        min(limit, 100)
    )

    with lock:

        with get_connection() as conn:

            rows = conn.execute(
                """
                SELECT
                    timestamp,
                    type,
                    severity,
                    source_ip,
                    message
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

    return [
        {
            "timestamp": row[0],
            "type": row[1],
            "severity": row[2],
            "source_ip": row[3],
            "message": row[4]
        }
        for row in rows
    ]


# ============================================================
# RESET ALL IDS DATA
# ============================================================

def reset_data():

    global _last_packet_count
    global _last_packet_time

    with lock:

        with get_connection() as conn:

            # ------------------------------------------------
            # CLEAR PACKETS
            # ------------------------------------------------

            conn.execute(
                "DELETE FROM packets"
            )


            # ------------------------------------------------
            # CLEAR ALERTS
            # ------------------------------------------------

            conn.execute(
                "DELETE FROM alerts"
            )


            # ------------------------------------------------
            # CLEAR CONNECTED DEVICES
            # ------------------------------------------------

            conn.execute(
                "DELETE FROM devices"
            )


            # ------------------------------------------------
            # RESET AUTO-INCREMENT COUNTERS
            # ------------------------------------------------

            conn.execute(
                """
                DELETE FROM sqlite_sequence
                WHERE name IN (
                    'packets',
                    'alerts',
                    'devices'
                )
                """
            )


            conn.commit()


    # --------------------------------------------------------
    # RESET PACKET RATE CALCULATION
    # --------------------------------------------------------

    _last_packet_count = 0

    _last_packet_time = time.time()


    print(
        "IDS data and connected-device history reset successfully."
    )

# ============================================================
# MONITORING STATE
# ============================================================

def set_monitoring_state(active):

    with lock:

        with get_connection() as conn:

            conn.execute(
                """
                INSERT OR REPLACE INTO settings
                (key, value)
                VALUES
                ('monitoring_active', ?)
                """,
                (
                    "1"
                    if active
                    else "0",
                )
            )

            conn.commit()


def get_monitoring_state():

    with lock:

        with get_connection() as conn:

            row = conn.execute(
                """
                SELECT value
                FROM settings
                WHERE key = 'monitoring_active'
                """
            ).fetchone()

            if row is None:

                conn.execute(
                    """
                    INSERT INTO settings
                    (key, value)
                    VALUES
                    ('monitoring_active', '1')
                    """
                )

                conn.commit()

                return True

            return row[0] == "1"

# ============================================================
# SECURITY OVERVIEW
# ============================================================

def get_security_overview():

    with lock:

        with get_connection() as conn:

            # ------------------------------------------------
            # TOTAL PACKETS
            # ------------------------------------------------

            total_packets = conn.execute(
                """
                SELECT COUNT(*)
                FROM packets
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # TOTAL ALERTS
            # ------------------------------------------------

            total_alerts = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # HIGH SEVERITY
            # ------------------------------------------------

            high_alerts = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'HIGH'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # MEDIUM SEVERITY
            # ------------------------------------------------

            medium_alerts = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'MEDIUM'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # LOW SEVERITY
            # ------------------------------------------------

            low_alerts = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'LOW'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # DEVICES
            # ------------------------------------------------

            total_devices = conn.execute(
                """
                SELECT COUNT(*)
                FROM devices
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # MOST COMMON ATTACK
            # ------------------------------------------------

            attack_row = conn.execute(
                """
                SELECT
                    type,
                    COUNT(*) AS total
                FROM alerts
                GROUP BY type
                ORDER BY total DESC
                LIMIT 1
                """
            ).fetchone()

            if attack_row:

                top_attack = attack_row[0]
                top_attack_count = attack_row[1]

            else:

                top_attack = "NONE"
                top_attack_count = 0

            # ------------------------------------------------
            # LATEST THREAT
            # ------------------------------------------------

            latest_row = conn.execute(
                """
                SELECT
                    timestamp,
                    type,
                    severity,
                    source_ip,
                    message
                FROM alerts
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

    # ========================================================
    # SECURITY SCORE
    # ========================================================

    score = 100

    score -= high_alerts * 15
    score -= medium_alerts * 5
    score -= low_alerts * 2

    score = max(
        0,
        min(score, 100)
    )

    # ========================================================
    # SECURITY STATUS
    # ========================================================

    if score >= 80:

        status = "SECURE"
        status_level = "secure"

    elif score >= 50:

        status = "WARNING"
        status_level = "warning"

    else:

        status = "CRITICAL"
        status_level = "critical"

    # ========================================================
    # RECOMMENDATION
    # ========================================================

    if high_alerts > 0:

        recommendation = (
            "High-severity threats detected. "
            "Investigate the affected source IP addresses immediately."
        )

    elif medium_alerts > 0:

        recommendation = (
            "Suspicious activity detected. "
            "Review recent security events and monitor affected devices."
        )

    elif total_devices > 0:

        recommendation = (
            "No major threats detected. "
            "Continue monitoring connected devices and network traffic."
        )

    else:

        recommendation = (
            "Monitoring is ready. "
            "Start IDS monitoring to analyze network activity."
        )

    # ========================================================
    # LATEST THREAT OBJECT
    # ========================================================

    latest_threat = None

    if latest_row:

        latest_threat = {

            "timestamp": latest_row[0],

            "type": latest_row[1],

            "severity": latest_row[2],

            "source_ip": latest_row[3],

            "message": latest_row[4]

        }

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "score": score,

        "status": status,

        "status_level": status_level,

        "total_packets": total_packets,

        "total_alerts": total_alerts,

        "high_alerts": high_alerts,

        "medium_alerts": medium_alerts,

        "low_alerts": low_alerts,

        "total_devices": total_devices,

        "top_attack": top_attack,

        "top_attack_count": top_attack_count,

        "latest_threat": latest_threat,

        "recommendation": recommendation

    }

def get_protocol_stats():

    with lock:

        with get_connection() as conn:

            rows = conn.execute(
                """
                SELECT
                    COALESCE(protocol, 'OTHER') AS protocol,
                    COUNT(*) AS packet_count
                FROM packets
                GROUP BY protocol
                ORDER BY packet_count DESC
                """
            ).fetchall()

    total_packets = sum(
        row[1]
        for row in rows
    )

    protocols = []

    for row in rows:

        protocol = row[0]
        count = row[1]

        percentage = (
            (count / total_packets) * 100
            if total_packets > 0
            else 0
        )

        protocols.append({

            "protocol": protocol,

            "packets": count,

            "percentage": round(
                percentage,
                2
            )

        })

    return {

        "total_packets": total_packets,

        "protocols": protocols

    }

    
# ============================================================
# INITIALIZE
# ============================================================

init_db()
init_devices_table()