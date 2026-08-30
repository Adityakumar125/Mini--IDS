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

        # ----------------------------------------------------
        # PACKETS
        # ----------------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL

            )
        """)

        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                type TEXT NOT NULL,

                severity TEXT NOT NULL,

                source_ip TEXT,

                message TEXT

            )
        """)

        # ----------------------------------------------------
        # SETTINGS
        # ----------------------------------------------------

        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (

                key TEXT PRIMARY KEY,

                value TEXT NOT NULL

            )
        """)

        # ----------------------------------------------------
        # DEFAULT MONITORING STATE
        # ----------------------------------------------------

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

def record_packet():

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with lock:

        with get_connection() as conn:

            conn.execute(
                """
                INSERT INTO packets (timestamp)
                VALUES (?)
                """,
                (timestamp,)
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
                "SELECT COUNT(*) FROM packets"
            ).fetchone()[0]

    elapsed = current_time - _last_packet_time

    if elapsed <= 0:

        return 0

    packet_rate = (
        current_count - _last_packet_count
    ) / elapsed

    _last_packet_count = current_count
    _last_packet_time = current_time

    return round(
        max(packet_rate, 0),
        2
    )


# ============================================================
# RECORD ALERT
# ============================================================

def record_alert(alert):

    if not alert:

        return None

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    alert_type = alert.get(
        "type",
        "UNKNOWN"
    )

    severity = alert.get(
        "severity",
        "MEDIUM"
    )

    source_ip = alert.get(
        "source_ip"
    )

    message = alert.get(
        "message",
        ""
    )

    with lock:

        with get_connection() as conn:

            cursor = conn.execute(
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
                    alert_type,
                    severity,
                    source_ip,
                    message
                )
            )

            conn.commit()

            return cursor.lastrowid


# ============================================================
# GET RECENT ALERTS
# ============================================================

def get_recent_alerts(limit=20):

    try:

        limit = int(limit)

    except (
        TypeError,
        ValueError
    ):

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
                    id,
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
            "id": row[0],
            "timestamp": row[1],
            "type": row[2],
            "severity": row[3],
            "source_ip": row[4],
            "message": row[5]
        }

        for row in rows

    ]


# ============================================================
# GET ALERT HISTORY
# ============================================================

def get_alert_history(
    limit=100,
    alert_type=None,
    severity=None
):

    try:

        limit = int(limit)

    except (
        TypeError,
        ValueError
    ):

        limit = 100

    limit = max(
        1,
        min(limit, 500)
    )

    query = """
        SELECT
            id,
            timestamp,
            type,
            severity,
            source_ip,
            message

        FROM alerts

        WHERE 1=1
    """

    params = []

    # --------------------------------------------------------
    # FILTER BY TYPE
    # --------------------------------------------------------

    if alert_type:

        query += """
            AND type = ?
        """

        params.append(
            alert_type
        )

    # --------------------------------------------------------
    # FILTER BY SEVERITY
    # --------------------------------------------------------

    if severity:

        query += """
            AND severity = ?
        """

        params.append(
            severity.upper()
        )

    # --------------------------------------------------------
    # ORDER
    # --------------------------------------------------------

    query += """
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(
        limit
    )

    with lock:

        with get_connection() as conn:

            rows = conn.execute(
                query,
                params
            ).fetchall()

    return [

        {
            "id": row[0],
            "timestamp": row[1],
            "type": row[2],
            "severity": row[3],
            "source_ip": row[4],
            "message": row[5]
        }

        for row in rows

    ]


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
            # HIGH ALERTS
            # ------------------------------------------------

            high = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'HIGH'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # MEDIUM ALERTS
            # ------------------------------------------------

            medium = conn.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'MEDIUM'
                """
            ).fetchone()[0]

            # ------------------------------------------------
            # LOW ALERTS
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

    # ========================================================
    # ATTACK TYPE DICTIONARY
    # ========================================================

    alert_types = {

        row[0]: row[1]

        for row in type_rows

    }

    # ========================================================
    # RECENT ALERTS
    # ========================================================

    recent_alerts = get_recent_alerts(20)

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
# RESET IDS DATA
# ============================================================

def reset_data():

    global _last_packet_count
    global _last_packet_time

    with lock:

        with get_connection() as conn:

            conn.execute(
                "DELETE FROM packets"
            )

            conn.execute(
                "DELETE FROM alerts"
            )

            conn.execute(
                """
                DELETE FROM sqlite_sequence
                WHERE name IN ('packets', 'alerts')
                """
            )

            conn.commit()

    _last_packet_count = 0

    _last_packet_time = time.time()

    print(
        "IDS data reset successfully."
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
                (
                    key,
                    value
                )

                VALUES
                (
                    'monitoring_active',
                    ?
                )
                """,
                (
                    "1"
                    if active
                    else "0",
                )
            )

            conn.commit()


# ============================================================
# GET MONITORING STATE
# ============================================================

def get_monitoring_state():

    with lock:

        with get_connection() as conn:

            row = conn.execute(
                """
                SELECT value

                FROM settings

                WHERE key =
                    'monitoring_active'
                """
            ).fetchone()

            if row is None:

                conn.execute(
                    """
                    INSERT INTO settings
                    (
                        key,
                        value
                    )

                    VALUES
                    (
                        'monitoring_active',
                        '1'
                    )
                    """
                )

                conn.commit()

                return True

            return row[0] == "1"


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()