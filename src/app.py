from pathlib import Path
import sys

from flask import(
    Flask,
    jsonify,
    render_template,
    request
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


DASHBOARD_DIR = BASE_DIR / "dashboard"

TEMPLATE_DIR = DASHBOARD_DIR / "templates"

STATIC_DIR = DASHBOARD_DIR / "static"


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)


# ============================================================
# IDS DATA
# ============================================================

from data.ids_data import (
    get_stats,
    get_packet_rate,
    reset_data,
    set_monitoring_state,
    get_monitoring_state,
    get_alert_history
)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    stats = get_stats()

    return render_template(
        "index.html",
        stats=stats
    )


# ============================================================
# API: GET STATISTICS
# ============================================================

@app.route("/api/stats")
def api_stats():

    stats = get_stats()

    monitoring_active = get_monitoring_state()

    if monitoring_active:

        stats["packet_rate"] = get_packet_rate()

    else:

        stats["packet_rate"] = 0

    stats["monitoring_active"] = monitoring_active

    return jsonify(stats)
# --------------------------------------------------
# API: ALERT HISTORY
# --------------------------------------------------

@app.route("/api/alerts")
def api_alerts():

    limit = request.args.get(
        "limit",
        default=100,
        type=int
    )

    alert_type = request.args.get(
        "type",
        default=None
    )

    severity = request.args.get(
        "severity",
        default=None
    )

    alerts = get_alert_history(
        limit=limit,
        alert_type=alert_type,
        severity=severity
    )

    return jsonify({
        "success": True,
        "count": len(alerts),
        "alerts": alerts
    })

# ============================================================
# API: START MONITORING
# ============================================================

@app.route(
    "/api/monitor/start",
    methods=["POST"]
)
def start_monitoring():

    set_monitoring_state(True)

    return jsonify({

        "success": True,

        "monitoring_active": True,

        "message": "IDS monitoring started"

    })


# ============================================================
# API: STOP MONITORING
# ============================================================

@app.route(
    "/api/monitor/stop",
    methods=["POST"]
)
def stop_monitoring():

    set_monitoring_state(False)

    return jsonify({

        "success": True,

        "monitoring_active": False,

        "message": "IDS monitoring stopped"

    })


# ============================================================
# API: MONITOR STATUS
# ============================================================

@app.route("/api/monitor/status")
def monitor_status():

    monitoring_active = get_monitoring_state()

    return jsonify({

        "monitoring_active": monitoring_active

    })


# ============================================================
# API: CLEAR IDS DATA
# ============================================================

@app.route(
    "/api/reset",
    methods=["POST"]
)
def reset_ids_data():

    reset_data()

    return jsonify({

        "success": True,

        "message": "IDS data cleared successfully"

    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health")
def health():

    return jsonify({

        "status": "ok",

        "service": "Mini IDS"

    })

# --------------------------------------------------
# API: ALERT HISTORY
# --------------------------------------------------

@app.route("/api/alerts")
def api_alerts():

    from data.ids_data import get_alert_history

    alerts = get_alert_history(100)

    return jsonify({
        "success": True,
        "alerts": alerts,
        "count": len(alerts)
    })

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("MINI IDS DASHBOARD")
    print("=" * 60)

    print(
        "Dashboard : "
        "http://127.0.0.1:5000"
    )

    print(
        "API       : "
        "http://127.0.0.1:5000/api/stats"
    )

    print(
        "Health    : "
        "http://127.0.0.1:5000/api/health"
    )

    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )