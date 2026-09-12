from pathlib import Path
import sys


from flask import (
    Flask,
    jsonify,
    render_template,
    send_file
)

from io import BytesIO
from datetime import datetime


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

if str(BASE_DIR) not in sys.path:

    sys.path.insert(
        0,
        str(BASE_DIR)
    )


DASHBOARD_DIR = (
    BASE_DIR / "dashboard"
)

TEMPLATE_DIR = (
    DASHBOARD_DIR / "templates"
)

STATIC_DIR = (
    DASHBOARD_DIR / "static"
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(

    __name__,

    template_folder=str(
        TEMPLATE_DIR
    ),

    static_folder=str(
        STATIC_DIR
    ),

    static_url_path="/static"
)


# ============================================================
# IDS DATA FUNCTIONS
# ============================================================

from data.ids_data import (

    # Basic statistics
    get_stats,
    get_packet_rate,

    # Monitoring
    set_monitoring_state,
    get_monitoring_state,

    # Alerts
    get_alert_history,

    # Devices
    get_connected_devices,

    # Protocol analytics
    get_protocol_stats,

    # Security overview
    get_security_overview,

    # Reset
    reset_data
)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    stats = get_stats()

    # Packet rate is calculated dynamically
    stats["packet_rate"] = 0

    stats["monitoring_active"] = (
        get_monitoring_state()
    )

    return render_template(

        "index.html",

        stats=stats

    )


# ============================================================
# API: STATISTICS
# ============================================================

@app.route("/api/stats")
def api_stats():

    try:

        stats = get_stats()

        monitoring_active = (
            get_monitoring_state()
        )

        # ----------------------------------------------------
        # Packet rate
        # ----------------------------------------------------

        if monitoring_active:

            stats["packet_rate"] = (
                get_packet_rate()
            )

        else:

            stats["packet_rate"] = 0

        # ----------------------------------------------------
        # Monitoring state
        # ----------------------------------------------------

        stats["monitoring_active"] = (
            monitoring_active
        )

        return jsonify(stats)

    except Exception as error:

        print(
            "ERROR /api/stats:",
            error
        )

        return jsonify({

            "success": False,

            "error":
                "Unable to retrieve IDS statistics"

        }), 500


# ============================================================
# API: START MONITORING
# ============================================================

@app.route(
    "/api/monitor/start",
    methods=["POST"]
)
def start_monitoring():

    try:

        set_monitoring_state(True)

        return jsonify({

            "success": True,

            "monitoring_active": True,

            "message":
                "IDS monitoring started"

        })

    except Exception as error:

        print(
            "ERROR starting monitoring:",
            error
        )

        return jsonify({

            "success": False,

            "message":
                "Unable to start IDS monitoring"

        }), 500


# ============================================================
# API: STOP MONITORING
# ============================================================

@app.route(
    "/api/monitor/stop",
    methods=["POST"]
)
def stop_monitoring():

    try:

        set_monitoring_state(False)

        return jsonify({

            "success": True,

            "monitoring_active": False,

            "message":
                "IDS monitoring stopped"

        })

    except Exception as error:

        print(
            "ERROR stopping monitoring:",
            error
        )

        return jsonify({

            "success": False,

            "message":
                "Unable to stop IDS monitoring"

        }), 500


# ============================================================
# API: MONITOR STATUS
# ============================================================

@app.route(
    "/api/monitor/status"
)
def monitor_status():

    try:

        monitoring_active = (
            get_monitoring_state()
        )

        return jsonify({

            "success": True,

            "monitoring_active":
                monitoring_active

        })

    except Exception as error:

        print(
            "ERROR /api/monitor/status:",
            error
        )

        return jsonify({

            "success": False,

            "monitoring_active": False,

            "message":
                "Unable to retrieve monitoring status"

        }), 500


# ============================================================
# API: PROTOCOL ANALYTICS
# ============================================================

@app.route(
    "/api/protocols"
)
def api_protocols():

    try:

        protocol_stats = (
            get_protocol_stats()
        )

        return jsonify({

            "success": True,

            "data":
                protocol_stats

        })

    except Exception as error:

        print(
            "ERROR /api/protocols:",
            error
        )

        return jsonify({

            "success": False,

            "data": {},

            "message":
                "Unable to retrieve protocol analytics"

        }), 500


# ============================================================
# API: SECURITY OVERVIEW
# ============================================================

@app.route(
    "/api/security-overview"
)
def api_security_overview():

    try:

        overview = (
            get_security_overview()
        )

        return jsonify({

            "success": True,

            "overview":
                overview

        })

    except Exception as error:

        print(
            "ERROR /api/security-overview:",
            error
        )

        return jsonify({

            "success": False,

            "overview": {},

            "message":
                "Unable to retrieve security overview"

        }), 500

# ============================================================
# API: EXPORT SECURITY REPORT
# ============================================================

@app.route(
    "/api/export-security-report"
)
def export_security_report():

    try:

        # ----------------------------------------------------
        # GET SECURITY OVERVIEW
        # ----------------------------------------------------

        overview = get_security_overview()

        # ----------------------------------------------------
        # GET RECENT ALERTS
        # ----------------------------------------------------

        alerts = get_alert_history(20)

        # ----------------------------------------------------
        # GET DEVICES
        # ----------------------------------------------------

        devices = get_connected_devices()

        # ----------------------------------------------------
        # CREATE PDF IN MEMORY
        # ----------------------------------------------------

        buffer = BytesIO()

        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors

        from reportlab.lib.styles import (
            getSampleStyleSheet,
            ParagraphStyle
        )

        from reportlab.lib.enums import (
            TA_CENTER,
            TA_LEFT
        )

        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak
        )

        # ----------------------------------------------------
        # PDF DOCUMENT
        # ----------------------------------------------------

        document = SimpleDocTemplate(

            buffer,

            pagesize=A4,

            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(

            "ReportTitle",

            parent=styles["Title"],

            alignment=TA_CENTER,

            fontSize=20,

            spaceAfter=10
        )

        heading_style = ParagraphStyle(

            "ReportHeading",

            parent=styles["Heading2"],

            fontSize=14,

            spaceBefore=12,

            spaceAfter=8
        )

        normal_style = ParagraphStyle(

            "ReportNormal",

            parent=styles["BodyText"],

            fontSize=9,

            leading=13
        )

        # ----------------------------------------------------
        # REPORT CONTENT
        # ----------------------------------------------------

        elements = []

        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        elements.append(
            Paragraph(
                "🛡️ Mini IDS Security Report",
                title_style
            )
        )

        elements.append(
            Paragraph(
                "Real-time Network Intrusion Detection System",
                ParagraphStyle(
                    "Subtitle",
                    parent=styles["BodyText"],
                    alignment=TA_CENTER,
                    fontSize=10
                )
            )
        )

        elements.append(
            Spacer(1, 15)
        )

        # ----------------------------------------------------
        # REPORT INFORMATION
        # ----------------------------------------------------

        generated_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        elements.append(
            Paragraph(
                f"<b>Report Generated:</b> {generated_time}",
                normal_style
            )
        )

        elements.append(
            Spacer(1, 10)
        )

        # ----------------------------------------------------
        # SECURITY STATUS
        # ----------------------------------------------------

        elements.append(
            Paragraph(
                "1. Security Status",
                heading_style
            )
        )

        status_data = [

            ["Security Score", f"{overview['score']} / 100"],

            ["Security Status", overview["status"]],

            ["Status Level", overview["status_level"].upper()],

            ["Recommendation", overview["recommendation"]]
        ]

        status_table = Table(

            status_data,

            colWidths=[150, 350]
        )

        status_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold"
                ),

                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])
        )

        elements.append(
            status_table
        )

        # ----------------------------------------------------
        # SECURITY METRICS
        # ----------------------------------------------------

        elements.append(
            Paragraph(
                "2. Security Metrics",
                heading_style
            )
        )

        metrics_data = [

            ["Metric", "Value"],

            [
                "Total Packets",
                str(overview["total_packets"])
            ],

            [
                "Total Alerts",
                str(overview["total_alerts"])
            ],

            [
                "High Severity Alerts",
                str(overview["high_alerts"])
            ],

            [
                "Medium Severity Alerts",
                str(overview["medium_alerts"])
            ],

            [
                "Low Severity Alerts",
                str(overview["low_alerts"])
            ],

            [
                "Connected Devices",
                str(overview["total_devices"])
            ]

        ]

        metrics_table = Table(

            metrics_data,

            colWidths=[300, 200]
        )

        metrics_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])
        )

        elements.append(
            metrics_table
        )

        # ----------------------------------------------------
        # THREAT SUMMARY
        # ----------------------------------------------------

        elements.append(
            Paragraph(
                "3. Threat Summary",
                heading_style
            )
        )

        threat_data = [

            ["Information", "Details"],

            [
                "Most Common Attack",
                overview["top_attack"]
            ],

            [
                "Occurrences",
                str(overview["top_attack_count"])
            ]

        ]

        latest_threat = overview.get(
            "latest_threat"
        )

        if latest_threat:

            threat_data.append(
                [
                    "Latest Threat",
                    latest_threat["type"]
                ]
            )

            threat_data.append(
                [
                    "Threat Severity",
                    latest_threat["severity"]
                ]
            )

            threat_data.append(
                [
                    "Source IP",
                    str(
                        latest_threat["source_ip"]
                        or "Unknown"
                    )
                ]
            )

            threat_data.append(
                [
                    "Threat Time",
                    latest_threat["timestamp"]
                ]
            )

        else:

            threat_data.append(
                [
                    "Latest Threat",
                    "No threats detected"
                ]
            )

        threat_table = Table(

            threat_data,

            colWidths=[180, 320]
        )

        threat_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])
        )

        elements.append(
            threat_table
        )

        # ----------------------------------------------------
        # RECENT SECURITY EVENTS
        # ----------------------------------------------------

        elements.append(
            PageBreak()
        )

        elements.append(
            Paragraph(
                "4. Recent Security Events",
                heading_style
            )
        )

        if alerts:

            alert_data = [

                [
                    "Time",
                    "Type",
                    "Severity",
                    "Source IP"
                ]

            ]

            for alert in alerts:

                alert_data.append(

                    [

                        alert["timestamp"],

                        alert["type"],

                        alert["severity"],

                        str(
                            alert["source_ip"]
                            or "Unknown"
                        )

                    ]

                )

            alert_table = Table(

                alert_data,

                colWidths=[
                    105,
                    145,
                    80,
                    120
                ],

                repeatRows=1
            )

            alert_table.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey
                    ),

                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),

                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),

                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        4
                    )

                ])
            )

            elements.append(
                alert_table
            )

        else:

            elements.append(
                Paragraph(
                    "No security events detected.",
                    normal_style
                )
            )

        # ----------------------------------------------------
        # CONNECTED DEVICES
        # ----------------------------------------------------

        elements.append(
            Spacer(1, 20)
        )

        elements.append(
            Paragraph(
                "5. Connected Devices",
                heading_style
            )
        )

        if devices:

            device_data = [

                [
                    "IP Address",
                    "Type",
                    "First Seen",
                    "Last Seen",
                    "Packets"
                ]

            ]

            for device in devices:

                device_data.append(

                    [

                        device["ip_address"],

                        device["device_type"],

                        device["first_seen"],

                        device["last_seen"],

                        str(
                            device["packet_count"]
                        )

                    ]

                )

            device_table = Table(

                device_data,

                colWidths=[
                    105,
                    70,
                    105,
                    105,
                    55
                ],

                repeatRows=1
            )

            device_table.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey
                    ),

                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),

                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),

                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        4
                    )

                ])
            )

            elements.append(
                device_table
            )

        else:

            elements.append(
                Paragraph(
                    "No connected devices detected.",
                    normal_style
                )
            )

        # ----------------------------------------------------
        # FOOTER
        # ----------------------------------------------------

        elements.append(
            Spacer(1, 20)
        )

        elements.append(
            Paragraph(
                "Generated by Mini IDS Dashboard",
                ParagraphStyle(
                    "Footer",
                    parent=normal_style,
                    alignment=TA_CENTER
                )
            )
        )

        # ----------------------------------------------------
        # BUILD PDF
        # ----------------------------------------------------

        document.build(
            elements
        )

        buffer.seek(0)

        # ----------------------------------------------------
        # SEND PDF
        # ----------------------------------------------------

        return send_file(

            buffer,

            mimetype="application/pdf",

            as_attachment=True,

            download_name=(
                "Mini_IDS_Security_Report.pdf"
            )

        )

    except Exception as error:

        print(
            "ERROR exporting security report:",
            error
        )

        return jsonify({

            "success": False,

            "message":
                "Unable to generate security report"

        }), 500
# ============================================================
# API: CONNECTED DEVICES
# ============================================================

@app.route(
    "/api/devices"
)
def api_devices():

    try:

        devices = (
            get_connected_devices()
        )

        return jsonify({

            "success": True,

            "devices":
                devices

        })

    except Exception as error:

        print(
            "ERROR /api/devices:",
            error
        )

        return jsonify({

            "success": False,

            "devices": [],

            "message":
                "Unable to retrieve connected devices"

        }), 500


# ============================================================
# API: ALERT HISTORY
# ============================================================

@app.route(
    "/api/alerts"
)
def api_alerts():

    try:

        alerts = (
            get_alert_history(50)
        )

        return jsonify({

            "success": True,

            "alerts":
                alerts

        })

    except Exception as error:

        print(
            "ERROR /api/alerts:",
            error
        )

        return jsonify({

            "success": False,

            "alerts": [],

            "message":
                "Unable to retrieve alert history"

        }), 500


# ============================================================
# API: CLEAR IDS DATA
# ============================================================

@app.route(
    "/api/reset",
    methods=["POST"]
)
def reset_ids_data():

    try:

        reset_data()

        return jsonify({

            "success": True,

            "message":
                "IDS data cleared successfully"

        })

    except Exception as error:

        print(
            "ERROR /api/reset:",
            error
        )

        return jsonify({

            "success": False,

            "message":
                "Unable to clear IDS data"

        }), 500


# ============================================================
# API: HEALTH CHECK
# ============================================================

@app.route(
    "/api/health"
)
def health():

    try:

        monitoring_active = (
            get_monitoring_state()
        )

        return jsonify({

            "status": "ok",

            "service": "Mini IDS",

            "monitoring_active":
                monitoring_active

        })

    except Exception as error:

        print(
            "ERROR /api/health:",
            error
        )

        return jsonify({

            "status": "error",

            "service": "Mini IDS"

        }), 500


# ============================================================
# API: SYSTEM INFORMATION
# ============================================================

@app.route(
    "/api/system"
)
def system_info():

    try:

        return jsonify({

            "success": True,

            "application":
                "Mini IDS",

            "version":
                "1.0",

            "description":
                "Real-time Network Intrusion Detection System",

            "components": {

                "packet_monitor":
                    "active",

                "database":
                    "SQLite",

                "backend":
                    "Flask",

                "frontend":
                    "HTML / CSS / JavaScript"

            }

        })

    except Exception as error:

        print(
            "ERROR /api/system:",
            error
        )

        return jsonify({

            "success": False

        }), 500


# ============================================================
# ERROR HANDLER: 404
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({

        "success": False,

        "error":
            "Endpoint not found"

    }), 404


# ============================================================
# ERROR HANDLER: 500
# ============================================================

@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({

        "success": False,

        "error":
            "Internal server error"

    }), 500


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("🛡️ MINI IDS DASHBOARD")
    print("=" * 60)

    print()
    print(
        "Dashboard : "
        "http://127.0.0.1:5000"
    )

    print(
        "Statistics: "
        "http://127.0.0.1:5000/api/stats"
    )

    print(
        "Alerts    : "
        "http://127.0.0.1:5000/api/alerts"
    )

    print(
        "Devices   : "
        "http://127.0.0.1:5000/api/devices"
    )

    print(
        "Protocols : "
        "http://127.0.0.1:5000/api/protocols"
    )

    print(
        "Security  : "
        "http://127.0.0.1:5000/api/security-overview"
    )

    print(
        "Health    : "
        "http://127.0.0.1:5000/api/health"
    )

    print("=" * 60)
    print()
    print(
        "Press CTRL+C to stop the server."
    )
    print()

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )