"use strict";


// ============================================================
// MINI IDS DASHBOARD JAVASCRIPT
// ============================================================


// ============================================================
// TRAFFIC DATA
// ============================================================

const trafficLabels = [];

const packetData = [];

const MAX_TRAFFIC_POINTS = 12;


// ============================================================
// CHART REFERENCES
// ============================================================

let trafficChart = null;

let attackChart = null;

let lastAlertId = null;
let lastAlertSignature = null;

// ============================================================
// ALERT NOTIFICATION TRACKING
// ============================================================

let knownAlertIds = new Set();

let dashboardInitialized = false;

// ============================================================
// DOM ELEMENTS
// ============================================================

const packetsElement =
    document.getElementById("packets");

const alertsElement =
    document.getElementById("alerts");

const highElement =
    document.getElementById("high");

const mediumElement =
    document.getElementById("medium");

const alertsBody =
    document.getElementById("alerts-body");

const trafficCanvas =
    document.getElementById("trafficChart");

const attackCanvas =
    document.getElementById("attackChart");

const attackEmpty =
    document.getElementById("attackEmpty");

const severityFilter =
    document.getElementById("severity-filter");

const typeFilter =
    document.getElementById("type-filter");

const resetAlertFilters =
    document.getElementById("reset-alert-filters");

const visibleAlertCount =
    document.getElementById("visible-alert-count");

let currentAlerts = [];

const ipFilter =
    document.getElementById("ip-filter");




function checkForNewAlert(stats) {

    const alerts =
        Array.isArray(stats.recent_alerts)
            ? stats.recent_alerts
            : [];


    if (alerts.length === 0) {

        return;

    }


    const latestAlert =
        alerts[0];


    const signature =
        [
            latestAlert.timestamp,
            latestAlert.type,
            latestAlert.source_ip,
            latestAlert.message
        ].join("|");


    // --------------------------------------------------------
    // First dashboard load
    // --------------------------------------------------------

    if (lastAlertSignature === null) {

        lastAlertSignature =
            signature;

        return;

    }


    // --------------------------------------------------------
    // No new alert
    // --------------------------------------------------------

    if (
        signature ===
        lastAlertSignature
    ) {

        return;

    }


    // --------------------------------------------------------
    // NEW ALERT DETECTED
    // --------------------------------------------------------

    lastAlertSignature =
        signature;


    const severity =
        String(
            latestAlert.severity || ""
        ).toUpperCase();


    let notificationType =
        "warning";


    if (severity === "HIGH") {

        notificationType =
            "error";

    }


    showNotification(
        `🚨 ${latestAlert.type}: ${latestAlert.message}`,
        notificationType
    );

}

// ============================================================
// CREATE TRAFFIC CHART
// ============================================================

function createTrafficChart() {

    if (!trafficCanvas) {

        console.error(
            "trafficChart canvas not found"
        );

        return;
    }


    const ctx =
        trafficCanvas.getContext("2d");


    trafficChart = new Chart(ctx, {

        type: "line",

        data: {

            labels: trafficLabels,

            datasets: [

                {

                    label: "Packets / Second",
                    data: packetData,

                    borderColor: "#22c55e",

                    backgroundColor:
                        "rgba(34, 197, 94, 0.16)",

                    borderWidth: 2,

                    pointRadius: 3,

                    pointHoverRadius: 5,

                    tension: 0.35,

                    fill: true

                }

            ]

        },


        options: {

            responsive: true,

            maintainAspectRatio: false,

            animation: false,


            interaction: {

                mode: "index",

                intersect: false

            },


            scales: {

                x: {

                    ticks: {

                        color: "#94a3b8",

                        maxTicksLimit: 8

                    },

                    grid: {

                        color:
                            "rgba(148,163,184,0.08)"

                    }

                },


                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: "Packets / Second",
                        color: "#94a3b8"
                    },
                    ticks: {
                        color: "#94a3b8"
                    }
                }
            },


            plugins: {

                legend: {

                    labels: {

                        color: "#ffffff",

                        usePointStyle: true

                    }

                }

            }

        }

    });

}


// ============================================================
// CREATE ATTACK CHART
// ============================================================

function createAttackChart() {

    if (!attackCanvas) {

        console.error(
            "attackChart canvas not found"
        );

        return;
    }


    const ctx =
        attackCanvas.getContext("2d");


    attackChart = new Chart(ctx, {

        type: "doughnut",

        data: {

            labels: [],

            datasets: [

                {

                    label: "Alerts",

                    data: [],

                    backgroundColor: [

                        "#ef4444",

                        "#f97316",

                        "#f59e0b",

                        "#a855f7",

                        "#3b82f6",

                        "#22c55e"

                    ],

                    borderColor: "#1e293b",

                    borderWidth: 3,

                    hoverOffset: 6

                }

            ]

        },


        options: {

            responsive: true,

            maintainAspectRatio: false,

            animation: false,

            cutout: "58%",


            plugins: {

                legend: {

                    position: "top",

                    labels: {

                        color: "#ffffff",

                        padding: 14,

                        usePointStyle: true

                    }

                }

            }

        }

    });

}


// ============================================================
// UPDATE SUMMARY CARDS
// ============================================================

function updateSummaryCards(stats) {

    if (packetsElement) {

        packetsElement.textContent =
            Number(
                stats.packets ?? 0
            ).toLocaleString();

    }


    if (alertsElement) {

        alertsElement.textContent =
            Number(
                stats.alerts ?? 0
            ).toLocaleString();

    }


    if (highElement) {

        highElement.textContent =
            Number(
                stats.high ?? 0
            ).toLocaleString();

    }


    if (mediumElement) {

        mediumElement.textContent =
            Number(
                stats.medium ?? 0
            ).toLocaleString();

    }

}


// ============================================================
// UPDATE TRAFFIC CHART
// ============================================================

function updateTrafficChart(stats) {

    if (!trafficChart) {
        return;
    }


    // --------------------------------------------------------
    // Do not add traffic points when monitoring is stopped
    // --------------------------------------------------------

    if (stats.monitoring_active !== true) {
        return;
    }


    const now =
        new Date().toLocaleTimeString();


    const packetRate =
        Number(stats.packet_rate) || 0;


    trafficLabels.push(now);

    packetData.push(packetRate);


    // --------------------------------------------------------
    // Keep only latest points
    // --------------------------------------------------------

    while (
        trafficLabels.length >
        MAX_TRAFFIC_POINTS
    ) {

        trafficLabels.shift();

        packetData.shift();

    }


    trafficChart.data.labels =
        trafficLabels;

    trafficChart.data.datasets[0].data =
        packetData;


    trafficChart.update("none");

}


// ============================================================
// UPDATE ATTACK ANALYTICS
// ============================================================

function updateAttackChart(stats) {

    if (!attackChart) {

        return;

    }


    const attackTypes =
        stats.alert_types || {};


    const labels =
        Object.keys(attackTypes);


    const values =
        Object.values(attackTypes)
            .map(
                value =>
                    Number(value) || 0
            );


    attackChart.data.labels =
        labels;


    attackChart.data.datasets[0].data =
        values;


    attackChart.update("none");


    if (attackEmpty) {

        if (labels.length === 0) {

            attackEmpty.style.display =
                "flex";

        } else {

            attackEmpty.style.display =
                "none";

        }

    }

}


// ============================================================
// UPDATE ATTACK TYPE FILTER
// ============================================================

function updateAttackTypeFilter(stats) {

    if (!typeFilter) {
        return;
    }

    const attackTypes =
        stats.alert_types || {};

    const currentValue =
        typeFilter.value;

    // Keep "All Attack Types"
    typeFilter.innerHTML = `
        <option value="ALL">
            All Attack Types
        </option>
    `;

    Object.keys(attackTypes)
        .sort()
        .forEach(type => {

            const option =
                document.createElement("option");

            option.value = type;

            option.textContent =
                type.replaceAll("_", " ");

            typeFilter.appendChild(option);

        });


    // Restore previous selection if it still exists

    if (
        currentValue !== "ALL" &&
        attackTypes[currentValue] !== undefined
    ) {

        typeFilter.value =
            currentValue;

    } else {

        typeFilter.value =
            "ALL";

    }

}


// ============================================================
// FILTER ALERTS
// ============================================================

function getFilteredAlerts() {

    let filtered =
        [...currentAlerts];


    // --------------------------------------------------------
    // SEVERITY FILTER
    // --------------------------------------------------------

    const severity =
        severityFilter
            ? severityFilter.value
            : "ALL";


    if (severity !== "ALL") {

        filtered =
            filtered.filter(alert =>
                String(
                    alert.severity ?? ""
                ).toUpperCase()
                === severity
            );

    }

    const ip =
        ipFilter
            ? ipFilter.value.trim().toLowerCase()
            : "";

    if (ip !== "") {

        filtered =
            filtered.filter(alert =>
                String(
                    alert.source_ip ?? ""
                )
                    .toLowerCase()
                    .includes(ip)
            );

    }


    // --------------------------------------------------------
    // ATTACK TYPE FILTER
    // --------------------------------------------------------

    const type =
        typeFilter
            ? typeFilter.value
            : "ALL";


    if (type !== "ALL") {

        filtered =
            filtered.filter(alert =>
                String(
                    alert.type ?? ""
                ).toUpperCase()
                === type
            );

    }


    return filtered;

}


// ============================================================
// RENDER ALERT TABLE
// ============================================================

function renderAlertTable() {

    if (!alertsBody) {
        return;
    }


    const alerts =
        getFilteredAlerts();


    // --------------------------------------------------------
    // UPDATE VISIBLE COUNT
    // --------------------------------------------------------

    if (visibleAlertCount) {

        visibleAlertCount.textContent =
            alerts.length;

    }


    alertsBody.innerHTML = "";


    // --------------------------------------------------------
    // NO ALERTS
    // --------------------------------------------------------

    if (alerts.length === 0) {

        const row =
            document.createElement("tr");


        row.innerHTML = `

            <td
                colspan="5"
                class="empty"
            >
                No security alerts match the selected filters.
            </td>

        `;


        alertsBody.appendChild(row);

        return;

    }


    // --------------------------------------------------------
    // CREATE ALERT ROWS
    // --------------------------------------------------------

    alerts.forEach(alert => {

        const row =
            document.createElement("tr");


        const severity =
            String(
                alert.severity ?? ""
            ).toLowerCase();


        row.innerHTML = `

            <td>
                ${escapeHTML(
            alert.timestamp ?? "-"
        )}
            </td>

            <td>
                ${escapeHTML(
            alert.type ?? "-"
        )}
            </td>

            <td class="${severity}">
                ${escapeHTML(
            alert.severity ?? "-"
        )}
            </td>

            <td class="ip-cell">
                ${escapeHTML(
            alert.source_ip ?? "-"
        )}
            </td>

            <td>
                ${escapeHTML(
            alert.message ?? "-"
        )}
            </td>

        `;


        alertsBody.appendChild(row);

    });

}


// ============================================================
// UPDATE ALERT TABLE
// ============================================================

function updateAlertTable(stats) {

    currentAlerts =
        Array.isArray(
            stats.recent_alerts
        )
            ? stats.recent_alerts
            : [];


    renderAlertTable();

}


// ============================================================
// DETECT NEW ALERTS
// ============================================================

function detectNewAlerts(stats) {

    const alerts =
        Array.isArray(stats.recent_alerts)
            ? stats.recent_alerts
            : [];

    if (alerts.length === 0) {
        return;
    }

    alerts.forEach(alert => {

        /*
         * The backend currently does not send
         * the database alert ID.
         *
         * Therefore create a unique fingerprint
         * using the alert contents.
         */

        const alertId = [
            alert.timestamp,
            alert.type,
            alert.severity,
            alert.source_ip,
            alert.message
        ].join("|");


        // Already processed
        if (knownAlertIds.has(alertId)) {
            return;
        }


        // Remember alert
        knownAlertIds.add(alertId);


        /*
         * Do not show notifications for every alert
         * already present when the page first loads.
         */

        if (!dashboardInitialized) {
            return;
        }


        const severity =
            String(
                alert.severity ?? ""
            ).toUpperCase();


        let notificationType = "warning";

        if (severity === "HIGH") {
            notificationType = "critical";
        }


        showNotification(
            `🚨 ${severity} — ${alert.message}`,
            notificationType
        );

    });

}

// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {

    return String(value)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );

}

function showNotification(message, type = "success") {

    const notification =
        document.getElementById("notification");

    if (!notification) {
        console.log(message);
        return;
    }

    notification.textContent = message;

    notification.className =
        `notification show ${type}`;

    clearTimeout(window.notificationTimeout);

    window.notificationTimeout =
        setTimeout(() => {

            notification.classList.remove("show");

        }, 3000);

}

// =========================================
// UPDATE SYSTEM THREAT STATUS
// =========================================

function updateSystemStatus(stats) {

    const status =
        document.getElementById("system-status");

    const statusDot =
        document.getElementById("status-dot");

    const statusText =
        document.getElementById("status-text");

    if (!status || !statusDot || !statusText) {
        return;
    }


    status.classList.remove(
        "secure",
        "warning",
        "critical",
        "stopped"
    );

    statusDot.classList.remove(
        "secure",
        "warning",
        "critical",
        "stopped"
    );


    // IDS STOPPED
    if (stats.monitoring_active === false) {

        status.classList.add("stopped");
        statusDot.classList.add("stopped");

        statusText.textContent =
            "IDS MONITORING STOPPED";

        return;

    }


    // CRITICAL THREAT
    if (Number(stats.high) > 0) {

        status.classList.add("critical");
        statusDot.classList.add("critical");

        statusText.textContent =
            "CRITICAL — THREATS DETECTED";

        return;

    }


    // WARNING
    if (Number(stats.medium) > 0) {

        status.classList.add("warning");
        statusDot.classList.add("warning");

        statusText.textContent =
            "WARNING — SUSPICIOUS ACTIVITY";

        return;

    }


    // SECURE
    status.classList.add("secure");
    statusDot.classList.add("secure");

    statusText.textContent =
        "IDS MONITORING ACTIVE";

}
function updateControlButtons(stats) {

    const startButton =
        document.getElementById(
            "start-monitoring-btn"
        );

    const stopButton =
        document.getElementById(
            "stop-monitoring-btn"
        );

    const liveStatus =
        document.querySelector(
            ".monitor-status"
        );

    const liveText =
        document.getElementById(
            "live-text"
        );


    if (!startButton || !stopButton) {

        return;

    }


    const isMonitoring =
        stats.monitoring_active === true;


    // ========================================================
    // BUTTON STATE
    // ========================================================

    startButton.disabled =
        isMonitoring;

    stopButton.disabled =
        !isMonitoring;


    // ========================================================
    // LIVE INDICATOR
    // ========================================================

    if (liveStatus && liveText) {

        if (isMonitoring) {

            liveStatus.classList.remove(
                "stopped"
            );

            liveText.textContent =
                "LIVE";

        }

        else {

            liveStatus.classList.add(
                "stopped"
            );

            liveText.textContent =
                "STOPPED";

        }

    }

}

// ============================================================
// FETCH DASHBOARD DATA
// ============================================================

async function updateDashboard() {

    try {

        const response =
            await fetch(
                "/api/stats",
                {
                    method: "GET",

                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );

        }


        const stats =
            await response.json();

        updateSystemStatus(stats);

        updateControlButtons(stats);

        updateSummaryCards(stats);

        checkForNewAlert(stats);

        // Update traffic
        updateTrafficChart(stats);


        // Update attacks
        updateAttackChart(stats);

        // Update attack type filter
        updateAttackTypeFilter(stats);


        // Update alerts
        updateAlertTable(stats);

        // Detect newly generated security alerts
        detectNewAlerts(stats);


        console.log(
            "IDS dashboard updated:",
            stats
        );

    }


    catch (error) {

        console.error(
            "Failed to update IDS dashboard:",
            error
        );

    }

}


// ============================================================
// INITIALIZE DASHBOARD
// ============================================================

function initializeDashboard() {

    createTrafficChart();

    createAttackChart();

    // ============================================================
    // MONITORING CONTROL BUTTONS
    // ============================================================

    const startButton = document.getElementById(
        "start-monitoring-btn"
    );

    const stopButton = document.getElementById(
        "stop-monitoring-btn"
    );

    const clearButton = document.getElementById(
        "clear-data-btn"
    );

    // ============================================================
    // ALERT FILTER CONTROLS
    // ============================================================

    if (severityFilter) {

        severityFilter.addEventListener(
            "change",
            renderAlertTable
        );

    }


    if (typeFilter) {

        typeFilter.addEventListener(
            "change",
            renderAlertTable
        );

    }

    if (ipFilter) {

        ipFilter.addEventListener(
            "input",
            renderAlertTable
        );

    }


    if (resetAlertFilters) {

        resetAlertFilters.addEventListener(
            "click",
            () => {

                if (severityFilter) {

                    severityFilter.value =
                        "ALL";

                }


                if (typeFilter) {

                    typeFilter.value =
                        "ALL";

                }

                if (ipFilter) {
                    ipFilter.value = "";
                }

                renderAlertTable();

            }
        );

    }


    // ------------------------------------------------------------
    // START MONITORING
    // ------------------------------------------------------------

    startButton.addEventListener(
        "click",
        async () => {

            try {

                const response =
                    await fetch(
                        "/api/monitor/start",
                        {
                            method: "POST"
                        }
                    );


                const result =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        result.message ||
                        "Unable to start monitoring"
                    );

                }


                // ------------------------------------------------
                // Start a fresh traffic session
                // ------------------------------------------------

                trafficLabels.length = 0;

                packetData.length = 0;

                if (trafficChart) {

                    trafficChart.update("none");

                }


                showNotification(
                    result.message ||
                    "IDS monitoring started successfully",
                    "success"
                );


                await updateDashboard();

            }

            catch (error) {

                console.error(
                    "Failed to start monitoring:",
                    error
                );

                showNotification(
                    "Failed to start IDS monitoring",
                    "error"
                );

            }

        }
    );


    // ------------------------------------------------------------
    // STOP MONITORING
    // ------------------------------------------------------------

    stopButton.addEventListener(
        "click",
        async () => {

            try {

                const response =
                    await fetch(
                        "/api/monitor/stop",
                        {
                            method: "POST"
                        }
                    );


                const result =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        result.message ||
                        "Unable to stop monitoring"
                    );

                }


                showNotification(
                    result.message ||
                    "IDS monitoring stopped",
                    "warning"
                );


                await updateDashboard();

            }

            catch (error) {

                console.error(
                    "Failed to stop monitoring:",
                    error
                );


                showNotification(
                    "Failed to stop IDS monitoring",
                    "error"
                );

            }

        }
    );


    // ------------------------------------------------------------
    // CLEAR IDS DATA
    // ------------------------------------------------------------

    clearButton.addEventListener(
        "click",
        async () => {

            const confirmed = confirm(
                "Are you sure you want to clear all IDS data?"
            );

            if (!confirmed) {

                return;

            }


            try {

                const response = await fetch(
                    "/api/reset",
                    {
                        method: "POST"
                    }
                );

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(
                        result.message || "Unable to clear IDS data"
                    );
                }

                showNotification(
                    result.message ||
                    "All IDS data cleared successfully",
                    "success"
                );

                console.log(result.message);


                // Clear traffic graph immediately
                trafficLabels.length = 0;

                packetData.length = 0;

                trafficChart.update();


                // Clear attack chart immediately
                attackChart.data.labels = [];

                attackChart.data.datasets[0].data = [];

                attackChart.update("none");

                // Refresh dashboard
                await updateDashboard();

            }

            catch (error) {

                console.error(
                    "Failed to clear IDS data:",
                    error
                );

            }

        }
    );

    updateDashboard().then(() => {

        dashboardInitialized = true;

    });
}
// Refresh every 3 seconds

setInterval(
    updateDashboard,
    3000
);



// ============================================================
// START
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    initializeDashboard
);