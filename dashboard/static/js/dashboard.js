"use strict";

/*
============================================================
🛡️ MINI IDS DASHBOARD
Complete Dashboard JavaScript
============================================================
*/

const REFRESH_INTERVAL = 3000;
const MAX_TRAFFIC_POINTS = 12;
const NOTIFICATION_DURATION = 3500;


// ============================================================
// GLOBAL STATE
// ============================================================

let trafficChart = null;
let attackChart = null;
let protocolChart = null;

let trafficLabels = [];
let packetData = [];

let currentAlerts = [];
let knownAlertIds = new Set();

let dashboardInitialized = false;
let refreshTimer = null;
let notificationTimer = null;


// ============================================================
// DOM REFERENCES
// ============================================================

let packetsElement;
let alertsElement;
let highElement;
let mediumElement;

let alertsBody;

let devicesBody;
let deviceCountElement;

let trafficCanvas;

let attackCanvas;
let attackEmpty;

let protocolCanvas;
let protocolEmpty;
let protocolTotal;
let protocolList;

let severityFilter;
let typeFilter;
let ipFilter;

let resetAlertFilters;
let visibleAlertCount;

let notification;

let startButton;
let stopButton;
let clearButton;


// ============================================================
// SECURITY OVERVIEW DOM REFERENCES
// ============================================================

let securityScore;
let securityStatus;
let securityStatusBadge;
let securityStatusDot;

let securityPackets;
let securityAlerts;
let securityHigh;
let securityMedium;
let securityLow;
let securityDevices;

let securityTopAttack;
let securityTopAttackCount;

let securityLatestThreat;
let securityLatestTime;

let securityRecommendation;


// ============================================================
// GET DOM ELEMENTS
// ============================================================

function initializeDOM() {

    packetsElement =
        document.getElementById("packets");

    alertsElement =
        document.getElementById("alerts");

    highElement =
        document.getElementById("high");

    mediumElement =
        document.getElementById("medium");

    alertsBody =
        document.getElementById("alerts-body");

    devicesBody =
        document.getElementById("devices-body");

    deviceCountElement =
        document.getElementById("device-count");

    trafficCanvas =
        document.getElementById("trafficChart");

    attackCanvas =
        document.getElementById("attackChart");

    attackEmpty =
        document.getElementById("attackEmpty");

    protocolCanvas =
        document.getElementById("protocolChart");

    protocolEmpty =
        document.getElementById("protocolEmpty");

    protocolTotal =
        document.getElementById("protocol-total");

    protocolList =
        document.getElementById("protocol-list");

    severityFilter =
        document.getElementById("severity-filter");

    typeFilter =
        document.getElementById("attack-filter");

    ipFilter =
        document.getElementById("ip-filter");

    resetAlertFilters =
        document.getElementById("reset-alert-filters");

    visibleAlertCount =
        document.getElementById("visible-alert-count");

    notification =
        document.getElementById("notification");

    startButton =
        document.getElementById("start-monitoring-btn");

    stopButton =
        document.getElementById("stop-monitoring-btn");

    clearButton =
        document.getElementById("clear-data-btn");


    // ========================================================
    // SECURITY OVERVIEW
    // ========================================================

    securityScore =
        document.getElementById("security-score");

    securityStatus =
        document.getElementById("security-status");

    securityStatusBadge =
        document.getElementById("security-status-badge");

    securityStatusDot =
        document.getElementById("security-status-dot");

    securityPackets =
        document.getElementById("security-packets");

    securityAlerts =
        document.getElementById("security-alerts");

    securityHigh =
        document.getElementById("security-high");

    securityMedium =
        document.getElementById("security-medium");

    securityLow =
        document.getElementById("security-low");

    securityDevices =
        document.getElementById("security-devices");

    securityTopAttack =
        document.getElementById("security-top-attack");

    securityTopAttackCount =
        document.getElementById("security-top-attack-count");

    securityLatestThreat =
        document.getElementById("security-latest-threat");

    securityLatestTime =
        document.getElementById("security-latest-time");

    securityRecommendation =
        document.getElementById("security-recommendation");


    console.log("✅ DOM elements loaded.");

}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


// ============================================================
// ALERT FINGERPRINT
// ============================================================

function createAlertFingerprint(alert) {

    return [
        alert.timestamp ?? "",
        alert.type ?? "",
        alert.severity ?? "",
        alert.source_ip ?? "",
        alert.message ?? ""
    ].join("|");

}


// ============================================================
// NOTIFICATION
// ============================================================

function showNotification(
    message,
    type = "success"
) {

    if (!notification) {

        console.log("Notification:", message);

        return;

    }


    notification.textContent =
        message;


    notification.className =
        "notification show " + type;


    notification.style.position =
        "fixed";

    notification.style.right =
        "24px";

    notification.style.bottom =
        "24px";

    notification.style.left =
        "auto";

    notification.style.top =
        "auto";

    notification.style.zIndex =
        "99999";

    notification.style.pointerEvents =
        "none";


    if (notificationTimer) {

        clearTimeout(
            notificationTimer
        );

    }


    notificationTimer =
        setTimeout(() => {

            notification.classList.remove(
                "show"
            );

        }, NOTIFICATION_DURATION);

}


// ============================================================
// CREATE TRAFFIC CHART
// ============================================================

function createTrafficChart() {

    if (!trafficCanvas) {

        console.error(
            "❌ trafficChart canvas not found."
        );

        return;

    }


    if (typeof Chart === "undefined") {

        console.error(
            "❌ Chart.js is not loaded."
        );

        return;

    }


    if (trafficChart) {

        trafficChart.destroy();

        trafficChart = null;

    }


    const ctx =
        trafficCanvas.getContext("2d");


    trafficChart =
        new Chart(ctx, {

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

                            text:
                                "Packets / Second",

                            color:
                                "#94a3b8"

                        },

                        ticks: {

                            color:
                                "#94a3b8"

                        },

                        grid: {

                            color:
                                "rgba(148,163,184,0.08)"

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
            "❌ attackChart canvas not found."
        );

        return;

    }


    if (typeof Chart === "undefined") {

        return;

    }


    if (attackChart) {

        attackChart.destroy();

        attackChart = null;

    }


    const ctx =
        attackCanvas.getContext("2d");


    attackChart =
        new Chart(ctx, {

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

                        borderColor:
                            "#1e293b",

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
// CREATE PROTOCOL CHART
// ============================================================

function createProtocolChart() {

    if (!protocolCanvas) {

        console.error(
            "❌ protocolChart canvas not found."
        );

        return;

    }


    if (typeof Chart === "undefined") {

        return;

    }


    if (protocolChart) {

        protocolChart.destroy();

        protocolChart = null;

    }


    const ctx =
        protocolCanvas.getContext("2d");


    protocolChart =
        new Chart(ctx, {

            type: "doughnut",

            data: {

                labels: [],

                datasets: [

                    {

                        label: "Packets",

                        data: [],

                        backgroundColor: [

                            "#38bdf8",
                            "#22c55e",
                            "#f59e0b",
                            "#a855f7",
                            "#ef4444",
                            "#64748b"

                        ],

                        borderColor:
                            "#1e293b",

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

                        position: "bottom",

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
// UPDATE PROTOCOL ANALYTICS
// ============================================================

function updateProtocolAnalytics(data) {

    if (!protocolChart) {

        return;

    }


    const source =
        data?.data ?? data ?? {};


    const protocolData =
        Array.isArray(source.protocols)
            ? source.protocols
            : [];


    const total =
        Number(
            source.total_packets ?? 0
        ) || 0;


    if (protocolTotal) {

        protocolTotal.textContent =
            total.toLocaleString();

    }


    const labels =
        protocolData.map(
            item =>
                String(
                    item.protocol ?? "OTHER"
                ).toUpperCase()
        );


    const values =
        protocolData.map(
            item =>
                Number(
                    item.packets ?? 0
                ) || 0
        );


    protocolChart.data.labels =
        labels;

    protocolChart.data.datasets[0].data =
        values;


    protocolChart.update("none");


    if (protocolEmpty) {

        protocolEmpty.style.display =
            protocolData.length === 0
                ? "flex"
                : "none";

    }


    if (!protocolList) {

        return;

    }


    protocolList.innerHTML = "";


    if (protocolData.length === 0) {

        protocolList.innerHTML = `

            <div class="protocol-empty">
                No protocol traffic recorded yet.
            </div>

        `;

        return;

    }


    protocolData.forEach(item => {

        const row =
            document.createElement("div");


        row.className =
            "protocol-item";


        const protocol =
            escapeHTML(
                item.protocol ?? "OTHER"
            );


        const packets =
            Number(
                item.packets ?? 0
            ) || 0;


        const percentage =
            Number(
                item.percentage ?? 0
            ) || 0;


        row.innerHTML = `

            <div class="protocol-name">
                ${protocol}
            </div>

            <div class="protocol-packets">
                ${packets.toLocaleString()} packets
            </div>

            <div class="protocol-percentage">
                ${percentage.toFixed(2)}%
            </div>

        `;


        protocolList.appendChild(row);

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
// CLEAR TRAFFIC CHART
// ============================================================

function clearTrafficChart() {

    trafficLabels.length = 0;

    packetData.length = 0;


    if (!trafficChart) {

        return;

    }


    trafficChart.data.labels =
        trafficLabels;

    trafficChart.data.datasets[0].data =
        packetData;


    trafficChart.update("none");

}


// ============================================================
// UPDATE TRAFFIC CHART
// ============================================================

function updateTrafficChart(stats) {

    if (!trafficChart) {

        return;

    }


    if (
        stats.monitoring_active !== true
    ) {

        return;

    }


    const packetRate =
        Number(
            stats.packet_rate ?? 0
        ) || 0;


    const now =
        new Date().toLocaleTimeString(
            [],
            {
                hour: "numeric",
                minute: "2-digit",
                second: "2-digit"
            }
        );


    trafficLabels.push(now);

    packetData.push(packetRate);


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
// UPDATE ATTACK CHART
// ============================================================

function updateAttackChart(stats) {

    if (!attackChart) {

        return;

    }


    const attackTypes =
        stats.alert_types &&
        typeof stats.alert_types === "object"
            ? stats.alert_types
            : {};


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

        attackEmpty.style.display =
            labels.length === 0
                ? "flex"
                : "none";

    }

}


// ============================================================
// UPDATE ATTACK TYPE FILTER
// ============================================================

function updateAttackTypeFilter(stats) {

    if (!typeFilter) {

        return;

    }


    const backendTypes =
        stats?.alert_types &&
        typeof stats.alert_types === "object"
            ? Object.keys(
                stats.alert_types
            )
            : [];


    const alertTypes =
        Array.isArray(
            stats?.recent_alerts
        )
            ? stats.recent_alerts
                .map(alert =>
                    String(
                        alert.type ?? ""
                    )
                        .trim()
                        .toUpperCase()
                )
                .filter(Boolean)
            : [];


    const availableTypes =
        [
            ...new Set([
                ...backendTypes,
                ...alertTypes
            ])
        ]
            .filter(Boolean)
            .sort();


    const currentValue =
        typeFilter.value || "ALL";


    typeFilter.innerHTML = "";


    const allOption =
        document.createElement("option");


    allOption.value =
        "ALL";


    allOption.textContent =
        "All Attack Types";


    typeFilter.appendChild(
        allOption
    );


    availableTypes.forEach(type => {

        const option =
            document.createElement("option");


        option.value =
            type;


        option.textContent =
            type.replaceAll(
                "_",
                " "
            );


        typeFilter.appendChild(
            option
        );

    });


    if (
        currentValue !== "ALL" &&
        availableTypes.includes(
            currentValue
        )
    ) {

        typeFilter.value =
            currentValue;

    }

    else {

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


    const severity =
        severityFilter
            ? severityFilter.value
            : "ALL";


    if (
        severity &&
        severity !== "ALL"
    ) {

        filtered =
            filtered.filter(alert => {

                return String(
                    alert.severity ?? ""
                )
                    .toUpperCase() ===
                    severity;

            });

    }


    const type =
        typeFilter
            ? typeFilter.value
            : "ALL";


    if (
        type &&
        type !== "ALL"
    ) {

        filtered =
            filtered.filter(alert => {

                return String(
                    alert.type ?? ""
                )
                    .toUpperCase() ===
                    type;

            });

    }


    const ip =
        ipFilter
            ? ipFilter.value
                .trim()
                .toLowerCase()
            : "";


    if (ip !== "") {

        filtered =
            filtered.filter(alert => {

                return String(
                    alert.source_ip ?? ""
                )
                    .toLowerCase()
                    .includes(ip);

            });

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


    if (visibleAlertCount) {

        visibleAlertCount.textContent =
            alerts.length;

    }


    alertsBody.innerHTML = "";


    if (alerts.length === 0) {

        const row =
            document.createElement("tr");


        row.innerHTML = `

            <td colspan="5" class="empty">

                No security alerts match
                the selected filters.

            </td>

        `;


        alertsBody.appendChild(row);

        return;

    }


    alerts.forEach(alert => {

        const row =
            document.createElement("tr");


        const severity =
            String(
                alert.severity ?? ""
            )
                .toLowerCase();


        if (severity === "high") {

            row.classList.add(
                "alert-high-row"
            );

        }

        else if (
            severity === "medium"
        ) {

            row.classList.add(
                "alert-medium-row"
            );

        }


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

            <td class="${escapeHTML(severity)}">
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
        Array.isArray(
            stats.recent_alerts
        )
            ? stats.recent_alerts
            : [];


    if (alerts.length === 0) {

        return;

    }


    const newAlerts = [];


    alerts.forEach(alert => {

        const fingerprint =
            createAlertFingerprint(
                alert
            );


        if (
            knownAlertIds.has(
                fingerprint
            )
        ) {

            return;

        }


        knownAlertIds.add(
            fingerprint
        );


        newAlerts.push(
            alert
        );

    });


    if (!dashboardInitialized) {

        return;

    }


    if (newAlerts.length === 0) {

        return;

    }


    const latestAlert =
        newAlerts[0];


    const severity =
        String(
            latestAlert.severity ?? ""
        )
            .toUpperCase();


    let notificationType =
        "warning";


    if (severity === "HIGH") {

        notificationType =
            "critical";

    }


    showNotification(
        `🚨 ${severity} — ${latestAlert.message}`,
        notificationType
    );

}


// ============================================================
// SECURITY STATE
// ============================================================

function getSecurityState(stats = {}) {

    const high =
        Number(stats.high ?? stats.high_alerts ?? 0);

    const medium =
        Number(stats.medium ?? stats.medium_alerts ?? 0);

    const monitoringActive =
        stats.monitoring_active === true;


    // --------------------------------------------------------
    // Monitoring stopped
    // --------------------------------------------------------

    if (!monitoringActive) {

        return {
            level: "stopped",
            text: "IDS MONITORING STOPPED"
        };

    }


    // --------------------------------------------------------
    // High severity threats
    // --------------------------------------------------------

    if (high > 0) {

        return {
            level: "critical",
            text: "CRITICAL — THREATS DETECTED"
        };

    }


    // --------------------------------------------------------
    // Medium severity threats
    // --------------------------------------------------------

    if (medium > 0) {

        return {
            level: "warning",
            text: "WARNING — SUSPICIOUS ACTIVITY"
        };

    }


    // --------------------------------------------------------
    // No threats
    // --------------------------------------------------------

    return {
        level: "secure",
        text: "IDS MONITORING ACTIVE"
    };

}


// ============================================================
// UPDATE SYSTEM STATUS
// ============================================================

function updateSystemStatus(stats) {

    const status =
        document.getElementById("system-status");

    const statusDot =
        document.getElementById("status-dot");

    const statusText =
        document.getElementById("status-text");


    if (
        !status ||
        !statusDot ||
        !statusText
    ) {

        console.warn(
            "⚠️ System status elements not found."
        );

        return;

    }


    const state =
        getSecurityState(stats);


    // --------------------------------------------------------
    // Remove previous states
    // --------------------------------------------------------

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


    // --------------------------------------------------------
    // Apply current state
    // --------------------------------------------------------

    status.classList.add(
        state.level
    );

    statusDot.classList.add(
        state.level
    );


    statusText.textContent =
        state.text;


    console.log(
        "🛡️ System security state:",
        state
    );

} 


// ============================================================
// UPDATE CONTROL BUTTONS
// ============================================================

function updateControlButtons(stats) {

    const liveStatus =
        document.querySelector(
            ".monitor-status"
        );


    const liveDot =
        document.getElementById(
            "live-dot"
        );


    const liveText =
        document.getElementById(
            "live-text"
        );


    if (
        !startButton ||
        !stopButton
    ) {

        return;

    }


    const isMonitoring =
        stats.monitoring_active === true;


    startButton.disabled =
        isMonitoring;


    stopButton.disabled =
        !isMonitoring;


    if (
        liveStatus &&
        liveText
    ) {

        liveStatus.classList.toggle(
            "stopped",
            !isMonitoring
        );


        liveText.textContent =
            isMonitoring
                ? "LIVE"
                : "STOPPED";

    }


    if (liveDot) {

        liveDot.classList.toggle(
            "stopped",
            !isMonitoring
        );

    }

}


// ============================================================
// UPDATE CONNECTED DEVICES
// ============================================================

async function updateConnectedDevices() {

    if (!devicesBody) {

        return;

    }


    try {

        const response =
            await fetch(
                "/api/devices",
                {
                    method: "GET",
                    cache: "no-store",
                    headers: {
                        "Accept":
                            "application/json"
                    }
                }
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );

        }


        const result =
            await response.json();


        const devices =
            Array.isArray(
                result.devices
            )
                ? result.devices
                : [];


        if (deviceCountElement) {

            deviceCountElement.textContent =
                devices.length;

        }


        if (devices.length === 0) {

            devicesBody.innerHTML = `

                <tr>

                    <td colspan="5" class="empty">
                        No devices detected yet.
                    </td>

                </tr>

            `;

            return;

        }


        devicesBody.innerHTML = "";


        devices.forEach(device => {

            const row =
                document.createElement("tr");


            const deviceType =
                String(
                    device.device_type ??
                    "UNKNOWN"
                ).toUpperCase();


            if (
                deviceType === "LOCAL"
            ) {

                row.classList.add(
                    "device-local"
                );

            }

            else if (
                deviceType === "EXTERNAL"
            ) {

                row.classList.add(
                    "device-external"
                );

            }


            row.innerHTML = `

                <td class="ip-cell">
                    ${escapeHTML(
                        device.ip_address ?? "-"
                    )}
                </td>

                <td>
                    ${escapeHTML(
                        deviceType
                    )}
                </td>

                <td>
                    ${escapeHTML(
                        device.first_seen ?? "-"
                    )}
                </td>

                <td>
                    ${escapeHTML(
                        device.last_seen ?? "-"
                    )}
                </td>

                <td>
                    ${Number(
                        device.packet_count ?? 0
                    ).toLocaleString()}
                </td>

            `;


            devicesBody.appendChild(
                row
            );

        });

    }

    catch (error) {

        console.error(
            "❌ Failed to fetch connected devices:",
            error
        );

    }

}


// ============================================================
// FETCH DASHBOARD STATS
// ============================================================

async function fetchDashboardStats() {

    const response =
        await fetch(
            "/api/stats",
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept":
                        "application/json"
                }
            }
        );


    if (!response.ok) {

        throw new Error(
            `HTTP ${response.status}`
        );

    }


    return await response.json();

}


// ============================================================
// FETCH PROTOCOL STATS
// ============================================================

async function fetchProtocolStats() {

    const response =
        await fetch(
            "/api/protocols",
            {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept":
                        "application/json"
                }
            }
        );


    if (!response.ok) {

        throw new Error(
            `Protocol API HTTP ${response.status}`
        );

    }


    return await response.json();

}


// ============================================================
// FETCH SECURITY OVERVIEW
// ============================================================

async function fetchSecurityOverview() {

    const response = await fetch(
        "/api/security-overview",
        {
            method: "GET",
            cache: "no-store",
            headers: {
                "Accept": "application/json"
            }
        }
    );

    if (!response.ok) {

        throw new Error(
            `Security Overview API HTTP ${response.status}`
        );

    }

    const result = await response.json();

    console.log(
        "🛡️ Security Overview API:",
        result
    );

    return result;

}

// ============================================================
// UPDATE SECURITY OVERVIEW
// ============================================================

function updateSecurityOverview(response) {

    if (!response) {
        return;
    }


    // ========================================================
    // SUPPORT BOTH API FORMATS
    // ========================================================
    //
    // Format 1:
    // {
    //     score: 85,
    //     status: "WARNING",
    //     ...
    // }
    //
    // Format 2:
    // {
    //     success: true,
    //     overview: {
    //         score: 85,
    //         status: "WARNING",
    //         ...
    //     }
    // }
    // ========================================================

    const data =
        response.overview &&
        typeof response.overview === "object"
            ? response.overview
            : response;


    // ========================================================
    // SECURITY SCORE
    // ========================================================

    const score =
        Math.max(
            0,
            Math.min(
                100,
                Number(data.score ?? 0)
            )
        );


    if (securityScore) {

        securityScore.textContent =
            score;

    }


    // ========================================================
    // SECURITY METRICS
    // ========================================================

    const totalPackets =
        Number(
            data.total_packets ?? 0
        );

    const totalAlerts =
        Number(
            data.total_alerts ?? 0
        );

    const highAlerts =
        Number(
            data.high_alerts ?? 0
        );

    const mediumAlerts =
        Number(
            data.medium_alerts ?? 0
        );

    const lowAlerts =
        Number(
            data.low_alerts ?? 0
        );

    const totalDevices =
        Number(
            data.total_devices ?? 0
        );


    if (securityPackets) {

        securityPackets.textContent =
            totalPackets.toLocaleString();

    }


    if (securityAlerts) {

        securityAlerts.textContent =
            totalAlerts.toLocaleString();

    }


    if (securityHigh) {

        securityHigh.textContent =
            highAlerts.toLocaleString();

    }


    if (securityMedium) {

        securityMedium.textContent =
            mediumAlerts.toLocaleString();

    }


    if (securityLow) {

        securityLow.textContent =
            lowAlerts.toLocaleString();

    }


    if (securityDevices) {

        securityDevices.textContent =
            totalDevices.toLocaleString();

    }


    // ========================================================
    // SECURITY STATUS
    // ========================================================
    //
    // IMPORTANT:
    // Do NOT blindly trust data.status from backend.
    // Derive the visual status from actual alert counts.
    // ========================================================

    const state =
        getSecurityState({

            monitoring_active:
                data.monitoring_active !== false,

            high:
                highAlerts,

            medium:
                mediumAlerts

        });


    const statusLevel =
        state.level;


    const statusText =
        statusLevel === "critical"
            ? "CRITICAL"
            : statusLevel === "warning"
                ? "WARNING"
                : statusLevel === "stopped"
                    ? "STOPPED"
                    : "SECURE";


    // --------------------------------------------------------
    // Status text
    // --------------------------------------------------------

    if (securityStatus) {

        securityStatus.textContent =
            statusText;

    }


    // --------------------------------------------------------
    // Status badge
    // --------------------------------------------------------

    if (securityStatusBadge) {

        securityStatusBadge.classList.remove(
            "secure",
            "warning",
            "critical",
            "stopped"
        );

        securityStatusBadge.classList.add(
            statusLevel
        );

    }


    // --------------------------------------------------------
    // Status dot
    // --------------------------------------------------------

    if (securityStatusDot) {

        securityStatusDot.className =
            "";

        securityStatusDot.classList.add(
            statusLevel
        );

    }


    // ========================================================
    // MOST COMMON ATTACK
    // ========================================================

    if (securityTopAttack) {

        securityTopAttack.textContent =
            data.top_attack || "NONE";

    }


    if (securityTopAttackCount) {

        const count =
            Number(
                data.top_attack_count ?? 0
            );


        securityTopAttackCount.textContent =
            `${count.toLocaleString()} occurrence${count === 1 ? "" : "s"}`;

    }


    // ========================================================
    // LATEST THREAT
    // ========================================================

    const latestThreat =
        data.latest_threat;


    if (!latestThreat) {

        if (securityLatestThreat) {

            securityLatestThreat.textContent =
                "No threats detected";

        }


        if (securityLatestTime) {

            securityLatestTime.textContent =
                "—";

        }

    }

    else {

        if (securityLatestThreat) {

            securityLatestThreat.textContent =
                latestThreat.message ||
                latestThreat.type ||
                "Security threat detected";

        }


        if (securityLatestTime) {

            securityLatestTime.textContent =
                latestThreat.timestamp ||
                "—";

        }

    }


    // ========================================================
    // RECOMMENDATION
    // ========================================================

    if (securityRecommendation) {

        securityRecommendation.textContent =
            data.recommendation ||
            "Continue monitoring network activity.";

    }


    // ========================================================
    // DEBUG
    // ========================================================

    console.log(
        "🛡️ Security Overview updated:",
        {
            score,
            status: statusText,
            statusLevel,
            totalPackets,
            totalAlerts,
            highAlerts,
            mediumAlerts,
            lowAlerts,
            totalDevices
        }
    );

}

// ============================================================
// EXPORT SECURITY REPORT
// ============================================================

async function exportSecurityReport() {

    const button = document.getElementById(
        "export-security-report-btn"
    );

    if (!button) {

        console.error(
            "Export Security Report button not found."
        );

        return;

    }


    const originalText =
        button.innerHTML;


    try {

        // ----------------------------------------------------
        // DISABLE BUTTON
        // ----------------------------------------------------

        button.disabled = true;

        button.innerHTML =
            "⏳ Generating Report...";


        // ----------------------------------------------------
        // REQUEST PDF
        // ----------------------------------------------------

        const response = await fetch(
            "/api/export-security-report"
        );


        if (!response.ok) {

            throw new Error(
                "Failed to generate security report."
            );

        }


        // ----------------------------------------------------
        // CONVERT RESPONSE TO BLOB
        // ----------------------------------------------------

        const blob =
            await response.blob();


        // ----------------------------------------------------
        // CREATE DOWNLOAD URL
        // ----------------------------------------------------

        const url =
            window.URL.createObjectURL(blob);


        // ----------------------------------------------------
        // CREATE TEMPORARY DOWNLOAD LINK
        // ----------------------------------------------------

        const link =
            document.createElement("a");


        link.href = url;

        link.download =
            "Mini_IDS_Security_Report.pdf";


        document.body.appendChild(
            link
        );


        link.click();


        // ----------------------------------------------------
        // CLEANUP
        // ----------------------------------------------------

        link.remove();

        window.URL.revokeObjectURL(
            url
        );


        // ----------------------------------------------------
        // SUCCESS NOTIFICATION
        // ----------------------------------------------------

        showNotification(
            "Security report exported successfully.",
            "success"
        );


    } catch (error) {

        console.error(
            "Security report export error:",
            error
        );


        showNotification(
            "Unable to export security report.",
            "error"
        );


    } finally {

        // ----------------------------------------------------
        // RESTORE BUTTON
        // ----------------------------------------------------

        button.disabled = false;

        button.innerHTML =
            originalText;

    }

}
// ============================================================
// UPDATE DASHBOARD
// ============================================================

async function updateDashboard() {

    try {

        // ====================================================
        // MAIN STATS
        // ====================================================

        const stats =
            await fetchDashboardStats();


        updateSummaryCards(
            stats
        );


        updateSystemStatus(
            stats
        );


        updateControlButtons(
            stats
        );


        updateTrafficChart(
            stats
        );


        updateAttackChart(
            stats
        );


        // ====================================================
        // PROTOCOL ANALYTICS
        // ====================================================

        try {

            const protocolStats =
                await fetchProtocolStats();


            updateProtocolAnalytics(
                protocolStats
            );

        }

        catch (error) {

            console.error(
                "❌ Protocol analytics failed:",
                error
            );

        }


        // ====================================================
        // SECURITY OVERVIEW
        // ====================================================

        try {

            const securityOverview =
                await fetchSecurityOverview();


            updateSecurityOverview(
                securityOverview
            );

        }

        catch (error) {

            console.error(
                "❌ Security Overview failed:",
                error
            );

        }


        // ====================================================
        // CONNECTED DEVICES
        // ====================================================

        await updateConnectedDevices();


        // ====================================================
        // ALERTS
        // ====================================================

        updateAlertTable(
            stats
        );


        updateAttackTypeFilter(
            stats
        );


        detectNewAlerts(
            stats
        );


        console.log(
            "🛡️ IDS dashboard updated."
        );

    }

    catch (error) {

        console.error(
            "❌ Dashboard update failed:",
            error
        );

    }

}


// ============================================================
// START MONITORING
// ============================================================

async function startMonitoring() {

    if (!startButton) {

        console.error(
            "❌ Start button not found."
        );

        return;

    }


    startButton.disabled =
        true;


    try {

        console.log(
            "▶ Starting IDS monitoring..."
        );


        const response =
            await fetch(
                "/api/monitor/start",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "Accept":
                            "application/json"
                    }
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


        clearTrafficChart();


        showNotification(
            result.message ||
            "IDS monitoring started successfully.",
            "success"
        );


        await updateDashboard();

    }

    catch (error) {

        console.error(
            "❌ Start monitoring failed:",
            error
        );


        showNotification(
            "Failed to start IDS monitoring: " +
            error.message,
            "error"
        );

    }

}


// ============================================================
// STOP MONITORING
// ============================================================

async function stopMonitoring() {

    if (!stopButton) {

        console.error(
            "❌ Stop button not found."
        );

        return;

    }


    stopButton.disabled =
        true;


    try {

        console.log(
            "⏹ Stopping IDS monitoring..."
        );


        const response =
            await fetch(
                "/api/monitor/stop",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "Accept":
                            "application/json"
                    }
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
            "IDS monitoring stopped.",
            "warning"
        );


        await updateDashboard();

    }

    catch (error) {

        console.error(
            "❌ Stop monitoring failed:",
            error
        );


        showNotification(
            "Failed to stop IDS monitoring: " +
            error.message,
            "error"
        );

    }

}


// ============================================================
// CLEAR IDS DATA
// ============================================================

async function clearIDSData() {

    if (!clearButton) {

        console.error(
            "❌ Clear button not found."
        );

        return;

    }


    const confirmed =
        window.confirm(
            "Are you sure you want to clear all IDS data?"
        );


    if (!confirmed) {

        return;

    }


    clearButton.disabled =
        true;


    try {

        console.log(
            "🗑 Clearing IDS data..."
        );


        const response =
            await fetch(
                "/api/reset",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "Accept":
                            "application/json"
                    }
                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                "Unable to clear IDS data"
            );

        }


        // ====================================================
        // CLEAR TRAFFIC
        // ====================================================

        clearTrafficChart();


        // ====================================================
        // CLEAR ATTACK CHART
        // ====================================================

        if (attackChart) {

            attackChart.data.labels =
                [];

            attackChart.data.datasets[0].data =
                [];

            attackChart.update("none");

        }


        // ====================================================
        // CLEAR PROTOCOL CHART
        // ====================================================

        if (protocolChart) {

            protocolChart.data.labels =
                [];

            protocolChart.data.datasets[0].data =
                [];

            protocolChart.update("none");

        }


        // ====================================================
        // CLEAR ALERTS
        // ====================================================

        currentAlerts =
            [];


        knownAlertIds.clear();


        // ====================================================
        // RESET FILTERS
        // ====================================================

        resetFilters();


        showNotification(
            result.message ||
            "All IDS data cleared successfully.",
            "success"
        );


        await updateDashboard();

    }

    catch (error) {

        console.error(
            "❌ Clear IDS data failed:",
            error
        );


        showNotification(
            "Failed to clear IDS data: " +
            error.message,
            "error"
        );

    }

    finally {

        clearButton.disabled =
            false;

    }

}


// ============================================================
// RESET ALERT FILTERS
// ============================================================

function resetFilters(event) {

    if (event) {

        event.preventDefault();

        event.stopPropagation();

    }


    if (severityFilter) {

        severityFilter.value =
            "ALL";

    }


    if (typeFilter) {

        typeFilter.value =
            "ALL";

    }


    if (ipFilter) {

        ipFilter.value =
            "";

    }


    renderAlertTable();

}


// ============================================================
// INITIALIZE FILTER EVENTS
// ============================================================

function initializeFilters() {

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
            resetFilters
        );

    }

}


// ============================================================
// INITIALIZE CONTROL EVENTS
// ============================================================

function initializeControls() {

    if (startButton) {

        startButton.addEventListener(
            "click",
            startMonitoring
        );

    }


    if (stopButton) {

        stopButton.addEventListener(
            "click",
            stopMonitoring
        );

    }


    if (clearButton) {

        clearButton.addEventListener(
            "click",
            clearIDSData
        );

    }


    console.log(
        "🎛️ Dashboard controls initialized."
    );

}


// ============================================================
// INITIALIZE DASHBOARD
// ============================================================

async function initializeDashboard() {

    console.log(
        "🛡️ Initializing Mini IDS Dashboard..."
    );


    // ========================================================
    // DOM
    // ========================================================

    initializeDOM();


    // ========================================================
    // CHARTS
    // ========================================================

    createTrafficChart();

    createAttackChart();

    createProtocolChart();


    // ========================================================
    // FILTERS
    // ========================================================

    initializeFilters();


    // ========================================================
    // CONTROLS
    // ========================================================

    initializeControls();


    // ========================================================
    // FIRST UPDATE
    // ========================================================

    await updateDashboard();


    // ========================================================
    // MARK EXISTING ALERTS AS KNOWN
    // ========================================================

    currentAlerts.forEach(
        alert => {

            knownAlertIds.add(
                createAlertFingerprint(
                    alert
                )
            );

        }
    );


    dashboardInitialized =
        true;


    console.log(
        "✅ Mini IDS Dashboard initialized successfully."
    );

}


// ============================================================
// START AUTO REFRESH
// ============================================================

function startAutoRefresh() {

    if (refreshTimer) {

        clearInterval(
            refreshTimer
        );

    }


    refreshTimer =
        setInterval(
            updateDashboard,
            REFRESH_INTERVAL
        );


    console.log(
        `🔄 Auto refresh started: every ${REFRESH_INTERVAL / 1000}s`
    );

}


// ============================================================
// STOP AUTO REFRESH
// ============================================================

function stopAutoRefresh() {

    if (refreshTimer) {

        clearInterval(
            refreshTimer
        );

        refreshTimer =
            null;

    }

}


// ============================================================
// PAGE LOAD
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        await initializeDashboard();

        startAutoRefresh();


        // ====================================================
        // EXPORT SECURITY REPORT
        // ====================================================

        const exportButton =
            document.getElementById(
                "export-security-report-btn"
            );


        if (exportButton) {

            exportButton.addEventListener(
                "click",
                exportSecurityReport
            );

        }

    }
)