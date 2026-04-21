// DoS Detection Dashboard - Frontend Script

// API Base URL
const API_URL = 'http://localhost:8000';

// Navigation Function
function navigateTo(page, event) {
    event.preventDefault();
    
    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
    
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(pageContent => {
        pageContent.style.display = 'none';
    });
    
    // Show selected page
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.style.display = 'block';
    }
    
    // Update page title
    const titles = {
        'dashboard': 'DoS Detection Dashboard',
        'analytics': 'Analytics Overview',
        'reports': 'Security Reports',
        'settings': 'System Settings'
    };
    
    const subtitles = {
        'dashboard': 'Real-time network traffic monitoring and threat detection',
        'analytics': 'Detailed traffic analysis and pattern detection',
        'reports': 'Generate and download security reports',
        'settings': 'Configure system detection parameters'
    };
    
    document.querySelector('.page-title').textContent = titles[page] || 'Dashboard';
    document.querySelector('.page-subtitle').textContent = subtitles[page] || '';
}

// State
let isRunning = false;
let updateInterval = null;
let trafficChart = null;

// Initialize Chart
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets per Second',
                data: [],
                borderColor: '#2196F3',
                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 0
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time (seconds ago)',
                        color: '#666'
                    },
                    grid: {
                        display: false
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Packets/sec',
                        color: '#666'
                    },
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 20
                    }
                }
            }
        }
    });
}

// Update Chart
function updateChart(history) {
    if (!trafficChart) return;
    
    // Generate labels (60, 59, 58, ... 1)
    const labels = history.map((_, index) => (history.length - index).toString());
    
    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = history;
    trafficChart.update('none');
}

// Start Detection System
async function startSystem() {
    try {
        const response = await fetch(`${API_URL}/start`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'started' || data.status === 'already_running') {
            isRunning = true;
            updateStatusUI();
            startUpdates();
        }
    } catch (error) {
        console.error('Error starting system:', error);
        alert('Failed to start detection system. Make sure the backend is running.');
    }
}

// Stop Detection System
async function stopSystem() {
    try {
        const response = await fetch(`${API_URL}/stop`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'stopped' || data.status === 'already_stopped') {
            isRunning = false;
            updateStatusUI();
            stopUpdates();
        }
    } catch (error) {
        console.error('Error stopping system:', error);
        alert('Failed to stop detection system.');
    }
}

// Update Status UI
function updateStatusUI() {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    
    if (isRunning) {
        statusDot.classList.add('running');
        statusText.textContent = 'Running';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        statusDot.classList.remove('running');
        statusText.textContent = 'Stopped';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

// Fetch Snapshot — single call replacing fetchStats, fetchAlerts, fetchHistory
async function fetchSnapshot() {
    try {
        const response = await fetch(`${API_URL}/snapshot`);
        const snapshot = await response.json();

        // Update stats
        const stats = snapshot.stats;
        document.getElementById('packetsPerSec').textContent = stats.packets_per_second;
        document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
        document.getElementById('activeConnections').textContent = stats.active_connections;
        document.getElementById('alertsCount').textContent = stats.total_alerts;

        // Update alerts, chart, and analytics from the same consistent payload
        updateAlertsDisplay(snapshot.alerts);
        updateChart(snapshot.history);
        updateAnalytics(snapshot.alerts);

        // Sync settings inputs if config changed server-side
        if (snapshot.config) {
            const pps = document.getElementById('inputPps');
            const conn = document.getElementById('inputConn');
            if (pps && document.activeElement !== pps) pps.value = snapshot.config.packets_per_second_threshold;
            if (conn && document.activeElement !== conn) conn.value = snapshot.config.connection_threshold;
        }

        // Sync running state in case it drifted server-side
        if (snapshot.running !== isRunning) {
            isRunning = snapshot.running;
            updateStatusUI();
        }
    } catch (error) {
        console.error('Error fetching snapshot:', error);
    }
}

// Reset Detection System
async function resetSystem() {
    try {
        const response = await fetch(`${API_URL}/reset`, { method: 'POST' });
        const data = await response.json();
        if (data.status === 'reset') {
            // Immediately clear UI without waiting for next poll
            document.getElementById('packetsPerSec').textContent = '0';
            document.getElementById('totalPackets').textContent = '0';
            document.getElementById('activeConnections').textContent = '0';
            document.getElementById('alertsCount').textContent = '0';
            updateAlertsDisplay([]);
            updateChart([]);
        }
    } catch (error) {
        console.error('Error resetting system:', error);
        alert('Failed to reset. Make sure the backend is running.');
    }
}

// Update Alerts Display
function updateAlertsDisplay(alerts) {
    const noAlerts = document.getElementById('noAlerts');
    const alertList = document.getElementById('alertList');
    const alertBadge = document.getElementById('alertBadge');
    
    if (alerts.length === 0) {
        noAlerts.style.display = 'flex';
        alertList.innerHTML = '';
        if (alertBadge) alertBadge.textContent = '0';
        return;
    }
    
    noAlerts.style.display = 'none';
    if (alertBadge) alertBadge.textContent = alerts.length;
    
    // Sort alerts by timestamp (newest first)
    const sortedAlerts = [...alerts].reverse();
    
    alertList.innerHTML = sortedAlerts.map(alert => `
        <div class="alert-item ${alert.severity}">
            <div class="alert-header">
                <span class="alert-severity ${alert.severity}">${alert.severity}</span>
                <span class="alert-timestamp">${alert.timestamp}</span>
            </div>
            <div class="alert-type">${alert.attack_type}</div>
            <div class="alert-ip">Source IP: ${alert.ip}</div>
        </div>
    `).join('');
}

// Start Updates
function startUpdates() {
    // Clear existing interval
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    // Update immediately
    fetchSnapshot();

    // Update every second
    updateInterval = setInterval(fetchSnapshot, 1000);
}

// Stop Updates
function stopUpdates() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

// Check Initial Status
async function checkInitialStatus() {
    try {
        const response = await fetch(`${API_URL}/status`);
        const data = await response.json();
        
        if (data.running) {
            isRunning = true;
            updateStatusUI();
            startUpdates();
        }
    } catch (error) {
        console.error('Error checking status:', error);
    }
}

// ============ ANALYTICS ============

// Analytics state — accumulated over the session
const analytics = {
    high: 0, medium: 0, low: 0,
    ddos: 0, syn: 0,
    // per-minute buckets: array of {minute, count}
    minuteBuckets: [],
    seenAlertIds: new Set(),  // deduplicate by timestamp+ip+type
    lastMinuteKey: null,
};

let frequencyChart = null;

function initFrequencyChart() {
    const ctx = document.getElementById('frequencyChart');
    if (!ctx) return;
    frequencyChart = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts per minute',
                data: [],
                backgroundColor: 'rgba(79, 70, 229, 0.7)',
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function updateAnalytics(alerts) {
    const now = new Date();
    const minuteKey = `${now.getHours()}:${String(now.getMinutes()).padStart(2,'0')}`;

    let newThisCall = 0;

    alerts.forEach(alert => {
        const id = `${alert.timestamp}|${alert.ip}|${alert.attack_type}`;
        if (analytics.seenAlertIds.has(id)) return;
        analytics.seenAlertIds.add(id);
        newThisCall++;

        // Severity counts
        if (alert.severity === 'HIGH') analytics.high++;
        else if (alert.severity === 'MEDIUM') analytics.medium++;
        else analytics.low++;

        // Attack type counts
        if (alert.attack_type.startsWith('DDoS')) analytics.ddos++;
        else if (alert.attack_type.startsWith('SYN')) analytics.syn++;
    });

    // Minute bucket
    if (newThisCall > 0) {
        if (analytics.lastMinuteKey === minuteKey && analytics.minuteBuckets.length > 0) {
            analytics.minuteBuckets[analytics.minuteBuckets.length - 1].count += newThisCall;
        } else {
            analytics.minuteBuckets.push({ minute: minuteKey, count: newThisCall });
            if (analytics.minuteBuckets.length > 10) analytics.minuteBuckets.shift();
            analytics.lastMinuteKey = minuteKey;
        }
    }

    renderAnalytics();
}

function renderAnalytics() {
    const total = analytics.high + analytics.medium + analytics.low;
    const setBar = (barId, countId, val) => {
        const pct = total > 0 ? Math.round((val / total) * 100) : 0;
        const el = document.getElementById(barId);
        const ct = document.getElementById(countId);
        if (el) el.style.width = pct + '%';
        if (ct) ct.textContent = val;
    };
    setBar('barHigh', 'countHigh', analytics.high);
    setBar('barMedium', 'countMedium', analytics.medium);
    setBar('barLow', 'countLow', analytics.low);

    const typeTotal = analytics.ddos + analytics.syn;
    // Simultaneous = ticks where both fired; approximate as min(ddos,syn) if one exceeds the other
    const both = Math.min(analytics.ddos, analytics.syn);
    const setTypeBar = (barId, countId, val) => {
        const pct = typeTotal > 0 ? Math.round((val / typeTotal) * 100) : 0;
        const el = document.getElementById(barId);
        const ct = document.getElementById(countId);
        if (el) el.style.width = pct + '%';
        if (ct) ct.textContent = val;
    };
    setTypeBar('barDdos', 'countDdos', analytics.ddos);
    setTypeBar('barSyn', 'countSyn', analytics.syn);
    setTypeBar('barBoth', 'countBoth', both);

    if (frequencyChart) {
        frequencyChart.data.labels = analytics.minuteBuckets.map(b => b.minute);
        frequencyChart.data.datasets[0].data = analytics.minuteBuckets.map(b => b.count);
        frequencyChart.update();
    }
}

// ============ SETTINGS ============

async function loadSettings() {
    try {
        const res = await fetch(`${API_URL}/config`);
        const cfg = await res.json();
        const pps = document.getElementById('inputPps');
        const conn = document.getElementById('inputConn');
        if (pps) pps.value = cfg.packets_per_second_threshold;
        if (conn) conn.value = cfg.connection_threshold;
    } catch (e) {
        console.error('Could not load settings:', e);
    }
}

async function saveSettings() {
    const pps = parseInt(document.getElementById('inputPps').value, 10);
    const conn = parseInt(document.getElementById('inputConn').value, 10);
    if (!pps || !conn || pps < 1 || conn < 1) {
        alert('Both thresholds must be positive numbers.');
        return;
    }
    try {
        const res = await fetch(`${API_URL}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packets_per_second_threshold: pps, connection_threshold: conn })
        });
        const data = await res.json();
        if (data.status === 'updated') {
            const msg = document.getElementById('settingsSaved');
            if (msg) { msg.style.display = 'inline'; setTimeout(() => msg.style.display = 'none', 2500); }
        }
    } catch (e) {
        alert('Failed to save settings. Make sure the backend is running.');
    }
}

// ============ INIT ============

// Initialize on Page Load
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    initFrequencyChart();
    loadSettings();
    checkInitialStatus();
});