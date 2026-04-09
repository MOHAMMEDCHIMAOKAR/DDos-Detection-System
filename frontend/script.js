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

// Fetch Stats
async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const stats = await response.json();
        
        // Update stats display
        document.getElementById('packetsPerSec').textContent = stats.packets_per_second;
        document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
        document.getElementById('activeConnections').textContent = stats.active_connections;
        document.getElementById('alertsCount').textContent = stats.total_alerts;
        
        return stats;
    } catch (error) {
        console.error('Error fetching stats:', error);
        return null;
    }
}

// Fetch Alerts
async function fetchAlerts() {
    try {
        const response = await fetch(`${API_URL}/alerts`);
        const alerts = await response.json();
        
        updateAlertsDisplay(alerts);
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

// Fetch History
async function fetchHistory() {
    try {
        const response = await fetch(`${API_URL}/history`);
        const history = await response.json();
        
        updateChart(history);
    } catch (error) {
        console.error('Error fetching history:', error);
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
    fetchStats();
    fetchAlerts();
    fetchHistory();
    
    // Update every second
    updateInterval = setInterval(() => {
        fetchStats();
        fetchAlerts();
        fetchHistory();
    }, 1000);
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

// Initialize on Page Load
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    checkInitialStatus();
});
