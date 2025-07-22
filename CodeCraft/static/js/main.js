// SentinelWatch Pro Web Interface JavaScript

// Global variables
let socket;
let performanceChart;
let alertsChart;
let currentTab = 'dashboard';
let alertCount = 0;
let systemStats = [];
let alerts = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Wait for all scripts to load, especially Chart.js
    setTimeout(() => {
        initializeSocket();
        initializeNavigation();
        initializeCharts();
        loadSettings();
        loadAlerts();
        loadSystemInfo();
        loadLogs();
        
        // Set default active tab
        showTab('dashboard');
        
        // Start periodic updates
        setInterval(updateDashboard, 5000);
    }, 100);
});

// Socket.IO initialization
function initializeSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('Connected to server');
        updateMonitoringStatus('Connected');
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateMonitoringStatus('Disconnected');
    });
    
    socket.on('new_alert', function(alert) {
        handleNewAlert(alert);
    });
    
    socket.on('system_stats', function(stats) {
        updateSystemStats(stats);
    });
    
    socket.on('monitoring_status', function(data) {
        updateMonitoringStatus(data.status);
    });
}

// Navigation handling
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link[data-tab]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tab = this.getAttribute('data-tab');
            showTab(tab);
            
            // Update active state
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Toggle monitoring button
    document.getElementById('toggle-monitoring').addEventListener('click', function() {
        const status = document.getElementById('monitoring-status').textContent;
        if (status === 'Protected') {
            socket.emit('stop_monitoring');
        } else {
            socket.emit('start_monitoring');
        }
    });
}

// Tab management
function showTab(tabName) {
    // Hide all tab contents
    const allTabs = document.querySelectorAll('.tab-content');
    allTabs.forEach(tab => tab.classList.add('d-none'));
    
    // Show selected tab
    const targetTab = document.getElementById(tabName);
    if (targetTab) {
        targetTab.classList.remove('d-none');
        targetTab.classList.add('fade-in');
        currentTab = tabName;
        
        // Load tab-specific data
        switch(tabName) {
            case 'alerts':
                loadAlerts();
                break;
            case 'system':
                loadSystemInfo();
                break;
            case 'logs':
                loadLogs();
                break;
            case 'settings':
                loadSettings();
                break;
        }
    }
}

// Chart initialization
function initializeCharts() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded');
        return;
    }
    
    const ctx1 = document.getElementById('performance-chart').getContext('2d');
    performanceChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU %',
                data: [],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.4
            }, {
                label: 'Memory %',
                data: [],
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#ffffff' },
                    grid: { color: '#495057' }
                },
                y: {
                    ticks: { color: '#ffffff' },
                    grid: { color: '#495057' },
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
    
    const ctx2 = document.getElementById('alerts-chart').getContext('2d');
    alertsChart = new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                }
            }
        }
    });
}

// Handle new alerts
function handleNewAlert(alert) {
    alerts.unshift(alert);
    alertCount++;
    
    // Update alert counter
    document.getElementById('alert-count').textContent = alertCount;
    
    // Add to alerts display
    if (currentTab === 'alerts') {
        displayAlerts();
    }
    
    // Update alerts chart
    updateAlertsChart();
    
    // Show notification
    showNotification(alert);
}

// Update system statistics
function updateSystemStats(stats) {
    // Update dashboard cards
    document.getElementById('cpu-usage').textContent = stats.cpu_percent.toFixed(1) + '%';
    document.getElementById('memory-usage').textContent = stats.memory_percent.toFixed(1) + '%';
    document.getElementById('disk-usage').textContent = stats.disk_percent.toFixed(1) + '%';
    document.getElementById('network-connections').textContent = stats.network_connections;
    
    // Add to chart data
    systemStats.push(stats);
    if (systemStats.length > 20) {
        systemStats.shift();
    }
    
    updatePerformanceChart();
}

// Update performance chart
function updatePerformanceChart() {
    if (!performanceChart) return;
    
    const labels = systemStats.map(stat => {
        const time = new Date(stat.timestamp);
        return time.toLocaleTimeString();
    });
    
    const cpuData = systemStats.map(stat => stat.cpu_percent);
    const memoryData = systemStats.map(stat => stat.memory_percent);
    
    performanceChart.data.labels = labels;
    performanceChart.data.datasets[0].data = cpuData;
    performanceChart.data.datasets[1].data = memoryData;
    performanceChart.update('none');
}

// Update alerts chart
function updateAlertsChart() {
    if (!alertsChart) return;
    
    const alertCounts = { high: 0, medium: 0, low: 0 };
    
    alerts.forEach(alert => {
        const severity = alert.severity || 'medium';
        alertCounts[severity.toLowerCase()]++;
    });
    
    alertsChart.data.datasets[0].data = [
        alertCounts.high,
        alertCounts.medium,
        alertCounts.low
    ];
    alertsChart.update();
}

// Load and display alerts
async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=50');
        const data = await response.json();
        alerts = data;
        displayAlerts();
        updateAlertsChart();
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

// Display alerts in the UI
function displayAlerts() {
    const container = document.getElementById('alerts-container');
    const filter = document.getElementById('alert-filter').value;
    
    let filteredAlerts = alerts;
    if (filter !== 'all') {
        filteredAlerts = alerts.filter(alert => 
            alert.severity === filter || alert.type === filter
        );
    }
    
    container.innerHTML = '';
    
    if (filteredAlerts.length === 0) {
        container.innerHTML = '<div class="col-12"><div class="alert alert-info">No alerts to display.</div></div>';
        return;
    }
    
    filteredAlerts.forEach(alert => {
        const alertCard = createAlertCard(alert);
        container.appendChild(alertCard);
    });
}

// Create alert card element
function createAlertCard(alert) {
    const col = document.createElement('div');
    col.className = 'col-12 col-lg-6';
    
    const severity = alert.severity || 'medium';
    const severityClass = `alert-${severity}`;
    const time = new Date(alert.timestamp).toLocaleString();
    
    col.innerHTML = `
        <div class="card alert-card ${severityClass} slide-in">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="card-title mb-1">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ${alert.title || 'Security Alert'}
                        </h6>
                        <p class="card-text text-muted small mb-2">${time}</p>
                        <p class="card-text">${alert.message || alert.description}</p>
                    </div>
                    <span class="badge bg-${severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'success'}">
                        ${severity.toUpperCase()}
                    </span>
                </div>
            </div>
        </div>
    `;
    
    return col;
}

// Load system information
async function loadSystemInfo() {
    try {
        const response = await fetch('/api/system-info');
        const data = await response.json();
        displaySystemInfo(data);
    } catch (error) {
        console.error('Error loading system info:', error);
        document.getElementById('system-info').innerHTML = '<p class="text-danger">Error loading system information.</p>';
    }
}

// Display system information
function displaySystemInfo(info) {
    const container = document.getElementById('system-info');
    
    container.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <p><strong>Platform:</strong> ${info.platform}</p>
                <p><strong>Release:</strong> ${info.release}</p>
                <p><strong>Machine:</strong> ${info.machine}</p>
                <p><strong>Processor:</strong> ${info.processor}</p>
            </div>
            <div class="col-md-6">
                <p><strong>CPU Cores:</strong> ${info.cpu_count}</p>
                <p><strong>Total Memory:</strong> ${(info.memory_total / (1024**3)).toFixed(2)} GB</p>
                <p><strong>Total Disk:</strong> ${(info.disk_total / (1024**3)).toFixed(2)} GB</p>
                <p><strong>Boot Time:</strong> ${new Date(info.boot_time).toLocaleString()}</p>
                <p><strong>Uptime:</strong> ${info.uptime}</p>
            </div>
        </div>
    `;
}

// Load logs
async function loadLogs() {
    try {
        const response = await fetch('/api/logs?lines=100');
        const data = await response.json();
        displayLogs(data);
    } catch (error) {
        console.error('Error loading logs:', error);
        document.getElementById('logs-content').textContent = 'Error loading logs.';
    }
}

// Display logs
function displayLogs(logs) {
    const container = document.getElementById('logs-content');
    container.textContent = logs.join('\n');
    container.scrollTop = container.scrollHeight;
}

// Load settings
async function loadSettings() {
    try {
        const response = await fetch('/api/config');
        const config = await response.json();
        populateSettings(config);
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

// Populate settings form
function populateSettings(config) {
    document.getElementById('monitor-processes').checked = config.monitor_processes;
    document.getElementById('monitor-network').checked = config.monitor_network;
    document.getElementById('monitor-files').checked = config.monitor_files;
    document.getElementById('monitor-logins').checked = config.monitor_logins;
    document.getElementById('cpu-threshold').value = config.process_cpu_threshold;
    document.getElementById('memory-threshold').value = config.process_mem_threshold;
    document.getElementById('monitoring-interval').value = config.monitoring_interval;
    document.getElementById('virustotal-api').value = config.virustotal_api_key === '***' ? '' : config.virustotal_api_key;
    document.getElementById('otx-api').value = config.otx_api_key === '***' ? '' : config.otx_api_key;
    document.getElementById('email-enabled').checked = config.email_enabled;
    document.getElementById('email-to').value = config.email_to;
    document.getElementById('email-from').value = config.email_from;
    document.getElementById('email-password').value = config.email_password === '***' ? '' : config.email_password;
}

// Save settings
async function saveSettings() {
    const config = {
        monitor_processes: document.getElementById('monitor-processes').checked,
        monitor_network: document.getElementById('monitor-network').checked,
        monitor_files: document.getElementById('monitor-files').checked,
        monitor_logins: document.getElementById('monitor-logins').checked,
        process_cpu_threshold: parseFloat(document.getElementById('cpu-threshold').value),
        process_mem_threshold: parseFloat(document.getElementById('memory-threshold').value),
        monitoring_interval: parseInt(document.getElementById('monitoring-interval').value),
        virustotal_api_key: document.getElementById('virustotal-api').value,
        otx_api_key: document.getElementById('otx-api').value,
        email_enabled: document.getElementById('email-enabled').checked,
        email_to: document.getElementById('email-to').value,
        email_from: document.getElementById('email-from').value,
        email_password: document.getElementById('email-password').value
    };
    
    try {
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        const result = await response.json();
        if (result.status === 'success') {
            showNotification({
                title: 'Settings Saved',
                message: 'Configuration has been updated successfully.',
                severity: 'low'
            });
        } else {
            throw new Error(result.message);
        }
    } catch (error) {
        console.error('Error saving settings:', error);
        showNotification({
            title: 'Error',
            message: 'Failed to save settings: ' + error.message,
            severity: 'high'
        });
    }
}

// Scan file
async function scanFile() {
    const filePath = document.getElementById('file-path').value;
    if (!filePath) {
        alert('Please enter a file path');
        return;
    }
    
    const resultsContainer = document.getElementById('scan-results');
    resultsContainer.innerHTML = '<div class="spinner"></div> Scanning...';
    
    try {
        const response = await fetch('/api/scan-file', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ file_path: filePath })
        });
        
        const result = await response.json();
        displayScanResults(result);
    } catch (error) {
        console.error('Error scanning file:', error);
        resultsContainer.innerHTML = '<p class="text-danger">Error scanning file.</p>';
    }
}

// Display scan results
function displayScanResults(result) {
    const container = document.getElementById('scan-results');
    
    if (result.error) {
        container.innerHTML = `<p class="text-danger">${result.error}</p>`;
        return;
    }
    
    const isThreat = result.is_malware || result.suspicious;
    const statusClass = isThreat ? 'text-danger' : 'text-success';
    const statusText = isThreat ? 'THREAT DETECTED' : 'Clean';
    
    container.innerHTML = `
        <div class="scan-result">
            <h6 class="${statusClass}">${statusText}</h6>
            <p><strong>File:</strong> ${result.file_path}</p>
            <p><strong>Size:</strong> ${result.file_size} bytes</p>
            <p><strong>Hash:</strong> ${result.file_hash}</p>
            ${result.virustotal_result ? `<p><strong>VirusTotal:</strong> ${result.virustotal_result}</p>` : ''}
            ${result.otx_result ? `<p><strong>OTX:</strong> ${result.otx_result}</p>` : ''}
        </div>
    `;
}

// Utility functions
function updateMonitoringStatus(status) {
    const statusElement = document.getElementById('monitoring-status');
    const toggleButton = document.getElementById('toggle-monitoring');
    
    if (status === 'started' || status === 'Connected') {
        statusElement.textContent = 'Protected';
        statusElement.className = 'badge bg-success';
        toggleButton.innerHTML = '<i class="fas fa-power-off"></i>';
    } else {
        statusElement.textContent = 'Stopped';
        statusElement.className = 'badge bg-danger';
        toggleButton.innerHTML = '<i class="fas fa-play"></i>';
    }
}

function showNotification(alert) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'info'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 70px; right: 20px; z-index: 9999; min-width: 300px;';
    
    notification.innerHTML = `
        <strong>${alert.title || 'Alert'}</strong><br>
        ${alert.message || alert.description}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function refreshSystemInfo() {
    loadSystemInfo();
}

function refreshLogs() {
    loadLogs();
}

function scanSystem() {
    showNotification({
        title: 'System Scan',
        message: 'Quick system scan initiated.',
        severity: 'low'
    });
}

function updateDashboard() {
    if (currentTab === 'dashboard') {
        // Dashboard updates are handled by socket events
    }
}

function updateCharts(period) {
    // Implementation for different time periods
    console.log('Updating charts for period:', period);
}

// Filter alerts
document.addEventListener('change', function(e) {
    if (e.target.id === 'alert-filter') {
        displayAlerts();
    }
});
