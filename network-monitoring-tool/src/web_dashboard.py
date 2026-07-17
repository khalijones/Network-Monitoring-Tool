"""
Flask Web Dashboard
Real-time web interface for network monitoring visualization.
"""
from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime
from typing import Dict, Any

from .discovery import NetworkDiscovery, DiscoveredDevice
from .health_monitor import HealthMonitor, AlertManager
from .snmp_manager import SNMPManager, SNMPConfig


def create_app() -> Flask:
    app = Flask(__name__)

    # Shared state (in production, use Redis or database)
    app.config["discovered_devices"] = []
    app.config["alert_manager"] = AlertManager()
    app.config["monitor"] = None

    @app.route("/")
    def index():
        """Main dashboard page."""
        return render_template("dashboard.html")

    @app.route("/api/devices")
    def api_devices():
        """Get discovered devices."""
        devices = app.config.get("discovered_devices", [])
        return jsonify([d.to_dict() for d in devices])

    @app.route("/api/devices/<ip>")
    def api_device_detail(ip):
        """Get detailed info for a specific device."""
        devices = app.config.get("discovered_devices", [])
        device = next((d for d in devices if d.ip_address == ip), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404

        return jsonify({
            "ip_address": device.ip_address,
            "hostname": device.hostname,
            "system_info": device.system_info,
            "interfaces": device.interfaces,
            "cpu_usage": device.cpu_usage,
            "memory_usage": device.memory_usage,
            "device_type": device.device_type,
        })

    @app.route("/api/alerts")
    def api_alerts():
        """Get all alerts."""
        alert_manager = app.config.get("alert_manager")
        if alert_manager:
            alerts = alert_manager.get_all_alerts()
            return jsonify([a.to_dict() for a in alerts])
        return jsonify([])

    @app.route("/api/alerts/active")
    def api_active_alerts():
        """Get active (unacknowledged) alerts."""
        alert_manager = app.config.get("alert_manager")
        if alert_manager:
            alerts = alert_manager.get_active_alerts()
            return jsonify([a.to_dict() for a in alerts])
        return jsonify([])

    @app.route("/api/metrics")
    def api_metrics():
        """Get latest health metrics."""
        monitor = app.config.get("monitor")
        if monitor:
            return jsonify(monitor.get_latest_metrics())
        return jsonify({})

    @app.route("/api/discover", methods=["POST"])
    def api_discover():
        """Trigger network discovery."""
        data = request.get_json() or {}
        subnets = data.get("subnets", ["192.168.1.0/24"])

        discovery = NetworkDiscovery(subnets=subnets)
        devices = discovery.discover()
        app.config["discovered_devices"] = devices

        # Auto-add SNMP devices to monitoring
        monitor = app.config.get("monitor")
        if monitor:
            for d in devices:
                if d.snmp_reachable:
                    monitor.add_device(d)

        return jsonify({
            "discovered": len(devices),
            "snmp_enabled": len([d for d in devices if d.snmp_reachable]),
            "devices": [d.to_dict() for d in devices]
        })

    @app.route("/api/health")
    def api_health():
        """System health check."""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "devices_tracked": len(app.config.get("discovered_devices", [])),
            "alerts_active": len(app.config.get("alert_manager", AlertManager()).get_active_alerts())
        })

    return app


# HTML Template (embedded for single-file deployment)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitoring Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.5rem;
            background: linear-gradient(90deg, #f472b6, #fb7185);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }
        .status-healthy { background: #064e3b; color: #34d399; }
        .status-warning { background: #451a03; color: #fbbf24; }
        .status-critical { background: #450a0a; color: #f87171; }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background: #1e293b;
            border-radius: 1rem;
            padding: 1.5rem;
            border: 1px solid #334155;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        .card-title {
            font-size: 0.875rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
        }
        .card-subtitle {
            font-size: 0.875rem;
            color: #64748b;
            margin-top: 0.5rem;
        }
        .devices-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .devices-table th {
            text-align: left;
            padding: 0.75rem 1rem;
            color: #94a3b8;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid #334155;
        }
        .devices-table td {
            padding: 1rem;
            border-bottom: 1px solid #1e293b;
        }
        .devices-table tr:hover td {
            background: #252f47;
        }
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-up { background: #064e3b; color: #34d399; }
        .badge-down { background: #450a0a; color: #f87171; }
        .badge-snmp { background: #1e3a5f; color: #60a5fa; }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #334155;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 0.5rem;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        .progress-green { background: linear-gradient(90deg, #10b981, #34d399); }
        .progress-yellow { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
        .progress-red { background: linear-gradient(90deg, #ef4444, #f87171); }
        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #ec4899, #f43f5e);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(236, 72, 153, 0.4);
        }
        .alerts-section {
            margin-top: 2rem;
        }
        .alert-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            background: #1e293b;
            border-radius: 0.75rem;
            margin-bottom: 0.75rem;
            border-left: 4px solid;
        }
        .alert-critical { border-left-color: #ef4444; }
        .alert-warning { border-left-color: #f59e0b; }
        .alert-info { border-left-color: #3b82f6; }
        .alert-icon {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-size: 1.25rem;
        }
        .alert-critical .alert-icon { background: #450a0a; }
        .alert-warning .alert-icon { background: #451a03; }
        .alert-info .alert-icon { background: #1e3a5f; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .live-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            margin-right: 0.5rem;
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔧 Network Monitoring Tool</h1>
            <span style="color: #64748b; font-size: 0.875rem;">Real-time device discovery & health monitoring</span>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span class="live-indicator"></span>
            <span id="status-badge" class="status-badge status-healthy">Healthy</span>
        </div>
    </div>

    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
            <h2 style="font-size: 1.25rem;">Dashboard Overview</h2>
            <button class="btn btn-primary" onclick="runDiscovery()">🚀 Run Discovery</button>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Total Devices</span>
                    <span style="font-size: 1.5rem;">🖥️</span>
                </div>
                <div class="card-value" id="total-devices">0</div>
                <div class="card-subtitle">Discovered network devices</div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">SNMP Enabled</span>
                    <span style="font-size: 1.5rem;">📡</span>
                </div>
                <div class="card-value" id="snmp-devices">0</div>
                <div class="card-subtitle">Devices with SNMP access</div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Active Alerts</span>
                    <span style="font-size: 1.5rem;">⚠️</span>
                </div>
                <div class="card-value" id="active-alerts">0</div>
                <div class="card-subtitle">Unacknowledged alerts</div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Avg CPU Usage</span>
                    <span style="font-size: 1.5rem;">💻</span>
                </div>
                <div class="card-value" id="avg-cpu">--</div>
                <div class="progress-bar">
                    <div class="progress-fill progress-green" id="cpu-bar" style="width: 0%"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 style="font-size: 1.125rem;">Discovered Devices</h3>
            </div>
            <table class="devices-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Status</th>
                        <th>SNMP</th>
                        <th>Type</th>
                        <th>CPU</th>
                        <th>Memory</th>
                    </tr>
                </thead>
                <tbody id="devices-tbody">
                    <tr>
                        <td colspan="7" style="text-align: center; color: #64748b; padding: 2rem;">
                            No devices discovered yet. Click "Run Discovery" to start.
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="alerts-section">
            <h3 style="font-size: 1.125rem; margin-bottom: 1rem;">Recent Alerts</h3>
            <div id="alerts-container">
                <div style="text-align: center; color: #64748b; padding: 2rem;">
                    No alerts to display
                </div>
            </div>
        </div>
    </div>

    <script>
        async function fetchData() {
            try {
                const [devicesRes, alertsRes, metricsRes, healthRes] = await Promise.all([
                    fetch('/api/devices'),
                    fetch('/api/alerts/active'),
                    fetch('/api/metrics'),
                    fetch('/api/health')
                ]);

                const devices = await devicesRes.json();
                const alerts = await alertsRes.json();
                const metrics = await metricsRes.json();
                const health = await healthRes.json();

                updateDashboard(devices, alerts, metrics, health);
            } catch (e) {
                console.error('Failed to fetch data:', e);
            }
        }

        function updateDashboard(devices, alerts, metrics, health) {
            // Update stats
            document.getElementById('total-devices').textContent = devices.length;
            document.getElementById('snmp-devices').textContent = devices.filter(d => d.snmp_reachable).length;
            document.getElementById('active-alerts').textContent = alerts.length;

            // Update status badge
            const statusBadge = document.getElementById('status-badge');
            if (alerts.some(a => a.severity === 'critical')) {
                statusBadge.className = 'status-badge status-critical';
                statusBadge.textContent = 'Critical';
            } else if (alerts.some(a => a.severity === 'warning')) {
                statusBadge.className = 'status-badge status-warning';
                statusBadge.textContent = 'Warning';
            } else {
                statusBadge.className = 'status-badge status-healthy';
                statusBadge.textContent = 'Healthy';
            }

            // Update CPU average
            const cpuValues = Object.values(metrics).map(m => m.metrics.cpu_usage?.value).filter(v => v !== undefined);
            const avgCpu = cpuValues.length > 0 ? Math.round(cpuValues.reduce((a, b) => a + b, 0) / cpuValues.length) : null;
            document.getElementById('avg-cpu').textContent = avgCpu !== null ? avgCpu + '%' : '--';
            const cpuBar = document.getElementById('cpu-bar');
            cpuBar.style.width = (avgCpu || 0) + '%';
            cpuBar.className = 'progress-fill ' + (avgCpu < 50 ? 'progress-green' : avgCpu < 80 ? 'progress-yellow' : 'progress-red');

            // Update devices table
            const tbody = document.getElementById('devices-tbody');
            if (devices.length > 0) {
                tbody.innerHTML = devices.map(d => `
                    <tr>
                        <td style="font-family: monospace; color: #60a5fa;">${d.ip_address}</td>
                        <td>${d.hostname || 'N/A'}</td>
                        <td><span class="badge ${d.is_reachable ? 'badge-up' : 'badge-down'}">${d.is_reachable ? 'Up' : 'Down'}</span></td>
                        <td><span class="badge badge-snmp">${d.snmp_reachable ? 'Yes' : 'No'}</span></td>
                        <td>${d.device_type}</td>
                        <td>${d.cpu_usage !== null ? d.cpu_usage + '%' : 'N/A'}</td>
                        <td>${d.memory_usage ? d.memory_usage.percent_used + '%' : 'N/A'}</td>
                    </tr>
                `).join('');
            }

            // Update alerts
            const alertsContainer = document.getElementById('alerts-container');
            if (alerts.length > 0) {
                alertsContainer.innerHTML = alerts.slice(0, 5).map(a => `
                    <div class="alert-item alert-${a.severity}">
                        <div class="alert-icon">${a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟡' : '🔵'}</div>
                        <div>
                            <div style="font-weight: 600; margin-bottom: 0.25rem;">${a.device_name} - ${a.metric}</div>
                            <div style="color: #94a3b8; font-size: 0.875rem;">${a.message}</div>
                            <div style="color: #64748b; font-size: 0.75rem; margin-top: 0.25rem;">${new Date(a.timestamp).toLocaleString()}</div>
                        </div>
                    </div>
                `).join('');
            }
        }

        async function runDiscovery() {
            const btn = document.querySelector('.btn-primary');
            btn.textContent = '🔍 Scanning...';
            btn.disabled = true;

            try {
                const res = await fetch('/api/discover', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subnets: ['192.168.1.0/24'] })
                });
                const data = await res.json();
                alert(`Discovered ${data.discovered} devices (${data.snmp_enabled} with SNMP)`);
                fetchData();
            } catch (e) {
                alert('Discovery failed: ' + e.message);
            } finally {
                btn.textContent = '🚀 Run Discovery';
                btn.disabled = false;
            }
        }

        // Initial load and polling
        fetchData();
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
"""

# Create templates directory and write HTML
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(templates_dir, exist_ok=True)

with open(os.path.join(templates_dir, "dashboard.html"), "w") as f:
    f.write(DASHBOARD_HTML)
