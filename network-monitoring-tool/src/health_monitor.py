"""
Health Monitoring Module
Monitors device health metrics and triggers alerts on threshold breaches.
"""
import time
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading

from .snmp_manager import SNMPManager, SNMPConfig
from .discovery import DiscoveredDevice


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents a monitoring alert."""
    timestamp: str
    device_ip: str
    device_name: str
    metric: str
    value: Any
    threshold: Any
    severity: AlertSeverity
    message: str
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "device_ip": self.device_ip,
            "device_name": self.device_name,
            "metric": self.metric,
            "value": self.value,
            "threshold": self.threshold,
            "severity": self.severity.value,
            "message": self.message,
            "acknowledged": self.acknowledged,
        }


@dataclass
class HealthMetric:
    """Represents a health metric reading."""
    timestamp: str
    device_ip: str
    metric_name: str
    value: Any
    unit: str = ""
    status: str = "normal"  # normal, warning, critical


class AlertManager:
    """Manages alert generation and notification."""

    def __init__(self):
        self.alerts: List[Alert] = []
        self._callbacks: List[Callable[[Alert], None]] = []
        self._lock = threading.Lock()

    def add_callback(self, callback: Callable[[Alert], None]):
        """Add an alert callback (e.g., webhook, email)."""
        self._callbacks.append(callback)

    def create_alert(
        self,
        device: DiscoveredDevice,
        metric: str,
        value: Any,
        threshold: Any,
        severity: AlertSeverity,
        message: str
    ) -> Alert:
        """Create and dispatch an alert."""
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            device_ip=device.ip_address,
            device_name=device.hostname or device.ip_address,
            metric=metric,
            value=value,
            threshold=threshold,
            severity=severity,
            message=message
        )

        with self._lock:
            self.alerts.append(alert)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception:
                pass

        return alert

    def get_active_alerts(self) -> List[Alert]:
        """Get all unacknowledged alerts."""
        with self._lock:
            return [a for a in self.alerts if not a.acknowledged]

    def get_all_alerts(self) -> List[Alert]:
        """Get all alerts."""
        with self._lock:
            return self.alerts.copy()

    def acknowledge_alert(self, index: int):
        """Acknowledge an alert by index."""
        with self._lock:
            if 0 <= index < len(self.alerts):
                self.alerts[index].acknowledged = True

    def clear_alerts(self):
        """Clear all alerts."""
        with self._lock:
            self.alerts.clear()


class HealthMonitor:
    """Monitors device health metrics."""

    def __init__(
        self,
        alert_manager: AlertManager,
        snmp_community: str = "public",
        check_interval: int = 300
    ):
        self.alert_manager = alert_manager
        self.snmp_community = snmp_community
        self.check_interval = check_interval
        self.metrics_history: List[HealthMetric] = []
        self._monitored_devices: Dict[str, DiscoveredDevice] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def add_device(self, device: DiscoveredDevice):
        """Add a device to monitoring."""
        with self._lock:
            self._monitored_devices[device.ip_address] = device

    def remove_device(self, ip: str):
        """Remove a device from monitoring."""
        with self._lock:
            if ip in self._monitored_devices:
                del self._monitored_devices[ip]

    def check_device(self, device: DiscoveredDevice) -> List[HealthMetric]:
        """Check health metrics for a single device."""
        if not device.snmp_reachable:
            return []

        metrics = []
        config = SNMPConfig(
            host=device.ip_address,
            community=self.snmp_community
        )
        snmp = SNMPManager(config)
        timestamp = datetime.now().isoformat()

        # Check CPU
        cpu = snmp.get_cpu_usage()
        if cpu is not None:
            status = "normal"
            if cpu >= 90:
                status = "critical"
                self.alert_manager.create_alert(
                    device, "cpu_usage", cpu, 90,
                    AlertSeverity.CRITICAL,
                    f"CPU usage is {cpu}% (threshold: 90%)"
                )
            elif cpu >= 80:
                status = "warning"
                self.alert_manager.create_alert(
                    device, "cpu_usage", cpu, 80,
                    AlertSeverity.WARNING,
                    f"CPU usage is {cpu}% (threshold: 80%)"
                )

            metric = HealthMetric(
                timestamp=timestamp,
                device_ip=device.ip_address,
                metric_name="cpu_usage",
                value=cpu,
                unit="%",
                status=status
            )
            metrics.append(metric)

        # Check Memory
        mem = snmp.get_memory_usage()
        if mem is not None:
            status = "normal"
            if mem["percent_used"] >= 90:
                status = "critical"
                self.alert_manager.create_alert(
                    device, "memory_usage", mem["percent_used"], 90,
                    AlertSeverity.CRITICAL,
                    f"Memory usage is {mem['percent_used']}% (threshold: 90%)"
                )
            elif mem["percent_used"] >= 80:
                status = "warning"
                self.alert_manager.create_alert(
                    device, "memory_usage", mem["percent_used"], 80,
                    AlertSeverity.WARNING,
                    f"Memory usage is {mem['percent_used']}% (threshold: 80%)"
                )

            metric = HealthMetric(
                timestamp=timestamp,
                device_ip=device.ip_address,
                metric_name="memory_usage",
                value=mem["percent_used"],
                unit="%",
                status=status
            )
            metrics.append(metric)

        # Check Interface Status
        interfaces = snmp.get_interfaces()
        down_interfaces = [
            iface for iface in interfaces
            if iface["oper_status"] == "down" and iface["admin_status"] == "up"
        ]

        if down_interfaces:
            iface_names = ", ".join([i["description"] for i in down_interfaces[:3]])
            self.alert_manager.create_alert(
                device, "interface_down", len(down_interfaces), 0,
                AlertSeverity.CRITICAL,
                f"{len(down_interfaces)} interfaces down: {iface_names}"
            )

            metric = HealthMetric(
                timestamp=timestamp,
                device_ip=device.ip_address,
                metric_name="down_interfaces",
                value=len(down_interfaces),
                unit="count",
                status="critical"
            )
            metrics.append(metric)

        # Store metrics
        with self._lock:
            self.metrics_history.extend(metrics)
            # Keep last 10000 metrics
            if len(self.metrics_history) > 10000:
                self.metrics_history = self.metrics_history[-10000:]

        return metrics

    def run_check(self):
        """Run a single health check cycle."""
        with self._lock:
            devices = list(self._monitored_devices.values())

        all_metrics = []
        for device in devices:
            try:
                metrics = self.check_device(device)
                all_metrics.extend(metrics)
            except Exception as e:
                print(f"Error checking {device.ip_address}: {e}")

        return all_metrics

    def start_monitoring(self):
        """Start continuous monitoring in background thread."""
        self._running = True

        def monitor_loop():
            while self._running:
                self.run_check()
                time.sleep(self.check_interval)

        self._thread = threading.Thread(target=monitor_loop, daemon=True)
        self._thread.start()

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_device_metrics(self, ip: str, limit: int = 100) -> List[HealthMetric]:
        """Get metrics history for a specific device."""
        with self._lock:
            device_metrics = [
                m for m in self.metrics_history 
                if m.device_ip == ip
            ]
        return device_metrics[-limit:]

    def get_latest_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get latest metrics for all monitored devices."""
        result = {}
        with self._lock:
            for ip, device in self._monitored_devices.items():
                device_metrics = [
                    m for m in self.metrics_history 
                    if m.device_ip == ip
                ]
                if device_metrics:
                    latest = {}
                    for m in reversed(device_metrics):
                        if m.metric_name not in latest:
                            latest[m.metric_name] = {
                                "value": m.value,
                                "unit": m.unit,
                                "status": m.status,
                                "timestamp": m.timestamp
                            }
                    result[ip] = {
                        "name": device.hostname or ip,
                        "metrics": latest
                    }
        return result
