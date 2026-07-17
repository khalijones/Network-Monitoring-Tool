"""
Network Monitoring Tool
Python-based CLI tool for automated network device discovery,
health checks, and alerting — leveraging CCNAv7 networking knowledge.
"""
__version__ = "1.0.0"
__author__ = "Network Engineer"

from .snmp_manager import SNMPManager, SNMPConfig
from .discovery import NetworkDiscovery, DiscoveredDevice
from .health_monitor import HealthMonitor, AlertManager, Alert, AlertSeverity
from .alert_channels import WebhookNotifier, EmailNotifier

__all__ = [
    "SNMPManager",
    "SNMPConfig", 
    "NetworkDiscovery",
    "DiscoveredDevice",
    "HealthMonitor",
    "AlertManager",
    "Alert",
    "AlertSeverity",
    "WebhookNotifier",
    "EmailNotifier",
]
