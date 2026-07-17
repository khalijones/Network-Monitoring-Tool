"""
Alert Notification Channels
Supports webhook (Slack/Teams) and email notifications.
"""
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .health_monitor import Alert, AlertSeverity


@dataclass
class WebhookConfig:
    url: str
    format: str = "slack"  # slack, teams, generic
    headers: Optional[Dict[str, str]] = None


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    to_addresses: list
    from_address: Optional[str] = None
    use_tls: bool = True


class WebhookNotifier:
    """Sends alerts to webhook endpoints."""

    def __init__(self, config: WebhookConfig):
        self.config = config

    def _format_slack(self, alert: Alert) -> Dict[str, Any]:
        color = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.WARNING: "#ff9900",
            AlertSeverity.CRITICAL: "#ff0000"
        }.get(alert.severity, "#808080")

        return {
            "attachments": [{
                "color": color,
                "title": f"🚨 Network Alert: {alert.severity.value.upper()}",
                "fields": [
                    {"title": "Device", "value": f"{alert.device_name} ({alert.device_ip})", "short": True},
                    {"title": "Metric", "value": alert.metric, "short": True},
                    {"title": "Value", "value": str(alert.value), "short": True},
                    {"title": "Threshold", "value": str(alert.threshold), "short": True},
                    {"title": "Time", "value": alert.timestamp, "short": False},
                    {"title": "Message", "value": alert.message, "short": False}
                ],
                "footer": "Network Monitoring Tool",
                "ts": alert.timestamp
            }]
        }

    def _format_teams(self, alert: Alert) -> Dict[str, Any]:
        color = {
            AlertSeverity.INFO: "36a64f",
            AlertSeverity.WARNING: "ff9900",
            AlertSeverity.CRITICAL: "ff0000"
        }.get(alert.severity, "808080")

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": f"Network Alert: {alert.severity.value.upper()}",
            "sections": [{
                "activityTitle": f"🚨 {alert.severity.value.upper()} Alert",
                "facts": [
                    {"name": "Device", "value": f"{alert.device_name} ({alert.device_ip})"},
                    {"name": "Metric", "value": alert.metric},
                    {"name": "Value", "value": str(alert.value)},
                    {"name": "Threshold", "value": str(alert.threshold)},
                    {"name": "Time", "value": alert.timestamp},
                    {"name": "Message", "value": alert.message}
                ]
            }]
        }

    def send(self, alert: Alert) -> bool:
        """Send alert to webhook."""
        try:
            if self.config.format == "slack":
                payload = self._format_slack(alert)
            elif self.config.format == "teams":
                payload = self._format_teams(alert)
            else:
                payload = alert.to_dict()

            headers = self.config.headers or {"Content-Type": "application/json"}
            response = requests.post(
                self.config.url,
                json=payload,
                headers=headers,
                timeout=10
            )
            return response.status_code in [200, 201, 204]
        except Exception as e:
            print(f"Webhook notification failed: {e}")
            return False


class EmailNotifier:
    """Sends alerts via email."""

    def __init__(self, config: EmailConfig):
        self.config = config

    def _format_body(self, alert: Alert) -> str:
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: {'#ff0000' if alert.severity == AlertSeverity.CRITICAL else '#ff9900' if alert.severity == AlertSeverity.WARNING else '#36a64f'};">
                🚨 Network Alert: {alert.severity.value.upper()}
            </h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Device</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.device_name} ({alert.device_ip})</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Metric</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.metric}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Value</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.value}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Threshold</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.threshold}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Time</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.timestamp}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Message</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{alert.message}</td></tr>
            </table>
            <p style="margin-top: 20px; color: #666; font-size: 12px;">
                Sent by Network Monitoring Tool
            </p>
        </body>
        </html>
        """

    def send(self, alert: Alert) -> bool:
        """Send alert via email."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{alert.severity.value.upper()}] Network Alert: {alert.metric}"
            msg["From"] = self.config.from_address or self.config.username
            msg["To"] = ", ".join(self.config.to_addresses)

            html_body = self._format_body(alert)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                if self.config.use_tls:
                    server.starttls()
                server.login(self.config.username, self.config.password)
                server.send_message(msg)

            return True
        except Exception as e:
            print(f"Email notification failed: {e}")
            return False
