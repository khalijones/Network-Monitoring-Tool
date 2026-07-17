Network Monitoring Tool

> Python-based CLI tool for automated network device discovery, health checks, and alerting — leveraging CCNAv7 networking knowledge.

Features

- Device Discovery: Automated ping sweeps and SNMP-based device enumeration across subnets
- Health Monitoring: Real-time CPU, memory, and interface status monitoring via SNMP
- Smart Alerting: Configurable thresholds with webhook (Slack/Teams) and email notifications
- Web Dashboard: Beautiful Flask-based real-time dashboard with dark theme
- CCNAv7 Compliant: Uses standard MIBs and OIDs from Cisco IOS
- Concurrent Scanning: Multi-threaded discovery for fast network sweeps
- Rich CLI: Beautiful terminal output with progress bars and color-coded status

Quick Start

Installation

```bash
git clone <repository-url>
cd network-monitoring-tool

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

-Install dependencies

pip install -r requirements.txt
```

Configuration

Edit `config/config.yaml` to match your network:

```yaml
network:
  discovery:
    subnets:
      - "192.168.1.0/24"
      - "10.0.0.0/24"
    snmp_community: "public"

alerting:
  enabled: true
  channels:
    - type: "webhook"
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      format: "slack"
```

Usage

```bash
python network_monitor.py discover

python network_monitor.py discover --quick 192.168.1.1-254

python network_monitor.py inspect 192.168.1.1

python network_monitor.py monitor

python network_monitor.py alerts

python network_monitor.py dashboard
```


License

MIT License — see LICENSE file for details.
