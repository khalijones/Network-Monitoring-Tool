"""
Network Monitoring Tool - CLI Interface
Rich terminal interface for device discovery, monitoring, and alerting.
"""
import click
import json
import yaml
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich import box
from datetime import datetime

from .snmp_manager import SNMPManager, SNMPConfig
from .discovery import NetworkDiscovery, DiscoveredDevice
from .health_monitor import HealthMonitor, AlertManager, AlertSeverity
from .alert_channels import WebhookNotifier, WebhookConfig, EmailNotifier, EmailConfig


console = Console()


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration from YAML file."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        console.print(f"[red]Config file not found: {config_path}[/red]")
        return {}


@click.group()
@click.option("--config", "-c", default="config/config.yaml", help="Path to config file")
@click.pass_context
def cli(ctx, config):
    """Network Monitoring Tool - Automated discovery, health checks, and alerting."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)
    ctx.obj["alert_manager"] = AlertManager()


@cli.command()
@click.option("--subnet", "-s", multiple=True, help="Subnet to scan (e.g., 192.168.1.0/24)")
@click.option("--quick", "-q", help="Quick scan IP range (e.g., 192.168.1.1-254)")
@click.option("--output", "-o", type=click.Path(), help="Save results to file")
@click.pass_context
def discover(ctx, subnet, quick, output):
    """Discover network devices via ping sweep and SNMP."""
    config = ctx.obj["config"]

    if quick:
        # Quick scan mode
        console.print(Panel(f"[bold cyan]Quick Scan: {quick}[/bold cyan]", box=box.ROUNDED))
        discovery = NetworkDiscovery(
            subnets=["192.168.1.0/24"],  # placeholder
            snmp_community=config.get("network", {}).get("discovery", {}).get("snmp_community", "public")
        )
        devices = discovery.quick_scan(quick)
    else:
        # Full discovery mode
        subnets = list(subnet) if subnet else config.get("network", {}).get("discovery", {}).get("subnets", [])
        if not subnets:
            console.print("[red]No subnets specified. Use --subnet or configure in config.yaml[/red]")
            return

        console.print(Panel(f"[bold cyan]Network Discovery[/bold cyan]
Subnets: {', '.join(subnets)}", box=box.ROUNDED))

        discovery_config = config.get("network", {}).get("discovery", {})
        discovery = NetworkDiscovery(
            subnets=subnets,
            ping_timeout=discovery_config.get("ping_timeout", 2),
            ping_count=discovery_config.get("ping_count", 2),
            snmp_community=discovery_config.get("snmp_community", "public"),
            snmp_port=discovery_config.get("snmp_port", 161)
        )
        devices = discovery.discover()

    # Display results
    if not devices:
        console.print("[yellow]No devices discovered.[/yellow]")
        return

    table = Table(
        title=f"Discovered Devices ({len(devices)})",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("IP Address", style="cyan")
    table.add_column("Hostname")
    table.add_column("Status", justify="center")
    table.add_column("SNMP", justify="center")
    table.add_column("Type")
    table.add_column("CPU", justify="right")
    table.add_column("Memory", justify="right")
    table.add_column("Interfaces", justify="right")

    for device in devices:
        status = "[green]● Up[/green]" if device.is_reachable else "[red]● Down[/red]"
        snmp_status = "[green]✓[/green]" if device.snmp_reachable else "[red]✗[/red]"
        cpu = f"{device.cpu_usage}%" if device.cpu_usage else "N/A"
        mem = f"{device.memory_usage['percent_used']}%" if device.memory_usage else "N/A"

        table.add_row(
            device.ip_address,
            device.hostname or "N/A",
            status,
            snmp_status,
            device.device_type,
            cpu,
            mem,
            str(len(device.interfaces))
        )

    console.print(table)

    # Save to file if requested
    if output:
        results = [d.to_dict() for d in devices]
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output}[/green]")


@cli.command()
@click.argument("ip")
@click.option("--community", "-c", default="public", help="SNMP community string")
@click.pass_context
def inspect(ctx, ip, community):
    """Inspect a specific device via SNMP."""
    console.print(Panel(f"[bold cyan]Device Inspection: {ip}[/bold cyan]", box=box.ROUNDED))

    config = SNMPConfig(host=ip, community=community)
    snmp = SNMPManager(config)

    if not snmp.is_reachable():
        console.print(f"[red]Device {ip} is not SNMP-reachable.[/red]")
        return

    # System info
    sys_info = snmp.get_system_info()
    console.print("[bold]System Information:[/bold]")
    for key, value in sys_info.items():
        console.print(f"  [dim]{key}:[/dim] {value}")

    # CPU
    cpu = snmp.get_cpu_usage()
    if cpu:
        color = "green" if cpu < 50 else "yellow" if cpu < 80 else "red"
        console.print(f"\n[bold]CPU Usage:[/bold] [{color}]{cpu}%[/{color}]")

    # Memory
    mem = snmp.get_memory_usage()
    if mem:
        color = "green" if mem["percent_used"] < 50 else "yellow" if mem["percent_used"] < 80 else "red"
        console.print(f"[bold]Memory:[/bold] [{color}]{mem['percent_used']}%[/{color}] ({mem['used']}/{mem['total']} bytes)")

    # Interfaces
    interfaces = snmp.get_interfaces()
    console.print(f"\n[bold]Interfaces ({len(interfaces)}):[/bold]")

    iface_table = Table(box=box.SIMPLE)
    iface_table.add_column("Index", justify="right")
    iface_table.add_column("Description")
    iface_table.add_column("Admin", justify="center")
    iface_table.add_column("Oper", justify="center")
    iface_table.add_column("Speed")

    for iface in interfaces[:20]:  # Show first 20
        admin_color = "green" if iface["admin_status"] == "up" else "red"
        oper_color = "green" if iface["oper_status"] == "up" else "red"
        speed = f"{iface['speed'] / 1_000_000:.0f} Mbps" if iface["speed"] > 0 else "N/A"

        iface_table.add_row(
            str(iface["index"]),
            iface["description"],
            f"[{admin_color}]{iface['admin_status']}[/{admin_color}]",
            f"[{oper_color}]{iface['oper_status']}[/{oper_color}]",
            speed
        )

    console.print(iface_table)


@cli.command()
@click.option("--interval", "-i", default=60, help="Check interval in seconds")
@click.option("--duration", "-d", type=int, help="Monitoring duration in seconds")
@click.option("--device", "-D", multiple=True, help="Specific devices to monitor")
@click.pass_context
def monitor(ctx, interval, duration, device):
    """Start continuous health monitoring."""
    config = ctx.obj["config"]
    alert_manager = ctx.obj["alert_manager"]

    # Setup alert channels from config
    alerting_config = config.get("alerting", {})
    if alerting_config.get("enabled", False):
        for channel in alerting_config.get("channels", []):
            if channel["type"] == "webhook":
                notifier = WebhookNotifier(WebhookConfig(
                    url=channel["url"],
                    format=channel.get("format", "slack")
                ))
                alert_manager.add_callback(notifier.send)
            elif channel["type"] == "email":
                email_config = EmailConfig(
                    smtp_host=channel["smtp_host"],
                    smtp_port=channel["smtp_port"],
                    username=channel["username"],
                    password=channel["password"],
                    to_addresses=channel["to_addresses"]
                )
                notifier = EmailNotifier(email_config)
                alert_manager.add_callback(notifier.send)

    monitor = HealthMonitor(
        alert_manager=alert_manager,
        snmp_community=config.get("network", {}).get("discovery", {}).get("snmp_community", "public"),
        check_interval=interval
    )

    # Add devices to monitor
    if device:
        for ip in device:
            from .discovery import DiscoveredDevice
            monitor.add_device(DiscoveredDevice(ip_address=ip, is_reachable=True, snmp_reachable=True))
    else:
        # Discover devices first
        console.print("[yellow]No devices specified. Running discovery first...[/yellow]")
        subnets = config.get("network", {}).get("discovery", {}).get("subnets", ["192.168.1.0/24"])
        discovery = NetworkDiscovery(subnets=subnets)
        devices = discovery.discover()
        for d in devices:
            if d.snmp_reachable:
                monitor.add_device(d)
        console.print(f"[green]Added {len(monitor._monitored_devices)} devices to monitoring.[/green]")

    if not monitor._monitored_devices:
        console.print("[red]No SNMP-enabled devices to monitor.[/red]")
        return

    console.print(Panel(
        f"[bold green]Starting Health Monitor[/bold green]\n"
        f"Interval: {interval}s | Devices: {len(monitor._monitored_devices)}",
        box=box.ROUNDED
    ))

    monitor.start_monitoring()

    try:
        import time
        start_time = time.time()
        while True:
            if duration and (time.time() - start_time) >= duration:
                break

            # Display current status
            latest = monitor.get_latest_metrics()
            alerts = alert_manager.get_active_alerts()

            console.clear()

            # Metrics table
            metrics_table = Table(title="Device Health Metrics", box=box.ROUNDED)
            metrics_table.add_column("Device")
            metrics_table.add_column("CPU", justify="right")
            metrics_table.add_column("Memory", justify="right")
            metrics_table.add_column("Status")

            for ip, data in latest.items():
                metrics = data.get("metrics", {})
                cpu = metrics.get("cpu_usage", {})
                mem = metrics.get("memory_usage", {})

                cpu_str = f"{cpu.get('value', 'N/A')}{cpu.get('unit', '')}" if cpu else "N/A"
                mem_str = f"{mem.get('value', 'N/A')}{mem.get('unit', '')}" if mem else "N/A"

                cpu_color = "green" if cpu and cpu.get("value", 0) < 50 else "yellow" if cpu and cpu.get("value", 0) < 80 else "red"
                mem_color = "green" if mem and mem.get("value", 0) < 50 else "yellow" if mem and mem.get("value", 0) < 80 else "red"

                status = "[green]Healthy[/green]"
                if any(m.get("status") == "critical" for m in metrics.values()):
                    status = "[red]Critical[/red]"
                elif any(m.get("status") == "warning" for m in metrics.values()):
                    status = "[yellow]Warning[/yellow]"

                metrics_table.add_row(
                    data["name"],
                    f"[{cpu_color}]{cpu_str}[/{cpu_color}]",
                    f"[{mem_color}]{mem_str}[/{mem_color}]",
                    status
                )

            console.print(metrics_table)

            # Active alerts
            if alerts:
                alert_table = Table(title=f"Active Alerts ({len(alerts)})", box=box.ROUNDED)
                alert_table.add_column("Time")
                alert_table.add_column("Device")
                alert_table.add_column("Metric")
                alert_table.add_column("Severity")
                alert_table.add_column("Message")

                for alert in alerts[-10:]:
                    sev_color = {"info": "blue", "warning": "yellow", "critical": "red"}.get(alert.severity.value, "white")
                    alert_table.add_row(
                        alert.timestamp.split("T")[1].split(".")[0],
                        alert.device_name,
                        alert.metric,
                        f"[{sev_color}]{alert.severity.value}[/{sev_color}]",
                        alert.message
                    )

                console.print(alert_table)

            console.print(f"\n[dim]Press Ctrl+C to stop | Next check in {interval}s[/dim]")
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor...[/yellow]")
    finally:
        monitor.stop_monitoring()

        # Summary
        all_alerts = alert_manager.get_all_alerts()
        console.print(Panel(
            f"[bold]Monitoring Summary[/bold]\n"
            f"Total Alerts: {len(all_alerts)}\n"
            f"Active Alerts: {len([a for a in all_alerts if not a.acknowledged])}",
            box=box.ROUNDED
        ))


@cli.command()
@click.pass_context
def alerts(ctx):
    """View and manage alerts."""
    alert_manager = ctx.obj["alert_manager"]
    all_alerts = alert_manager.get_all_alerts()

    if not all_alerts:
        console.print("[yellow]No alerts recorded.[/yellow]")
        return

    table = Table(title="Alert History", box=box.ROUNDED)
    table.add_column("#", justify="right")
    table.add_column("Time")
    table.add_column("Device")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_column("Severity")
    table.add_column("Status")

    for i, alert in enumerate(all_alerts):
        sev_color = {"info": "blue", "warning": "yellow", "critical": "red"}.get(alert.severity.value, "white")
        status = "[green]Ack[/green]" if alert.acknowledged else "[red]Active[/red]"
        table.add_row(
            str(i),
            alert.timestamp.split("T")[0],
            alert.device_name,
            alert.metric,
            str(alert.value),
            f"[{sev_color}]{alert.severity.value}[/{sev_color}]",
            status
        )

    console.print(table)


@cli.command()
@click.argument("ip")
@click.option("--community", "-c", default="public")
@click.option("--oid")
@click.pass_context
def snmp_get(ctx, ip, community, oid):
    """Perform SNMP GET on a specific OID."""
    config = SNMPConfig(host=ip, community=community)
    snmp = SNMPManager(config)

    if oid:
        result = snmp.get(oid)
        console.print(f"[bold]{oid}[/bold] = {result}")
    else:
        # Get system info by default
        info = snmp.get_system_info()
        for key, value in info.items():
            console.print(f"[bold]{key}:[/bold] {value}")


@cli.command()
@click.pass_context
def dashboard(ctx):
    """Launch the Flask web dashboard."""
    config = ctx.obj["config"]
    flask_config = config.get("flask", {})

    console.print(Panel(
        f"[bold green]Starting Flask Dashboard[/bold green]\n"
        f"URL: http://{flask_config.get('host', '0.0.0.0')}:{flask_config.get('port', 5000)}",
        box=box.ROUNDED
    ))

    from .web_dashboard import create_app
    app = create_app()
    app.run(
        host=flask_config.get("host", "0.0.0.0"),
        port=flask_config.get("port", 5000),
        debug=flask_config.get("debug", False)
    )


if __name__ == "__main__":
    cli()
