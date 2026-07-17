"""
Network Discovery Module
Discovers network devices using ping sweeps and SNMP queries.
"""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pythonping import ping
from rich.progress import Progress, SpinnerColumn, TextColumn

from .snmp_manager import SNMPManager, SNMPConfig


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""
    ip_address: str
    hostname: Optional[str] = None
    is_reachable: bool = False
    snmp_reachable: bool = False
    system_info: Dict[str, Any] = field(default_factory=dict)
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    cpu_usage: Optional[int] = None
    memory_usage: Optional[Dict[str, int]] = None
    last_seen: Optional[str] = None
    device_type: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "is_reachable": self.is_reachable,
            "snmp_reachable": self.snmp_reachable,
            "system_info": self.system_info,
            "interfaces_count": len(self.interfaces),
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "device_type": self.device_type,
        }


class NetworkDiscovery:
    """Discovers network devices via ping and SNMP."""

    def __init__(
        self,
        subnets: List[str],
        ping_timeout: int = 2,
        ping_count: int = 2,
        snmp_community: str = "public",
        snmp_port: int = 161,
        max_workers: int = 50
    ):
        self.subnets = [ipaddress.ip_network(s, strict=False) for s in subnets]
        self.ping_timeout = ping_timeout
        self.ping_count = ping_count
        self.snmp_community = snmp_community
        self.snmp_port = snmp_port
        self.max_workers = max_workers

    def _ping_host(self, ip: str) -> bool:
        """Check if host is reachable via ICMP ping."""
        try:
            response = ping(ip, count=self.ping_count, timeout=self.ping_timeout)
            return response.success()
        except Exception:
            return False

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    def _probe_snmp(self, ip: str) -> Optional[DiscoveredDevice]:
        """Probe device via SNMP and gather info."""
        config = SNMPConfig(
            host=ip,
            community=self.snmp_community,
            port=self.snmp_port
        )
        snmp = SNMPManager(config)

        if not snmp.is_reachable():
            return None

        device = DiscoveredDevice(
            ip_address=ip,
            is_reachable=True,
            snmp_reachable=True
        )

        # Get system info
        device.system_info = snmp.get_system_info()
        device.hostname = device.system_info.get("name")

        # Get interfaces
        device.interfaces = snmp.get_interfaces()

        # Get CPU usage
        device.cpu_usage = snmp.get_cpu_usage()

        # Get memory usage
        device.memory_usage = snmp.get_memory_usage()

        # Determine device type from sysObjectID
        obj_id = device.system_info.get("object_id", "")
        if "cisco" in obj_id.lower() or "9.1" in obj_id:
            device.device_type = "cisco_router_switch"
        elif "juniper" in obj_id.lower():
            device.device_type = "juniper"
        elif "hp" in obj_id.lower() or "hewlett" in obj_id.lower():
            device.device_type = "hp"

        return device

    def discover(self, progress_callback=None) -> List[DiscoveredDevice]:
        """
        Run full network discovery.

        Phase 1: Ping sweep to find live hosts
        Phase 2: SNMP probe live hosts for detailed info
        """
        # Generate all IPs
        all_ips = []
        for subnet in self.subnets:
            all_ips.extend([str(ip) for ip in subnet.hosts()])

        live_hosts = []
        discovered_devices = []

        # Phase 1: Ping sweep
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(all_ips)} hosts...",
                total=len(all_ips)
            )

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {
                    executor.submit(self._ping_host, ip): ip 
                    for ip in all_ips
                }
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            live_hosts.append(ip)
                    except Exception:
                        pass
                    progress.advance(task)

        if progress_callback:
            progress_callback(f"Found {len(live_hosts)} live hosts")

        # Phase 2: SNMP probing
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(
                f"[green]Probing {len(live_hosts)} hosts via SNMP...",
                total=len(live_hosts)
            )

            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {
                    executor.submit(self._probe_snmp, ip): ip 
                    for ip in live_hosts
                }
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        device = future.result()
                        if device:
                            discovered_devices.append(device)
                        else:
                            # Host is up but no SNMP - add basic entry
                            hostname = self._resolve_hostname(ip)
                            discovered_devices.append(DiscoveredDevice(
                                ip_address=ip,
                                hostname=hostname,
                                is_reachable=True,
                                snmp_reachable=False
                            ))
                    except Exception:
                        pass
                    progress.advance(task)

        return discovered_devices

    def quick_scan(self, ip_range: str) -> List[DiscoveredDevice]:
        """Quick scan a specific IP range (e.g., '192.168.1.1-254')."""
        if "-" in ip_range:
            base, end = ip_range.rsplit(".", 1)[0], ip_range.split("-")
            start_ip = int(end[0].split(".")[-1])
            end_ip = int(end[1])
            ips = [f"{base}.{i}" for i in range(start_ip, end_ip + 1)]
        else:
            ips = [ip_range]

        devices = []
        for ip in ips:
            device = self._probe_snmp(ip)
            if device:
                devices.append(device)
            elif self._ping_host(ip):
                devices.append(DiscoveredDevice(
                    ip_address=ip,
                    is_reachable=True,
                    snmp_reachable=False
                ))

        return devices
