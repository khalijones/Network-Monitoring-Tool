"""
SNMP Operations Module
Handles SNMP v1/v2c queries for device discovery and monitoring.
Based on CCNAv7 SNMP knowledge.
"""
from typing import Optional, Dict, List, Any, Tuple
import socket
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd,
    usmHMACMD5AuthProtocol, usmDESPrivProtocol,
    UsmUserData
)
from dataclasses import dataclass
from enum import Enum


class SNMPVersion(Enum):
    V1 = 0
    V2C = 1
    V3 = 3


@dataclass
class SNMPConfig:
    host: str
    community: str = "public"
    port: int = 161
    timeout: int = 3
    retries: int = 2
    version: SNMPVersion = SNMPVersion.V2C


class SNMPManager:
    """SNMP Manager for network device operations."""

    # Standard MIB OIDs
    OIDS = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysServices": "1.3.6.1.2.1.1.7.0",
        # Interface table
        "ifNumber": "1.3.6.1.2.1.2.1.0",
        "ifTable": "1.3.6.1.2.1.2.2.1",
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",
        "ifType": "1.3.6.1.2.1.2.2.1.3",
        "ifMtu": "1.3.6.1.2.1.2.2.1.4",
        "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
        "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
        "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
        "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
        "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
        "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
        # Cisco-specific OIDs
        "cisco_cpu_5sec": "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",
        "cisco_cpu_1min": "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1",
        "cisco_cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
        "cisco_mem_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
        "cisco_mem_free": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    }

    STATUS_MAP = {
        1: "up",
        2: "down",
        3: "testing",
        4: "unknown",
        5: "dormant",
        6: "notPresent",
        7: "lowerLayerDown"
    }

    def __init__(self, config: SNMPConfig):
        self.config = config
        self._engine = SnmpEngine()

    def _get_target(self) -> UdpTransportTarget:
        return UdpTransportTarget(
            (self.config.host, self.config.port),
            timeout=self.config.timeout,
            retries=self.config.retries
        )

    def _get_community(self) -> CommunityData:
        return CommunityData(
            self.config.community,
            mpModel=1 if self.config.version == SNMPVersion.V2C else 0
        )

    def get(self, oid: str) -> Optional[Any]:
        """Perform SNMP GET operation."""
        try:
            iterator = getCmd(
                self._engine,
                self._get_community(),
                self._get_target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            error_indication, error_status, error_index, var_binds = next(iterator)

            if error_indication:
                return None
            if error_status:
                return None

            for var_bind in var_binds:
                return var_bind[1]
            return None
        except Exception:
            return None

    def walk(self, oid: str) -> Dict[str, Any]:
        """Perform SNMP WALK operation."""
        results = {}
        try:
            for (error_indication, error_status, error_index, var_binds) in nextCmd(
                self._engine,
                self._get_community(),
                self._get_target(),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    results[str(var_bind[0])] = var_bind[1]
        except Exception:
            pass
        return results

    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information from device."""
        info = {}
        for key, oid in [
            ("description", self.OIDS["sysDescr"]),
            ("object_id", self.OIDS["sysObjectID"]),
            ("uptime", self.OIDS["sysUpTime"]),
            ("contact", self.OIDS["sysContact"]),
            ("name", self.OIDS["sysName"]),
            ("location", self.OIDS["sysLocation"]),
        ]:
            value = self.get(oid)
            if value is not None:
                info[key] = str(value)
        return info

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get interface information."""
        interfaces = []
        if_count = self.get(self.OIDS["ifNumber"])
        if not if_count:
            return interfaces

        # Walk interface table
        descriptions = self.walk(self.OIDS["ifDescr"])
        types = self.walk(self.OIDS["ifType"])
        speeds = self.walk(self.OIDS["ifSpeed"])
        admin_statuses = self.walk(self.OIDS["ifAdminStatus"])
        oper_statuses = self.walk(self.OIDS["ifOperStatus"])
        in_octets = self.walk(self.OIDS["ifInOctets"])
        out_octets = self.walk(self.OIDS["ifOutOctets"])

        # Parse index from OID
        for oid_str, descr in descriptions.items():
            idx = oid_str.split(".")[-1]
            interfaces.append({
                "index": int(idx),
                "description": str(descr),
                "type": int(types.get(f"{self.OIDS['ifType']}.{idx}", 0)),
                "speed": int(speeds.get(f"{self.OIDS['ifSpeed']}.{idx}", 0)),
                "admin_status": self.STATUS_MAP.get(
                    int(admin_statuses.get(f"{self.OIDS['ifAdminStatus']}.{idx}", 0)), "unknown"
                ),
                "oper_status": self.STATUS_MAP.get(
                    int(oper_statuses.get(f"{self.OIDS['ifOperStatus']}.{idx}", 0)), "unknown"
                ),
                "in_octets": int(in_octets.get(f"{self.OIDS['ifInOctets']}.{idx}", 0)),
                "out_octets": int(out_octets.get(f"{self.OIDS['ifOutOctets']}.{idx}", 0)),
            })

        return interfaces

    def get_cpu_usage(self) -> Optional[int]:
        """Get CPU usage percentage (Cisco-specific)."""
        cpu = self.get(self.OIDS["cisco_cpu_1min"])
        if cpu is not None:
            return int(cpu)
        return None

    def get_memory_usage(self) -> Optional[Dict[str, int]]:
        """Get memory usage (Cisco-specific)."""
        used = self.get(self.OIDS["cisco_mem_used"])
        free = self.get(self.OIDS["cisco_mem_free"])
        if used is not None and free is not None:
            used_val = int(used)
            free_val = int(free)
            total = used_val + free_val
            return {
                "used": used_val,
                "free": free_val,
                "total": total,
                "percent_used": round((used_val / total) * 100, 2) if total > 0 else 0
            }
        return None

    def is_reachable(self) -> bool:
        """Check if device is SNMP-reachable."""
        result = self.get(self.OIDS["sysDescr"])
        return result is not None
