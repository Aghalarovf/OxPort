from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"


class ScanTechnique(Enum):
    CONNECT = "connect"
    SYN = "syn"
    UDP = "udp"
    FIN = "fin"
    NULL = "null"
    XMAS = "xmas"
    ACK = "ack"


class DiscoveryMethod(Enum):
    ARP = "arp"
    ICMP = "icmp"
    TCP_PING = "tcp_ping"
    SKIPPED = "skipped"
    NONE = "none"


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    alive: bool = False
    discovery_method: DiscoveryMethod = DiscoveryMethod.NONE
    mac: Optional[str] = None
    ttl_observed: Optional[int] = None
    reason: Optional[str] = None
    os_hint: Optional[str] = None


@dataclass
class PortResult:
    port: int
    protocol: Protocol
    state: PortState
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class OSMatch:
    name: str
    confidence: float
    family: Optional[str] = None


@dataclass
class ScanResult:
    host: Host
    ports: List[PortResult] = field(default_factory=list)
    os_match: Optional[OSMatch] = None
    scan_duration_s: Optional[float] = None

    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]


@dataclass
class ScanProfile:
    name: str
    threads: int
    rate: int
    timeout_ms: int
    jitter_ms: int
    default_technique: ScanTechnique
    retries: int = 1

    @staticmethod
    def from_dict(name: str, data: Dict[str, Any]) -> "ScanProfile":
        return ScanProfile(
            name=name,
            threads=int(data.get("threads", 50)),
            rate=int(data.get("rate", 0)),
            timeout_ms=int(data.get("timeout_ms", 1000)),
            jitter_ms=int(data.get("jitter_ms", 0)),
            default_technique=ScanTechnique(data.get("default_technique", "connect")),
            retries=int(data.get("retries", 1)),
        )


@dataclass
class ScanConfig:
    targets_raw: List[str] = field(default_factory=list)
    exclude_raw: List[str] = field(default_factory=list)
    input_file: Optional[str] = None
    cidr: Optional[str] = None
    ip_range: Optional[str] = None

    ports: str = "1-1000"
    all_ports: bool = False
    os_profile: Optional[str] = None

    techniques: List[ScanTechnique] = field(default_factory=lambda: [ScanTechnique.CONNECT])

    use_arp: bool = False
    use_icmp: bool = False
    ping_only: bool = False
    skip_discovery: bool = False

    detect_version: bool = False
    detect_os: bool = False
    grab_banner: bool = False

    profile_name: str = "normal"
    threads: Optional[int] = None
    rate: Optional[int] = None

    output_file: Optional[str] = None
    output_format: str = "txt"
    verbose: bool = False
    live: bool = False
