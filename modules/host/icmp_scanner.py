import platform
import subprocess
from typing import Optional, Tuple

try:
    from scapy.all import IP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def probe(ip: str, timeout_ms: int = 1000) -> Tuple[bool, Optional[int]]:
    if SCAPY_AVAILABLE:
        return _probe_with_scapy(ip, timeout_ms)
    return _probe_with_subprocess(ip, timeout_ms)


def _probe_with_scapy(ip: str, timeout_ms: int) -> Tuple[bool, Optional[int]]:
    conf.verb = 0
    packet = IP(dst=ip) / ICMP()
    response = sr1(packet, timeout=timeout_ms / 1000.0, verbose=0)

    if response is None:
        return False, None

    ttl = int(response.ttl) if hasattr(response, "ttl") else None
    return True, ttl


def _probe_with_subprocess(ip: str, timeout_ms: int) -> Tuple[bool, Optional[int]]:
    system = platform.system().lower()
    timeout_s = max(1, round(timeout_ms / 1000))

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_s + 1)
        alive = result.returncode == 0
        return alive, None
    except (subprocess.TimeoutExpired, OSError):
        return False, None
