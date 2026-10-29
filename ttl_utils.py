from typing import Optional

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

_WINDOWS_RANGE = range(65, 128)
_LINUX_RANGE = range(1, 64)
_NETWORK_RANGE = range(129, 256)


def ttl_to_os(ttl: int) -> Optional[str]:
    if ttl == 127 or ttl == 128:
        return "Windows"
    if ttl == 63 or ttl == 64:
        return "Linux"
    if ttl in _WINDOWS_RANGE:
        return "Windows"
    if ttl in _LINUX_RANGE:
        return "Linux"
    if ttl in _NETWORK_RANGE:
        return "Network"
    return None


def get_tcp_ttl(ip: str, port: int, timeout_ms: int = 1000) -> Optional[int]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        conf.verb = 0
        response = sr1(
            IP(dst=ip) / TCP(dport=port, flags="S"),
            timeout=timeout_ms / 1000.0,
            verbose=0,
        )
        if response is not None and response.haslayer(TCP):
            return int(response.ttl)
    except Exception:
        pass
    return None
