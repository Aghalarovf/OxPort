from typing import Optional, Tuple

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def probe(ip: str, timeout_ms: int = 1000) -> Tuple[bool, Optional[str]]:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for ARP discovery, install it with: pip install scapy")

    conf.verb = 0
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(request, timeout=timeout_ms / 1000.0, verbose=0)

    if answered:
        mac = answered[0][1].hwsrc
        return True, mac
    return False, None
