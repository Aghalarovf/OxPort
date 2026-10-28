from core.models import PortResult, PortState, Protocol

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def scan_port(ip: str, port: int, timeout_ms: int = 1000) -> PortResult:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for SYN scan, install it with: pip install scapy")

    conf.verb = 0
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout_ms / 1000.0, verbose=0)

    if response is None:
        return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:
            rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
            sr1(rst_packet, timeout=0.2, verbose=0)
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.OPEN)
        if flags == 0x14:
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.CLOSED)

    if response.haslayer("ICMP"):
        icmp_type = response.getlayer("ICMP").type
        icmp_code = response.getlayer("ICMP").code
        if int(icmp_type) == 3 and int(icmp_code) in (1, 2, 3, 9, 10, 13):
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)
