from core.models import PortResult, PortState, Protocol, ScanTechnique

try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


_FLAGS_MAP = {
    ScanTechnique.FIN: "F",
    ScanTechnique.NULL: "",
    ScanTechnique.XMAS: "FPU",
    ScanTechnique.ACK: "A",
}


def scan_port(ip: str, port: int, technique: ScanTechnique, timeout_ms: int = 1000) -> PortResult:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(f"scapy is required for {technique.value} scan, install it with: pip install scapy")

    if technique not in _FLAGS_MAP:
        raise ValueError(f"unsupported stealth technique: {technique}")

    conf.verb = 0
    flags = _FLAGS_MAP[technique]
    packet = IP(dst=ip) / TCP(dport=port, flags=flags)
    response = sr1(packet, timeout=timeout_ms / 1000.0, verbose=0)

    if technique == ScanTechnique.ACK:
        return _interpret_ack(response, port)
    return _interpret_closed_style(response, port)


def _interpret_closed_style(response, port: int) -> PortResult:
    if response is None:
        return PortResult(port=port, protocol=Protocol.TCP, state=PortState.OPEN_FILTERED)

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x14:
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.CLOSED)

    if response.haslayer("ICMP"):
        icmp_type = int(response.getlayer("ICMP").type)
        icmp_code = int(response.getlayer("ICMP").code)
        if icmp_type == 3 and icmp_code in (1, 2, 3, 9, 10, 13):
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    return PortResult(port=port, protocol=Protocol.TCP, state=PortState.OPEN_FILTERED)


def _interpret_ack(response, port: int) -> PortResult:
    if response is None:
        return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x04:
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.UNFILTERED)

    if response.haslayer("ICMP"):
        icmp_type = int(response.getlayer("ICMP").type)
        icmp_code = int(response.getlayer("ICMP").code)
        if icmp_type == 3 and icmp_code in (1, 2, 3, 9, 10, 13):
            return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)
