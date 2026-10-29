import socket

from core.models import PortResult, PortState, Protocol

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def scan_port(ip: str, port: int, timeout_ms: int = 1000) -> PortResult:
    if SCAPY_AVAILABLE:
        return _scan_with_scapy(ip, port, timeout_ms)
    return _scan_with_socket(ip, port, timeout_ms)


def _scan_with_scapy(ip: str, port: int, timeout_ms: int) -> PortResult:
    conf.verb = 0
    packet = IP(dst=ip) / UDP(dport=port)
    response = sr1(packet, timeout=timeout_ms / 1000.0, verbose=0)

    if response is None:
        return PortResult(port=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)

    if response.haslayer(ICMP):
        icmp_type = int(response.getlayer(ICMP).type)
        icmp_code = int(response.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code == 3:
            return PortResult(port=port, protocol=Protocol.UDP, state=PortState.CLOSED)
        if icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
            return PortResult(port=port, protocol=Protocol.UDP, state=PortState.FILTERED)

    if response.haslayer(UDP):
        return PortResult(port=port, protocol=Protocol.UDP, state=PortState.OPEN)

    return PortResult(port=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)


def _scan_with_socket(ip: str, port: int, timeout_ms: int) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.sendto(b"", (ip, port))
        try:
            sock.recvfrom(1024)
            return PortResult(port=port, protocol=Protocol.UDP, state=PortState.OPEN)
        except socket.timeout:
            return PortResult(port=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)
        except ConnectionResetError:
            return PortResult(port=port, protocol=Protocol.UDP, state=PortState.CLOSED)
    except OSError:
        return PortResult(port=port, protocol=Protocol.UDP, state=PortState.FILTERED)
    finally:
        sock.close()
