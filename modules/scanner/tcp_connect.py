import socket
import time

from core.models import PortResult, PortState, Protocol


def scan_port(ip: str, port: int, timeout_ms: int = 1000) -> PortResult:
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        result = sock.connect_ex((ip, port))
        elapsed_ms = (time.monotonic() - start) * 1000
        state = PortState.OPEN if result == 0 else PortState.CLOSED
        return PortResult(port=port, protocol=Protocol.TCP, state=state, response_time_ms=round(elapsed_ms, 2))
    except socket.timeout:
        elapsed_ms = (time.monotonic() - start) * 1000
        return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED, response_time_ms=round(elapsed_ms, 2))
    except OSError:
        return PortResult(port=port, protocol=Protocol.TCP, state=PortState.FILTERED)
    finally:
        sock.close()
