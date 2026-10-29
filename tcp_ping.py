import socket
from typing import List, Optional

_COMMON_PROBE_PORTS = [80, 443, 22, 445, 3389]


def probe(ip: str, timeout_ms: int = 1000, probe_ports: List[int] = None) -> Optional[int]:
    ports = probe_ports or _COMMON_PROBE_PORTS

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_ms / 1000.0)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
        except OSError:
            continue
        finally:
            sock.close()

    return None
