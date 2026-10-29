import json
import os
import socket
from typing import Dict, Optional

_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "signatures", "port_name.json")

_cache: Optional[Dict[str, Dict[str, str]]] = None


def _load_signatures() -> Dict[str, Dict[str, str]]:
    global _cache
    if _cache is None:
        with open(_SIGNATURES_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def identify_service(port: int, protocol: str) -> Optional[str]:
    signatures = _load_signatures()
    protocol_table = signatures.get(protocol, {})
    service = protocol_table.get(str(port))

    if service:
        return service

    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None


def grab_banner(ip: str, port: int, timeout_ms: int = 1500) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((ip, port))

        probe = b""
        if port in (80, 8080, 8000, 8008, 8888):
            probe = b"HEAD / HTTP/1.0\r\n\r\n"

        if probe:
            sock.sendall(probe)

        data = sock.recv(1024)
        return data.decode(errors="ignore").strip() or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        sock.close()
