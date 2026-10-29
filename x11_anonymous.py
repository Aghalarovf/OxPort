import socket
import struct

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "x11"
PROTOCOL = "tcp"

_FAILED = 0
_SUCCESS = 1
_AUTHENTICATE = 2


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading connection setup reply")
        buf += chunk
    return buf


def _build_setup_request() -> bytes:
    header = struct.pack("<ccHHHH2x", b"l", b"\x00", 11, 0, 0, 0)
    return header


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        sock.sendall(_build_setup_request())
        header = _recv_exact(sock, 8)
        status = header[0]
        reason_len = header[1]
        rest_len_words = struct.unpack("<H", header[6:8])[0]
        remaining = _recv_exact(sock, rest_len_words * 4) if rest_len_words else b""

        if status == _SUCCESS:
            return ok(SERVICE, host, port, PROTOCOL, "server accepted the connection with no authentication protocol supplied")
        if status == _AUTHENTICATE:
            return no(SERVICE, host, port, PROTOCOL, "server requires authentication (MIT-MAGIC-COOKIE-1 or similar) before granting a connection")

        reason = remaining[:reason_len].decode(errors="ignore") if reason_len else ""
        return no(SERVICE, host, port, PROTOCOL, f"server refused unauthenticated connection, reason={reason!r}")
    except (socket.timeout, ConnectionError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
