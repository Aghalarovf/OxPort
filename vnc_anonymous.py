import re
import socket
import struct

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "vnc"
PROTOCOL = "tcp"

_VERSION_RE = re.compile(rb"^RFB (\d{3})\.(\d{3})\n$")
_SECURITY_NONE = 1


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading handshake")
        buf += chunk
    return buf


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        server_version = _recv_exact(sock, 12)
        match = _VERSION_RE.match(server_version)
        if not match:
            return failed(SERVICE, host, port, PROTOCOL, f"unexpected protocol handshake: {server_version!r}")

        major, minor = int(match.group(1)), int(match.group(2))
        sock.sendall(server_version)

        if major == 3 and minor <= 3:
            raw = _recv_exact(sock, 4)
            security_type = struct.unpack("!I", raw)[0]
            if security_type == _SECURITY_NONE:
                return ok(SERVICE, host, port, PROTOCOL, f"server (RFB {major}.{minor}) selected security type 'None', no authentication required")
            if security_type == 0:
                reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                reason = _recv_exact(sock, reason_len).decode(errors="ignore") if reason_len else ""
                return failed(SERVICE, host, port, PROTOCOL, f"connection refused by server: {reason}")
            return no(SERVICE, host, port, PROTOCOL, f"server (RFB {major}.{minor}) requires security type {security_type}")

        count = _recv_exact(sock, 1)[0]
        if count == 0:
            reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
            reason = _recv_exact(sock, reason_len).decode(errors="ignore") if reason_len else ""
            return failed(SERVICE, host, port, PROTOCOL, f"connection refused by server: {reason}")

        types = _recv_exact(sock, count)
        if _SECURITY_NONE not in types:
            return no(SERVICE, host, port, PROTOCOL, f"server (RFB {major}.{minor}) only offers security type(s) {list(types)}, 'None' not available")

        sock.sendall(bytes([_SECURITY_NONE]))

        if major == 3 and minor >= 8:
            result = struct.unpack("!I", _recv_exact(sock, 4))[0]
            if result != 0:
                reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                reason = _recv_exact(sock, reason_len).decode(errors="ignore") if reason_len else ""
                return no(SERVICE, host, port, PROTOCOL, f"server rejected security type 'None' with result={result}, reason={reason!r}")

        return ok(SERVICE, host, port, PROTOCOL, f"server (RFB {major}.{minor}) accepted security type 'None', no authentication required")
    except (socket.timeout, ConnectionError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
