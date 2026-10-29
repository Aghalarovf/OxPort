import socket
import struct

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "tftp"
PROTOCOL = "udp"

_OPCODE_RRQ = 1
_OPCODE_DATA = 3
_OPCODE_ERROR = 5
_PROBE_FILENAME = "oxport-anonymous-probe.txt"


def _build_rrq(filename: str) -> bytes:
    return struct.pack("!H", _OPCODE_RRQ) + filename.encode("ascii") + b"\x00" + b"octet" + b"\x00"


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.sendto(_build_rrq(_PROBE_FILENAME), (host, port))
        data, _ = sock.recvfrom(1024)
    except socket.timeout:
        return no(SERVICE, host, port, PROTOCOL, "no response to unauthenticated read request")
    except OSError as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()

    if len(data) < 2:
        return no(SERVICE, host, port, PROTOCOL, "malformed response to unauthenticated read request")

    opcode = struct.unpack("!H", data[:2])[0]

    if opcode == _OPCODE_DATA:
        return ok(SERVICE, host, port, PROTOCOL, "server served file contents without any authentication")
    if opcode == _OPCODE_ERROR:
        code = struct.unpack("!H", data[2:4])[0] if len(data) >= 4 else -1
        message = data[4:-1].decode(errors="ignore") if len(data) > 4 else ""
        return ok(SERVICE, host, port, PROTOCOL, f"server answered without authentication (error code={code}, message={message!r}); TFTP has no built-in access control")

    return no(SERVICE, host, port, PROTOCOL, f"unexpected opcode {opcode} in response")
