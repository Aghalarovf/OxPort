import socket
import struct

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "nfs"
PROTOCOL = "tcp"

_RPC_VERSION = 2
_NFS_PROGRAM = 100003
_NFS_VERSION = 3
_NFS_PROC_NULL = 0
_AUTH_NONE = 0


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading RPC reply")
        buf += chunk
    return buf


def _build_null_call(xid: int) -> bytes:
    body = struct.pack(
        "!IIIIII",
        xid,
        0,
        _RPC_VERSION,
        _NFS_PROGRAM,
        _NFS_VERSION,
        _NFS_PROC_NULL,
    )
    body += struct.pack("!II", _AUTH_NONE, 0)
    body += struct.pack("!II", _AUTH_NONE, 0)
    record_marking = struct.pack("!I", 0x80000000 | len(body))
    return record_marking + body


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    xid = 0x4F58504F

    try:
        sock.connect((host, port))
        sock.sendall(_build_null_call(xid))

        fragment_header = _recv_exact(sock, 4)
        fragment_len = struct.unpack("!I", fragment_header)[0] & 0x7FFFFFFF
        reply = _recv_exact(sock, fragment_len)
    except (socket.timeout, ConnectionError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()

    if len(reply) < 24:
        return failed(SERVICE, host, port, PROTOCOL, "truncated RPC reply")

    reply_xid, msg_type, reply_stat = struct.unpack("!III", reply[0:12])

    if reply_xid != xid or msg_type != 1:
        return failed(SERVICE, host, port, PROTOCOL, "unexpected RPC reply header")

    if reply_stat != 0:
        return no(SERVICE, host, port, PROTOCOL, f"RPC call rejected before reaching the NFS procedure, reply_stat={reply_stat}")

    verf_flavor, verf_len = struct.unpack("!II", reply[12:20])
    cursor = 20 + verf_len
    if len(reply) < cursor + 4:
        return failed(SERVICE, host, port, PROTOCOL, "truncated RPC accepted-reply body")

    accept_stat = struct.unpack("!I", reply[cursor:cursor + 4])[0]

    if accept_stat == 0:
        return ok(SERVICE, host, port, PROTOCOL, "NFSPROC3_NULL accepted with AUTH_NONE (no credentials at all), the server processes unauthenticated RPC calls")

    return no(SERVICE, host, port, PROTOCOL, f"unauthenticated NULL call was not accepted, accept_stat={accept_stat}")
