import socket
import struct

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "smb"
PROTOCOL = "tcp"

_SMB_MAGIC = b"\xffSMB"
_CMD_NEGOTIATE = 0x72
_CMD_SESSION_SETUP_ANDX = 0x73

_STATUS_SUCCESS_NAMES = {0x00000000: "STATUS_SUCCESS"}
_STATUS_FAIL_NAMES = {
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC0000064: "STATUS_NO_SUCH_USER",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
}


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading SMB response")
        buf += chunk
    return buf


def _recv_nbss_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    length = int.from_bytes(header[1:4], "big")
    return _recv_exact(sock, length)


def _send_nbss_frame(sock: socket.socket, payload: bytes) -> None:
    header = bytes([0x00]) + len(payload).to_bytes(3, "big")
    sock.sendall(header + payload)


def _build_smb_header(command: int, mid: int, uid: int = 0, tid: int = 0) -> bytes:
    return struct.pack(
        "<4sBIBHH8sHHHHH",
        _SMB_MAGIC,
        command,
        0,
        0x18,
        0xC853,
        0,
        b"\x00" * 8,
        0,
        tid,
        0,
        uid,
        mid,
    )


def _build_negotiate_request() -> bytes:
    header = _build_smb_header(_CMD_NEGOTIATE, mid=1)
    dialect = b"\x02" + b"NT LM 0.12" + b"\x00"
    body = struct.pack("<BH", 0, len(dialect)) + dialect
    return header + body


def _build_session_setup_request() -> bytes:
    header = _build_smb_header(_CMD_SESSION_SETUP_ANDX, mid=2)
    account_name = b"\x00"
    primary_domain = b"\x00"
    native_os = b"oxport\x00"
    native_lanman = b"oxport\x00"
    data = account_name + primary_domain + native_os + native_lanman

    word_block = struct.pack(
        "<BBHHHHIHHIIH",
        0xFF, 0, 0,
        4356,
        50,
        1,
        0,
        0, 0,
        0,
        0x00000050,
        len(data),
    )
    body = bytes([13]) + word_block + data
    return header + body


def _status_from_header(frame: bytes) -> int:
    return struct.unpack("<I", frame[5:9])[0]


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))

        _send_nbss_frame(sock, _build_negotiate_request())
        negotiate_reply = _recv_nbss_frame(sock)

        if len(negotiate_reply) < 9 or negotiate_reply[:4] != _SMB_MAGIC:
            return failed(SERVICE, host, port, PROTOCOL, "server did not reply with a valid SMB1 negotiate response")

        negotiate_status = _status_from_header(negotiate_reply)
        if negotiate_status != 0:
            return failed(SERVICE, host, port, PROTOCOL, f"negotiate protocol rejected, status=0x{negotiate_status:08X}")

        _send_nbss_frame(sock, _build_session_setup_request())
        setup_reply = _recv_nbss_frame(sock)

        if len(setup_reply) < 9 or setup_reply[:4] != _SMB_MAGIC:
            return failed(SERVICE, host, port, PROTOCOL, "server did not reply with a valid SMB1 session setup response")

        setup_status = _status_from_header(setup_reply)

        if setup_status == 0:
            action = struct.unpack("<H", setup_reply[37:39])[0] if len(setup_reply) >= 39 else 0
            guest = bool(action & 0x0001)
            mode = "guest" if guest else "anonymous/null"
            return ok(SERVICE, host, port, PROTOCOL, f"session setup with empty username and empty password succeeded ({mode} session)")

        status_name = _STATUS_FAIL_NAMES.get(setup_status, f"0x{setup_status:08X}")
        return no(SERVICE, host, port, PROTOCOL, f"null session setup rejected, status={status_name}")
    except (socket.timeout, ConnectionError, OSError, struct.error) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
