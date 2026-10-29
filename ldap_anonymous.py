import socket

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "ldap"
PROTOCOL = "tcp"

_RESULT_CODE_NAMES = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
}


def _ber_length(value_len: int) -> bytes:
    if value_len < 0x80:
        return bytes([value_len])
    encoded = bytearray()
    remaining = value_len
    while remaining:
        encoded.insert(0, remaining & 0xFF)
        remaining >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _build_anonymous_bind_request(message_id: int = 1) -> bytes:
    version = _ber_tlv(0x02, bytes([3]))
    name = _ber_tlv(0x04, b"")
    simple_auth = _ber_tlv(0x80, b"")
    bind_request = _ber_tlv(0x60, version + name + simple_auth)
    msg_id = _ber_tlv(0x02, bytes([message_id]))
    return _ber_tlv(0x30, msg_id + bind_request)


def _read_ber_length(sock: socket.socket) -> int:
    first = _recv_exact(sock, 1)[0]
    if first < 0x80:
        return first
    num_bytes = first & 0x7F
    raw = _recv_exact(sock, num_bytes)
    length = 0
    for byte in raw:
        length = (length << 8) | byte
    return length


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading bind response")
        buf += chunk
    return buf


def _read_tlv(sock: socket.socket):
    tag = _recv_exact(sock, 1)[0]
    length = _read_ber_length(sock)
    value = _recv_exact(sock, length) if length else b""
    return tag, value


def _parse_bind_response(body: bytes) -> int:
    pos = 0
    tag = body[pos]
    pos += 1
    length_byte = body[pos]
    pos += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num_bytes = length_byte & 0x7F
        length = int.from_bytes(body[pos:pos + num_bytes], "big")
        pos += num_bytes
    return int.from_bytes(body[pos:pos + length], "big", signed=False) if length else 0


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        sock.sendall(_build_anonymous_bind_request())

        outer_tag, outer_value = _read_tlv(sock)
        if outer_tag != 0x30:
            return failed(SERVICE, host, port, PROTOCOL, f"unexpected top level tag 0x{outer_tag:02x} in LDAP response")

        cursor = 0
        msg_id_tag = outer_value[cursor]
        cursor += 1
        msg_id_len = outer_value[cursor]
        cursor += 1
        cursor += msg_id_len

        op_tag = outer_value[cursor]
        if op_tag != 0x61:
            return failed(SERVICE, host, port, PROTOCOL, f"expected bindResponse (0x61), got 0x{op_tag:02x}")

        result_code = _parse_bind_response(outer_value[cursor:])
        code_name = _RESULT_CODE_NAMES.get(result_code, str(result_code))

        if result_code == 0:
            return ok(SERVICE, host, port, PROTOCOL, "anonymous simple bind (empty DN, empty password) succeeded")

        return no(SERVICE, host, port, PROTOCOL, f"anonymous simple bind rejected, resultCode={result_code} ({code_name})")
    except (socket.timeout, ConnectionError, OSError, IndexError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
