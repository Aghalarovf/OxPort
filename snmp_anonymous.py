import socket

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "snmp"
PROTOCOL = "udp"

_SYS_DESCR_OID = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])


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


def _ber_int(value: int) -> bytes:
    if value == 0:
        return _ber_tlv(0x02, b"\x00")
    encoded = bytearray()
    while value:
        encoded.insert(0, value & 0xFF)
        value >>= 8
    if encoded[0] & 0x80:
        encoded.insert(0, 0)
    return _ber_tlv(0x02, bytes(encoded))


def _build_get_request(community: bytes = b"public", request_id: int = 1234) -> bytes:
    oid = _ber_tlv(0x06, _SYS_DESCR_OID)
    null_value = _ber_tlv(0x05, b"")
    varbind = _ber_tlv(0x30, oid + null_value)
    varbind_list = _ber_tlv(0x30, varbind)

    pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbind_list
    pdu = _ber_tlv(0xA0, pdu_body)

    version = _ber_int(0)
    community_der = _ber_tlv(0x04, community)

    return _ber_tlv(0x30, version + community_der + pdu)


def _parse_len(data: bytes, pos: int):
    length_byte = data[pos]
    pos += 1
    if length_byte < 0x80:
        return length_byte, pos
    num_bytes = length_byte & 0x7F
    length = int.from_bytes(data[pos:pos + num_bytes], "big")
    pos += num_bytes
    return length, pos


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.sendto(_build_get_request(), (host, port))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return no(SERVICE, host, port, PROTOCOL, "no response to GetRequest using community string 'public'")
    except OSError as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()

    try:
        pos = 0
        if data[pos] != 0x30:
            return failed(SERVICE, host, port, PROTOCOL, "malformed SNMP response, missing outer SEQUENCE")
        pos += 1
        _, pos = _parse_len(data, pos)

        version_tag = data[pos]
        pos += 1
        version_len, pos = _parse_len(data, pos)
        pos += version_len

        community_tag = data[pos]
        pos += 1
        community_len, pos = _parse_len(data, pos)
        community_value = data[pos:pos + community_len]
        pos += community_len

        pdu_tag = data[pos]
        pos += 1
        pdu_len, pos = _parse_len(data, pos)

        if pdu_tag != 0xA2:
            return no(SERVICE, host, port, PROTOCOL, f"unexpected PDU type 0x{pdu_tag:02x} in response")

        request_id_tag = data[pos]
        pos += 1
        request_id_len, pos = _parse_len(data, pos)
        pos += request_id_len

        error_status_tag = data[pos]
        pos += 1
        error_status_len, pos = _parse_len(data, pos)
        error_status = int.from_bytes(data[pos:pos + error_status_len], "big", signed=False)
        pos += error_status_len

        if error_status == 0:
            return ok(SERVICE, host, port, PROTOCOL, f"GetRequest using community string {community_value.decode(errors='ignore')!r} answered successfully, read access granted without real authentication")

        return no(SERVICE, host, port, PROTOCOL, f"GetRequest rejected, error-status={error_status}")
    except (IndexError, ValueError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, f"could not parse response: {exc}")
