import socket

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "redis"
PROTOCOL = "tcp"

_NOAUTH_MARKERS = (b"-noauth", b"-err noauth", b"-err wrongpass", b"-err operation not permitted")


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        sock.sendall(b"PING\r\n")
        reply = sock.recv(512)

        try:
            sock.sendall(b"INFO server\r\n")
            info_reply = sock.recv(4096)
        except OSError:
            info_reply = b""
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()

    lowered = reply.lower()

    if lowered.startswith(b"+pong"):
        return ok(SERVICE, host, port, PROTOCOL, "PING succeeded without authentication, 'requirepass' is not enforced")

    if any(marker in lowered for marker in _NOAUTH_MARKERS):
        return no(SERVICE, host, port, PROTOCOL, f"server requires authentication: {reply[:120].decode(errors='ignore').strip()!r}")

    if info_reply:
        return ok(SERVICE, host, port, PROTOCOL, "server accepted commands without authentication")

    if not reply:
        return no(SERVICE, host, port, PROTOCOL, "no response to unauthenticated PING")

    return no(SERVICE, host, port, PROTOCOL, f"unexpected response to unauthenticated PING: {reply[:120].decode(errors='ignore').strip()!r}")
