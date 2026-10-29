import socket
import time

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "telnet"
PROTOCOL = "tcp"

_IAC = 255
_WILL = 251
_WONT = 252
_DO = 253
_DONT = 254

_AUTH_KEYWORDS = (b"login:", b"username:", b"user:", b"password:")
_SHELL_HINTS = (b"$", b"#", b">", b"welcome", b"busybox", b"shell")


def _strip_negotiation(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == _IAC and i + 2 < len(data):
            i += 3
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def _read_available(sock: socket.socket, deadline: float) -> bytes:
    buf = b""
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(2048)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        sock.settimeout(max(0.1, deadline - time.monotonic()))
    return buf


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        banner = _read_available(sock, deadline)
        clean = _strip_negotiation(banner)

        try:
            sock.settimeout(max(0.2, timeout_ms / 1000.0 / 2))
            sock.sendall(b"\r\n")
            deadline2 = time.monotonic() + (timeout_ms / 1000.0)
            follow_up = _read_available(sock, deadline2)
            clean += _strip_negotiation(follow_up)
        except OSError:
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()

    lowered = clean.lower()

    if any(keyword in lowered for keyword in _AUTH_KEYWORDS):
        return no(SERVICE, host, port, PROTOCOL, "server presented a login/password prompt before granting a session")

    if any(hint in lowered for hint in _SHELL_HINTS):
        snippet = clean[:120].decode(errors="ignore").strip()
        return ok(SERVICE, host, port, PROTOCOL, f"server returned a session/prompt without requesting credentials, banner={snippet!r}")

    if not clean:
        return no(SERVICE, host, port, PROTOCOL, "no banner or prompt received to evaluate")

    snippet = clean[:120].decode(errors="ignore").strip()
    return no(SERVICE, host, port, PROTOCOL, f"inconclusive, no login prompt detected but no shell prompt either, banner={snippet!r}")
