import ftplib

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "ftp"
PROTOCOL = "tcp"


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    timeout_s = timeout_ms / 1000.0
    ftp = ftplib.FTP(timeout=timeout_s)

    try:
        ftp.connect(host, port, timeout=timeout_s)
        welcome = ftp.getwelcome() or ""
        ftp.login("anonymous", "anonymous@oxport.local")
        listing = []
        try:
            ftp.retrlines("LIST", listing.append)
        except ftplib.error_perm:
            pass
        try:
            pwd = ftp.pwd()
        except ftplib.error_perm:
            pwd = "?"
        detail = f"anonymous login accepted, cwd={pwd}, {len(listing)} entries listed, banner={welcome!r}"
        return ok(SERVICE, host, port, PROTOCOL, detail)
    except ftplib.error_perm as exc:
        return no(SERVICE, host, port, PROTOCOL, f"anonymous login rejected: {exc}")
    except (*ftplib.all_errors, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        try:
            ftp.close()
        except Exception:
            pass
