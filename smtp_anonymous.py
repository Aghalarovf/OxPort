import smtplib

from plugins.anonymous.base import AnonymousCheckResult, failed, no, ok

SERVICE = "smtp"
PROTOCOL = "tcp"

_PROBE_SENDER = "oxport-probe@oxport.local"
_PROBE_RECIPIENT = "oxport-relay-check@oxport-external-test.invalid"


def check(host: str, port: int, timeout_ms: int = 3000) -> AnonymousCheckResult:
    timeout_s = timeout_ms / 1000.0
    smtp = None

    try:
        smtp = smtplib.SMTP(timeout=timeout_s)
        code, banner = smtp.connect(host, port)
        smtp.ehlo_or_helo_if_needed()

        auth_required = "auth" in smtp.esmtp_features

        code, _ = smtp.mail(_PROBE_SENDER)
        if code >= 400:
            return no(SERVICE, host, port, PROTOCOL, f"MAIL FROM rejected without authentication (code={code})")

        code, message = smtp.rcpt(_PROBE_RECIPIENT)
        smtp.rset()

        if code in (250, 251):
            relay_note = "despite advertising AUTH support" if auth_required else "no AUTH advertised"
            return ok(SERVICE, host, port, PROTOCOL, f"RCPT TO an external domain accepted without authentication ({relay_note}), server may act as an open relay")

        return no(SERVICE, host, port, PROTOCOL, f"RCPT TO an external domain rejected (code={code}, message={message!r}), relaying is restricted")
    except (smtplib.SMTPException, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
