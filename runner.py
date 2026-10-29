from typing import List, Optional

from core.models import PortResult, PortState, Protocol, ScanResult
from plugins.anonymous import (
    ftp_anonymous,
    ldap_anonymous,
    nfs_anonymous,
    redis_anonymous,
    smb_anonymous,
    smtp_anonymous,
    snmp_anonymous,
    telnet_anonymous,
    tftp_anonymous,
    vnc_anonymous,
    x11_anonymous,
)
from plugins.anonymous.base import AnonymousCheckResult

MODULES = {
    "ftp": ftp_anonymous,
    "tftp": tftp_anonymous,
    "smb": smb_anonymous,
    "nfs": nfs_anonymous,
    "vnc": vnc_anonymous,
    "telnet": telnet_anonymous,
    "x11": x11_anonymous,
    "redis": redis_anonymous,
    "ldap": ldap_anonymous,
    "snmp": snmp_anonymous,
    "smtp": smtp_anonymous,
}

_SERVICE_NAME_TO_KEY = {
    "FTP": "ftp",
    "TFTP": "tftp",
    "SMB": "smb",
    "NETBIOS-SSN": "smb",
    "NFS": "nfs",
    "NFS-OR-IIS": "nfs",
    "VNC": "vnc",
    "TELNET": "telnet",
    "X11": "x11",
    "REDIS": "redis",
    "LDAP": "ldap",
    "LDAPS": "ldap",
    "SNMP": "snmp",
    "SMTP": "smtp",
    "SMTP-SUBMISSION": "smtp",
    "SMTPS": "smtp",
}

_PORT_FALLBACK = {
    21: "ftp",
    69: "tftp",
    139: "smb",
    445: "smb",
    2049: "nfs",
    23: "telnet",
    6379: "redis",
    389: "ldap",
    636: "ldap",
    161: "snmp",
    25: "smtp",
    465: "smtp",
    587: "smtp",
}


def _service_key_for_port(port_result: PortResult) -> Optional[str]:
    service_name = (port_result.service_name or "").upper()
    if service_name in _SERVICE_NAME_TO_KEY:
        return _SERVICE_NAME_TO_KEY[service_name]

    if service_name.startswith("VNC"):
        return "vnc"

    port = port_result.port

    if port in _PORT_FALLBACK:
        return _PORT_FALLBACK[port]

    if 5900 <= port <= 5999:
        return "vnc"
    if 6000 <= port <= 6063:
        return "x11"

    return None


def plan_checks(scan_results: List[ScanResult]):
    planned = []
    for scan_result in scan_results:
        if not scan_result.host.alive:
            continue
        for port_result in scan_result.open_ports():
            if port_result.protocol != Protocol.TCP and port_result.protocol != Protocol.UDP:
                continue
            service_key = _service_key_for_port(port_result)
            if service_key is None:
                continue
            planned.append((scan_result.host.ip, port_result, service_key))
    return planned


def run(scan_results: List[ScanResult], options: Optional[dict] = None, logger=None) -> List[AnonymousCheckResult]:
    options = options or {}
    raw_timeout = options.get("TIMEOUT", options.get("timeout", 3000))
    try:
        timeout_ms = int(raw_timeout)
    except (TypeError, ValueError):
        timeout_ms = 3000
    return run_anonymous_checks(scan_results, timeout_ms=timeout_ms, logger=logger)


def run_anonymous_checks(scan_results: List[ScanResult], timeout_ms: int = 3000,
                          logger=None) -> List[AnonymousCheckResult]:
    results: List[AnonymousCheckResult] = []
    planned = plan_checks(scan_results)

    if not planned:
        if logger:
            logger.info("Anonymous access testing requested but no matching open ports (ftp/tftp/smb/nfs/vnc/telnet/x11/redis/ldap/snmp/smtp) were found")
        return results

    if logger:
        logger.info(f"Running anonymous access checks on {len(planned)} open port(s)")

    for host_ip, port_result, service_key in planned:
        module = MODULES[service_key]
        if logger:
            logger.info(f"Testing anonymous access: {service_key} on {host_ip}:{port_result.port}")
        try:
            result = module.check(host_ip, port_result.port, timeout_ms)
        except Exception as exc:
            result = AnonymousCheckResult(
                service=service_key,
                host=host_ip,
                port=port_result.port,
                protocol=port_result.protocol.value,
                vulnerable=False,
                detail="check could not complete",
                error=str(exc),
            )
        results.append(result)

    return results
