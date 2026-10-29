import csv
import json
import os
import sys
from typing import List, Optional, TextIO

from core.models import ScanResult
from core.os_profiles import classify_port

_BRIGHT_BLUE = "\033[94m"
_BRIGHT_ORANGE = "\033[38;5;208m"
_BRIGHT_GREEN = "\033[92m"
_LIGHT_BLUE = "\033[38;5;117m"
_BRIGHT_PINK = "\033[38;5;213m"
_DARK_PINK = "\033[38;5;162m"
_GRAY = "\033[38;5;244m"
_PURPLE = "\033[38;5;135m"
_RESET = "\033[0m"

_GUESS_COLOR_MAP = {
    "windows": _LIGHT_BLUE,
    "linux": _BRIGHT_PINK,
    "both": _PURPLE,
    "other": _GRAY,
}


def _colors_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{_RESET}"


_LIVE_TARGET_WIDTH = 16
_LIVE_PORT_WIDTH = 7
_LIVE_STATUS_WIDTH = 11


def _format_port_row(host_ip: str, port, target_width: int, port_width: int, status_width: int, colors: bool) -> Optional[str]:
    if port.state.value not in ("open", "open|filtered"):
        return None

    status = _STATUS_LABEL.get(port.state.value, port.state.value)
    guess = port.service_name or port.version or ""

    target_field = _colorize(f"{host_ip:<{target_width}}", _BRIGHT_BLUE, colors)
    port_field = _colorize(f"{port.port:<{port_width}}", _BRIGHT_ORANGE, colors)
    status_color = _BRIGHT_GREEN if port.state.value == "open" else None
    status_field = _colorize(f"{status:<{status_width}}", status_color, colors) if status_color else f"{status:<{status_width}}"

    os_class = classify_port(port.port, port.protocol.value)
    guess_field = _colorize(guess, _GUESS_COLOR_MAP[os_class], colors)

    return f"{target_field}{port_field}{status_field}{guess_field}"


def print_live_header(stream: TextIO = sys.stdout) -> None:
    header = f"{'TARGET':<{_LIVE_TARGET_WIDTH}}{'PORT':<{_LIVE_PORT_WIDTH}}{'STATUS':<{_LIVE_STATUS_WIDTH}}{'GUESS'}"
    stream.write(header + "\n")
    stream.flush()


def print_live_port(host_ip: str, port, stream: TextIO = sys.stdout) -> None:
    colors = _colors_enabled(stream)
    row = _format_port_row(host_ip, port, _LIVE_TARGET_WIDTH, _LIVE_PORT_WIDTH, _LIVE_STATUS_WIDTH, colors)
    if row is None:
        return
    stream.write(row + "\n")
    stream.flush()


_LIVE_HOST_TARGET_WIDTH = 16
_LIVE_HOST_STATUS_WIDTH = 11
_LIVE_HOST_TYPE_WIDTH = 8
_LIVE_HOST_OS_WIDTH = 10

_DISCOVERY_TYPE_LABEL = {
    "tcp_ping": "TCP",
    "arp": "ARP",
    "icmp": "ICMP",
    "skipped": "SKIPPED",
    "none": "NONE",
}


def print_live_hosts_header(stream: TextIO = sys.stdout) -> None:
    header = (
        f"{'TARGET':<{_LIVE_HOST_TARGET_WIDTH}}"
        f"{'STATUS':<{_LIVE_HOST_STATUS_WIDTH}}"
        f"{'TYPE':<{_LIVE_HOST_TYPE_WIDTH}}"
        f"{'OS':<{_LIVE_HOST_OS_WIDTH}}"
        f"REASON"
    )
    stream.write(header + "\n")
    stream.flush()


def print_live_host(host, stream: TextIO = sys.stdout) -> None:
    colors = _colors_enabled(stream)
    target_field = _colorize(f"{host.ip:<{_LIVE_HOST_TARGET_WIDTH}}", _BRIGHT_BLUE, colors)
    status_field = _colorize(f"{'LIVE':<{_LIVE_HOST_STATUS_WIDTH}}", _BRIGHT_GREEN, colors)
    type_label = _DISCOVERY_TYPE_LABEL.get(host.discovery_method.value, host.discovery_method.value.upper())
    type_field = _colorize(f"{type_label:<{_LIVE_HOST_TYPE_WIDTH}}", _BRIGHT_ORANGE, colors)
    os_label = host.os_hint or "-"
    os_color = (
        _LIGHT_BLUE if os_label == "Windows"
        else _BRIGHT_PINK if os_label == "Linux"
        else _DARK_PINK if os_label == "Network"
        else None
    )
    os_field = _colorize(f"{os_label:<{_LIVE_HOST_OS_WIDTH}}", os_color, colors) if os_color else f"{os_label:<{_LIVE_HOST_OS_WIDTH}}"
    reason_field = host.reason or ""
    stream.write(f"{target_field}{status_field}{type_field}{os_field}{reason_field}\n")
    stream.flush()


def print_staged_subnet_results(subnet_results, stream: TextIO = sys.stdout) -> None:
    for index, (subnet, hosts) in enumerate(subnet_results):
        if index > 0:
            stream.write("\n" * 4)

        stream.write(subnet + "\n")
        print_live_hosts_header(stream)
        for host in hosts:
            if host.alive:
                print_live_host(host, stream)

    stream.flush()


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "ip": result.host.ip,
        "hostname": result.host.hostname,
        "alive": result.host.alive,
        "discovery_method": result.host.discovery_method.value,
        "os_match": {
            "name": result.os_match.name,
            "confidence": result.os_match.confidence,
            "family": result.os_match.family,
        } if result.os_match else None,
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol.value,
                "state": p.state.value,
                "service": p.service_name,
                "version": p.version,
                "banner": p.banner,
                "response_time_ms": p.response_time_ms,
            }
            for p in result.ports
        ],
        "scan_duration_s": result.scan_duration_s,
    }


def export_json(results: List[ScanResult], stream: TextIO):
    data = [_result_to_dict(r) for r in results]
    json.dump(data, stream, indent=2)
    stream.write("\n")


def export_csv(results: List[ScanResult], stream: TextIO):
    writer = csv.writer(stream)
    writer.writerow(["ip", "hostname", "port", "protocol", "state", "service", "version", "banner"])
    for result in results:
        for p in result.ports:
            writer.writerow([
                result.host.ip,
                result.host.hostname or "",
                p.port,
                p.protocol.value,
                p.state.value,
                p.service_name or "",
                p.version or "",
                p.banner or "",
            ])


_STATUS_LABEL = {
    "open": "REACHABLE",
    "closed": "UNREACHABLE",
    "filtered": "NO-RESPONSE",
    "open|filtered": "UNCERTAIN",
    "unfiltered": "UNREACHABLE",
}


def export_txt(results: List[ScanResult], stream: TextIO):
    target_width = max([len("TARGET")] + [len(r.host.ip) for r in results]) + 2
    port_width = 7
    status_width = 11

    colors = _colors_enabled(stream)

    header = f"{'TARGET':<{target_width}}{'PORT':<{port_width}}{'STATUS':<{status_width}}{'GUESS'}"
    stream.write(header + "\n")

    row_count = 0
    for result in results:
        for p in sorted(result.ports, key=lambda x: x.port):
            row = _format_port_row(result.host.ip, p, target_width, port_width, status_width, colors)
            if row is None:
                continue
            stream.write(row + "\n")
            row_count += 1
            if p.banner:
                stream.write(f"{'':<{target_width}}{'':<{port_width}}banner: {p.banner}\n")

    if row_count == 0:
        stream.write("no reachable ports on any target\n")

    for result in results:
        if result.os_match:
            stream.write(f"\n{result.host.ip} os guess: {result.os_match.name} ({result.os_match.confidence:.0f}% confidence)\n")


def _port_to_template_dict(p) -> dict:
    return {
        "port": p.port,
        "protocol": p.protocol.value,
        "status": p.state.value,
        "service": p.service_name,
        "version": p.version,
        "banner": p.banner,
        "notes": None,
    }


def _host_to_template_entry(result: ScanResult, include_ports: bool) -> dict:
    host = result.host

    os_name = None
    if result.os_match:
        os_name = result.os_match.name
    elif host.os_hint:
        os_name = host.os_hint

    return {
        "host": host.ip,
        "ports": [_port_to_template_dict(p) for p in result.ports] if include_ports else [],
        "os": os_name,
        "type": host.discovery_method.value,
        "reason": host.reason,
        "notes": None,
    }


def export_template(results: List[ScanResult], stream: TextIO, template_meta: Optional[dict] = None) -> None:
    meta = template_meta or {}
    mode = meta.get("mode")
    port_scan = bool(meta.get("port_scan"))
    host_scan = bool(meta.get("host_scan"))

    alive_results = [r for r in results if r.host.alive]

    data = {
        "mode": mode,
        "threads": meta.get("threads"),
        "port_scan": port_scan,
        "host_scan": host_scan,
        "subnets": meta.get("subnets") or [],
        "hosts": [_host_to_template_entry(r, include_ports=port_scan) for r in alive_results],
    }

    json.dump(data, stream, indent=2)
    stream.write("\n")


_ANON_TARGET_WIDTH = 16
_ANON_PORT_WIDTH = 7
_ANON_SERVICE_WIDTH = 10
_ANON_STATUS_WIDTH = 14


def print_anonymous_results(results, stream: TextIO = sys.stdout) -> None:
    if not results:
        return

    colors = _colors_enabled(stream)

    header = (
        f"{'TARGET':<{_ANON_TARGET_WIDTH}}"
        f"{'PORT':<{_ANON_PORT_WIDTH}}"
        f"{'SERVICE':<{_ANON_SERVICE_WIDTH}}"
        f"{'RESULT':<{_ANON_STATUS_WIDTH}}DETAIL"
    )
    stream.write("\n" + header + "\n")

    for result in results:
        if result.error:
            status = "ERROR"
            status_color = None
        elif result.vulnerable:
            status = "ANONYMOUS"
            status_color = _BRIGHT_GREEN if colors else None
        else:
            status = "PROTECTED"
            status_color = None

        target_field = _colorize(f"{result.host:<{_ANON_TARGET_WIDTH}}", _BRIGHT_BLUE, colors)
        port_field = _colorize(f"{result.port:<{_ANON_PORT_WIDTH}}", _BRIGHT_ORANGE, colors)
        service_field = f"{result.service.upper():<{_ANON_SERVICE_WIDTH}}"
        status_text = f"{status:<{_ANON_STATUS_WIDTH}}"
        status_field = _colorize(status_text, status_color, colors) if status_color else status_text
        detail_field = result.error if result.error else result.detail

        stream.write(f"{target_field}{port_field}{service_field}{status_field}{detail_field}\n")

    stream.flush()


def export_multi(results: List[ScanResult], outputs: dict, template_meta: Optional[dict] = None) -> None:
    """outputs: {"normal": path_or_None, "json": ..., "csv": ...}

    Each requested path is written to independently (nmap -oN/-oJ/-oC style: any
    combination can be given at once). If nothing is requested, falls back to
    printing the normal (plain text) format to stdout, same as the old default.
    -oJ writes the structured template format (mode/threads/port_scan/host_scan/
    subnets/hosts), not the old flat per-host dump.
    """
    writers = {
        "normal": export_txt,
        "json": lambda res, stream: export_template(res, stream, template_meta),
        "csv": export_csv,
    }

    requested = {key: path for key, path in outputs.items() if path}

    if not requested:
        export_txt(results, sys.stdout)
        return

    for key, path in requested.items():
        writer_func = writers[key]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer_func(results, f)
