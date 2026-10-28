import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List

import yaml

from core import exporter
from core.dns_resolver import build_target_list
from core.logger import get_logger
from core.os_profiles import get_os_ports
from core.models import (
    Host,
    PortResult,
    PortState,
    Protocol,
    ScanConfig,
    ScanProfile,
    ScanResult,
    ScanTechnique,
)
from core.threads import RateLimiter, ThreadedExecutor, split_into_ranges
from modules.detection import os_fingerprint, service_detect, version_probe
from modules.host.discovery import discover_hosts, discover_hosts_ranged
from modules.scanner import stealth, tcp_connect, tcp_syn, udp_scan

_RULES_PATH_TEMPLATE = "rules/{name}.yaml"

_STEALTH_TECHNIQUES = {ScanTechnique.FIN, ScanTechnique.NULL, ScanTechnique.XMAS, ScanTechnique.ACK}


def load_profile(name: str) -> ScanProfile:
    path = _RULES_PATH_TEMPLATE.format(name=name)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ScanProfile.from_dict(name, data)


def parse_port_spec(spec: str, all_ports: bool) -> List[int]:
    if all_ports:
        return list(range(1, 65536))

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-")
            start, end = int(start_str), int(end_str)
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    return sorted(ports)


def _scan_single_port(ip: str, port: int, technique: ScanTechnique, timeout_ms: int) -> PortResult:
    if technique == ScanTechnique.CONNECT:
        return tcp_connect.scan_port(ip, port, timeout_ms)
    if technique == ScanTechnique.SYN:
        return tcp_syn.scan_port(ip, port, timeout_ms)
    if technique == ScanTechnique.UDP:
        return udp_scan.scan_port(ip, port, timeout_ms)
    if technique in _STEALTH_TECHNIQUES:
        return stealth.scan_port(ip, port, technique, timeout_ms)
    raise ValueError(f"unsupported technique: {technique}")


def _detect_single_port(host: Host, port_result: PortResult, config: ScanConfig) -> None:
    if port_result.state != PortState.OPEN:
        return

    protocol_str = port_result.protocol.value
    service_name = service_detect.identify_service(port_result.port, protocol_str)
    port_result.service_name = service_name

    if config.grab_banner or config.detect_version:
        if port_result.protocol == Protocol.TCP:
            banner = service_detect.grab_banner(host.ip, port_result.port)
            port_result.banner = banner

            if config.detect_version and service_name:
                version = version_probe.extract_version(service_name, banner)
                port_result.version = version


def _on_host_result(config: ScanConfig):
    def handler(host: Host) -> None:
        if not host.alive:
            return
        if config.live:
            exporter.print_live_host(host)

    return handler


def _on_port_result(host: Host, config: ScanConfig):
    def handler(port_result: PortResult) -> None:
        if port_result.state != PortState.OPEN:
            return
        _detect_single_port(host, port_result, config)
        if config.live:
            exporter.print_live_port(host.ip, port_result)

    return handler


def _scan_host_ports(host: Host, ports: List[int], techniques: List[ScanTechnique],
                      profile: ScanProfile, config: ScanConfig) -> List[PortResult]:
    logger = get_logger()
    results: List[PortResult] = []
    threads = config.threads or profile.threads
    rate = config.rate if config.rate is not None else profile.rate

    executor = ThreadedExecutor(max_workers=threads, rate_per_second=rate, jitter_ms=profile.jitter_ms)
    on_result = _on_port_result(host, config)

    for technique in techniques:
        logger.debug(f"Scanning {host.ip} with technique={technique.value} on {len(ports)} port(s)")
        technique_results = executor.run(
            lambda port: _scan_single_port(host.ip, port, technique, profile.timeout_ms),
            ports,
            on_result=on_result,
        )
        results.extend(technique_results)

    return results


def _scan_host_ports_ranged(host: Host, ports: List[int], techniques: List[ScanTechnique],
                             profile: ScanProfile, config: ScanConfig) -> List[PortResult]:
    logger = get_logger()
    n_threads = config.threads
    chunks = split_into_ranges(ports, n_threads)

    logger.info(f"Splitting {len(ports)} port(s) across {len(chunks)} thread(s) for {host.ip}")
    for idx, chunk in enumerate(chunks, start=1):
        if chunk:
            logger.info(f"  thread {idx}: ports {chunk[0]}-{chunk[-1]} ({len(chunk)} port(s))")

    if config.live:
        exporter.print_live_header()

    rate = config.rate if config.rate is not None else profile.rate
    rate_limiter = RateLimiter(rate)
    on_result = _on_port_result(host, config)

    results: List[PortResult] = []
    results_lock = threading.Lock()

    def _worker(chunk: List[int]) -> None:
        local_results: List[PortResult] = []
        for port in chunk:
            for technique in techniques:
                rate_limiter.wait()
                port_result = _scan_single_port(host.ip, port, technique, profile.timeout_ms)
                on_result(port_result)
                local_results.append(port_result)

        with results_lock:
            results.extend(local_results)

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [pool.submit(_worker, chunk) for chunk in chunks]
        for future in futures:
            future.result()

    return results


def _apply_os_detection(host: Host, config: ScanConfig):
    if config.detect_os and host.ttl_observed:
        return os_fingerprint.guess_os(host.ttl_observed)
    return None


def run(config: ScanConfig) -> List[ScanResult]:
    logger = get_logger()
    profile = load_profile(config.profile_name)

    targets = build_target_list(
        host=config.targets_raw[0] if config.targets_raw else None,
        cidr=config.cidr,
        ip_range=config.ip_range,
        input_file=config.input_file,
        exclude=config.exclude_raw,
    )

    if not targets:
        logger.error("No valid targets resolved, aborting")
        return []

    discovery_only = bool(config.ping_only or config.cidr)
    discovery_threads = config.threads or profile.threads
    use_ranged_hosts = bool(config.cidr and config.threads)

    host_live_handler = _on_host_result(config)
    header_printer = exporter.print_live_hosts_header if (config.live and discovery_only) else None

    if config.cidr:
        logger.info("CIDR target detected: host discovery only, port scan will be skipped")

    if use_ranged_hosts:
        logger.info(
            f"CIDR target with --threads={config.threads}: splitting discovery into "
            f"{config.threads} contiguous, non-overlapping host range(s)"
        )
        hosts = discover_hosts_ranged(targets, config, config.threads, profile.timeout_ms,
                                       on_result=host_live_handler, on_start=header_printer)
    else:
        hosts = discover_hosts(targets, config, discovery_threads, profile.timeout_ms,
                                on_result=host_live_handler, on_start=header_printer)

    alive_hosts = [h for h in hosts if h.alive]

    if discovery_only:
        return [ScanResult(host=h) for h in hosts]

    if not alive_hosts:
        logger.warning("No alive hosts found, nothing to scan")
        return []

    if config.os_profile:
        ports = get_os_ports(config.os_profile)
        logger.info(f"OS profile '{config.os_profile}' selected: restricting scan to {len(ports)} OS-specific port(s)")
    else:
        ports = parse_port_spec(config.ports, config.all_ports)

    logger.info(f"Scanning {len(alive_hosts)} host(s) on {len(ports)} port(s) with techniques={[t.value for t in config.techniques]}")

    use_ranged_threads = bool(config.all_ports and config.threads)

    if config.live and not use_ranged_threads:
        exporter.print_live_header()

    results: List[ScanResult] = []

    for host in alive_hosts:
        start = time.monotonic()

        if use_ranged_threads:
            port_results = _scan_host_ports_ranged(host, ports, config.techniques, profile, config)
        else:
            port_results = _scan_host_ports(host, ports, config.techniques, profile, config)

        os_match = _apply_os_detection(host, config)

        duration = time.monotonic() - start
        results.append(ScanResult(host=host, ports=port_results, os_match=os_match, scan_duration_s=round(duration, 2)))

    return results
