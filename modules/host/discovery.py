import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

from core.dns_resolver import reverse_resolve
from core.logger import get_logger
from core.models import DiscoveryMethod, Host, ScanConfig
from core.threads import ThreadedExecutor, split_into_ranges
from modules.host import arp_scanner, icmp_scanner, tcp_ping
from modules.host.ttl_utils import get_tcp_ttl, ttl_to_os


def _discover_single(ip: str, config: ScanConfig, timeout_ms: int) -> Host:
    logger = get_logger()

    if config.skip_discovery:
        return Host(ip=ip, alive=True, discovery_method=DiscoveryMethod.SKIPPED)

    arp_attempted = False

    if config.use_arp:
        arp_attempted = True
        try:
            alive, mac = arp_scanner.probe(ip, timeout_ms)
            if alive:
                return Host(ip=ip, alive=True, discovery_method=DiscoveryMethod.ARP, mac=mac,
                            reason=f"ARP reply from {mac}")
        except RuntimeError as exc:
            logger.warning(str(exc))

    if config.use_icmp or not config.use_arp:
        try:
            alive, ttl = icmp_scanner.probe(ip, timeout_ms)
            if alive:
                reason = "ICMP echo reply"
                if ttl is not None:
                    reason += f" (TTL={ttl})"
                os_hint = ttl_to_os(ttl) if ttl is not None else None
                return Host(ip=ip, alive=True, discovery_method=DiscoveryMethod.ICMP,
                            ttl_observed=ttl, reason=reason, os_hint=os_hint)
        except RuntimeError as exc:
            logger.warning(str(exc))

    open_port = tcp_ping.probe(ip, timeout_ms)
    if open_port is not None:
        if arp_attempted:
            reason = f"ARP no reply; TCP port {open_port} open"
        else:
            reason = f"TCP port {open_port} open"
        ttl = get_tcp_ttl(ip, open_port, timeout_ms)
        os_hint = ttl_to_os(ttl) if ttl is not None else None
        if ttl is not None:
            reason += f" (TTL={ttl})"
        return Host(ip=ip, alive=True, discovery_method=DiscoveryMethod.TCP_PING,
                    reason=reason, os_hint=os_hint)

    return Host(ip=ip, alive=False, discovery_method=DiscoveryMethod.NONE)


def discover_hosts(targets: List[str], config: ScanConfig, threads: int, timeout_ms: int,
                    on_result: Optional[Callable[[Host], None]] = None,
                    on_start: Optional[Callable[[], None]] = None) -> List[Host]:
    logger = get_logger()
    logger.info(f"Starting host discovery for {len(targets)} target(s)")

    if on_start:
        on_start()

    executor = ThreadedExecutor(max_workers=threads)
    hosts = executor.run(lambda ip: _discover_single(ip, config, timeout_ms), targets, on_result=on_result)

    for host in hosts:
        if host.alive:
            host.hostname = reverse_resolve(host.ip)

    alive_count = sum(1 for h in hosts if h.alive)
    logger.info(f"Discovery complete: {alive_count}/{len(hosts)} host(s) alive")

    return sorted(hosts, key=lambda h: h.ip)


def discover_hosts_ranged(targets: List[str], config: ScanConfig, n_threads: int, timeout_ms: int,
                           on_result: Optional[Callable[[Host], None]] = None,
                           on_start: Optional[Callable[[], None]] = None) -> List[Host]:
    logger = get_logger()
    chunks = split_into_ranges(targets, n_threads)

    logger.info(f"Splitting {len(targets)} host(s) across {len(chunks)} thread(s) for discovery")
    for idx, chunk in enumerate(chunks, start=1):
        if chunk:
            logger.info(f"  thread {idx}: hosts {chunk[0]}-{chunk[-1]} ({len(chunk)} host(s))")

    if on_start:
        on_start()

    hosts: List[Host] = []
    hosts_lock = threading.Lock()

    def _worker(chunk: List[str]) -> None:
        local_hosts: List[Host] = []
        for ip in chunk:
            host = _discover_single(ip, config, timeout_ms)
            if on_result:
                on_result(host)
            local_hosts.append(host)

        with hosts_lock:
            hosts.extend(local_hosts)

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [pool.submit(_worker, chunk) for chunk in chunks]
        for future in futures:
            future.result()

    for host in hosts:
        if host.alive:
            host.hostname = reverse_resolve(host.ip)

    alive_count = sum(1 for h in hosts if h.alive)
    logger.info(f"Discovery complete: {alive_count}/{len(hosts)} host(s) alive")

    return sorted(hosts, key=lambda h: h.ip)
