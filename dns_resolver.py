import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set

_REVERSE_RESOLVE_TIMEOUT_S = 1.5


def resolve_hostname(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def reverse_resolve(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def reverse_resolve_many(ips: List[str], threads: int = 32,
                          timeout_s: float = _REVERSE_RESOLVE_TIMEOUT_S) -> Dict[str, Optional[str]]:
    if not ips:
        return {}

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_s)

    results: Dict[str, Optional[str]] = {}
    try:
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            future_to_ip = {pool.submit(reverse_resolve, ip): ip for ip in ips}
            for future in future_to_ip:
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception:
                    results[ip] = None
    finally:
        socket.setdefaulttimeout(previous_timeout)

    return results


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()] or [str(network.network_address)]


def expand_range(range_str: str) -> List[str]:
    start_str, end_str = [p.strip() for p in range_str.split("-")]
    start_ip = ipaddress.ip_address(start_str)
    if is_ip_address(end_str):
        end_ip = ipaddress.ip_address(end_str)
    else:
        octets = start_str.split(".")
        octets[-1] = end_str
        end_ip = ipaddress.ip_address(".".join(octets))

    result = []
    current = int(start_ip)
    last = int(end_ip)
    while current <= last:
        result.append(str(ipaddress.ip_address(current)))
        current += 1
    return result


def load_targets_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def expand_excludes(exclude: List[str]) -> Set[str]:
    excluded: Set[str] = set()
    for entry in exclude:
        if "/" in entry:
            excluded.update(expand_cidr(entry))
        else:
            excluded.add(entry)
    return excluded


def build_target_list(host: Optional[str], cidr: Optional[str], ip_range: Optional[str],
                       input_file: Optional[str], exclude: List[str]) -> List[str]:
    targets: Set[str] = set()

    if host:
        if is_ip_address(host):
            targets.add(host)
        else:
            resolved = resolve_hostname(host)
            if resolved:
                targets.add(resolved)

    if cidr:
        targets.update(expand_cidr(cidr))

    if ip_range:
        targets.update(expand_range(ip_range))

    if input_file:
        for line in load_targets_from_file(input_file):
            if is_ip_address(line):
                targets.add(line)
            else:
                resolved = resolve_hostname(line)
                if resolved:
                    targets.add(resolved)

    final_targets = targets - expand_excludes(exclude)
    return sorted(final_targets, key=lambda ip: ipaddress.ip_address(ip))


def normalize_subnet_line(line: str) -> str:
    return line if "/" in line else f"{line}/24"


def load_subnets_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return [normalize_subnet_line(line) for line in lines]
