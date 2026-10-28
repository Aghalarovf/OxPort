import argparse
import json
import os
import sys

from core.models import ScanConfig, ScanTechnique

_VERSION_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "version.json")


def _load_tool_version() -> str:
    try:
        with open(_VERSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("version", "unknown"))
    except (OSError, ValueError):
        return "unknown"


TOOL_VERSION = _load_tool_version()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxport",
        description="Professional modular port scanner",
    )

    target = parser.add_argument_group("Target")
    target.add_argument("--host", type=str, help="Single IP address or hostname")
    target.add_argument("--cidr", type=str, help="Subnet in CIDR notation, e.g. 192.168.1.0/24")
    target.add_argument("--range", dest="ip_range", type=str, help="IP range, e.g. 192.168.1.1-254")
    target.add_argument("--input-file", type=str, help="File containing a list of targets")
    target.add_argument("--exclude", action="append", default=[], help="IP or CIDR to exclude, repeatable")

    ports = parser.add_argument_group("Ports")
    ports.add_argument("-p", "--ports", type=str, default="1-1000", help="Port list or range, e.g. 80,443,8000-9000")
    ports.add_argument("-A", "--all-ports", action="store_true", help="Scan all 65535 ports")
    ports.add_argument("--os", dest="os_profile", type=str, choices=["windows", "linux"], default=None,
                        help="Restrict the scan to ports typically associated with the given OS, ignoring --ports")

    technique = parser.add_argument_group("Scan technique")
    technique.add_argument("--syn", action="store_true", help="TCP SYN scan")
    technique.add_argument("--udp", action="store_true", help="UDP scan")
    technique.add_argument("--fin", action="store_true", help="TCP FIN scan")
    technique.add_argument("--null", action="store_true", help="TCP NULL scan")
    technique.add_argument("--xmas", action="store_true", help="TCP XMAS scan")
    technique.add_argument("--ack", action="store_true", help="TCP ACK scan")

    discovery = parser.add_argument_group("Host discovery")
    discovery.add_argument("--arp", action="store_true", help="Force ARP based discovery")
    discovery.add_argument("--icmp", action="store_true", help="Force ICMP based discovery")
    discovery.add_argument("--ping-only", action="store_true", help="Only perform host discovery, skip port scan")
    discovery.add_argument("-Pn", dest="skip_discovery", action="store_true", help="Skip host discovery, treat all targets as alive")

    detection = parser.add_argument_group("Detection")
    detection.add_argument("-V", "--service-version", dest="detect_version", action="store_true", help="Enable service version detection")
    detection.add_argument("-O", "--os-detect", dest="detect_os", action="store_true", help="Enable OS fingerprinting")
    detection.add_argument("--banner", action="store_true", help="Enable banner grabbing")

    profile = parser.add_argument_group("Profile")
    profile.add_argument("--profile", type=str, choices=["stealth", "normal", "aggressive", "ultra"], default="normal")

    perf = parser.add_argument_group("Performance")
    perf.add_argument("-T", "--threads", type=int, default=None, help="Number of worker threads")
    perf.add_argument("--rate", type=int, default=None, help="Max requests per second")

    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", dest="output_file", type=str, help="Output file path")
    output.add_argument("--format", dest="output_format", type=str, choices=["json", "csv", "txt"], default="txt")
    output.add_argument("-v", "--verbose", action="store_true")
    output.add_argument("--live", action="store_true", help="Print each open port immediately as it is discovered, before the scan finishes")
    output.add_argument("--version", action="version", version=f"oxport {TOOL_VERSION}")

    return parser


def parse_args(argv=None) -> ScanConfig:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not any([args.host, args.cidr, args.ip_range, args.input_file]):
        parser.error("at least one target source is required: --host, --cidr, --range or --input-file")

    techniques = []
    if args.syn:
        techniques.append(ScanTechnique.SYN)
    if args.udp:
        techniques.append(ScanTechnique.UDP)
    if args.fin:
        techniques.append(ScanTechnique.FIN)
    if args.null:
        techniques.append(ScanTechnique.NULL)
    if args.xmas:
        techniques.append(ScanTechnique.XMAS)
    if args.ack:
        techniques.append(ScanTechnique.ACK)
    if not techniques:
        techniques.append(ScanTechnique.CONNECT)

    config = ScanConfig(
        targets_raw=[args.host] if args.host else [],
        exclude_raw=args.exclude,
        input_file=args.input_file,
        ports=args.ports,
        all_ports=args.all_ports,
        os_profile=args.os_profile,
        techniques=techniques,
        use_arp=args.arp,
        use_icmp=args.icmp,
        ping_only=args.ping_only,
        skip_discovery=args.skip_discovery,
        detect_version=args.detect_version,
        detect_os=args.detect_os,
        grab_banner=args.banner,
        profile_name=args.profile,
        threads=args.threads,
        rate=args.rate,
        output_file=args.output_file,
        output_format=args.output_format,
        verbose=args.verbose,
        live=args.live,
        cidr=args.cidr,
        ip_range=args.ip_range,
    )

    return config
