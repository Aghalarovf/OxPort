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
    target.add_argument("-i", "--subnets-file", dest="subnets_file", type=str,
                         help="File containing one subnet per line (bare network IP defaults to /24, e.g. 10.0.1.0, "
                              "or explicit CIDR, e.g. 10.0.40.0/24); each subnet is host-discovered in its own stage, "
                              "one after another, and results are printed grouped by subnet (host discovery only, no port scan)")
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
    discovery.add_argument("--only-host", dest="only_host", action="store_true",
                            help="Only perform host discovery, skip port scan entirely (no ports are checked on any "
                                 "host). Equivalent to --ping-only; with -i/--subnets-file each subnet is still "
                                 "fully discovered, one after another, before moving to the next")
    discovery.add_argument("-Pn", dest="skip_discovery", action="store_true", help="Skip host discovery, treat all targets as alive")
    discovery.add_argument("--resume", action="store_true",
                            help="Resume a staged subnet scan (-i/--subnets-file) that was interrupted (Ctrl+C): "
                                 "reads scan.cache from the current directory, skips subnets already completed "
                                 "and continues with the remaining ones")

    detection = parser.add_argument_group("Detection")
    detection.add_argument("-V", "--service-version", dest="detect_version", action="store_true", help="Enable service version detection")
    detection.add_argument("-O", "--os-detect", dest="detect_os", action="store_true", help="Enable OS fingerprinting")
    detection.add_argument("--banner", action="store_true", help="Enable banner grabbing")

    anonymous = parser.add_argument_group("Anonymous access")
    anonymous.add_argument("--anonymous", action="store_true",
                            help="Shortcut for -M anonymous: after the port scan finishes, test anonymous/unauthenticated access "
                                 "on every open port whose service matches a supported plugin "
                                 "(ftp, tftp, smb, nfs, vnc, telnet, x11, redis, ldap, snmp, smtp)")
    anonymous.add_argument("--anonymous-timeout", type=int, default=3000,
                            help="Per-service timeout in milliseconds for anonymous access checks (default: 3000)")

    modules = parser.add_argument_group("Modules")
    modules.add_argument("-M", "--module", dest="modules", action="append", default=[], metavar="MODULE",
                          help="Run a post-scan module by name, nxc style, repeatable (currently supported: anonymous)")
    modules.add_argument("--option", dest="module_options", action="append", default=[], metavar="KEY=VALUE",
                          help="Pass an option to the selected module(s) as KEY=VALUE, repeatable, nxc -o style "
                               "(e.g. --option TIMEOUT=5000)")

    profile = parser.add_argument_group("Profile")
    profile.add_argument("--profile", type=str, choices=["stealth", "normal", "aggressive", "ultra"], default="normal")

    perf = parser.add_argument_group("Performance")
    perf.add_argument("-T", "--threads", type=int, default=None, help="Number of worker threads")
    perf.add_argument("--rate", type=int, default=None, help="Max requests per second")

    output = parser.add_argument_group("Output")
    output.add_argument("-oN", dest="output_normal", metavar="FILE",
                         help="Write results in normal (plain text) format to FILE")
    output.add_argument("-oJ", dest="output_json", metavar="FILE",
                         help="Write a single structured JSON summary to FILE (mode, threads, "
                              "port_scan/host_scan flags, subnets, hosts with their ports)")
    output.add_argument("-oC", dest="output_csv", metavar="FILE",
                         help="Write results as CSV to FILE")
    output.add_argument("-v", "--verbose", action="store_true")
    output.add_argument("--live", action="store_true", help="Print each open port immediately as it is discovered, before the scan finishes")
    output.add_argument("--version", action="version", version=f"oxport {TOOL_VERSION}")

    return parser


def parse_args(argv=None) -> ScanConfig:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not any([args.host, args.cidr, args.ip_range, args.input_file, args.subnets_file]):
        parser.error("at least one target source is required: --host, --cidr, --range, --input-file or -i/--subnets-file")

    if args.resume and not args.subnets_file:
        parser.error("--resume is only supported together with -i/--subnets-file")

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

    module_options = {}
    for raw_option in args.module_options:
        if "=" not in raw_option:
            parser.error(f"invalid --option value {raw_option!r}, expected KEY=VALUE")
        key, _, value = raw_option.partition("=")
        module_options[key.strip().upper()] = value.strip()

    selected_modules = [m.lower() for m in args.modules]
    if args.anonymous and "anonymous" not in selected_modules:
        selected_modules.append("anonymous")
    if selected_modules and "TIMEOUT" not in module_options:
        module_options["TIMEOUT"] = str(args.anonymous_timeout)

    config = ScanConfig(
        targets_raw=[args.host] if args.host else [],
        exclude_raw=args.exclude,
        input_file=args.input_file,
        subnets_file=args.subnets_file,
        ports=args.ports,
        all_ports=args.all_ports,
        os_profile=args.os_profile,
        techniques=techniques,
        use_arp=args.arp,
        use_icmp=args.icmp,
        ping_only=args.ping_only,
        only_host=args.only_host,
        skip_discovery=args.skip_discovery,
        resume=args.resume,
        detect_version=args.detect_version,
        detect_os=args.detect_os,
        grab_banner=args.banner,
        profile_name=args.profile,
        threads=args.threads,
        rate=args.rate,
        output_normal=args.output_normal,
        output_json=args.output_json,
        output_csv=args.output_csv,
        verbose=args.verbose,
        live=args.live,
        cidr=args.cidr,
        ip_range=args.ip_range,
        anonymous=args.anonymous,
        anonymous_timeout=args.anonymous_timeout,
        modules=selected_modules,
        module_options=module_options,
    )

    return config
