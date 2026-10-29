import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, _PROJECT_ROOT)
sys.pycache_prefix = os.path.join(_PROJECT_ROOT, "pycache")

from core import cli, engine, exporter
from core.dns_resolver import load_subnets_from_file
from core.logger import setup_logger
from plugins.registry import get_module


def _build_template_meta(config, mode: str) -> dict:
    if config.subnets_file:
        subnets = load_subnets_from_file(config.subnets_file)
    elif config.cidr:
        subnets = [config.cidr]
    else:
        subnets = []

    return {
        "mode": mode,
        "threads": config.threads,
        "port_scan": mode == "port_scan",
        "host_scan": mode == "host_scan",
        "subnets": subnets,
    }


def _requested_outputs(config) -> dict:
    return {
        "normal": config.output_normal,
        "json": config.output_json,
        "csv": config.output_csv,
    }


def _any_output_requested(config) -> bool:
    return any(_requested_outputs(config).values())

try:
    from version_checker import check_and_update as _check_version
except Exception:
    _check_version = None


def main():
    if _check_version is not None:
        _check_version(background=True)

    config = cli.parse_args()
    logger = setup_logger(config.verbose)

    try:
        results = engine.run(config)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        sys.exit(1)

    if not results:
        sys.exit(0)

    if config.subnets_file:
        # -i/--subnets-file is always a host scan: the terminal output was already printed
        # live (or in one batch) by engine.run_staged_subnet_discovery. Only write a file/
        # extra format here if the user actually asked for one (-oN/-oJ/-oC/-oT), so default
        # behavior is unchanged.
        if _any_output_requested(config):
            exporter.export_multi(
                results, _requested_outputs(config),
                template_meta=_build_template_meta(config, "host_scan"),
            )
        sys.exit(0)

    discovery_only = bool(config.ping_only or config.only_host or config.cidr)
    mode = "host_scan" if discovery_only else "port_scan"

    already_printed_live = config.live and not _any_output_requested(config)
    if not already_printed_live:
        exporter.export_multi(
            results, _requested_outputs(config),
            template_meta=_build_template_meta(config, mode),
        )

    for module_name in config.modules:
        module = get_module(module_name)
        if module is None:
            logger.warning(f"Unknown module: {module_name}")
            continue
        module_results = module.run(results, config.module_options, logger=logger)
        exporter.print_anonymous_results(module_results)


if __name__ == "__main__":
    main()
