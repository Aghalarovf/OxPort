import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, _PROJECT_ROOT)
sys.pycache_prefix = os.path.join(_PROJECT_ROOT, "pycache")

from core import cli, engine, exporter
from core.logger import setup_logger

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

    already_printed_live = config.live and not config.output_file and config.output_format == "txt"
    if not already_printed_live:
        exporter.export_results(results, config.output_file, config.output_format)


if __name__ == "__main__":
    main()
