import json
import os
import re
from typing import Dict, List, Optional

_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "signatures", "version_pattern.json")

_cache: Optional[Dict[str, List[Dict[str, str]]]] = None


def _load_patterns() -> Dict[str, List[Dict[str, str]]]:
    global _cache
    if _cache is None:
        with open(_SIGNATURES_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def extract_version(service_name: Optional[str], banner: Optional[str]) -> Optional[str]:
    if not service_name or not banner:
        return None

    patterns = _load_patterns()
    service_patterns = patterns.get(service_name.lower())

    if not service_patterns:
        return None

    for entry in service_patterns:
        regex = entry.get("regex")
        if not regex:
            continue
        match = re.search(regex, banner, re.IGNORECASE)
        if match:
            template = entry.get("template", "{0}")
            try:
                return template.format(*match.groups())
            except (IndexError, KeyError):
                return match.group(0)

    return None
