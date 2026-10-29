import json
import os
from typing import Dict, List, Optional

from core.models import OSMatch

_SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "signatures", "os_pattern.json")

_cache: Optional[List[Dict]] = None


def _load_patterns() -> List[Dict]:
    global _cache
    if _cache is None:
        with open(_SIGNATURES_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def guess_os(ttl: Optional[int]) -> Optional[OSMatch]:
    if ttl is None:
        return None

    patterns = _load_patterns()
    best_match: Optional[OSMatch] = None
    best_diff = None

    for entry in patterns:
        baseline = entry.get("ttl_baseline")
        if baseline is None:
            continue

        diff = abs(baseline - ttl)
        if diff > entry.get("ttl_tolerance", 5):
            continue

        if best_diff is None or diff < best_diff:
            best_diff = diff
            confidence = max(0.0, 100.0 - (diff * 15))
            best_match = OSMatch(name=entry.get("name", "unknown"), confidence=confidence, family=entry.get("family"))

    return best_match
