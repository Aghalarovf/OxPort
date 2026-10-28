import json
import os
from typing import Dict, List, Optional

_SIGNATURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures")

_PROFILE_FILES = {
    "windows": "windows.json",
    "linux": "linux.json",
}

_cache: Dict[str, Dict[str, Dict[str, str]]] = {}


def available_profiles() -> List[str]:
    return sorted(_PROFILE_FILES.keys())


def _load_profile(name: str) -> Dict[str, Dict[str, str]]:
    if name not in _PROFILE_FILES:
        raise ValueError(f"unknown OS profile: {name}")

    if name not in _cache:
        path = os.path.join(_SIGNATURES_DIR, _PROFILE_FILES[name])
        with open(path, "r", encoding="utf-8") as f:
            _cache[name] = json.load(f)

    return _cache[name]


def get_os_ports(name: str, protocol: Optional[str] = None) -> List[int]:
    profile = _load_profile(name)

    if protocol:
        port_map = profile.get(protocol, {})
        return sorted(int(p) for p in port_map.keys())

    ports = set()
    for port_map in profile.values():
        ports.update(int(p) for p in port_map.keys())

    return sorted(ports)


def get_os_service_name(name: str, port: int, protocol: str) -> Optional[str]:
    profile = _load_profile(name)
    port_map = profile.get(protocol, {})
    return port_map.get(str(port))


def classify_port(port: int, protocol: str) -> str:
    is_windows = port in get_os_ports("windows", protocol=protocol)
    is_linux = port in get_os_ports("linux", protocol=protocol)

    if is_windows and is_linux:
        return "both"
    if is_windows:
        return "windows"
    if is_linux:
        return "linux"
    return "other"
