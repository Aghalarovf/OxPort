from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import traceback
from typing import Dict, Optional, Tuple

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

_VERSION_FILE = os.path.join(_PROJECT_ROOT, "version.json")
_STATE_FILE = os.path.join(_PROJECT_ROOT, ".version_state.json")
_LOCK_FILE = os.path.join(_PROJECT_ROOT, ".version_checker.lock")
_ERROR_LOG = os.path.join(_PROJECT_ROOT, ".version_checker.log")

_RULES = (
    {"bump_index": 1, "watched_paths": ("modules",), "bump": "x", "reset_lower": True},
    {"bump_index": 2, "watched_paths": ("signatures", "rules"), "bump": "y", "reset_lower": True},
    {"bump_index": 3, "watched_paths": ("core",), "bump": "z", "reset_lower": False},
)

_TRACKED_EXTENSIONS = (".py", ".json", ".yaml", ".yml")
_IGNORED_DIR_NAMES = {"__pycache__", "pycache", ".git", ".version_checker.lock"}


def _log_error(message: str) -> None:
    try:
        with open(_ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_tracked_files(dir_path: str):
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in _IGNORED_DIR_NAMES]
        for name in files:
            if name.endswith(_TRACKED_EXTENSIONS):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, dir_path)
                yield full, rel.replace(os.sep, "/")


def _snapshot_directory(dir_name: str) -> Dict[str, str]:
    dir_path = os.path.join(_PROJECT_ROOT, dir_name)
    snapshot: Dict[str, str] = {}
    if not os.path.isdir(dir_path):
        return snapshot
    for full_path, rel_path in _iter_tracked_files(dir_path):
        try:
            snapshot[rel_path] = _hash_file(full_path)
        except OSError:
            continue
    return snapshot


def _compute_all_snapshots() -> Dict[str, Dict[str, str]]:
    watched = set()
    for rule in _RULES:
        watched.update(rule["watched_paths"])
    return {name: _snapshot_directory(name) for name in sorted(watched)}


def _load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save_json_atomic(path: str, data: dict) -> None:
    tmp_path = f"{path}.tmp-{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, path)


class _FileLock:
    def __init__(self, lock_path: str, timeout: float = 5.0, stale_after: float = 30.0):
        self._lock_path = lock_path
        self._timeout = timeout
        self._stale_after = stale_after
        self._acquired = False

    def __enter__(self):
        deadline = time.time() + self._timeout
        while True:
            try:
                fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode("utf-8"))
                os.close(fd)
                self._acquired = True
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self._lock_path) > self._stale_after:
                        os.remove(self._lock_path)
                        continue
                except OSError:
                    pass
                if time.time() >= deadline:
                    raise TimeoutError("version_checker: lock timeout")
                time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb):
        if self._acquired:
            try:
                os.remove(self._lock_path)
            except OSError:
                pass


def _parse_version(version_str: str) -> Tuple[int, int, int]:
    parts = version_str.strip().split(".")
    parts = (parts + ["0", "0", "0"])[:3]
    return tuple(int(p) for p in parts)  # type: ignore[return-value]


def _format_version(x: int, y: int, z: int) -> str:
    return f"{x}.{y}.{z}"


def _changed_groups(previous: Dict[str, Dict[str, str]], current: Dict[str, Dict[str, str]]) -> set:
    changed = set()
    for name in current.keys() | previous.keys():
        if current.get(name, {}) != previous.get(name, {}):
            changed.add(name)
    return changed


def _select_rule(changed_groups: set):
    applicable = [r for r in _RULES if changed_groups & set(r["watched_paths"])]
    if not applicable:
        return None
    return min(applicable, key=lambda r: r["bump_index"])


def _apply_bump(version_tuple: Tuple[int, int, int], rule: dict) -> Tuple[int, int, int]:
    x, y, z = version_tuple
    if rule["bump"] == "x":
        x += 1
        if rule["reset_lower"]:
            y, z = 0, 0
    elif rule["bump"] == "y":
        y += 1
        if rule["reset_lower"]:
            z = 0
    elif rule["bump"] == "z":
        z += 1
    return x, y, z


def _run_check() -> None:
    current_snapshots = _compute_all_snapshots()

    with _FileLock(_LOCK_FILE):
        state = _load_json(_STATE_FILE) or {"snapshots": {}}
        previous_snapshots = state.get("snapshots", {})

        if not previous_snapshots:
            _save_json_atomic(_STATE_FILE, {"snapshots": current_snapshots, "updated_at": time.time()})
            return

        changed_groups = _changed_groups(previous_snapshots, current_snapshots)
        if not changed_groups:
            return

        rule = _select_rule(changed_groups)
        if rule is None:
            _save_json_atomic(_STATE_FILE, {"snapshots": current_snapshots, "updated_at": time.time()})
            return

        version_data = _load_json(_VERSION_FILE)
        if version_data is None:
            _log_error("could not read version.json, bump not applied")
            return

        old_version_str = str(version_data.get("version", "0.0.0"))
        old_tuple = _parse_version(old_version_str)
        new_tuple = _apply_bump(old_tuple, rule)
        new_version_str = _format_version(*new_tuple)

        if new_version_str == old_version_str:
            _save_json_atomic(_STATE_FILE, {"snapshots": current_snapshots, "updated_at": time.time()})
            return

        version_data["previous_version"] = old_version_str
        version_data["version"] = new_version_str
        version_data["release_date"] = time.strftime("%Y-%m-%d")

        changelog = version_data.setdefault("changelog", [])
        changelog.insert(0, {
            "version": new_version_str,
            "date": time.strftime("%Y-%m-%d"),
            "changes": [
                f"Auto-detected changes in: {', '.join(sorted(changed_groups))} "
                f"('{rule['bump']}' bumped automatically by version_checker.py)"
            ],
        })

        try:
            _save_json_atomic(_VERSION_FILE, version_data)
        except OSError as exc:
            _log_error(f"could not write version.json: {exc}")
            return

        _save_json_atomic(_STATE_FILE, {"snapshots": current_snapshots, "updated_at": time.time()})


def check_and_update(background: bool = True) -> Optional[threading.Thread]:
    def _safe_run():
        try:
            _run_check()
        except Exception:
            _log_error("unexpected error:\n" + traceback.format_exc())

    if not background:
        _safe_run()
        return None

    t = threading.Thread(target=_safe_run, name="version-checker", daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    check_and_update(background=False)
    data = _load_json(_VERSION_FILE) or {}
    print(f"oxport version: {data.get('version', 'unknown')}")
