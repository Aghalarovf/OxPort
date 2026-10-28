import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class RateLimiter:
    def __init__(self, rate_per_second: int = 0):
        self.rate_per_second = rate_per_second
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self):
        if self.rate_per_second <= 0:
            return
        interval = 1.0 / self.rate_per_second
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last_call = time.monotonic()


class ThreadedExecutor:
    def __init__(self, max_workers: int = 50, rate_per_second: int = 0, jitter_ms: int = 0):
        self.max_workers = max(1, max_workers)
        self.rate_limiter = RateLimiter(rate_per_second)
        self.jitter_ms = jitter_ms

    def _wrapped(self, func: Callable[[T], R], item: T) -> R:
        self.rate_limiter.wait()
        if self.jitter_ms > 0:
            time.sleep(random.uniform(0, self.jitter_ms / 1000.0))
        return func(item)

    def run(self, func: Callable[[T], R], items: Iterable[T], on_result: Optional[Callable[[R], None]] = None) -> List[R]:
        results: List[R] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self._wrapped, func, item) for item in items]
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    continue
                if on_result:
                    on_result(result)
                results.append(result)
        return results


def split_into_ranges(items: List[T], n_chunks: int) -> List[List[T]]:
    n_chunks = max(1, n_chunks)
    if not items:
        return []
    chunk_size = -(-len(items) // n_chunks)
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]
