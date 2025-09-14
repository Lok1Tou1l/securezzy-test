import time
from collections import defaultdict, deque
from typing import Deque, Dict


# Simple per-IP sliding window request counter
REQUEST_WINDOW_SECONDS = 10
REQUEST_THRESHOLD = 20


_ip_to_timestamps: Dict[str, Deque[float]] = defaultdict(deque)


def record_request(source_ip: str) -> None:
    now = time.time()
    timestamps = _ip_to_timestamps[source_ip]
    timestamps.append(now)
    _evict_old(timestamps, now)


def is_ddos(source_ip: str) -> bool:
    now = time.time()
    timestamps = _ip_to_timestamps[source_ip]
    _evict_old(timestamps, now)
    return len(timestamps) > REQUEST_THRESHOLD


def _evict_old(timestamps: Deque[float], now: float) -> None:
    threshold = now - REQUEST_WINDOW_SECONDS
    while timestamps and timestamps[0] < threshold:
        timestamps.popleft()


