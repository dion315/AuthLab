"""A small in-process throttle for local password sign-in.

Scope is deliberately modest: it slows down online guessing against the local
admin account from a single instance. It is not a distributed rate limiter —
with several replicas each keeps its own counters. For this app's purpose
(a test harness, with one local account, usually one replica) that is the right
amount of machinery. A real deployment fronting many users should use the
platform's rate limiting instead.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300
LOCKOUT_SECONDS = 300

_attempts: dict[str, list[float]] = defaultdict(list)
_lock = Lock()


def _prune(key: str, now: float) -> list[float]:
    recent = [t for t in _attempts[key] if now - t < WINDOW_SECONDS]
    _attempts[key] = recent
    return recent


def check(key: str) -> tuple[bool, int]:
    """Return (allowed, seconds_until_retry)."""
    now = time.time()
    with _lock:
        recent = _prune(key, now)
        if len(recent) >= MAX_ATTEMPTS:
            retry_in = int(LOCKOUT_SECONDS - (now - recent[0]))
            if retry_in > 0:
                return False, retry_in
            _attempts[key] = []
        return True, 0


def record_failure(key: str) -> None:
    with _lock:
        _attempts[key].append(time.time())


def reset(key: str) -> None:
    with _lock:
        _attempts.pop(key, None)
