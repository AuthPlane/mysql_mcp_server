"""Throttle for repeated authentication failures.

**Be clear about what this does and does not do.** It does not make
authentication stronger. Guessing a JWT signature is infeasible regardless of how
many attempts are allowed — that is settled by cryptography, not by a counter.

What it protects is **availability**. Every rejected token still costs a signature
verification before it is rejected, so an unauthenticated caller can spend our CPU
at will and flood the log while doing it. This makes that expensive.

Scope is deliberately narrow. A general-purpose rate limiter — per-route budgets,
sliding windows, shared state across replicas — belongs in a reverse proxy or API
gateway, and building one here would be both scope creep and a worse version of
something that already exists. This counts *authentication failures* per client
address and nothing else.

**The honest caveat:** the key is the socket peer address. Behind a reverse proxy
every request arrives from the proxy, so all callers share one bucket and the
throttle becomes useless or harmful. ``X-Forwarded-For`` is not consulted, because
it is caller-controlled: trusting it without a configured proxy allowlist would
let an attacker rotate a header to get unlimited attempts, *and* let them exhaust
someone else's bucket. Off by default for exactly this reason — it is only safe to
enable when you know how the server is exposed.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Mapping

logger = logging.getLogger(__name__)

#: Cap on tracked addresses, so the throttle cannot itself become the memory
#: exhaustion it is meant to prevent.
MAX_TRACKED_CLIENTS = 8192


class FailureThrottle:
    """Counts recent authentication failures per client address.

    A caller that exceeds ``max_failures`` within ``window_seconds`` is refused
    *before* its token is verified, which is the point: the refusal has to be
    cheaper than the work it avoids.

    Successful authentication clears the caller's record. A legitimate client that
    briefly misconfigures itself and then fixes it is not left in a penalty box.
    """

    def __init__(
        self,
        *,
        max_failures: int = 20,
        window_seconds: float = 60.0,
        max_clients: int = MAX_TRACKED_CLIENTS,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max_failures must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._failures: dict[str, deque[float]] = {}

    @staticmethod
    def client_key(scope: Mapping[str, Any]) -> str:
        """The socket peer address. See the module docstring on why not XFF."""
        client = scope.get("client")
        if isinstance(client, (tuple, list)) and client:
            return str(client[0])
        return ""

    def _prune(self, key: str, now: float) -> deque[float]:
        timestamps = self._failures.get(key)
        if timestamps is None:
            timestamps = deque()
            if len(self._failures) >= self.max_clients:
                # Evict the least recently inserted. Eviction always degrades
                # toward *allowing* traffic, never toward blocking a caller who
                # has not failed -- a throttle that locks people out under
                # pressure would be a denial of service of its own making.
                oldest = next(iter(self._failures), None)
                if oldest is not None:
                    self._failures.pop(oldest, None)
            self._failures[key] = timestamps
        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        return timestamps

    def is_throttled(self, key: str) -> bool:
        if not key:
            return False
        return len(self._prune(key, time.monotonic())) >= self.max_failures

    def record_failure(self, key: str) -> int:
        """Note a failure. Returns the number now counted in the window."""
        if not key:
            return 0
        now = time.monotonic()
        timestamps = self._prune(key, now)
        timestamps.append(now)
        count = len(timestamps)
        if count == self.max_failures:
            logger.warning(
                "Client %s reached %d authentication failures in %.0fs; "
                "further attempts are throttled",
                key,
                count,
                self.window_seconds,
            )
        return count

    def record_success(self, key: str) -> None:
        """Clear a caller's record after it authenticates successfully."""
        if key:
            self._failures.pop(key, None)

    def retry_after_seconds(self, key: str) -> int:
        """Seconds until the caller's oldest counted failure ages out.

        Sent as ``Retry-After`` so a legitimate but misconfigured client is told
        when to come back instead of hammering.
        """
        timestamps = self._failures.get(key)
        if not timestamps:
            return 0
        remaining = self.window_seconds - (time.monotonic() - timestamps[0])
        return max(1, int(remaining) + 1)

    def __len__(self) -> int:  # pragma: no cover - diagnostics
        return len(self._failures)
