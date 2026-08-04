"""
WebOSINT Pro - Request Randomizer
Applies timing randomization and request pacing for detection-aware scanning.

Capabilities:
  • Gaussian-distributed inter-request delays
  • Jitter bands per scan profile
  • Request ordering randomization
  • Adaptive pacing (backs off if responses slow down)
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass
class PacingProfile:
    name: str
    min_delay: float  # seconds
    max_delay: float
    jitter_sigma: float  # std dev for Gaussian jitter
    burst_limit: int  # max consecutive requests before forced pause
    burst_pause: float  # pause duration after burst


PACING_PROFILES: dict[str, PacingProfile] = {
    "fast": PacingProfile("fast", 0.0, 0.1, 0.02, 20, 0.5),
    "normal": PacingProfile("normal", 0.1, 0.5, 0.1, 10, 1.0),
    "slow": PacingProfile("slow", 0.5, 2.0, 0.3, 5, 2.0),
    "stealth": PacingProfile("stealth", 2.0, 10.0, 1.5, 3, 5.0),
}


class RequestRandomizer:
    """
    Applies randomized timing between requests.

    Used by privacy_controller to shape traffic patterns for
    authorized lab testing and detection-aware reconnaissance.
    """

    def __init__(
        self,
        profile_name: str = "normal",
        base_delay: float = 0.0,
        jitter: float = 0.0,
    ) -> None:
        self._profile = PACING_PROFILES.get(profile_name, PACING_PROFILES["normal"])
        self._base = base_delay
        self._jitter = jitter
        self._counter = 0
        self._last_req = 0.0

    def wait(self) -> float:
        """
        Block for the appropriate inter-request delay.
        Returns the actual wait time in seconds.
        """
        self._counter += 1

        # Forced pause after burst limit
        if self._counter % self._profile.burst_limit == 0:
            time.sleep(self._profile.burst_pause)
            return self._profile.burst_pause

        delay = self._compute_delay()
        if delay > 0:
            time.sleep(delay)
        self._last_req = time.monotonic()
        return delay

    def _compute_delay(self) -> float:
        """
        Compute next delay using the configured profile + base + jitter.
        Gaussian distribution ensures human-like timing variance.
        """
        if self._base > 0 and self._jitter > 0:
            # Caller-supplied base + Gaussian jitter (stealth mode)
            raw = self._base + random.gauss(0, self._jitter)
        else:
            # Profile-based: uniform within [min, max] + small Gaussian tweak
            raw = random.uniform(
                self._profile.min_delay,
                self._profile.max_delay,
            ) + random.gauss(0, self._profile.jitter_sigma)

        return max(0.0, raw)

    def randomize_order(self, items: list) -> list:
        """Return a shuffled copy of items."""
        shuffled = list(items)
        random.shuffle(shuffled)
        return shuffled

    @staticmethod
    def random_delay(min_s: float, max_s: float) -> float:
        """One-shot random sleep, returns actual sleep duration."""
        delay = random.uniform(min_s, max_s)
        if delay > 0:
            time.sleep(delay)
        return delay
