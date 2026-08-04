"""
WebOSINT Pro - Browser Profile Simulation
Provides realistic browser header sets for privacy-aware scanning.

Purpose: Simulate legitimate browser traffic patterns to reduce
detection noise in authorized testing environments.
NOT for bypassing security controls — only for realistic recon simulation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class BrowserProfile:
    name: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: str = ""
    sec_ch_ua_platform: str = ""
    sec_ch_ua_mobile: str = "?0"
    connection: str = "keep-alive"
    upgrade_insecure: str = "1"
    extra_headers: dict[str, str] = field(default_factory=dict)

    def to_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept": self.accept,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
            "Connection": self.connection,
        }
        if self.sec_ch_ua:
            headers["sec-ch-ua"] = self.sec_ch_ua
            headers["sec-ch-ua-mobile"] = self.sec_ch_ua_mobile
            headers["sec-ch-ua-platform"] = self.sec_ch_ua_platform
        if self.upgrade_insecure:
            headers["Upgrade-Insecure-Requests"] = self.upgrade_insecure
        headers.update(self.extra_headers)
        return headers


# ── Profile database ─────────────────────────────────────────────────────────────

PROFILES: list[BrowserProfile] = [
    BrowserProfile(
        name="chrome-win11",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
    ),
    BrowserProfile(
        name="firefox-linux",
        user_agent=("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        upgrade_insecure="1",
    ),
    BrowserProfile(
        name="safari-mac",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.4 Safari/605.1.15"
        ),
        accept=("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
        accept_language="en-GB,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        upgrade_insecure="1",
    ),
    BrowserProfile(
        name="edge-win11",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
    ),
    BrowserProfile(
        name="chrome-android",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.6367.82 Mobile Safari/537.36"
        ),
        accept=(
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"Android"',
    ),
    BrowserProfile(
        name="googlebot",
        user_agent=("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        accept="*/*",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        upgrade_insecure="",
    ),
    BrowserProfile(
        name="bingbot",
        user_agent=("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
        accept="*/*",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate",
        upgrade_insecure="",
    ),
]

_PROFILE_MAP: dict[str, BrowserProfile] = {p.name: p for p in PROFILES}


class BrowserProfileManager:
    """Selects and rotates browser profiles for detection-aware scanning."""

    def __init__(
        self,
        profile_name: str | None = None,
        rotate: bool = False,
    ) -> None:
        self._rotate = rotate
        self._idx = 0

        if profile_name and profile_name in _PROFILE_MAP:
            self._profiles = [_PROFILE_MAP[profile_name]]
        else:
            # Default: realistic non-bot profiles only
            self._profiles = [p for p in PROFILES if p.name not in ("googlebot", "bingbot")]

    def get_headers(self) -> dict[str, str]:
        """Return headers for the next profile in rotation."""
        if self._rotate:
            profile = self._profiles[self._idx % len(self._profiles)]
            self._idx += 1
        else:
            profile = self._profiles[0]
        return profile.to_headers()

    def get_random_headers(self) -> dict[str, str]:
        return random.choice(self._profiles).to_headers()

    def get_user_agent(self) -> str:
        return self.get_headers()["User-Agent"]

    @classmethod
    def profile_names(cls) -> list[str]:
        return [p.name for p in PROFILES]
