import asyncio
import os
import re
import time
import unicodedata
from typing import Optional

from telethon.tl.types import User

_pacer: "Optional[Pacer]" = None


def is_debug():
    return "true" == os.getenv("DEBUG", "False").lower()


def entity_name(entity) -> str:
    if isinstance(entity, User):
        return entity.first_name or str(entity.id)
    return entity.title


def norm(s: Optional[str]) -> str:
    """lowercase, strip accents/punctuation; keeps latin + cyrillic letters."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower().replace("ё", "е")
    return re.sub(r"[^0-9a-zа-я]+", "", s)


class Pacer:
    """Queue-poll-style sleep pacing: min interval between consecutive waits."""

    def __init__(self, min_interval_seconds: float):
        self._min = min_interval_seconds
        self._last = 0.0
        self._lock: Optional[asyncio.Lock] = None  # created lazily (loop-bound)

    async def wait(self) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            delay = self._last + self._min - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = time.monotonic()


def get_pacer() -> Pacer:
    global _pacer
    if _pacer is None:
        import config

        _pacer = Pacer(config.send_min_interval_seconds)
    return _pacer
