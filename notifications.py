import asyncio
import dataclasses
import logging
import re
from datetime import datetime, timedelta

from telethon import TelegramClient
from telethon.errors import FloodWaitError

import config
from common import get_pacer

logger = logging.getLogger(__file__)

_KEY_LINE_RE = re.compile(r"`key:([^`]+)`\s*$")


@dataclasses.dataclass
class DM:
    user_id: int
    key: str
    text: str


_queue: asyncio.Queue | None = None


def _dm_queue() -> asyncio.Queue:
    global _queue
    if _queue is None:
        _queue = asyncio.Queue(maxsize=config.dm_queue_maxsize)
    return _queue


def enqueue_error_dm(user_id: int, key: str, text: str) -> None:
    try:
        _dm_queue().put_nowait(DM(user_id, key, text))
    except asyncio.QueueFull:
        logger.warning(f"DM queue is full, dropping DM {key} for {user_id}")


async def run_dm_processor(bot_client: TelegramClient) -> None:
    while True:
        dm = await _dm_queue().get()
        await _deliver(bot_client, dm)


async def _deliver(bot_client: TelegramClient, dm: DM) -> None:
    backoff = config.dm_backoff_start_seconds
    for attempt in range(1, config.dm_max_attempts + 1):
        try:
            await get_pacer().wait()
            recent_keys = await _recent_dm_keys(bot_client, dm.user_id)
            if dm.key in recent_keys:
                logger.debug(f"dropping duplicate DM {dm.key} for {dm.user_id}")
                return
            await bot_client.send_message(dm.user_id, f"{dm.text}\n\n`key:{dm.key}`")
            return
        except FloodWaitError as e:
            await asyncio.sleep(e.seconds + 1)
        except Exception:
            if attempt == config.dm_max_attempts:
                logger.warning(f"dropping DM after {attempt} attempts: {dm}")
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, config.dm_backoff_cap_seconds)


async def _recent_dm_keys(bot_client: TelegramClient, user_id: int) -> set[str]:
    offset_date = datetime.now() - timedelta(
        seconds=config.error_notify_throttle_seconds
    )
    keys = set()
    async for message in bot_client.iter_messages(user_id, offset_date=offset_date):
        match = _KEY_LINE_RE.search(message.message or "")
        if match:
            keys.add(match.group(1))
    return keys
