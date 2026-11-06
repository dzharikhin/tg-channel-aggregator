import asyncio
import contextlib

from fakes import USER_ID, FakeBot, dm_message
from telethon.errors import FloodWaitError

import config
import notifications


def dm_history(*keys):
    return [dm_message(f"report\n\n`key:{key}`") for key in keys]


async def test_enqueue_then_processor_delivers_with_key_line():
    bot = FakeBot()
    task = asyncio.create_task(notifications.run_dm_processor(bot))
    notifications.enqueue_error_dm(USER_ID, "k1", "something broke")
    for _ in range(100):
        if bot.sent_messages:
            break
        await asyncio.sleep(0.01)
    with contextlib.suppress(asyncio.CancelledError):
        task.cancel()
        await task
    assert len(bot.sent_messages) == 1
    user_id, text = bot.sent_messages[0]
    assert user_id == USER_ID
    assert text.startswith("something broke")
    assert text.endswith("`key:k1`")


async def test_duplicate_key_in_recent_history_is_dropped():
    bot = FakeBot(history=dm_history("k1"))
    await notifications._deliver(bot, notifications.DM(USER_ID, "k1", "boom"))
    assert bot.sent_messages == []


async def test_different_key_in_history_is_delivered():
    bot = FakeBot(history=dm_history("other"))
    await notifications._deliver(bot, notifications.DM(USER_ID, "k1", "boom"))
    assert len(bot.sent_messages) == 1


def test_full_queue_drops_newest_without_raising(monkeypatch):
    monkeypatch.setattr(config, "dm_queue_maxsize", 2)
    notifications.enqueue_error_dm(USER_ID, "k1", "one")
    notifications.enqueue_error_dm(USER_ID, "k2", "two")
    notifications.enqueue_error_dm(USER_ID, "k3", "three")
    assert notifications._dm_queue().qsize() == 2


async def test_send_failures_backoff_then_give_up(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(config, "dm_max_attempts", 9)
    bot = FakeBot()
    bot.message_errors = [RuntimeError("nope")] * 9
    await notifications._deliver(bot, notifications.DM(USER_ID, "k1", "boom"))
    assert bot.sent_messages == []
    assert sleeps == [30, 60, 120, 240, 480, 960, 1920, 3600]


async def test_floodwait_sleeps_server_wait_without_backoff_growth(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    bot = FakeBot()
    bot.message_errors = [FloodWaitError(None, 17)]
    await notifications._deliver(bot, notifications.DM(USER_ID, "k1", "boom"))
    assert sleeps == [18]
    assert len(bot.sent_messages) == 1
