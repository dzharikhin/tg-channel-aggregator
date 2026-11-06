import asyncio
import json
from types import SimpleNamespace

import pytest
from fakes import (
    DST,
    MP3_PARAMS,
    SRC,
    USER_ID,
    FakeBot,
    FakeUserClient,
    mp3_message,
    pending_dms,
    photo_message,
    sink_message,
    text_message,
)
from telethon.errors import ChatWriteForbiddenError, FloodWaitError, RPCError
from telethon.tl.types import PeerChat, PeerUser

import common
import config
from subscription import (
    ChannelHistoryError,
    Outcome,
    Sink,
    build_caption,
    deliver_to_sink,
    forward_channel_history,
    forward_to_sinks,
    new_message_in_target_channel_handler,
)

MARKED_SRC = -1000000000100


def make_sink(sink_id=DST, caption="link"):
    return Sink(
        str(sink_id),
        json.dumps(
            {
                "sink_name": f"sink{sink_id}",
                "caption": caption,
                "filter": {
                    "type": "mp3",
                    "params": {"min_seconds": 10, "max_seconds": 600},
                },
            }
        ),
    )


def recorded_sleep(monkeypatch):
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return sleeps


async def test_same_document_id_in_history_is_skipped():
    source = mp3_message(5, document_id=101)
    user_client = FakeUserClient(sink_history=[sink_message(1, media=source.media)])
    bot = FakeBot()
    result = await deliver_to_sink(USER_ID, user_client, bot, make_sink(), source)
    assert result.outcome == Outcome.SKIPPED_DUPLICATE
    assert bot.sent_files == []


async def test_fallback_tuple_match_is_skipped():
    source = mp3_message(5, document_id=101, file_name="track.mp3", size=1000)
    other = mp3_message(9, document_id=999, file_name="track.mp3", size=1000)
    user_client = FakeUserClient(sink_history=[sink_message(1, media=other.media)])
    bot = FakeBot()
    result = await deliver_to_sink(USER_ID, user_client, bot, make_sink(), source)
    assert result.outcome == Outcome.SKIPPED_DUPLICATE
    assert bot.sent_files == []


async def test_different_document_is_sent():
    source = mp3_message(5, document_id=101, file_name="a.mp3", size=1000)
    other = mp3_message(9, document_id=999, file_name="b.mp3", size=2000)
    user_client = FakeUserClient(sink_history=[sink_message(1, media=other.media)])
    bot = FakeBot()
    result = await deliver_to_sink(USER_ID, user_client, bot, make_sink(), source)
    assert result.outcome == Outcome.SENT
    assert len(bot.sent_files) == 1


async def test_text_only_dedup_uses_normalized_caption():
    sink = make_sink(caption="original")
    source = text_message(5, "Hello, World!")
    user_client = FakeUserClient(sink_history=[sink_message(1, text="hello   world")])
    bot = FakeBot()
    result = await deliver_to_sink(USER_ID, user_client, bot, sink, source)
    assert result.outcome == Outcome.SKIPPED_DUPLICATE
    assert bot.sent_files == []


async def test_dedup_read_failure_fails_closed_and_enqueues_dm():
    user_client = FakeUserClient(iter_errors=[RPCError(None, "history unreadable")])
    bot = FakeBot()
    await forward_to_sinks(USER_ID, user_client, mp3_message(5), [make_sink()], bot)
    assert bot.sent_files == []
    assert [dm.key for dm in pending_dms()] == [f"dedup-read-fail:{DST}"]


async def test_floodwait_once_then_sent(monkeypatch):
    sleeps = recorded_sleep(monkeypatch)
    user_client = FakeUserClient()
    bot = FakeBot()
    bot.file_errors = [FloodWaitError(None, 10)]
    result = await deliver_to_sink(
        USER_ID, user_client, bot, make_sink(), mp3_message(5)
    )
    assert result.outcome == Outcome.SENT
    assert sleeps == [11]
    assert len(bot.sent_files) == 1


async def test_floodwait_twice_fails_and_enqueues_dm(monkeypatch):
    sleeps = recorded_sleep(monkeypatch)
    user_client = FakeUserClient()
    bot = FakeBot()
    bot.file_errors = [FloodWaitError(None, 10), FloodWaitError(None, 20)]
    await forward_to_sinks(USER_ID, user_client, mp3_message(5), [make_sink()], bot)
    assert bot.sent_files == []
    assert sleeps == [11]
    assert [dm.key for dm in pending_dms()] == [f"send-flood:{DST}"]


async def test_permission_error_fails_and_stops_step():
    user_client = FakeUserClient()
    bot = FakeBot()
    bot.file_errors = [ChatWriteForbiddenError(None)]
    result = await deliver_to_sink(
        USER_ID, user_client, bot, make_sink(), mp3_message(5)
    )
    assert result.outcome == Outcome.FAILED
    assert result.key == f"send-perm:{DST}"
    assert result.stop_step is True


async def test_unknown_error_fails_without_raising():
    user_client = FakeUserClient()
    bot = FakeBot()
    bot.file_errors = [ValueError("boom")]
    result = await deliver_to_sink(
        USER_ID, user_client, bot, make_sink(), mp3_message(5)
    )
    assert result.outcome == Outcome.FAILED
    assert result.key == f"send-unknown:{DST}:ValueError"
    assert result.stop_step is False


async def test_pacer_spaces_consecutive_bot_calls(monkeypatch):
    monkeypatch.setattr(common, "_pacer", common.Pacer(0.05))
    call_times = []
    user_client = FakeUserClient(call_times=call_times)
    bot = FakeBot(call_times=call_times)
    await deliver_to_sink(
        USER_ID,
        user_client,
        bot,
        make_sink(),
        mp3_message(5, document_id=101),
    )
    await deliver_to_sink(
        USER_ID,
        user_client,
        bot,
        make_sink(),
        mp3_message(6, document_id=102),
    )
    assert len(call_times) == 4
    gaps = [b - a for a, b in zip(call_times, call_times[1:])]
    assert min(gaps) >= 0.045


async def test_forward_channel_history_returns_last_processed_id(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    user_client = FakeUserClient([mp3_message(1), photo_message(2), mp3_message(3)])
    bot = FakeBot()

    last_id = await forward_channel_history(USER_ID, user_client, bot, SRC, min_id=0)

    assert last_id == 3
    assert len(bot.sent_files) == 2


async def test_forward_channel_history_full_walk_without_min_id(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    user_client = FakeUserClient([mp3_message(1), mp3_message(2)])
    bot = FakeBot()

    last_id = await forward_channel_history(USER_ID, user_client, bot, SRC)

    assert last_id == 2
    assert len(bot.sent_files) == 2


async def test_forward_channel_history_without_sinks_returns_none(data_path):
    user_client = FakeUserClient([mp3_message(1)])
    bot = FakeBot()

    last_id = await forward_channel_history(USER_ID, user_client, bot, SRC)

    assert last_id is None
    assert bot.sent_files == []


async def test_forward_channel_history_unavailable_channel_raises():
    user_client = FakeUserClient(
        get_entity_error=ValueError("Could not find the input entity")
    )
    with pytest.raises(ValueError):
        await forward_channel_history(USER_ID, user_client, FakeBot(), SRC)


async def test_forward_channel_history_failure_carries_progress(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    user_client = FakeUserClient(
        [mp3_message(1), mp3_message(2)],
        fail_after=1,
        fail_with=RPCError(None, "takeout died"),
    )

    with pytest.raises(ChannelHistoryError) as exc_info:
        await forward_channel_history(USER_ID, user_client, FakeBot(), SRC, min_id=0)

    assert exc_info.value.last_processed_id == 1
    assert isinstance(exc_info.value.cause, RPCError)


def test_link_caption_keeps_tme_link_for_channel_messages():
    message = mp3_message(5)
    assert build_caption("link", message) == f"https://t.me/c/{SRC}/{message.id}"


def test_link_caption_falls_back_to_original_text_for_chat_messages():
    message = text_message(5, "hello")
    message.peer_id = PeerChat(456)
    assert build_caption("link", message) == "hello"


def test_link_caption_falls_back_to_original_text_for_dm_messages():
    message = text_message(5, "hello")
    message.peer_id = PeerUser(88)
    assert build_caption("link", message) == "hello"


async def test_realtime_handler_uses_marked_chat_id(data_path):
    config.create_subscription(USER_ID, MARKED_SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    bot = FakeBot()
    event = SimpleNamespace(chat_id=MARKED_SRC, message=mp3_message(1))

    await new_message_in_target_channel_handler(USER_ID, FakeUserClient(), bot, event)

    assert len(bot.sent_files) == 1


async def test_realtime_handler_ignores_non_canonical_chat_id_spelling(data_path):
    config.create_subscription(USER_ID, MARKED_SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    bot = FakeBot()
    event = SimpleNamespace(chat_id=SRC, message=mp3_message(1))

    await new_message_in_target_channel_handler(USER_ID, FakeUserClient(), bot, event)

    assert bot.sent_files == []
