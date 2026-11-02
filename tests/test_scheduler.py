import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from telethon.errors import RPCError
from telethon.tl.types import (
    Document,
    DocumentAttributeAudio,
    Message,
    MessageMediaDocument,
    MessageMediaPhoto,
    PeerChannel,
)

import config
import scheduler
from subscription import Sink, forward_to_sinks

USER_ID = 42
SRC = 100
DST = 200
MP3_PARAMS = '{"min_seconds": 10, "max_seconds": 600}'


def mp3_message(id, duration=100):
    document = Document(
        id=1,
        access_hash=2,
        file_reference=b"",
        date=datetime(2026, 1, 1),
        mime_type="audio/mpeg",
        size=100,
        dc_id=1,
        attributes=[DocumentAttributeAudio(voice=False, duration=duration)],
    )
    return Message(
        id=id,
        peer_id=PeerChannel(channel_id=SRC),
        media=MessageMediaDocument(document=document),
    )


def photo_message(id):
    return Message(
        id=id, peer_id=PeerChannel(channel_id=SRC), media=MessageMediaPhoto()
    )


class FakeUserClient:
    def __init__(self, messages=()):
        self.messages = sorted(messages, key=lambda m: m.id)
        self.sent = []
        self.error_on_send = None

    async def __call__(self, request):
        return SimpleNamespace(chats=[SimpleNamespace(id=SRC)])

    async def get_messages(self, entity, limit=1):
        return self.messages[-limit:] if self.messages else []

    def iter_messages(self, entity, min_id=None, reverse=False):
        msgs = [m for m in self.messages if m.id > (min_id or 0)]
        if not reverse:
            msgs = list(reversed(msgs))

        async def _gen():
            for m in msgs:
                yield m

        return _gen()

    async def send_file(self, sink_id, media, caption=None):
        if self.error_on_send:
            raise self.error_on_send
        self.sent.append((sink_id, media, caption))


class FakeBot:
    def __init__(self):
        self.sent = []

    async def send_message(self, user_id, text, *args, **kwargs):
        self.sent.append((user_id, text))


@pytest.fixture
def data_path(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "data_path", tmp_path)
    tmp_path.joinpath(str(USER_ID)).mkdir()
    return tmp_path


def make_scheduled_sink(data_path, **kwargs):
    config.create_subscription(
        USER_ID,
        SRC,
        (DST, "sink"),
        ("mp3", MP3_PARAMS),
        schedule="0 9 * * *",
        **kwargs,
    )
    return config.get_channel_subscriptions(USER_ID, SRC)[0]


def read_state(data_path):
    raw = json.loads(
        data_path.joinpath(str(USER_ID))
        .joinpath("subscriptions")
        .joinpath(str(SRC))
        .joinpath(f"{DST}.json")
        .read_text()
    )
    return raw.get("state", {})


NOW = datetime(2026, 11, 2, 9, 0, 5)


def test_next_run_returns_first_occurrence_after_reference():
    assert scheduler.next_run("0 9 * * *", None, datetime(2026, 11, 2, 8, 0)) == (
        datetime(2026, 11, 2, 9, 0)
    )
    assert scheduler.next_run(
        "0 9 * * *", datetime(2026, 11, 1, 9, 0), datetime(2026, 11, 2, 9, 30)
    ) == datetime(2026, 11, 2, 9, 0)


def test_is_due_when_occurrence_missed():
    # last run yesterday, cron is daily: today's run is due (catch-up)
    assert scheduler.is_due("0 9 * * *", datetime(2026, 11, 1, 9, 0), NOW) is True


def test_is_due_false_before_next_occurrence():
    assert scheduler.is_due("0 9 * * *", datetime(2026, 11, 2, 9, 0), NOW) is False
    assert scheduler.is_due("0 9 * * *", None, datetime(2026, 11, 2, 8, 59)) is False


async def test_first_run_without_start_skips_whole_history(data_path):
    sink = make_scheduled_sink(data_path)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2)])

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    assert user_client.sent == []
    state = read_state(data_path)
    assert state["last_forwarded_message_id"] == 2
    assert state["last_run_at"] == NOW.isoformat()


async def test_start_message_id_defines_first_candidates(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2), mp3_message(3)])

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    # default batch is 1: only the next matching message is forwarded
    assert len(user_client.sent) == 1
    assert read_state(data_path)["last_forwarded_message_id"] == 2


async def test_batch_forwards_several_messages_per_run(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1, batch=2)
    user_client = FakeUserClient(
        [mp3_message(1), mp3_message(2), mp3_message(3), mp3_message(4)]
    )

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    assert len(user_client.sent) == 2
    assert read_state(data_path)["last_forwarded_message_id"] == 3
    # 4th message stays for the next run


async def test_next_run_resumes_after_drip_feed_pointer(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2), mp3_message(3)])

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)
    sink = config.get_channel_subscriptions(USER_ID, SRC)[0]
    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    assert len(user_client.sent) == 2


async def test_non_matching_tail_is_skipped_not_rescanned(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0)
    user_client = FakeUserClient([mp3_message(1), photo_message(2), photo_message(3)])

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    assert len(user_client.sent) == 1
    # history exhausted: pointer moves to the newest examined message
    assert read_state(data_path)["last_forwarded_message_id"] == 3


async def test_send_failure_notifies_and_keeps_failed_message(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0, batch=2)
    user_client = FakeUserClient([photo_message(1), mp3_message(2), mp3_message(3)])
    user_client.error_on_send = RPCError(None, "no write rights")
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert user_client.sent == []
    assert len(bot.sent) == 1
    state = read_state(data_path)
    # non-matching message before the failure is skipped, the failed one
    # stays the first candidate for the next run
    assert state["last_forwarded_message_id"] == 1
    # the run counts as done: retry happens on the next cron occurrence
    assert state["last_run_at"] == NOW.isoformat()


async def test_no_new_messages_is_a_noop(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=3)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2), mp3_message(3)])

    await scheduler.forward_step(USER_ID, user_client, FakeBot(), SRC, sink, NOW)

    assert user_client.sent == []
    state = read_state(data_path)
    assert state["last_forwarded_message_id"] == 3
    assert state["last_run_at"] == NOW.isoformat()


async def test_forward_to_sinks_skips_scheduled_sinks():
    scheduled = Sink(
        str(DST),
        json.dumps(
            {
                "sink_name": "scheduled",
                "schedule": "0 9 * * *",
                "filter": {"type": "mp3", "params": json.loads(MP3_PARAMS)},
            }
        ),
    )
    realtime = Sink(
        str(DST + 1),
        json.dumps(
            {
                "sink_name": "realtime",
                "filter": {"type": "mp3", "params": json.loads(MP3_PARAMS)},
            }
        ),
    )
    user_client = FakeUserClient()

    await forward_to_sinks(
        USER_ID, user_client, mp3_message(5), [scheduled, realtime], FakeBot()
    )

    assert [sink_id for sink_id, _, _ in user_client.sent] == [DST + 1]


def test_create_subscription_writes_schedule_and_anchor(data_path):
    make_scheduled_sink(data_path, start_message_id=10, batch=2)
    raw = json.loads(
        data_path.joinpath(str(USER_ID))
        .joinpath("subscriptions")
        .joinpath(str(SRC))
        .joinpath(f"{DST}.json")
        .read_text()
    )
    assert raw["schedule"] == "0 9 * * *"
    assert raw["start_message_id"] == 10
    assert raw["batch"] == 2
    assert "last_run_at" in raw["state"]
    assert "last_forwarded_message_id" not in raw["state"]


def test_create_subscription_without_schedule_has_no_state(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    raw = json.loads(
        data_path.joinpath(str(USER_ID))
        .joinpath("subscriptions")
        .joinpath(str(SRC))
        .joinpath(f"{DST}.json")
        .read_text()
    )
    assert "schedule" not in raw
    assert "state" not in raw
    assert "batch" not in raw


def test_resubscribe_preserves_state_when_schedule_unchanged(data_path):
    make_scheduled_sink(data_path, start_message_id=1)
    config.update_sink_state(
        USER_ID, SRC, DST, {"last_forwarded_message_id": 99, "last_run_at": "x"}
    )
    # batch/caption changes do not define the schedule: state must survive
    make_scheduled_sink(data_path, start_message_id=1, batch=5)
    assert read_state(data_path)["last_forwarded_message_id"] == 99


def test_resubscribe_resets_state_when_schedule_defining_option_changed(data_path):
    make_scheduled_sink(data_path, start_message_id=1)
    config.update_sink_state(
        USER_ID, SRC, DST, {"last_forwarded_message_id": 99, "last_run_at": "x"}
    )
    make_scheduled_sink(data_path, start_message_id=2)
    state = read_state(data_path)
    assert "last_forwarded_message_id" not in state
    assert "last_run_at" in state


def test_resubscribe_resets_state_when_schedule_removed_or_added(data_path):
    make_scheduled_sink(data_path)
    config.update_sink_state(
        USER_ID, SRC, DST, {"last_forwarded_message_id": 99, "last_run_at": "x"}
    )
    # turning back into a realtime sink drops the state entirely
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    assert read_state(data_path) == {}

    # and a fresh scheduled subscription starts with a new anchor
    make_scheduled_sink(data_path)
    assert "last_run_at" in read_state(data_path)


def test_update_sink_state_roundtrip(data_path):
    make_scheduled_sink(data_path)
    config.update_sink_state(USER_ID, SRC, DST, {"last_forwarded_message_id": 7})
    assert read_state(data_path) == {"last_forwarded_message_id": 7}
