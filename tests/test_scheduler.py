import json
from datetime import datetime

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
)
from telethon.errors import ChatWriteForbiddenError

import config
import scheduler
from subscription import Sink, forward_to_sinks


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
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert bot.sent_files == []
    state = read_state(data_path)
    assert state["last_forwarded_message_id"] == 2
    assert state["last_run_at"] == NOW.isoformat()


async def test_start_message_id_defines_first_candidates(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1)
    user_client = FakeUserClient(
        [mp3_message(1), mp3_message(2), mp3_message(3)]
    )
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    # default batch is 1: only the next matching message is forwarded
    assert len(bot.sent_files) == 1
    assert read_state(data_path)["last_forwarded_message_id"] == 2


async def test_batch_forwards_several_messages_per_run(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1, batch=2)
    user_client = FakeUserClient(
        [mp3_message(1), mp3_message(2), mp3_message(3), mp3_message(4)]
    )
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert len(bot.sent_files) == 2
    assert read_state(data_path)["last_forwarded_message_id"] == 3
    # 4th message stays for the next run


async def test_next_run_resumes_after_drip_feed_pointer(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=1)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2), mp3_message(3)])
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)
    sink = config.get_channel_subscriptions(USER_ID, SRC)[0]
    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert len(bot.sent_files) == 2


async def test_non_matching_tail_is_skipped_not_rescanned(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0)
    user_client = FakeUserClient(
        [mp3_message(1), photo_message(2), photo_message(3)]
    )
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert len(bot.sent_files) == 1
    # history exhausted: pointer moves to the newest examined message
    assert read_state(data_path)["last_forwarded_message_id"] == 3


async def test_send_failure_advances_pointer_enqueues_dm_and_continues(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0, batch=2)
    user_client = FakeUserClient([photo_message(1), mp3_message(2), mp3_message(3)])
    bot = FakeBot()
    bot.file_errors = [RuntimeError("boom")]

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    # message 2 failed permanently, message 3 was still processed
    assert len(bot.sent_files) == 1
    state = read_state(data_path)
    assert state["last_forwarded_message_id"] == 3
    # the run counts as done: no retry of the failed message
    assert state["last_run_at"] == NOW.isoformat()
    assert "send-unknown:200:RuntimeError" in state["last_send_error"]
    assert [dm.key for dm in pending_dms()] == ["send-unknown:200:RuntimeError"]


async def test_permission_failure_stops_step_and_enqueues_dm(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0, batch=2)
    user_client = FakeUserClient([photo_message(1), mp3_message(2), mp3_message(3)])
    bot = FakeBot()
    bot.file_errors = [ChatWriteForbiddenError(None)]

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert bot.sent_files == []
    state = read_state(data_path)
    # pointer advances PAST the failed message, but the step stops
    assert state["last_forwarded_message_id"] == 2
    assert state["last_run_at"] == NOW.isoformat()
    assert "send-perm:200" in state["last_send_error"]
    assert [dm.key for dm in pending_dms()] == ["send-perm:200"]


async def test_dedup_skip_advances_pointer_without_dm(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=0, batch=5)
    duplicated = mp3_message(2, document_id=102, file_name="2.mp3", size=102)
    user_client = FakeUserClient(
        [
            mp3_message(1, document_id=101, file_name="1.mp3", size=101),
            duplicated,
            mp3_message(3, document_id=103, file_name="3.mp3", size=103),
        ]
    )
    bot = FakeBot(history=[sink_message(7, media=duplicated.media)])

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    # only the duplicated middle message is suppressed
    assert len(bot.sent_files) == 2
    state = read_state(data_path)
    assert state["last_forwarded_message_id"] == 3
    assert pending_dms() == []


async def test_no_new_messages_is_a_noop(data_path):
    sink = make_scheduled_sink(data_path, start_message_id=3)
    user_client = FakeUserClient([mp3_message(1), mp3_message(2), mp3_message(3)])
    bot = FakeBot()

    await scheduler.forward_step(USER_ID, user_client, bot, SRC, sink, NOW)

    assert bot.sent_files == []
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
    bot = FakeBot()

    await forward_to_sinks(USER_ID, mp3_message(5), [scheduled, realtime], bot)

    assert [sink_id for sink_id, _, _ in bot.sent_files] == [DST + 1]


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
