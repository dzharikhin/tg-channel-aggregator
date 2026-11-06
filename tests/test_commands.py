import asyncio
from argparse import ArgumentTypeError
from datetime import datetime
from types import SimpleNamespace

import pytest
from fakes import (
    DST,
    MP3_PARAMS,
    SRC,
    USER_ID,
    FakeBot,
    FakeHandlerClient,
    FakeQueue,
    FakeUserClient,
    mp3_message,
    pending_dms,
    photo_message,
)
from telethon.errors import ChannelPrivateError, RPCError
from telethon.tl.types import Channel, ChatPhotoEmpty

import channels
import client
import config


class _Msg:
    def __init__(self, text):
        self.message = text


class FakeEvent:
    def __init__(self, text, is_channel=False):
        self.is_channel = is_channel
        self.message = _Msg(text)


class FakeSubscribeEvent:
    def __init__(self, sender_id=USER_ID):
        self.sender_id = sender_id
        self.responses = []

    async def respond(self, text, **kwargs):
        self.responses.append(text)


def subscribe_args(src=SRC, dst=DST):
    args, err = client._parse_args(
        client.SUBSCRIBE_CMD,
        f"-s {src} -d {dst} -f mp3 -p '{MP3_PARAMS}'",
    )
    assert err is None
    return args


def fake_channel(post_messages=True, title="sink channel"):
    return SimpleNamespace(
        title=title,
        admin_rights=SimpleNamespace(post_messages=post_messages),
    )


def cancel_after_sleeps(sleeps, after):
    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= after:
            raise asyncio.CancelledError()

    return fake_sleep


def test_not_matched_command_matches_every_registered_cmd():
    samples = {
        "/start": True,
        "/start now": True,
        "/list": True,
        "/list --subs": True,
        "/subscribe -s 1 -d 2 -f mp3 -p {}": True,
        '/subscribe -s 1 -d 2 -f mp3 -p {} -r "0 9 * * *" -b 2': True,
        "/unsubscribe -s 1 -d 2": True,
        "/sync --pairs 1=full": True,
        "/nope": False,
        "hello": False,
        "04abcd1234": False,
    }
    for text, matched in samples.items():
        assert (
            client._not_matched_command(text) is not matched
        ), f"{text!r} registration mismatch"


def test_new_cmd_list_membership_keeps_not_matched_in_sync():
    # _not_matched_command is derived from CMDS: no hand-maintained tuples
    assert client.LIST_CMD in client.CMDS
    assert client.CMDS[0] is client.START_CMD


def test_filter_not_mapped():
    assert client._filter_not_mapped(FakeEvent("hello")) is True
    assert client._filter_not_mapped(FakeEvent("/list")) is False
    assert client._filter_not_mapped(FakeEvent("hello", is_channel=True)) is False


def test_parse_args_ok():
    args, err = client._parse_args(client.SUBSCRIBE_CMD, "-s 1 -d 2 -f mp3 -p {}")
    assert err is None
    assert (args.src_channel_id, args.dst_channel_id) == (1, 2)
    assert args.filter_type == "mp3" and args.filter_params == "{}"


def test_parse_args_missing_required_prints_help():
    args, err = client._parse_args(client.SUBSCRIBE_CMD, "-s 1")
    assert args is None
    assert "usage:" in err


def test_syncpairarg():
    fn = client.syncpairarg
    assert fn("err", "123=456") == (123, 456)
    assert fn("err", "all=full") == ("all", "full")
    assert fn("err", "123=full") == (123, "full")
    with pytest.raises(ArgumentTypeError):
        fn("err", "x=y")


def test_jsonarg():
    assert client.jsonarg('{"a": 1}') == '{"a": 1}'
    with pytest.raises(ArgumentTypeError):
        client.jsonarg("not json")


def test_cronarg():
    assert client.cronarg("0 9 * * *") == "0 9 * * *"
    assert client.cronarg("*/15 * * * *") == "*/15 * * * *"
    with pytest.raises(ArgumentTypeError):
        client.cronarg("not a cron")


def test_parse_args_schedule_options():
    args, err = client._parse_args(
        client.SUBSCRIBE_CMD, '-s 1 -d 2 -f mp3 -p {} -r "0 9 * * *" -m 100 -b 3'
    )
    assert err is None
    assert (args.src_channel_id, args.dst_channel_id) == (1, 2)
    assert args.schedule == "0 9 * * *"
    assert args.start_message_id == 100
    assert args.batch == 3


def test_parse_args_schedule_defaults():
    args, err = client._parse_args(client.SUBSCRIBE_CMD, "-s 1 -d 2 -f mp3 -p {}")
    assert err is None
    assert args.schedule is None
    assert args.start_message_id is None
    assert args.batch == 1


def test_parse_args_rejects_invalid_cron():
    args, err = client._parse_args(
        client.SUBSCRIBE_CMD, "-s 1 -d 2 -f mp3 -p {} -r nonsense"
    )
    assert args is None
    assert "usage:" in err


def test_build_help_covers_all_cmds_except_start():
    help_text = client.build_help()
    for cmd in client.CMDS[1:]:
        assert f"/{cmd.prog}" in help_text
        assert cmd.description in help_text
    assert "/sync" in help_text and "usage: sync" in help_text


async def test_subscribe_checks_bot_permission(data_path):
    event = FakeSubscribeEvent()
    bot = FakeBot(chats=[fake_channel(post_messages=False)])

    await client.process_subscribe(
        event, SimpleNamespace(user_client=FakeHandlerClient()), bot, subscribe_args()
    )

    assert "no permission to post" in event.responses[0]
    assert config.get_channel_subscriptions(USER_ID, SRC) == []


async def test_subscribe_unreachable_channel_reports_no_permission(data_path):
    event = FakeSubscribeEvent()
    bot = FakeBot(call_error=ChannelPrivateError(None))

    await client.process_subscribe(
        event, SimpleNamespace(user_client=FakeHandlerClient()), bot, subscribe_args()
    )

    assert "no permission to post" in event.responses[0]
    assert config.get_channel_subscriptions(USER_ID, SRC) == []


async def test_subscribe_creates_subscription_when_bot_may_post(data_path):
    event = FakeSubscribeEvent()
    bot = FakeBot(chats=[fake_channel(post_messages=True, title="the sink")])

    await client.process_subscribe(
        event, SimpleNamespace(user_client=FakeHandlerClient()), bot, subscribe_args()
    )

    assert event.responses[0].startswith(f"subscribed {SRC} -> {DST}")
    sinks = config.get_channel_subscriptions(USER_ID, SRC)
    assert [sink.name for sink in sinks] == ["the sink"]


async def test_subscribe_unreadable_source_reports_read_error(data_path):
    event = FakeSubscribeEvent()
    session = SimpleNamespace(
        user_client=FakeHandlerClient(
            call_error=ValueError("Could not find the input entity")
        )
    )
    bot = FakeBot(chats=[fake_channel(post_messages=True)])

    await client.process_subscribe(event, session, bot, subscribe_args())

    assert "READ access" in event.responses[0]
    assert "no permission" not in event.responses[0]
    assert config.get_channel_subscriptions(USER_ID, SRC) == []


async def test_subscribe_unresolvable_sink_reports_write_error(data_path):
    event = FakeSubscribeEvent()
    bot = FakeBot(call_error=ValueError("Could not find the input entity"))

    await client.process_subscribe(
        event, SimpleNamespace(user_client=FakeHandlerClient()), bot, subscribe_args()
    )

    assert "no permission to post" in event.responses[0]
    assert "READ access" not in event.responses[0]
    assert config.get_channel_subscriptions(USER_ID, SRC) == []


async def test_subscribe_reports_read_and_write_errors_together(data_path):
    event = FakeSubscribeEvent()
    session = SimpleNamespace(
        user_client=FakeHandlerClient(call_error=ChannelPrivateError(None))
    )
    bot = FakeBot(call_error=ValueError("Could not find the input entity"))

    await client.process_subscribe(event, session, bot, subscribe_args())

    assert "READ access" in event.responses[0]
    assert "no permission to post" in event.responses[0]
    assert config.get_channel_subscriptions(USER_ID, SRC) == []


async def test_subscribed_channel_list_falls_back_to_per_channel_resolution(
    data_path,
):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    src_channel = Channel(
        id=SRC,
        title="the source",
        access_hash=1,
        photo=ChatPhotoEmpty(),
        date=datetime(2026, 1, 1),
    )
    calls = []

    class FlakyUserClient(FakeHandlerClient):
        async def __call__(self, request):
            calls.append(request)
            if len(calls) == 1:
                raise ValueError("Could not find the input entity")
            return SimpleNamespace(chats=[src_channel])

    message_text, _, _ = await channels.build_subscribed_channel_response(
        USER_ID, FlakyUserClient(), []
    )

    assert len(calls) == 2
    assert "the source" in message_text
    assert "Unavailable" not in message_text


async def test_subscribed_channel_list_reports_unavailable_channels(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))

    class NoResolveUserClient(FakeHandlerClient):
        async def __call__(self, request):
            raise ValueError("Could not find the input entity")

    message_text, _, _ = await channels.build_subscribed_channel_response(
        USER_ID, NoResolveUserClient(), []
    )

    assert f"Unavailable: {SRC}" in message_text


def test_requeue_sync_with_progress():
    cmd = {"cmd": "sync", "channel_id": SRC, "from": "full"}
    queue = FakeQueue([cmd])
    queue.get_nowait()

    client.requeue_sync_with_progress(queue, cmd, 17)

    assert queue.acked == [cmd]
    assert queue.puts == [{"cmd": "sync", "channel_id": SRC, "from": 17}]

    queue.unacked.append(cmd)
    client.requeue_sync_with_progress(queue, cmd, None)
    assert queue.puts[-1] == {"cmd": "sync", "channel_id": SRC, "from": "full"}


async def test_sync_midwalk_rpcerror_acks_requeues_with_progress_and_backs_off(
    data_path, monkeypatch
):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    user_client = FakeUserClient(
        [mp3_message(1), photo_message(2), mp3_message(3)],
        fail_after=2,
        fail_with=RPCError(None, "takeout died"),
    )
    bot = FakeBot()
    cmd = {"cmd": "sync", "channel_id": SRC, "from": 1}
    queue = FakeQueue([cmd])
    sleeps = []
    monkeypatch.setattr(asyncio, "sleep", cancel_after_sleeps(sleeps, after=2))

    with pytest.raises(asyncio.CancelledError):
        await client.handle_queue_tasks(USER_ID, queue, user_client, bot)

    assert len(bot.sent_files) == 1  # message 1 went out before the failure
    assert queue.acked == [cmd]
    assert queue.puts == [{"cmd": "sync", "channel_id": SRC, "from": 2}]
    assert sleeps == [config.queue_retry_backoff_seconds, 1]
    assert [dm.key for dm in pending_dms()] == [f"sync-fail:{SRC}"]


async def test_sync_walk_completion_acks_command(data_path, monkeypatch):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    user_client = FakeUserClient([photo_message(1), photo_message(2)])
    cmd = {"cmd": "sync", "channel_id": SRC, "from": 1}
    queue = FakeQueue([cmd])
    sleeps = []
    monkeypatch.setattr(asyncio, "sleep", cancel_after_sleeps(sleeps, after=1))

    with pytest.raises(asyncio.CancelledError):
        await client.handle_queue_tasks(USER_ID, queue, user_client, FakeBot())

    assert queue.acked == [cmd]
    assert queue.puts == []
    assert pending_dms() == []


async def test_sync_unknown_from_token_fails_and_enqueues_dm(
    data_path, monkeypatch
):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    cmd = {"cmd": "sync", "channel_id": SRC, "from": "bogus"}
    queue = FakeQueue([cmd])
    sleeps = []
    monkeypatch.setattr(asyncio, "sleep", cancel_after_sleeps(sleeps, after=1))

    with pytest.raises(asyncio.CancelledError):
        await client.handle_queue_tasks(USER_ID, queue, FakeUserClient(), FakeBot())

    assert queue.acked_failed == [cmd]
    dms = pending_dms()
    assert [dm.key for dm in dms] == [f"cmd-fail:sync:{SRC}"]
    assert sleeps == [1]


async def test_unknown_cmd_fails_and_enqueues_dm(data_path, monkeypatch):
    cmd = {"cmd": "bogus"}
    queue = FakeQueue([cmd])
    sleeps = []
    monkeypatch.setattr(asyncio, "sleep", cancel_after_sleeps(sleeps, after=1))

    with pytest.raises(asyncio.CancelledError):
        await client.handle_queue_tasks(
            USER_ID, queue, FakeUserClient(), FakeBot()
        )

    assert queue.acked_failed == [cmd]
    dms = pending_dms()
    assert len(dms) == 1
    assert dms[0].key.startswith("cmd-fail:bogus")
    assert sleeps == [1]
