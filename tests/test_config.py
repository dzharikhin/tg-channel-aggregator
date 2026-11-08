import json
import logging

from fakes import DST, MP3_PARAMS, SRC, USER_ID

import config


def sink_file_path(data_path, sink_id=DST):
    return (
        data_path.joinpath(str(USER_ID))
        .joinpath("subscriptions")
        .joinpath(str(SRC))
        .joinpath(f"{sink_id}.json")
    )


def test_atomic_write_leaves_valid_json_and_no_tmp(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    raw = json.loads(sink_file_path(data_path).read_text())
    assert raw["sink_name"] == "sink"
    assert list(sink_file_path(data_path).parent.iterdir()) == [
        sink_file_path(data_path)
    ]


def test_update_sink_state_is_atomic(data_path):
    config.create_subscription(
        USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS), schedule="0 9 * * *"
    )
    config.update_sink_state(USER_ID, SRC, DST, {"last_forwarded_message_id": 5})
    raw = json.loads(sink_file_path(data_path).read_text())
    assert raw["state"] == {"last_forwarded_message_id": 5}
    assert not sink_file_path(data_path).with_suffix(".json.tmp").exists()


def test_corrupt_sink_file_is_skipped_with_warning(data_path, caplog):
    config.create_subscription(USER_ID, SRC, (DST, "good"), ("mp3", MP3_PARAMS))
    sink_file_path(data_path, 999).write_bytes(b"\xff\xfe\x00corrupt")
    with caplog.at_level(logging.WARNING):
        sinks = config.get_channel_subscriptions(USER_ID, SRC)
    assert [sink.id for sink in sinks] == [DST]
    assert any("skipping corrupt sink config" in rec.message for rec in caplog.records)


def test_tmp_files_are_not_sinks(data_path, caplog):
    config.create_subscription(USER_ID, SRC, (DST, "good"), ("mp3", MP3_PARAMS))
    sink_file_path(data_path).with_suffix(".json.tmp").write_text("garbage")
    with caplog.at_level(logging.WARNING):
        sinks = config.get_channel_subscriptions(USER_ID, SRC)
    assert [sink.id for sink in sinks] == [DST]
    assert not any("skipping corrupt" in rec.message for rec in caplog.records)


def test_get_all_user_subscriptions_survives_corrupt_file(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "good"), ("mp3", MP3_PARAMS))
    sink_file_path(data_path, 999).write_bytes(b"\xff\xfe")
    subscriptions = config.get_all_user_subscriptions(USER_ID)
    assert subscriptions[0][0] == SRC
    assert [sink.id for sink in subscriptions[0][1]] == [DST]


def test_create_subscription_writes_no_via_key(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    raw = json.loads(sink_file_path(data_path).read_text())
    assert "via" not in raw


def test_stale_via_key_in_sink_config_is_ignored(data_path):
    config.create_subscription(USER_ID, SRC, (DST, "sink"), ("mp3", MP3_PARAMS))
    raw = json.loads(sink_file_path(data_path).read_text())
    for stale_via in ("bot", "user"):
        raw["via"] = stale_via
        sink_file_path(data_path).write_text(json.dumps(raw))
        sinks = config.get_channel_subscriptions(USER_ID, SRC)
        assert [sink.id for sink in sinks] == [DST]
