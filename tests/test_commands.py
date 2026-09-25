from argparse import ArgumentTypeError

import pytest

import client


class _Msg:
    def __init__(self, text):
        self.message = text


class FakeEvent:
    def __init__(self, text, is_channel=False):
        self.is_channel = is_channel
        self.message = _Msg(text)


def test_not_matched_command_matches_every_registered_cmd():
    samples = {
        "/start": True,
        "/start now": True,
        "/list": True,
        "/list --subs": True,
        "/subscribe -s 1 -d 2 -f mp3 -p {}": True,
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


def test_build_help_covers_all_cmds_except_start():
    help_text = client.build_help()
    for cmd in client.CMDS[1:]:
        assert f"/{cmd.prog}" in help_text
        assert cmd.description in help_text
    assert "/sync" in help_text and "usage: sync" in help_text
