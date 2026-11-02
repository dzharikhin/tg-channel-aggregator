from datetime import datetime

import pytest
from telethon.tl.types import (
    Document,
    DocumentAttributeAudio,
    Message,
    MessageEntityHashtag,
    MessageMediaDocument,
    MessageMediaEmpty,
    MessageMediaPhoto,
    PeerChannel,
)

from subscription import Filter, HashtagFilter, Mp3Filter, Sink, build_caption


def audio_message(mime_type="audio/mpeg", duration=100, with_audio_attr=True):
    document = Document(
        id=1,
        access_hash=2,
        file_reference=b"",
        date=datetime(2026, 1, 1),
        mime_type=mime_type,
        size=100,
        dc_id=1,
        attributes=(
            [DocumentAttributeAudio(voice=False, duration=duration)]
            if with_audio_attr
            else []
        ),
    )
    return _message(MessageMediaDocument(document=document))


def _message(media):
    return Message(id=5, peer_id=PeerChannel(channel_id=7), media=media)


def _text_message(text, hashtags=()):
    # server-side entity offsets are UTF-16 code units; test strings are BMP-only
    # (except the surrogate test below), so python indices == UTF-16 offsets here
    entities = [
        MessageEntityHashtag(offset=text.index(tag), length=len(tag))
        for tag in hashtags
    ]
    return Message(
        id=5, peer_id=PeerChannel(channel_id=7), message=text, entities=entities
    )


def test_factory_returns_mp3_filter():
    f = Filter.get_filter(
        **{"type": "mp3", "params": {"min_seconds": 1, "max_seconds": 2}}
    )
    assert isinstance(f, Mp3Filter)
    assert f.min_length_seconds == 1 and f.max_length_seconds == 2


def test_factory_rejects_unknown_type():
    with pytest.raises(ValueError):
        Filter.get_filter(**{"type": "flac", "params": {}})


def test_factory_returns_hashtag_filter():
    f = Filter.get_filter(**{"type": "hashtag", "params": {"tags": ["#podcast"]}})
    assert isinstance(f, HashtagFilter)
    assert f.tags == {"podcast"}


def test_hashtag_filter_accepts_single_string_tag():
    f = HashtagFilter(tags="podcast")
    assert f.tags == {"podcast"}
    assert (
        f.filter_message(_text_message("listen #podcast now", hashtags=("#podcast",)))
        is True
    )


@pytest.mark.parametrize(
    "message,expected",
    [
        (None, False),
        ("plain string, not a Message", False),
        (_message(MessageMediaEmpty()), False),
        (_text_message("no tags at all"), False),
        (_text_message("example.com/#podcast", hashtags=()), False),
        (_text_message("new track #music", hashtags=("#music",)), False),
        (_text_message("listen #podcast now", hashtags=("#podcast",)), True),
        (_text_message("listen #Podcast now", hashtags=("#Podcast",)), True),
        (_text_message("#news and #podcast", hashtags=("#news", "#podcast")), True),
    ],
)
def test_hashtag_filter_matrix(message, expected):
    f = HashtagFilter(tags=["#podcast"])
    assert f.filter_message(message) is expected


def test_hashtag_filter_multiple_configured_tags_any_match():
    f = HashtagFilter(tags=["#daily", "#podcast"])
    assert (
        f.filter_message(_text_message("hey #podcast", hashtags=("#podcast",))) is True
    )
    assert f.filter_message(_text_message("hey #music", hashtags=("#music",))) is False


def test_hashtag_filter_handles_utf16_surrogate_offsets():
    # 🎧 is 2 UTF-16 code units but 1 python char, so entity offsets differ
    text = "🎧 #podcast"
    message = Message(
        id=5,
        peer_id=PeerChannel(channel_id=7),
        message=text,
        entities=[MessageEntityHashtag(offset=3, length=8)],
    )
    assert HashtagFilter(tags=["podcast"]).filter_message(message) is True


def test_hashtag_filter_repr():
    assert "HashtagFilter" in repr(HashtagFilter(tags=["#podcast"]))


@pytest.mark.parametrize(
    "message,expected",
    [
        (None, False),
        ("plain string, not a Message", False),
        (_message(MessageMediaEmpty()), False),
        (_message(MessageMediaPhoto()), False),
        (audio_message(mime_type="audio/vorbis"), False),
        (audio_message(with_audio_attr=False), False),
        (audio_message(duration=30), False),
        (audio_message(duration=600), False),
        (audio_message(duration=200), True),
        (audio_message(duration=90), True),
        (audio_message(duration=480), True),
    ],
)
def test_mp3_filter_matrix(message, expected):
    f = Mp3Filter(min_seconds=90, max_seconds=480)
    assert f.filter_message(message) is expected


def test_sink_reads_stored_config():
    sink = Sink(
        "123",
        '{"sink_name": "mine", "filter": {"type": "mp3", "params":'
        ' {"min_seconds": 10, "max_seconds": 600}}}',
    )
    assert sink.id == 123 and sink.name == "mine"
    assert sink.filter_message(audio_message(duration=200)) is True
    assert "Mp3Filter" in repr(sink)


def test_sink_caption_defaults_to_link_when_absent():
    sink = Sink(
        "123",
        '{"sink_name": "mine", "filter": {"type": "mp3", "params":'
        ' {"min_seconds": 10, "max_seconds": 600}}}',
    )
    assert sink.caption == "link"


def test_sink_schedule_fields_default_when_absent():
    sink = Sink(
        "123",
        '{"sink_name": "mine", "filter": {"type": "mp3", "params":'
        ' {"min_seconds": 10, "max_seconds": 600}}}',
    )
    assert sink.schedule is None
    assert sink.start_message_id is None
    assert sink.batch == 1
    assert sink.state == {}


def test_sink_reads_schedule_fields_from_config():
    sink = Sink(
        "123",
        '{"sink_name": "mine", "schedule": "0 9 * * *", "start_message_id": 42,'
        ' "batch": 3, "state": {"last_forwarded_message_id": 43}, "filter":'
        ' {"type": "mp3", "params": {"min_seconds": 10, "max_seconds": 600}}}',
    )
    assert sink.schedule == "0 9 * * *"
    assert sink.start_message_id == 42
    assert sink.batch == 3
    assert sink.state == {"last_forwarded_message_id": 43}


def test_sink_reads_caption_from_config():
    sink = Sink(
        "123",
        '{"sink_name": "mine", "caption": "none", "filter": {"type": "hashtag",'
        ' "params": {"tags": ["#podcast"]}}}',
    )
    assert sink.caption == "none"
    assert (
        sink.filter_message(_text_message("#podcast", hashtags=("#podcast",))) is True
    )
    assert "HashtagFilter" in repr(sink)


def test_sink_rejects_unknown_caption_mode():
    with pytest.raises(ValueError):
        Sink(
            "123",
            '{"sink_name": "mine", "caption": "asterisks", "filter": {"type":'
            ' "mp3", "params": {"min_seconds": 10, "max_seconds": 600}}}',
        )


def test_build_caption_modes():
    message = _text_message("original text #podcast", hashtags=("#podcast",))
    assert build_caption("none", message) is None
    assert build_caption("link", message) == "https://t.me/c/7/5"
    assert build_caption("original", message) == "original text #podcast"


def test_build_caption_rejects_unknown_mode():
    with pytest.raises(ValueError):
        build_caption("asterisks", _text_message("hi"))
