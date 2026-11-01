from datetime import datetime

import pytest
from telethon.tl.types import (
    Document,
    DocumentAttributeAudio,
    Message,
    MessageMediaDocument,
    MessageMediaEmpty,
    MessageMediaPhoto,
    PeerChannel,
)

from subscription import Filter, Mp3Filter, Sink


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


def test_factory_returns_mp3_filter():
    f = Filter.get_filter(
        **{"type": "mp3", "params": {"min_seconds": 1, "max_seconds": 2}}
    )
    assert isinstance(f, Mp3Filter)
    assert f.min_length_seconds == 1 and f.max_length_seconds == 2


def test_factory_rejects_unknown_type():
    with pytest.raises(ValueError):
        Filter.get_filter(**{"type": "flac", "params": {}})


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
