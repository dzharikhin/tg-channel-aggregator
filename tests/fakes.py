"""Shared test fakes: bot/user clients, queue, message builders."""

import time
from datetime import datetime
from types import SimpleNamespace

import persistqueue
from telethon.errors import RPCError
from telethon.tl.types import (
    Document,
    DocumentAttributeAudio,
    DocumentAttributeFilename,
    Message,
    MessageMediaDocument,
    MessageMediaPhoto,
    PeerChannel,
)

import notifications

USER_ID = 42
SRC = 100
DST = 200
MP3_PARAMS = '{"min_seconds": 10, "max_seconds": 600}'


def mp3_message(
    id,
    duration=100,
    document_id=1,
    file_name=None,
    mime_type="audio/mpeg",
    size=100,
):
    attributes = [DocumentAttributeAudio(voice=False, duration=duration)]
    if file_name is not None:
        attributes.append(DocumentAttributeFilename(file_name=file_name))
    document = Document(
        id=document_id,
        access_hash=2,
        file_reference=b"",
        date=datetime(2026, 1, 1),
        mime_type=mime_type,
        size=size,
        dc_id=1,
        attributes=attributes,
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


def text_message(id, text):
    return Message(id=id, peer_id=PeerChannel(channel_id=SRC), message=text)


def sink_message(id, media=None, text=""):
    return Message(
        id=id, peer_id=PeerChannel(channel_id=DST), media=media, message=text
    )


def dm_message(text):
    return SimpleNamespace(message=text)


def pending_dms() -> list:
    queue = notifications._dm_queue()
    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


class FakeBot:
    """Fake bot client for the delivery pipeline, DM processor and commands."""

    def __init__(self, history=(), chats=None, call_error=None, call_times=None):
        self.history = list(history)
        self.chats = chats
        self.call_error = call_error
        self.call_times = call_times
        self.sent_files = []  # (sink_id, media, caption)
        self.sent_messages = []  # (user_id, text)
        self.file_errors = []
        self.message_errors = []
        self.iter_errors = []
        self.requests = []

    def _track_call(self):
        if self.call_times is not None:
            self.call_times.append(time.monotonic())

    async def __call__(self, request):
        self._track_call()
        self.requests.append(request)
        if self.call_error is not None:
            raise self.call_error
        return SimpleNamespace(chats=self.chats)

    async def send_file(self, sink_id, media, caption=None):
        self._track_call()
        if self.file_errors:
            raise self.file_errors.pop(0)
        self.sent_files.append((sink_id, media, caption))

    async def send_message(self, user_id, text, *args, **kwargs):
        self._track_call()
        if self.message_errors:
            raise self.message_errors.pop(0)
        self.sent_messages.append((user_id, text))

    def iter_messages(self, entity, offset_date=None, **kwargs):
        self._track_call()
        if self.iter_errors:
            raise self.iter_errors.pop(0)

        async def _gen():
            for message in self.history:
                yield message

        return _gen()


class FakeUserClient:
    """Fake user client: listens to sources, never sends."""

    def __init__(self, messages=(), fail_after=None, fail_with=None, chats=None):
        self.messages = sorted(messages, key=lambda m: m.id)
        self.fail_after = fail_after
        self.fail_with = fail_with
        self.chats = chats

    async def __call__(self, request):
        chats = self.chats if self.chats is not None else [SimpleNamespace(id=SRC)]
        return SimpleNamespace(chats=chats)

    async def get_messages(self, entity, limit=1):
        return self.messages[-limit:] if self.messages else []

    def iter_messages(self, entity, min_id=None, reverse=False, **kwargs):
        msgs = [m for m in self.messages if m.id > (min_id or 0)]
        if not reverse:
            msgs = list(reversed(msgs))

        async def _gen():
            for count, message in enumerate(msgs, 1):
                yield message
                if self.fail_after is not None and count == self.fail_after:
                    raise self.fail_with or RPCError(None, "iteration failed")

        return _gen()

    async def end_takeout(self, success):
        pass

    def takeout(self, channels=True):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class FakeQueue:
    """persistqueue-like fake: no redelivery, records ack/ack_failed/put."""

    def __init__(self, cmds=()):
        self._cmds = list(cmds)
        self.unacked = []
        self.acked = []
        self.acked_failed = []
        self.puts = []

    def get_nowait(self):
        if not self._cmds:
            raise persistqueue.exceptions.Empty
        cmd = self._cmds.pop(0)
        self.unacked.append(cmd)
        return cmd

    def ack(self, cmd):
        self.unacked.remove(cmd)
        self.acked.append(cmd)

    def ack_failed(self, cmd):
        self.unacked.remove(cmd)
        self.acked_failed.append(cmd)

    def put(self, cmd):
        self.puts.append(cmd)


class FakeHandlerClient:
    """Minimal user client with telethon's handler-registry no-op semantics."""

    def __init__(self):
        self._handlers = []

    def add_event_handler(self, callback, event=None):
        self._handlers.append((callback, event))

    def remove_event_handler(self, callback, event=None):
        self._handlers = [
            (h, e) for h, e in self._handlers if h != callback or e != event
        ]

    def list_event_handlers(self):
        return list(self._handlers)
