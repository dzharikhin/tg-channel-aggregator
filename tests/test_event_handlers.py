from telethon import events

from subscription import (
    handler_channel_ids,
    subscribe_to_channel,
    unsubscribe_from_channel,
)

CHANNEL_A = 100200300
CHANNEL_B = 400500600


class FakeClient:
    """Replicates telethon's handler registry semantics: no dedup on add,
    removal matches strictly by callback equality and builder type."""

    def __init__(self):
        self._event_builders = []

    def add_event_handler(self, callback, event=None):
        self._event_builders.append((event, callback))

    def remove_event_handler(self, callback, event=None):
        event_type = type(event) if event is not None else None
        found = 0
        i = len(self._event_builders)
        while i:
            i -= 1
            ev, cb = self._event_builders[i]
            if cb == callback and (event_type is None or isinstance(ev, event_type)):
                del self._event_builders[i]
                found += 1
        return found

    def list_event_handlers(self):
        return [(callback, event) for event, callback in self._event_builders]


def resolve(event, channel_id):
    # telethon's _into_id_set rewrites chats to all peer-type variants
    event.chats = {channel_id, -channel_id, -1000000000000 - channel_id}


def channel_ids(client):
    counts = {}
    for _, event in client.list_event_handlers():
        for ch in handler_channel_ids(event):
            counts[ch] = counts.get(ch, 0) + 1
    return counts


def test_subscribe_is_idempotent():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_A, None)
    subscribe_to_channel(1, client, CHANNEL_A, None)
    subscribe_to_channel(1, client, CHANNEL_A, None)
    assert channel_ids(client) == {CHANNEL_A: 1}


def test_unsubscribe_removes_duplicates_and_keeps_other_channels():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_A, None)
    client.add_event_handler(
        lambda e: None, events.NewMessage(chats=[CHANNEL_A])
    )  # simulate a stray duplicate
    subscribe_to_channel(1, client, CHANNEL_B, None)

    unsubscribe_from_channel(client, CHANNEL_A)

    assert channel_ids(client) == {CHANNEL_B: 1}


def test_subscribe_and_unsubscribe_work_after_resolution():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_A, None)
    for _, event in client.list_event_handlers():
        resolve(event, CHANNEL_A)

    # a re-subscribe must not add a second handler next to the resolved one
    subscribe_to_channel(1, client, CHANNEL_A, None)
    assert channel_ids(client) == {CHANNEL_A: 1}

    unsubscribe_from_channel(client, CHANNEL_A)
    assert channel_ids(client) == {}


def test_unsubscribe_unknown_channel_is_noop():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_A, None)
    unsubscribe_from_channel(client, CHANNEL_B)
    assert channel_ids(client) == {CHANNEL_A: 1}


def test_handler_channel_ids_variants():
    unresolved = events.NewMessage(chats=[CHANNEL_A])
    assert handler_channel_ids(unresolved) == {CHANNEL_A}

    resolved = events.NewMessage(chats=[CHANNEL_A])
    resolve(resolved, CHANNEL_A)
    assert handler_channel_ids(resolved) == {CHANNEL_A}

    assert handler_channel_ids(events.NewMessage()) == set()
    assert handler_channel_ids("not a builder") == set()
