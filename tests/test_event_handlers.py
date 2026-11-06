from telethon import events

from subscription import (
    handler_channel_ids,
    subscribe_to_channel,
    unsubscribe_from_channel,
)

CHANNEL_M = -1000000000300  # marked channel/supergroup
CHAT_M = -400  # marked small group
DM_ID = 500  # user ids are their own canonical form


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


def resolve_positive(event, peer_id):
    # telethon's _into_id_set rewrites positive ids to all peer-type variants
    event.chats = {peer_id, -peer_id, -1000000000000 - peer_id}


def channel_ids(client):
    counts = {}
    for _, event in client.list_event_handlers():
        for ch in handler_channel_ids(event):
            counts[ch] = counts.get(ch, 0) + 1
    return counts


def test_subscribe_is_idempotent_for_marked_channel():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_M)
    subscribe_to_channel(1, client, CHANNEL_M)
    subscribe_to_channel(1, client, CHANNEL_M)
    assert channel_ids(client) == {CHANNEL_M: 1}


def test_subscribe_is_idempotent_for_marked_chat_and_dm():
    client = FakeClient()
    subscribe_to_channel(1, client, CHAT_M)
    subscribe_to_channel(1, client, CHAT_M)
    subscribe_to_channel(1, client, DM_ID)
    subscribe_to_channel(1, client, DM_ID)
    assert channel_ids(client) == {CHAT_M: 1, DM_ID: 1}


def test_unsubscribe_removes_duplicates_and_keeps_other_channels():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_M)
    client.add_event_handler(
        lambda e: None, events.NewMessage(chats=[CHANNEL_M])
    )  # simulate a stray duplicate
    subscribe_to_channel(1, client, CHAT_M)

    unsubscribe_from_channel(client, CHANNEL_M)

    assert channel_ids(client) == {CHAT_M: 1}


def test_subscribe_and_unsubscribe_work_after_resolution():
    client = FakeClient()
    subscribe_to_channel(1, client, DM_ID)
    for _, event in client.list_event_handlers():
        resolve_positive(event, DM_ID)

    # a re-subscribe must not add a second handler next to the resolved one
    subscribe_to_channel(1, client, DM_ID)
    assert channel_ids(client) == {DM_ID: 1}

    unsubscribe_from_channel(client, DM_ID)
    assert channel_ids(client) == {}


def test_unsubscribe_unknown_channel_is_noop():
    client = FakeClient()
    subscribe_to_channel(1, client, CHANNEL_M)
    unsubscribe_from_channel(client, CHAT_M)
    assert channel_ids(client) == {CHANNEL_M: 1}


def test_handler_channel_ids_variants():
    assert handler_channel_ids(events.NewMessage(chats=[CHANNEL_M])) == {CHANNEL_M}
    assert handler_channel_ids(events.NewMessage(chats=[CHAT_M])) == {CHAT_M}

    unresolved = events.NewMessage(chats=[DM_ID])
    assert handler_channel_ids(unresolved) == {DM_ID}

    resolved = events.NewMessage(chats=[DM_ID])
    resolve_positive(resolved, DM_ID)
    assert handler_channel_ids(resolved) == {DM_ID}

    assert handler_channel_ids(events.NewMessage()) == set()
    assert handler_channel_ids("not a builder") == set()
