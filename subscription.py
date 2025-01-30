import json
import logging
from functools import partial
from typing import cast, Any

from telethon import events, TelegramClient
from telethon.errors import RPCError
from telethon.events import NewMessage
from telethon.tl.types import DocumentAttributeAudio

import config

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


class Filter:
    def filter_update_event(self, event: events.NewMessage.Event) -> bool:
        pass

    @staticmethod
    def get_filter(**filter_data: str | dict[str, Any]) -> "Filter":
        if "mp3" == filter_data["type"].lower():
            return Mp3Filter(**filter_data["params"])
        else:
            raise ValueError(f"Unknown filter type {filter_data["type"]}")


class Mp3Filter(Filter):

    def __init__(self, **params):
        self.min_length_seconds = params["min_seconds"]
        self.max_length_seconds = params["max_seconds"]

    def filter_update_event(self, event: events.NewMessage.Event) -> bool:
        if not event.message.media or not event.message.media.document:
            return False
        if event.message.media.document.mime_type != "audio/mpeg":
            return False
        if not event.message.media.document.attributes or not [
            audio_attr := cast(DocumentAttributeAudio, attr)
            for attr in event.message.media.document.attributes
            if isinstance(attr, DocumentAttributeAudio)
        ]:
            return False
        if (
            audio_attr.duration < self.min_length_seconds
            or audio_attr.duration > self.max_length_seconds
        ):
            return False
        return True

    def __repr__(self):
        return f"Mp3Filter[min_length_seconds={self.min_length_seconds}, max_length_seconds={self.max_length_seconds}]"


class Sink(Filter):

    def __init__(self, sink_id: str, sink_config: str):
        self.id = int(sink_id)
        sink_cfg = json.loads(sink_config)
        self.name = sink_cfg["sink_name"]
        self._filter = Filter.get_filter(**sink_cfg["filter"])

    def filter_update_event(self, event: events.NewMessage.Event) -> bool:
        return self._filter.filter_update_event(event)

    def __repr__(self):
        return f"Sink[id={self.id}, name={self.name}, filter={self._filter}]"


async def new_message_in_target_channel_handler(
    user_id: int, bot_client: TelegramClient, event: NewMessage.Event
):
    sinks_for_channel = config.get_channel_subscriptions(user_id, event.sender_id)
    for sink in sinks_for_channel:
        if not sink.filter_update_event(event):
            logger.debug(
                f"For user {user_id} got event {event.stringify()}, did not match for sink {sink}, skipping"
            )
            continue
        try:
            result = await event.client.forward_messages(sink.id, event.message)
            logging.debug(f"Forwarded {event} to {sink} with result {result}")
        except RPCError as e:
            logger.warning(
                f"User {user_id} has no permission to send messages in {sink.name}({sink.id})",
                e,
            )
            await bot_client.send_message(
                user_id,
                f"You have no permission to send messages in {sink.name}(`{sink.id}`). Please, grant permission or unsubscribe",
            )


def subscribe_to_channel(
    user_id: int,
    user_client: TelegramClient,
    source_channel_id: int,
    bot_client: TelegramClient,
):
    user_client.add_event_handler(
        partial(new_message_in_target_channel_handler, user_id, bot_client),
        event=events.NewMessage(chats=[int(source_channel_id)]),
    )


def unsubscribe_from_channel(
    user_client: TelegramClient, source_channel_id: int, bot_client: TelegramClient
):
    user_client.remove_event_handler(
        partial(new_message_in_target_channel_handler, bot_client),
        event=events.NewMessage(chats=[int(source_channel_id)]),
    )
