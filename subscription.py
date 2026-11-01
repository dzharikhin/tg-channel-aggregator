import json
import logging
from functools import partial
from typing import Any, Optional, cast

from telethon import TelegramClient, events
from telethon.errors import RPCError
from telethon.events import NewMessage
from telethon.tl.types import (
    DocumentAttributeAudio,
    Message,
    MessageEntityHashtag,
    MessageMediaPhoto,
)

import config

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)

CAPTION_MODES = {"none", "link", "original"}


class Filter:
    def filter_message(self, message) -> bool:
        pass

    @staticmethod
    def get_filter(**filter_data: str | dict[str, Any]) -> "Filter":
        if "mp3" == filter_data["type"].lower():
            return Mp3Filter(**filter_data["params"])
        elif "hashtag" == filter_data["type"].lower():
            return HashtagFilter(**filter_data["params"])
        else:
            raise ValueError(f"Unknown filter type {filter_data["type"]}")


class Mp3Filter(Filter):

    def __init__(self, **params):
        self.min_length_seconds = params["min_seconds"]
        self.max_length_seconds = params["max_seconds"]

    def filter_message(self, message) -> bool:
        if not message:
            return False
        if not isinstance(message, Message):
            return False
        if isinstance(message.media, MessageMediaPhoto):
            return False
        if not hasattr(message, "media") or not hasattr(message.media, "document"):
            return False
        if not hasattr(
            message.media.document, "mime_type"
        ) or message.media.document.mime_type not in {"audio/mpeg", "audio/mp3"}:
            return False
        if not hasattr(message.media.document, "attributes") or not [
            audio_attr := cast(DocumentAttributeAudio, attr)
            for attr in message.media.document.attributes
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


class HashtagFilter(Filter):

    def __init__(self, **params):
        tags = params["tags"]
        if isinstance(tags, str):
            tags = [tags]
        self.tags = {self._normalize(tag) for tag in tags}

    @staticmethod
    def _normalize(tag: str) -> str:
        return tag.lstrip("#").lower()

    def filter_message(self, message) -> bool:
        if not message or not isinstance(message, Message):
            return False
        message_tags = {
            self._normalize(text)
            for _, text in message.get_entities_text(MessageEntityHashtag)
        }
        return bool(self.tags & message_tags)

    def __repr__(self):
        return (
            f"HashtagFilter[tags={", ".join(f"#{tag}" for tag in sorted(self.tags))}]"
        )


def build_caption(caption_mode: str, message: Message) -> Optional[str]:
    match caption_mode:
        case "none":
            return None
        case "link":
            return f"https://t.me/c/{message.peer_id.channel_id}/{message.id}"
        case "original":
            return message.message
        case _:
            raise ValueError(f"Unknown caption mode {caption_mode}")


class Sink(Filter):

    def __init__(self, sink_id: str, sink_config: str):
        self.id = int(sink_id)
        sink_cfg = json.loads(sink_config)
        self.name = sink_cfg["sink_name"]
        self.caption = sink_cfg.get("caption", "link")
        if self.caption not in CAPTION_MODES:
            raise ValueError(
                f"Unknown caption mode {self.caption} for sink {self.id}, must be one of {sorted(CAPTION_MODES)}"
            )
        self.filter = Filter.get_filter(**sink_cfg["filter"])

    def filter_message(self, message) -> bool:
        return self.filter.filter_message(message)

    def __repr__(self):
        return f"Sink[id={self.id}, name={self.name}, filter={self.filter}]"


async def new_message_in_target_channel_handler(
    user_id: int, bot_client: TelegramClient, event: NewMessage.Event
):
    sinks_for_channel = config.get_channel_subscriptions(user_id, event.sender_id)
    await forward_to_sinks(
        user_id, event.client, event.message, sinks_for_channel, bot_client
    )


async def forward_to_sinks(
    user_id,
    user_client: TelegramClient,
    message: Message,
    sinks_for_channel,
    bot_client: TelegramClient,
):
    for sink in sinks_for_channel:
        if not sink.filter_message(message):
            logger.debug(
                f"For user {user_id} got message {message.stringify()}, did not match for sink {sink}, skipping"
            )
            continue
        try:
            result = await user_client.send_file(
                sink.id,
                message.media,
                caption=build_caption(sink.caption, message),
            )
            logging.debug(f"Forwarded {message} to {sink} with result {result}")
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
