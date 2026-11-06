import asyncio
import dataclasses
import enum
import json
import logging
from datetime import datetime, timedelta
from functools import partial
from typing import Any, Optional, cast

from telethon import TelegramClient, events, utils
from telethon.errors import (
    ChannelPrivateError,
    ChatWriteForbiddenError,
    FloodWaitError,
    RPCError,
    UserBannedInChannelError,
)
from telethon.events import NewMessage
from telethon.tl.types import (
    Document,
    DocumentAttributeAudio,
    DocumentAttributeFilename,
    Message,
    MessageEntityHashtag,
    MessageMediaPhoto,
    PeerChannel,
)

import config
import notifications
from common import get_pacer, norm

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
            if isinstance(message.peer_id, PeerChannel):
                return f"https://t.me/c/{message.peer_id.channel_id}/{message.id}"
            return message.message
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
        self.schedule = sink_cfg.get("schedule")
        self.start_message_id = sink_cfg.get("start_message_id")
        self.batch = sink_cfg.get("batch", 1)
        self.state = sink_cfg.get("state", {})

    def filter_message(self, message) -> bool:
        return self.filter.filter_message(message)

    def __repr__(self):
        return f"Sink[id={self.id}, name={self.name}, filter={self.filter}]"


class Outcome(str, enum.Enum):
    SENT = "sent"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    FAILED = "failed"


@dataclasses.dataclass
class DeliveryResult:
    outcome: Outcome
    key: str | None = None
    stop_step: bool = False


PERMISSION_ERRORS = (
    ChatWriteForbiddenError,
    ChannelPrivateError,
    UserBannedInChannelError,
)


def _message_document(message) -> Optional[Document]:
    media = getattr(message, "media", None)
    return getattr(media, "document", None)


def _document_fallback_tuple(document) -> tuple:
    duration = None
    file_name = None
    for attr in getattr(document, "attributes", None) or []:
        if isinstance(attr, DocumentAttributeAudio):
            duration = attr.duration
        elif isinstance(attr, DocumentAttributeFilename):
            file_name = attr.file_name
    return (document.mime_type, document.size, duration, file_name)


def is_duplicate(sink: Sink, source_message: Message, sink_message: Message) -> bool:
    source_doc = _message_document(source_message)
    sink_doc = _message_document(sink_message)
    if source_doc is not None and sink_doc is not None:
        if source_doc.id == sink_doc.id:
            return True
        return _document_fallback_tuple(source_doc) == _document_fallback_tuple(
            sink_doc
        )
    if source_doc is None and sink_doc is None:
        caption = build_caption(sink.caption, source_message)
        return norm(caption) == norm(sink_message.message)
    return False


async def _sink_recently_received(
    bot_client: TelegramClient, sink: Sink, message: Message
) -> bool:
    for attempt in (1, 2):
        try:
            await get_pacer().wait()
            offset_date = datetime.now() - timedelta(
                minutes=config.dedup_window_minutes
            )
            async for sink_message in bot_client.iter_messages(
                sink.id, offset_date=offset_date
            ):
                if is_duplicate(sink, message, sink_message):
                    return True
            return False
        except FloodWaitError as e:
            if attempt == 2:
                raise
            await asyncio.sleep(e.seconds + 1)
    return False


async def deliver_to_sink(
    user_id: int,
    bot_client: TelegramClient,
    sink: Sink,
    message: Message,
) -> DeliveryResult:
    """Single send pipeline for one message to one sink: dedup, pacing, bounded errors."""
    try:
        duplicate = await _sink_recently_received(bot_client, sink, message)
    except Exception as e:
        logger.warning(
            f"Could not read history of {sink.name}({sink.id}) to dedup message {message.id}",
            exc_info=e,
        )
        return DeliveryResult(Outcome.FAILED, key=f"dedup-read-fail:{sink.id}")
    if duplicate:
        logger.debug(
            f"Message {message.id} for user {user_id} is already in {sink}, skipping"
        )
        return DeliveryResult(Outcome.SKIPPED_DUPLICATE)
    for attempt in (1, 2):
        try:
            await get_pacer().wait()
            await bot_client.send_file(
                sink.id,
                message.media,
                caption=build_caption(sink.caption, message),
            )
            logger.debug(f"Forwarded message {message.id} to {sink} via bot")
            return DeliveryResult(Outcome.SENT)
        except FloodWaitError as e:
            if attempt == 2:
                logger.warning(
                    f"FloodWait persisted after a retry, skipping message {message.id} for {sink}"
                )
                return DeliveryResult(Outcome.FAILED, key=f"send-flood:{sink.id}")
            await asyncio.sleep(e.seconds + 1)
        except PERMISSION_ERRORS as e:
            logger.warning(
                f"Bot has no permission to post in {sink.name}({sink.id})",
                exc_info=e,
            )
            return DeliveryResult(
                Outcome.FAILED, key=f"send-perm:{sink.id}", stop_step=True
            )
        except Exception as e:
            logger.warning(
                f"Unexpected error sending message {message.id} to {sink}",
                exc_info=e,
            )
            return DeliveryResult(
                Outcome.FAILED, key=f"send-unknown:{sink.id}:{type(e).__name__}"
            )
    return DeliveryResult(Outcome.FAILED, key=f"send-unknown:{sink.id}:RetryExhausted")


def dm_text_for_failure(sink: Sink, key: str) -> str:
    kind, _, rest = key.partition(":")
    if "send-perm" == kind:
        return (
            f"Bot has no permission to send messages in {sink.name}({sink.id}). "
            f"Grant the bot post rights or /unsubscribe."
        )
    if "send-flood" == kind:
        return (
            f"Telegram FloodWait exceeded the single retry; a message for "
            f"{sink.name}({sink.id}) was skipped."
        )
    if "send-unknown" == kind:
        error_class = rest.partition(":")[2] or "UnknownError"
        return (
            f"Unexpected error while sending to {sink.name}({sink.id}): "
            f"{error_class}. The message was skipped."
        )
    if "dedup-read-fail" == kind:
        return (
            f"Could not read {sink.name}({sink.id}) history to check for "
            f"duplicates; the message was skipped."
        )
    return f"Delivery to {sink.name}({sink.id}) failed ({key})."


async def new_message_in_target_channel_handler(
    user_id: int, bot_client: TelegramClient, event: NewMessage.Event
):
    sinks_for_channel = config.get_channel_subscriptions(user_id, event.chat_id)
    await forward_to_sinks(user_id, event.message, sinks_for_channel, bot_client)


async def forward_to_sinks(
    user_id,
    message: Message,
    sinks_for_channel,
    bot_client: TelegramClient,
):
    for sink in sinks_for_channel:
        try:
            if sink.schedule:
                logger.debug(
                    f"For user {user_id} sink {sink} is scheduled ({sink.schedule}), skipping realtime/sync forwarding"
                )
                continue
            if not sink.filter_message(message):
                logger.debug(
                    f"For user {user_id} message {message.id} did not match for sink {sink}, skipping"
                )
                continue
            result = await deliver_to_sink(user_id, bot_client, sink, message)
            if result.outcome == Outcome.FAILED and result.key:
                notifications.enqueue_error_dm(
                    user_id, result.key, dm_text_for_failure(sink, result.key)
                )
        except Exception as e:
            logger.warning(
                f"Forwarding message {message.id} to {sink} failed", exc_info=e
            )


class ChannelHistoryError(Exception):
    """Channel history walk failed; carries the reached progress."""

    def __init__(self, last_processed_id: Optional[int], cause: BaseException):
        super().__init__(f"channel history walk failed at message {last_processed_id}")
        self.last_processed_id = last_processed_id
        self.cause = cause


async def forward_channel_history(
    user_id: int,
    user_client: TelegramClient,
    bot_client: TelegramClient,
    channel_id: int,
    min_id: int | None = None,
) -> Optional[int]:
    """Walk a channel's history via takeout and forward matching messages.

    Returns the id of the last processed message, or None when there are no
    sinks for the channel. Raises ChannelHistoryError (wrapping the RPCError)
    on failures; the caller is expected to requeue with the carried progress.
    """
    last_processed_id = None
    try:
        channel = await user_client.get_entity(int(channel_id))
        if not channel:
            raise ValueError(f"Channel {channel_id} is not available")
        sinks = config.get_channel_subscriptions(user_id, channel_id)
        if not sinks:
            return None
        await user_client.end_takeout(False)
        async with user_client.takeout(
            channels=True, chats=True, users=True
        ) as takeout_client:
            async for message in takeout_client.iter_messages(
                channel, reverse=True, min_id=min_id
            ):
                last_processed_id = message.id
                await forward_to_sinks(user_id, message, sinks, bot_client)
    except RPCError as e:
        raise ChannelHistoryError(last_processed_id, e) from e
    return last_processed_id


def handler_channel_ids(event) -> set[int]:
    """Canonical marked peer ids of a NewMessage builder, pre- and post-resolution.

    Positive ids (users) are rewritten by telethon on resolution into all
    peer-type variants; keep the original positive id and drop the artifacts.
    Negative (marked chat/channel) ids are kept as-is - those are what
    subscription config stores.
    """
    if not isinstance(event, events.NewMessage) or event.chats is None:
        return set()
    ids = {chat for chat in event.chats if isinstance(chat, int)}
    result = {chat for chat in ids if chat > 0}
    result |= {
        chat for chat in ids if chat < 0 and utils.resolve_id(chat)[0] not in result
    }
    return result


def subscribe_to_channel(
    user_id: int,
    user_client: TelegramClient,
    source_channel_id: int,
    bot_client: TelegramClient,
):
    channel_id = int(source_channel_id)
    already_subscribed = any(
        channel_id in handler_channel_ids(event)
        for _, event in user_client.list_event_handlers()
    )
    if already_subscribed:
        logger.debug(f"Handler for channel {channel_id} already exists, skipping")
        return
    user_client.add_event_handler(
        partial(new_message_in_target_channel_handler, user_id, bot_client),
        event=events.NewMessage(chats=[channel_id]),
    )


def unsubscribe_from_channel(user_client: TelegramClient, source_channel_id: int):
    channel_id = int(source_channel_id)
    removed = 0
    for handler, event in user_client.list_event_handlers():
        if channel_id in handler_channel_ids(event):
            user_client.remove_event_handler(handler)
            removed += 1
    if removed:
        logger.debug(f"Removed {removed} handlers for channel {channel_id}")
