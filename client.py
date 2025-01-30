import asyncio
import datetime
import json
import logging
import re
from types import CoroutineType
from typing import Optional, cast

from telethon import TelegramClient, events, Button, functions, utils
from telethon.errors import RPCError
from telethon.events import CallbackQuery, NewMessage
from telethon.tl.custom import Dialog
from telethon.tl.functions.channels import GetChannelsRequest
from telethon.tl.types import DocumentAttributeFilename, Chat
from telethon.tl.types.messages import Chats
from typing_extensions import Literal

import config
from auth import UserClientState, NotAuthorizedClient, init_user_client
from subscription import (
    Sink,
    subscribe_to_channel,
    unsubscribe_from_channel,
)

# commands to implement:
# - list-channels [subs]- shows user channels and ids, subs - show only subscribed channels
# subscribe {channel_id_from} {channel_id_to} {filter} - add/update subscription
# unsubscribe - {channel_id_from} {channel_id_to}
# sync - sync messages {cnannel_id/all}={full/msg_id/}[ {cnannel_id}={full/msg_id}...]: mapping channel(may be "all") to sink start offset(full means from first message)

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


async def check_clients_consistency(
    user_clients: dict[int, UserClientState], bot_client: TelegramClient
):
    while True:
        user_id = None
        try:
            await ensure_clients_consistency(user_clients, bot_client)
        except RPCError as e:
            logger.warning(f"Exception on consistency check for {user_id}, continue", e)
            await bot_client.send_message(
                config.owner_user_id, "exception on consistency check"
            )
        await asyncio.sleep(config.user_client_check_period_seconds)


async def ensure_clients_consistency(
    user_clients: dict[int, UserClientState],
    bot_client: TelegramClient,
    reinit_handlers: bool = False,
):
    for user_id, state in user_clients.items():
        user_client = await state.get_or_create_client(
            user_clients, bot_client, user_id
        )
        if not user_client:
            continue

        if reinit_handlers:
            for handler, event in user_client.list_event_handlers():
                user_client.remove_event_handler(handler, event)
        subscriptions = config.get_all_user_subscriptions(user_id)
        channels_to_listen = {ch for ch, _ in subscriptions}
        current_handlers = user_client.list_event_handlers()
        actual_subscribed_channels = {
            list(e.chats)[0]
            for _, e in current_handlers
            if isinstance(e, events.NewMessage)
        }
        if len(actual_subscribed_channels) != len(current_handlers):
            logger.warning(f"For user {user_id} there are duplicate handlers")
        for to_add in channels_to_listen - actual_subscribed_channels:
            subscribe_to_channel(user_id, user_client, to_add, bot_client)
        for to_remove in actual_subscribed_channels - channels_to_listen:
            unsubscribe_from_channel(user_client, to_remove, bot_client)


async def get_all_channels_page(
    user_client: TelegramClient,
    offset_stack: list[float],
    action: Optional[tuple[float, Literal["backward", "forward"]]],
) -> tuple[list[Dialog], list[float | None], Optional[float], Optional[float]]:
    target_offset, action_type = action if action else (None, None)
    channels = []
    async for dialog in user_client.iter_dialogs(
        archived=False,
        ignore_migrated=True,
        **(
            dict(offset_date=datetime.datetime.fromtimestamp(target_offset))
            if target_offset and target_offset != -1
            else {}
        ),
    ):
        if dialog.is_channel and not dialog.is_group and not dialog.is_user:
            channels.append(
                dialog
            )  # dialog.entity.admin_rights.post_messages = True to get sinkable
        if len(channels) >= config.dialog_list_page_size:
            break

    if not action_type:
        previous_offset = None
        offset_stack.append(-1)
        next_offset = (
            channels[-1].date.timestamp()
            if len(channels) >= config.dialog_list_page_size
            else None
        )
    elif "forward" == action_type:
        previous_offset = offset_stack[-1] if offset_stack else None
        offset_stack.append(target_offset)
        next_offset = (
            channels[-1].date.timestamp()
            if len(channels) >= config.dialog_list_page_size
            else None
        )
    elif "backward" == action_type:
        offset_stack.pop()
        next_offset = (
            channels[-1].date.timestamp()
            if len(channels) >= config.dialog_list_page_size
            else None
        )
        previous_offset = offset_stack[-2] if len(offset_stack) >= 2 else None
    else:
        raise f"Unknown action type {action_type}"
    logger.debug(
        f"returning for all channels request {action=}: {offset_stack=},{previous_offset=},{next_offset=}"
    )
    return channels, offset_stack, previous_offset, next_offset


async def build_all_channel_response(
    user_id: int,
    user_client: TelegramClient,
    offset_stack: list[float],
    action: Optional[tuple[float, Literal["backward", "forward"]]] = None,
) -> tuple[str, list[Button], tuple[bytes, list[DocumentAttributeFilename]]]:
    channels_page, offset_stack, previous_offset, next_offset = (
        await get_all_channels_page(user_client, offset_stack, action)
    )
    return await format_channel_response(
        "all",
        channels_page,
        offset_stack,
        previous_offset,
        next_offset,
        dict(config.get_all_user_subscriptions(user_id)),
    )


async def build_subscribed_channel_response(
    user_id: int,
    user_client: TelegramClient,
    offset_stack: list[int],
    action: Optional[tuple[int, Literal["backward", "forward"]]] = None,
) -> tuple[str, list[Button], tuple[bytes, list[DocumentAttributeFilename]]]:
    target_offset, action_type = action if action else (0, None)
    subscriptions = config.get_all_user_subscriptions(user_id)
    subscription_slice = subscriptions[
        target_offset : target_offset + config.dialog_list_page_size
    ]
    subscriptions_page = await user_client(
        functions.channels.GetChannelsRequest(id=[s for s, _ in subscription_slice])
    )

    if not action_type:
        previous_offset = None
        offset_stack.append(0)
        next_offset = (
            subscription_slice[-1]
            if len(subscription_slice) >= config.dialog_list_page_size
            else None
        )
    elif "forward" == action_type:
        previous_offset = offset_stack[-1] if offset_stack else None
        offset_stack.append(target_offset)
        next_offset = (
            subscription_slice[-1]
            if len(subscription_slice) >= config.dialog_list_page_size
            else None
        )
    elif "backward" == action_type:
        offset_stack.pop()
        next_offset = (
            subscription_slice[-1]
            if len(subscription_slice) >= config.dialog_list_page_size
            else None
        )
        previous_offset = offset_stack[-2] if len(offset_stack) >= 2 else None
    else:
        raise f"Unknown action type {action_type}"
    logger.debug(
        f"returning for subscribed channel request {action=}: {offset_stack=},{previous_offset=},{next_offset=}"
    )

    return await format_channel_response(
        "subs",
        subscriptions_page.chats,
        offset_stack,
        previous_offset,
        next_offset,
        dict(subscriptions),
    )


async def format_channel_response(
    request_type: str,
    items: list[Dialog] | list[object],
    offset_stack: list[float | None] | list[int],
    previous_offset: Optional[float],
    next_offset: Optional[float],
    subscriptions: dict[int, list[Sink]],
) -> tuple[str, list[Button], tuple[bytes, list[DocumentAttributeFilename]]]:
    previous_button = (
        Button.inline("<--", f"ch-list-{request_type}(backward:{previous_offset})")
        if previous_offset is not None
        else None
    )
    next_button = (
        Button.inline("-->", f"ch-list-{request_type}(forward:{next_offset})")
        if next_offset is not None
        else None
    )
    channels_formatted = "\n".join(
        [
            f"- {channel.title}: `{channel.id}`"
            f"{f" - subscribed to {", ".join((f"{sink.name}(`{sink.id}`)" for sink in subscriptions[utils.get_peer_id(channel)]))}" if utils.get_peer_id(channel) in subscriptions else ""}"
            for channel in items
        ]
    )
    if not items:
        channels_formatted = "No items to show"
    serialized_offset_stack = json.dumps(offset_stack).encode("utf-8")
    file_name = [DocumentAttributeFilename("pagination-state.json")]
    return (
        channels_formatted,
        [b for b in [previous_button, next_button] if b],
        (serialized_offset_stack, file_name),
    )


async def launch_current_users(
    bot_client: TelegramClient,
) -> dict[int, UserClientState]:
    return {
        user_id: NotAuthorizedClient(
            user_client=await init_user_client(user_id),
            bot_client=bot_client,
        )
        for user_id in config.get_existing_users()
    }


def has_send_message_permission(chat: Chat):
    return chat.admin_rights.post_messages if chat else False


def unwrap_single_chat(chat: Chats) -> Optional[Chat]:
    if not chat or not chat.chats:
        return None
    return chat.chats[0]


START_CMD = "(?i)^/start"
LIST_CMD = "(?i)^/list"
SUBSCRIBE_CMD = "(?i)^/subscribe (-?\\d+) (-?\\d+) ([\\S]+) ({.+})"
UNSUBSCRIBE_CMD = "(?i)^/unsubscribe (-?\\d+) (-?\\d+)"


def not_matched_command(txt: str) -> bool:
    return not any(
        (
            re.match(pattern, txt)
            for pattern in (START_CMD, LIST_CMD, SUBSCRIBE_CMD, UNSUBSCRIBE_CMD)
        )
    )


async def main():
    bot_client = await cast(
        CoroutineType,
        TelegramClient(
            config.data_path.joinpath("bot"), config.api_id, config.api_hash
        ).start(bot_token=config.bot_token),
    )
    tasks = []
    async with bot_client:
        logger.debug(f"Started bot {await bot_client.get_me()}")
        user_client_registry = await launch_current_users(bot_client)

        @bot_client.on(events.NewMessage(incoming=True, pattern=not_matched_command))
        @bot_client.on(events.NewMessage(incoming=True, pattern=START_CMD))
        async def list_channels_handler(event: NewMessage.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            logger.debug(f"Received unknown command: <{event.message.message}>")
            await event.respond(
                "/list - to list your channels\n/subscribe - to create/edit subscription\n/unsubscribe - to remove subscription\n/sync - to sync some channels historical data",
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=LIST_CMD))
        async def list_channels_handler(event: NewMessage.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return

            if "subs" == event.text.removeprefix("/list").strip():
                message_text, buttons, (pagination_data, attributes) = (
                    await build_subscribed_channel_response(
                        event.sender_id, user_client, []
                    )
                )
            else:
                message_text, buttons, (pagination_data, attributes) = (
                    await build_all_channel_response(event.sender_id, user_client, [])
                )
            conditional_params = (
                {"buttons": buttons, "file": pagination_data} if buttons else {}
            )
            await event.respond(
                message_text,
                attributes=attributes,
                **conditional_params,
            )

        @bot_client.on(
            events.CallbackQuery(
                data=re.compile("^ch-list-([^(]+)\\(([^:]+):([^:]+)\\)")
            )
        )
        async def channels_pagination_handler(event: CallbackQuery.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return

            message = (
                await bot_client.get_messages(event.chat_id, ids=[event.message_id])
            )[0]
            request_type = event.pattern_match.group(1).decode("utf-8").strip()
            action_type = event.pattern_match.group(2).decode("utf-8").strip()
            value = (await message.download_media(file=bytes)).decode("utf-8")
            offset_stack = json.loads(value)
            if "all" == request_type:
                target_offset = float(
                    event.pattern_match.group(3).decode("utf-8").strip()
                )
                message_text, buttons, (pagination_data, attributes) = (
                    await build_all_channel_response(
                        event.sender_id,
                        user_client,
                        offset_stack,
                        (target_offset, action_type),
                    )
                )
            elif "subs" == request_type:
                target_offset = int(
                    event.pattern_match.group(3).decode("utf-8").strip()
                )
                message_text, buttons, (pagination_data, attributes) = (
                    await build_subscribed_channel_response(
                        event.sender_id,
                        user_client,
                        offset_stack,
                        (target_offset, action_type),
                    )
                )
            else:
                raise f"Unknown request type {request_type}"
            await event.edit(
                message_text,
                file=pagination_data,
                attributes=attributes,
                buttons=buttons,
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=SUBSCRIBE_CMD))
        async def subscribe_handler(event: NewMessage.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            source_channel_id = event.pattern_match.group(1).strip()
            sink_channel_id = event.pattern_match.group(2).strip()
            filter_type = event.pattern_match.group(3).strip()
            filter_params = event.pattern_match.group(4).strip()
            logger.debug(
                f"subscribing user {event.sender_id}: {source_channel_id=} -> {sink_channel_id} with filter {filter_type}({filter_params})"
            )
            channel = unwrap_single_chat(
                await user_client(GetChannelsRequest(id=[int(sink_channel_id)]))
            )
            if not has_send_message_permission(channel):
                await event.respond(
                    f"You have no permission to send messages in {sink_channel_id}"
                )
                return

            config.create_subscription(
                event.sender_id,
                source_channel_id,
                (sink_channel_id, channel.title),
                (filter_type, filter_params),
            )
            subscribe_to_channel(
                event.sender_id, user_client, source_channel_id, bot_client
            )
            await event.respond(f"subscribed {source_channel_id} -> {sink_channel_id}")

        @bot_client.on(events.NewMessage(incoming=True, pattern=UNSUBSCRIBE_CMD))
        async def unsubscribe_handler(event: NewMessage.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            source_channel_id = event.pattern_match.group(1).strip()
            sink_channel_id = event.pattern_match.group(2).strip()
            logger.debug(
                f"unsubscribing user {event.sender_id}: {source_channel_id=} -> {sink_channel_id}"
            )
            if config.remove_subscription(
                event.sender_id, source_channel_id, sink_channel_id
            ):
                unsubscribe_from_channel(user_client, source_channel_id, bot_client)
            await event.respond(
                f"unsubscribed {source_channel_id} -> {sink_channel_id}"
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern="^[^/].+"))
        async def common_message_handler(event: NewMessage.Event):
            await UserClientState.get_or_create_client(
                user_client_registry, bot_client, event.sender_id, event
            )

        await ensure_clients_consistency(
            user_client_registry, bot_client, reinit_handlers=True
        )
        tasks.append(
            asyncio.create_task(
                check_clients_consistency(user_client_registry, bot_client)
            )
        )

        await bot_client.run_until_disconnected()
        for task in tasks:
            task.cancel("shutdown")


# api_id = os.getenv("API_ID")
# api_hash = os.getenv("API_HASH")
# bot_token = os.getenv("BOT_TOKEN")
if __name__ == "__main__":
    asyncio.run(main())
