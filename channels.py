import datetime
import json
import logging
from typing import Optional

from telethon import TelegramClient, Button, functions, utils
from telethon.tl.custom import Dialog
from telethon.tl.types import DocumentAttributeFilename
from typing_extensions import Literal

import config
from subscription import Sink

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


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
            f"* {channel.title}: `{channel.id}`"
            f"{f" - subscribed to {", ".join((f"{sink.name}(`{sink.id}`>{sink.filter})" for sink in subscriptions[utils.get_peer_id(utils.get_input_peer(channel))]))}" if utils.get_peer_id(utils.get_input_peer(channel)) in subscriptions else ""}"
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
