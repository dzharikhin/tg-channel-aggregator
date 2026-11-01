import asyncio
import io
import json
import logging
import re
import shlex
from argparse import ArgumentError, ArgumentParser, ArgumentTypeError, Namespace
from asyncio import Task
from functools import partial
from types import CoroutineType
from typing import Optional, cast

import persistqueue
from telethon import TelegramClient, events
from telethon.errors import BadRequestError, RPCError
from telethon.events import CallbackQuery, NewMessage
from telethon.tl.functions.channels import GetChannelsRequest
from telethon.tl.types import Chat
from telethon.tl.types.messages import Chats

import config
from auth import AuthManager
from channels import build_all_channel_response, build_subscribed_channel_response
from subscription import (
    forward_to_sinks,
    subscribe_to_channel,
    unsubscribe_from_channel,
)

# commands to implement:
# - list-channels [subs] - shows user channels and ids, subs - show only subscribed channels
# - subscribe <channel_id_from> <channel_id_to> {<filter json>} - add/update subscription
# - unsubscribe <channel_id_from> <channel_id_to>
# - sync {"<channel_id>"/"all"="full"/<msg_id>[, "<channel_id>"="full"/<msg_id>]} - sync channels from offset

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


async def check_clients_consistency(
    auth_manager: AuthManager,
    tasks: dict[str, Task],
    bot_client: TelegramClient,
):
    while True:
        try:
            await ensure_clients_consistency(auth_manager, tasks, bot_client)
        except RPCError as e:
            logger.warning(
                "Exception on consistency check, continue",
                exc_info=e,
            )
            await bot_client.send_message(
                config.owner_user_id, "exception on consistency check"
            )
        await asyncio.sleep(config.user_client_check_period_seconds)


async def handle_queue_tasks(
    user_id: int,
    queue: persistqueue.SQLiteAckQueue,
    user_client: TelegramClient,
    bot_client: TelegramClient,
):
    while True:
        cmd = None
        try:
            cmd = queue.get_nowait()
            if "sync" == cmd["cmd"]:
                channel_id = cmd["channel_id"]
                channel = unwrap_single_chat(
                    await user_client(GetChannelsRequest(id=[int(channel_id)]))
                )
                if not channel:
                    raise ValueError(f"Channel {channel_id} is not available")
                sinks = config.get_channel_subscriptions(user_id, channel_id)
                if sinks:
                    iter_params = {}
                    from_offset = cmd["from"]
                    if isinstance(from_offset, int):
                        iter_params["min_id"] = from_offset - 1
                    elif "full" == from_offset:
                        pass
                    else:
                        raise ValueError(f"unknown <from> cmd: {cmd["from"]}")
                    await user_client.end_takeout(False)
                    async with user_client.takeout(channels=True) as takeout_client:
                        async for message in takeout_client.iter_messages(
                            channel, reverse=True, **iter_params
                        ):
                            await forward_to_sinks(
                                user_id, user_client, message, sinks, bot_client
                            )
                queue.ack(cmd)
            else:
                raise ValueError(f"unknown cmd: {cmd}")
        except persistqueue.exceptions.Empty:
            await asyncio.sleep(1)
        except (ValueError, BadRequestError) as e:
            cmd_id = queue.ack_failed(cmd)
            logger.warning(
                f"cannot handle {cmd_id}: {cmd} - marked as failed",
                exc_info=e,
            )
            await bot_client.send_message(user_id, f"Failed to execute {cmd}: {e}")
        except RPCError as e:
            cmd_id = queue.nack(cmd)
            logger.info(
                f"{cmd_id}: {cmd} - failed with {type(e)}, going to retry",
                exc_info=e,
            )


async def ensure_clients_consistency(
    auth_manager: AuthManager,
    tasks: dict[str, Task],
    bot_client: TelegramClient,
    reinit_handlers: bool = False,
):
    for user_id in auth_manager.tracked_users():
        session = await auth_manager.ensure_authorized(user_id)
        if not session:
            continue

        user_client = session.user_client
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

        handle_task_id = f"queue_handler-{user_id}"
        current_task = tasks.get(handle_task_id)
        if not current_task or current_task.done() or current_task.cancelled():
            tasks[handle_task_id] = asyncio.create_task(
                handle_queue_tasks(user_id, session.queue, user_client, bot_client),
            )


def has_send_message_permission(chat: Chat):
    return chat.admin_rights.post_messages if chat else False


def unwrap_single_chat(chat: Chats) -> Optional[Chat]:
    if not chat or not chat.chats:
        return None
    return chat.chats[0]


def jsonarg(arg: str) -> str:
    try:
        json.loads(arg)
        return arg
    except json.JSONDecodeError:
        raise ArgumentTypeError(f"{arg} is not a valid json")


def syncpairarg(err_msg: str, arg: str) -> tuple[int | str, int | str]:
    k, v = tuple(arg.split("="))
    if re.match("\\d+", k):
        k = int(k)
    if re.match("\\d+", v):
        v = int(v)
    if not isinstance(k, int) and k != "all" or not isinstance(v, int) and v != "full":
        raise ArgumentTypeError(err_msg)

    return k, v


START_CMD = ArgumentParser(
    prog="start",
    epilog="(?i)^/start.*$",
    description="print available commands",
    exit_on_error=False,
    add_help=False,
)
LIST_CMD = (
    parser := ArgumentParser(
        prog="list",
        epilog="(?i)^/list(.*)$",
        description="list channels/subscriptions",
        exit_on_error=False,
        add_help=False,
    ),
    parser.add_argument(
        "--subs",
        action="store_true",
        help="list subscriptions only",
    ),
    parser,
)[-1]
SUBSCRIBE_CMD = (
    parser := ArgumentParser(
        prog="subscribe",
        epilog="(?i)^/subscribe(.*)$",
        description="create forwarding route",
        exit_on_error=False,
        add_help=False,
    ),
    parser.add_argument(
        "-s",
        "--src_channel_id",
        required=True,
        type=int,
        help="channel to listen messages from",
    ),
    parser.add_argument(
        "-d",
        "--dst_channel_id",
        required=True,
        type=int,
        help="channel to sink messages to",
    ),
    parser.add_argument(
        "-f",
        "--filter_type",
        required=True,
        type=str,
        choices=["mp3"],
        help="source filter type",
    ),
    parser.add_argument(
        "-p",
        "--filter_params",
        required=True,
        type=jsonarg,
        help="params for filter. must be a valid JSON",
    ),
    parser,
)[-1]
UNSUBSCRIBE_CMD = (
    parser := ArgumentParser(
        prog="unsubscribe",
        epilog="(?i)^/unsubscribe(.*)$",
        description="create forwarding route",
        exit_on_error=False,
        add_help=False,
    ),
    parser.add_argument(
        "-s",
        "--src_channel_id",
        required=True,
        type=int,
        help="channel to listen messages from",
    ),
    parser.add_argument(
        "-d",
        "--dst_channel_id",
        required=True,
        type=int,
        help="channel to sink messages to",
    ),
    parser,
)[-1]
SYNC_CMD = (
    parser := ArgumentParser(
        prog="sync",
        epilog="(?i)^/sync(.*)$",
        description="sync messages in subscriptions",
        exit_on_error=False,
        add_help=False,
    ),
    pair_help := 'space-separated pairs <channel>=<offset>: channel must be <channel_id> or "all", offset must be <from_offset_msg_id> or "full"',
    parser.add_argument(
        "--pairs",
        required=True,
        type=partial(syncpairarg, pair_help),
        nargs="+",
        help=pair_help,
    ),
    parser,
)[-1]


CMDS = [
    START_CMD,  # always first element
    LIST_CMD,
    SUBSCRIBE_CMD,
    UNSUBSCRIBE_CMD,
    SYNC_CMD,
]


def _parse_args(
    arg_parser: ArgumentParser, cmd_line: str
) -> tuple[Namespace | None, str | None]:
    try:
        args = arg_parser.parse_args(shlex.split(cmd_line))
        return args, None
    except ArgumentError:
        buffer = io.StringIO()
        arg_parser.print_help(buffer)
        return None, buffer.getvalue()


def _not_matched_command(txt: str) -> bool:
    return not any((re.match(pattern, txt) for pattern in (cmd.epilog for cmd in CMDS)))


def _filter_not_mapped(event: NewMessage.Event) -> bool:
    return not event.is_channel and _not_matched_command(event.message.message or "")


def build_help() -> str:
    buffer = io.StringIO()
    for cmd in CMDS[1:]:
        buffer.write(f"/{cmd.prog} - {cmd.description}\n")
        cmd.print_usage(buffer)
        buffer.write("\n")
    return buffer.getvalue()


async def main():
    bot_client = await cast(
        CoroutineType,
        TelegramClient(
            config.data_path.joinpath("bot"),
            config.api_id,
            config.api_hash,
            connection_retries=None,
            retry_delay=10,
            catch_up=True,
        ).start(bot_token=config.bot_token),
    )
    tasks = {}
    async with bot_client:
        logger.debug(f"Started bot {await bot_client.get_me()}")
        auth_manager = AuthManager(bot_client)
        await auth_manager.bootstrap()

        @bot_client.on(events.NewMessage(incoming=True, func=_filter_not_mapped))
        @bot_client.on(events.NewMessage(incoming=True, pattern=START_CMD.epilog))
        async def start_handler(event: NewMessage.Event):
            if not (await auth_manager.ensure_authorized(event.sender_id)):
                return
            logger.debug(f"Received unknown command: <{event.message.message}>")
            await event.respond(build_help())

        @bot_client.on(events.NewMessage(incoming=True, pattern=LIST_CMD.epilog))
        async def list_handler(event: NewMessage.Event):
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
                return

            args, help_to_print = _parse_args(
                LIST_CMD, event.pattern_match.group(1).strip()
            )
            if help_to_print:
                await event.respond(help_to_print)
                return

            if args.subs:
                message_text, buttons, (pagination_data, attributes) = (
                    await build_subscribed_channel_response(
                        event.sender_id, session.user_client, []
                    )
                )
            else:
                message_text, buttons, (pagination_data, attributes) = (
                    await build_all_channel_response(
                        event.sender_id, session.user_client, []
                    )
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
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
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
                        session.user_client,
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
                        session.user_client,
                        offset_stack,
                        (target_offset, action_type),
                    )
                )
            else:
                raise ValueError(f"Unknown request type {request_type}")
            await event.edit(
                message_text,
                file=pagination_data,
                attributes=attributes,
                buttons=buttons,
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=SUBSCRIBE_CMD.epilog))
        async def subscribe_handler(event: NewMessage.Event):
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
                return

            args, help_to_print = _parse_args(
                SUBSCRIBE_CMD, event.pattern_match.group(1).strip()
            )
            if help_to_print:
                await event.respond(help_to_print)
                return

            logger.debug(
                f"subscribing user {event.sender_id}: {args.src_channel_id} -> {args.dst_channel_id} with filter {args.filter_type}({args.filter_params})"
            )
            channel = unwrap_single_chat(
                await session.user_client(GetChannelsRequest(id=[args.dst_channel_id]))
            )
            if not has_send_message_permission(channel):
                await event.respond(
                    f"You have no permission to send messages in {args.dst_channel_id}"
                )
                return

            config.create_subscription(
                event.sender_id,
                args.src_channel_id,
                (args.dst_channel_id, channel.title),
                (args.filter_type, args.filter_params),
            )
            subscribe_to_channel(
                event.sender_id, session.user_client, args.src_channel_id, bot_client
            )
            await event.respond(
                f"subscribed {args.src_channel_id} -> {args.dst_channel_id}"
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=UNSUBSCRIBE_CMD.epilog))
        async def unsubscribe_handler(event: NewMessage.Event):
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
                return

            args, help_to_print = _parse_args(
                UNSUBSCRIBE_CMD, event.pattern_match.group(1).strip()
            )
            if help_to_print:
                await event.respond(help_to_print)
                return

            logger.debug(
                f"unsubscribing user {event.sender_id}: {args.src_channel_id=} -> {args.dst_channel_id}"
            )
            if config.remove_subscription(
                event.sender_id, args.src_channel_id, args.dst_channel_id
            ):
                unsubscribe_from_channel(
                    session.user_client, args.src_channel_id, bot_client
                )
            await event.respond(
                f"unsubscribed {args.src_channel_id} -> {args.dst_channel_id}"
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=SYNC_CMD.epilog))
        async def sync_handler(event: NewMessage.Event):
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
                return

            args, help_to_print = _parse_args(
                SYNC_CMD, event.pattern_match.group(1).strip()
            )
            if help_to_print:
                await event.respond(help_to_print)
                return

            mapping = dict(args.pairs)
            default_offset = mapping.pop("all", None)
            if default_offset:
                for channel_id, _ in config.get_all_user_subscriptions(event.sender_id):
                    if channel_id not in mapping:
                        mapping[channel_id] = default_offset

            for channel_id, offset in mapping.items():
                session.queue.put(
                    {"cmd": "sync", "channel_id": channel_id, "from": offset}
                )

        @bot_client.on(events.NewMessage(incoming=True, pattern="^[^/].+"))
        async def common_message_handler(event: NewMessage.Event):
            await auth_manager.feed_message(event.sender_id, event)

        await ensure_clients_consistency(auth_manager, tasks, bot_client, True)
        tasks["check_clients_consistency"] = asyncio.create_task(
            check_clients_consistency(auth_manager, tasks, bot_client)
        )
        await bot_client.run_until_disconnected()
    for task in tasks.values():
        task.cancel("shutdown")
    await auth_manager.disconnect_clients()


# api_id = os.getenv("API_ID")
# api_hash = os.getenv("API_HASH")
# bot_token = os.getenv("BOT_TOKEN")
if __name__ == "__main__":
    asyncio.run(main())
