import asyncio
import io
import json
import logging
import re
import shlex
from argparse import ArgumentError, ArgumentParser, ArgumentTypeError, Namespace
from asyncio import Task
from collections import Counter
from functools import partial
from types import CoroutineType
from typing import cast

import persistqueue
from croniter import croniter
from telethon import TelegramClient, events
from telethon.errors import BadRequestError, RPCError
from telethon.events import CallbackQuery, NewMessage
from telethon.tl.types import Channel, Chat, User

import config
import notifications
from auth import AuthManager
from channels import build_all_channel_response, build_subscribed_channel_response
from common import entity_name
from notifications import enqueue_error_dm
from scheduler import run_scheduled_forwardings
from subscription import (
    CAPTION_MODES,
    ChannelHistoryError,
    forward_channel_history,
    handler_channel_ids,
    subscribe_to_channel,
    unsubscribe_from_channel,
)

# commands to implement:
# - list-channels [subs] - shows user channels and ids, subs - show only subscribed channels
# - subscribe <channel_id_from> <channel_id_to> {<filter json>} [<caption>] [<cron schedule> <start_msg_id> <batch>] - add/update subscription
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
            enqueue_error_dm(
                config.owner_user_id,
                "consistency-fail",
                "exception on consistency check",
            )
        await asyncio.sleep(config.user_client_check_period_seconds)


def requeue_sync_with_progress(
    queue: persistqueue.SQLiteAckQueue, cmd: dict, last_processed_id: int | None
) -> None:
    queue.ack(cmd)
    queue.put(
        {
            "cmd": "sync",
            "channel_id": cmd["channel_id"],
            "from": last_processed_id if last_processed_id is not None else cmd["from"],
        }
    )


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
                from_offset = cmd["from"]
                if isinstance(from_offset, int):
                    min_id = from_offset - 1
                elif "full" == from_offset:
                    min_id = None
                else:
                    raise ValueError(f"unknown <from> cmd: {cmd["from"]}")
                await forward_channel_history(
                    user_id,
                    user_client,
                    bot_client,
                    cmd["channel_id"],
                    min_id,
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
            enqueue_error_dm(
                user_id,
                f"cmd-fail:{cmd.get("cmd")}:{cmd.get("channel_id")}",
                f"Failed to execute {cmd}: {e}",
            )
        except ChannelHistoryError as e:
            logger.info(
                f"{cmd} - failed with {type(e.cause).__name__}, requeued from progress",
                exc_info=e,
            )
            requeue_sync_with_progress(queue, cmd, e.last_processed_id)
            enqueue_error_dm(
                user_id,
                f"sync-fail:{cmd["channel_id"]}",
                f"Sync of channel {cmd["channel_id"]} failed with "
                f"{type(e.cause).__name__} and was requeued from message "
                f"{e.last_processed_id or cmd["from"]}.",
            )
            await asyncio.sleep(config.queue_retry_backoff_seconds)


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
        channel_handler_counts = Counter(
            channel_id
            for _, event in user_client.list_event_handlers()
            for channel_id in handler_channel_ids(event)
        )
        for channel_id, count in channel_handler_counts.items():
            if count > 1:
                logger.warning(
                    f"For user {user_id} there are duplicate handlers for channel {channel_id}, deduplicating"
                )
                unsubscribe_from_channel(user_client, channel_id)
                if channel_id in channels_to_listen:
                    subscribe_to_channel(user_id, user_client, channel_id, bot_client)
        actual_subscribed_channels = set(channel_handler_counts)
        for to_add in channels_to_listen - actual_subscribed_channels:
            subscribe_to_channel(user_id, user_client, to_add, bot_client)
        for to_remove in actual_subscribed_channels - channels_to_listen:
            unsubscribe_from_channel(user_client, to_remove)

        handle_task_id = f"queue_handler-{user_id}"
        current_task = tasks.get(handle_task_id)
        if not current_task or current_task.done() or current_task.cancelled():
            tasks[handle_task_id] = asyncio.create_task(
                handle_queue_tasks(user_id, session.queue, user_client, bot_client),
            )


def bot_can_write(entity) -> bool:
    if isinstance(entity, Channel) and not entity.megagroup:
        return bool(entity.admin_rights and entity.admin_rights.post_messages)
    if isinstance(entity, (Channel, Chat)):
        banned = entity.default_banned_rights
        return not (banned and banned.send_messages)
    if isinstance(entity, User):
        return True
    return False


async def process_subscribe(
    event: NewMessage.Event,
    session,
    bot_client: TelegramClient,
    args: Namespace,
):
    logger.debug(
        f"subscribing user {event.sender_id}: {args.src_channel_id} -> {args.dst_channel_id} with filter {args.filter_type}({args.filter_params})"
    )
    errors = []
    try:
        await session.user_client.get_entity(args.src_channel_id)
    except (RPCError, ValueError) as e:
        logger.warning(
            f"User client cannot read source channel {args.src_channel_id}",
            exc_info=e,
        )
        errors.append(
            f"Your account has no READ access to source channel "
            f"{args.src_channel_id}. Make sure your account is a member there; "
            f"check the id via /list."
        )

    try:
        await session.user_client.get_entity(args.dst_channel_id)
    except (RPCError, ValueError) as e:
        logger.warning(
            f"User client cannot read sink channel {args.dst_channel_id} " f"for dedup",
            exc_info=e,
        )
        errors.append(
            f"Your account has no READ access to sink channel "
            f"{args.dst_channel_id}. Duplicate checks read its history via "
            f"your account; join the channel and retry."
        )

    try:
        sink_entity = await bot_client.get_entity(args.dst_channel_id)
    except (RPCError, ValueError) as e:
        logger.warning(
            f"Bot cannot access sink channel {args.dst_channel_id}", exc_info=e
        )
        sink_entity = None
    if not sink_entity or not bot_can_write(sink_entity):
        errors.append(
            f"Bot has no permission to post in {args.dst_channel_id}. "
            f"Add the bot there with post rights and retry."
        )

    if errors:
        await event.respond("\n".join(errors))
        return

    config.create_subscription(
        event.sender_id,
        args.src_channel_id,
        (args.dst_channel_id, entity_name(sink_entity)),
        (args.filter_type, args.filter_params),
        caption=args.caption,
        schedule=args.schedule,
        start_message_id=args.start_message_id,
        batch=args.batch,
    )
    subscribe_to_channel(
        event.sender_id, session.user_client, args.src_channel_id, bot_client
    )
    await event.respond(
        f"subscribed {args.src_channel_id} -> {args.dst_channel_id}"
        + (f" on schedule {args.schedule!r}" if args.schedule else "")
    )


def jsonarg(arg: str) -> str:
    try:
        json.loads(arg)
        return arg
    except json.JSONDecodeError:
        raise ArgumentTypeError(f"{arg} is not a valid json")


def cronarg(arg: str) -> str:
    if not croniter.is_valid(arg):
        raise ArgumentTypeError(f"{arg} is not a valid cron expression")
    return arg


def peerarg(arg: str) -> int:
    try:
        peer_id = int(arg)
    except ValueError:
        raise ArgumentTypeError(
            f"{arg} is not a canonical peer id: user 123456789, "
            f"group -123456789, channel -1001234567890"
        )
    if peer_id == 0:
        raise ArgumentTypeError(
            f"{arg} is not a canonical peer id: user 123456789, "
            f"group -123456789, channel -1001234567890"
        )
    return peer_id


def syncpairarg(err_msg: str, arg: str) -> tuple[int | str, int | str]:
    k, v = tuple(arg.split("="))
    if re.fullmatch("-?\\d+", k):
        k = peerarg(k)
    if re.fullmatch("-?\\d+", v):
        v = peerarg(v)
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
        type=peerarg,
        help="canonical id of the source peer to listen messages from: user 123456789, group -123456789, channel -1001234567890",
    ),
    parser.add_argument(
        "-d",
        "--dst_channel_id",
        required=True,
        type=peerarg,
        help="canonical id of the destination peer to sink messages to: user 123456789, group -123456789, channel -1001234567890",
    ),
    parser.add_argument(
        "-f",
        "--filter_type",
        required=True,
        type=str,
        choices=["mp3", "hashtag"],
        help="source filter type",
    ),
    parser.add_argument(
        "-p",
        "--filter_params",
        required=True,
        type=jsonarg,
        help="params for filter: single-quoted JSON, e.g. -p "
        '\'{"min_seconds": 90, "max_seconds": 480}\'',
    ),
    parser.add_argument(
        "-c",
        "--caption",
        required=False,
        type=str,
        choices=sorted(CAPTION_MODES),
        default="link",
        help="caption for forwarded media: none - no caption, link - link to original message (default), original - original message text",
    ),
    parser.add_argument(
        "-r",
        "--schedule",
        required=False,
        type=cronarg,
        default=None,
        help="cron expression to forward on schedule (e.g. '0 9 * * *'). if omitted, messages are forwarded in realtime",
    ),
    parser.add_argument(
        "-m",
        "--start_message_id",
        required=False,
        type=int,
        default=None,
        help="id of the last handled source message: scheduled forwarding starts from the next one. without it the first run skips the whole history. used only with --schedule",
    ),
    parser.add_argument(
        "-b",
        "--batch",
        required=False,
        type=int,
        default=1,
        help="max messages to forward per scheduled run",
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
        type=peerarg,
        help="canonical id of the source peer to stop listening: user 123456789, group -123456789, channel -1001234567890",
    ),
    parser.add_argument(
        "-d",
        "--dst_channel_id",
        required=True,
        type=peerarg,
        help="canonical id of the destination peer to stop sinking: user 123456789, group -123456789, channel -1001234567890",
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


TYPOGRAPHIC_CHARS = str.maketrans(
    {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00a0": " "}
)


def _parse_args(
    arg_parser: ArgumentParser, cmd_line: str
) -> tuple[Namespace | None, str | None]:
    try:
        args = arg_parser.parse_args(shlex.split(cmd_line.translate(TYPOGRAPHIC_CHARS)))
        return args, None
    except ArgumentError as e:
        logger.warning(
            f"cannot parse {arg_parser.prog} command from {cmd_line!r}", exc_info=e
        )
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


def report_errors(handler):
    async def wrapper(event):
        try:
            return await handler(event)
        except Exception as e:
            logger.error(f"Unhandled exception in {handler.__name__}", exc_info=e)
            for feedback in ("respond", "answer", "edit"):
                feedback_call = getattr(event, feedback, None)
                if not feedback_call:
                    continue
                try:
                    await feedback_call(
                        "Internal error while processing the command, it has been logged"
                    )
                except Exception:
                    continue
                break

    wrapper.__name__ = handler.__name__
    return wrapper


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
        @report_errors
        async def start_handler(event: NewMessage.Event):
            if not (await auth_manager.ensure_authorized(event.sender_id)):
                return
            logger.debug(f"Received unknown command: <{event.message.message}>")
            await event.respond(build_help())

        @bot_client.on(events.NewMessage(incoming=True, pattern=LIST_CMD.epilog))
        @report_errors
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
        @report_errors
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
        @report_errors
        async def subscribe_handler(event: NewMessage.Event):
            if not (session := await auth_manager.ensure_authorized(event.sender_id)):
                return

            args, help_to_print = _parse_args(
                SUBSCRIBE_CMD, event.pattern_match.group(1).strip()
            )
            if help_to_print:
                await event.respond(help_to_print)
                return

            await process_subscribe(event, session, bot_client, args)

        @bot_client.on(events.NewMessage(incoming=True, pattern=UNSUBSCRIBE_CMD.epilog))
        @report_errors
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
                unsubscribe_from_channel(session.user_client, args.src_channel_id)
            await event.respond(
                f"unsubscribed {args.src_channel_id} -> {args.dst_channel_id}"
            )

        @bot_client.on(events.NewMessage(incoming=True, pattern=SYNC_CMD.epilog))
        @report_errors
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
        @report_errors
        async def common_message_handler(event: NewMessage.Event):
            await auth_manager.feed_message(event.sender_id, event)

        await ensure_clients_consistency(auth_manager, tasks, bot_client, True)
        tasks["check_clients_consistency"] = asyncio.create_task(
            check_clients_consistency(auth_manager, tasks, bot_client)
        )
        tasks["scheduled_forwarding"] = asyncio.create_task(
            run_scheduled_forwardings(auth_manager, bot_client)
        )
        tasks["dm_processor"] = asyncio.create_task(
            notifications.run_dm_processor(bot_client)
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
