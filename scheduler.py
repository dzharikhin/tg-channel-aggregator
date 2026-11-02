import asyncio
import logging
from datetime import datetime

from croniter import croniter
from telethon import TelegramClient
from telethon.errors import RPCError
from telethon.tl.functions.channels import GetChannelsRequest

import config
from auth import AuthManager
from common import unwrap_single_chat
from subscription import Sink, build_caption

logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


def next_run(schedule: str, last_run_at: datetime | None, now: datetime) -> datetime:
    return croniter(schedule, last_run_at or now).get_next(datetime)


def is_due(schedule: str, last_run_at: datetime | None, now: datetime) -> bool:
    return next_run(schedule, last_run_at, now) <= now


def sink_last_run_at(sink: Sink) -> datetime | None:
    raw = sink.state.get("last_run_at")
    return datetime.fromisoformat(raw) if raw else None


async def forward_step(
    user_id: int,
    user_client: TelegramClient,
    bot_client: TelegramClient,
    source_channel_id: int,
    sink: Sink,
    now: datetime,
):
    channel = unwrap_single_chat(
        await user_client(GetChannelsRequest(id=[source_channel_id]))
    )
    if not channel:
        raise ValueError(f"Channel {source_channel_id} is not available")

    state = dict(sink.state)
    pointer = state.get("last_forwarded_message_id", sink.start_message_id)
    if pointer is None:
        # first run without an explicit start: skip the whole history
        newest = await user_client.get_messages(channel, limit=1)
        pointer = newest[0].id if newest else 0
    if "last_forwarded_message_id" not in state:
        state["last_forwarded_message_id"] = pointer
        config.update_sink_state(user_id, source_channel_id, sink.id, state)

    sent = 0
    async for message in user_client.iter_messages(
        channel, min_id=pointer, reverse=True
    ):
        if not sink.filter_message(message):
            # examined and not matching: permanently skipped once the
            # pointer is persisted
            state["last_forwarded_message_id"] = message.id
            continue
        if sent >= sink.batch:
            # batch is full: leave the rest, starting from this message,
            # for the next scheduled run
            break
        try:
            result = await user_client.send_file(
                sink.id,
                message.media,
                caption=build_caption(sink.caption, message),
            )
            logger.debug(f"Forwarded {message} to {sink} with result {result}")
        except RPCError as e:
            logger.warning(
                f"User {user_id} has no permission to send messages in {sink.name}({sink.id})",
                exc_info=e,
            )
            await bot_client.send_message(
                user_id,
                f"You have no permission to send messages in {sink.name}(`{sink.id}`). Please, grant permission or unsubscribe",
            )
            # pointer stays before the failed message: it is retried on the
            # next scheduled run
            break
        sent += 1
        state["last_forwarded_message_id"] = message.id
        config.update_sink_state(user_id, source_channel_id, sink.id, state)
    state["last_run_at"] = now.isoformat()
    config.update_sink_state(user_id, source_channel_id, sink.id, state)
    logger.debug(
        f"Scheduled step done for user {user_id}: {source_channel_id} -> {sink}, sent {sent} message(s)"
    )


async def run_scheduled_forwardings(
    auth_manager: AuthManager,
    bot_client: TelegramClient,
):
    while True:
        try:
            now = datetime.now()
            for user_id in auth_manager.tracked_users():
                session = await auth_manager.ensure_authorized(user_id)
                if not session:
                    continue
                for source_channel_id, sinks in config.get_all_user_subscriptions(
                    user_id
                ):
                    for sink in sinks:
                        if not sink.schedule or not is_due(
                            sink.schedule, sink_last_run_at(sink), now
                        ):
                            continue
                        logger.debug(
                            f"Running scheduled forwarding for user {user_id}: {source_channel_id} -> {sink}"
                        )
                        try:
                            await forward_step(
                                user_id,
                                session.user_client,
                                bot_client,
                                source_channel_id,
                                sink,
                                now,
                            )
                        except Exception as e:
                            # step not marked done: retried on the next tick
                            logger.warning(
                                f"Scheduled forwarding failed for user {user_id}: {source_channel_id} -> {sink}, will retry",
                                exc_info=e,
                            )
        except Exception as e:
            logger.warning("Scheduled forwarding loop iteration failed", exc_info=e)
        await asyncio.sleep(config.scheduler_tick_seconds)
