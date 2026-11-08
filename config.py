import json
import logging
import os
import pathlib
import re
from datetime import datetime

from subscription import Sink

logger = logging.getLogger(__file__)

api_id = os.getenv("API_ID")
api_hash = os.getenv("API_HASH")
bot_token = os.getenv("BOT_TOKEN")
owner_user_id = int(os.getenv("OWNER_USER_ID", "0"))
data_path = pathlib.Path("data")


def v_name(fstr: str) -> str:
    return fstr.split("=", 2)[0]


not_overridable_properties = {
    v_name(f"{api_id=}"),
    v_name(f"{api_hash=}"),
    v_name(f"{bot_token=}"),
    v_name(f"{owner_user_id=}"),
    v_name(f"{data_path=}"),
}

user_client_check_period_seconds = 10
dialog_list_page_size = 10
scheduler_tick_seconds = 30
error_notify_throttle_seconds = 3600  # DM dedup window per key
dedup_window_minutes = 60  # sink content dedup look-back
send_min_interval_seconds = 1.0  # global bot API pacing
queue_retry_backoff_seconds = 30  # /sync requeue backoff
dm_queue_maxsize = 100
dm_max_attempts = 5
dm_backoff_start_seconds = 30
dm_backoff_cap_seconds = 3600


def _atomic_write(path: pathlib.Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def override():
    overrides = {}
    override_from = data_path.joinpath("config.py")
    if override_from.exists():
        exec(override_from.read_text(), locals=overrides)
    for override_key, override_value in filter(
        lambda t: t[0] not in not_overridable_properties, overrides.items()
    ):
        globals()[override_key] = override_value


override()


def get_all_user_subscriptions(user_id: int) -> list[tuple[int, list[Sink]]]:
    user_data_path = data_path.joinpath(str(user_id))
    subscriptions_path = user_data_path.joinpath("subscriptions")
    if not subscriptions_path.exists():
        return []

    subscriptions = []
    for source_channel_dir_path in subscriptions_path.iterdir():
        subscriptions.append(
            (
                int(source_channel_dir_path.name),
                get_channel_subscriptions(user_id, int(source_channel_dir_path.name)),
            )
        )
    return subscriptions


def get_channel_subscriptions(user_id: int, source_channel_id: int) -> list[Sink]:
    subscription_path = (
        data_path.joinpath(str(user_id))
        .joinpath("subscriptions")
        .joinpath(str(source_channel_id))
    )
    if not subscription_path.exists():
        return []
    sinks = []
    for sink_file in subscription_path.iterdir():
        if sink_file.suffix != ".json" or not sink_file.is_file():
            continue
        try:
            sinks.append(Sink(sink_file.stem, sink_file.read_text()))
        except Exception as e:
            logger.warning(f"skipping corrupt sink config {sink_file}: {e}")
    return sinks


def get_existing_users() -> list[int]:
    return [
        int(user_data.name)
        for user_data in data_path.iterdir()
        if re.match("\\d+", user_data.name)
    ]


def create_subscription(
    user_id: int,
    source_channel_id: int,
    sink: tuple[int, str],
    subscription_filter: tuple[str, str],
    caption: str = "link",
    schedule: str | None = None,
    start_message_id: int | None = None,
    batch: int = 1,
):
    user_path = data_path.joinpath(str(user_id))
    if not user_path.exists() or not user_path.is_dir():
        raise Exception(f"No data folder for user {user_id}")

    user_subscriptions_dir = user_path.joinpath("subscriptions")
    user_subscriptions_dir.mkdir(exist_ok=True)
    source_config_path = user_subscriptions_dir.joinpath(str(source_channel_id))
    source_config_path.mkdir(exist_ok=True)
    sink_config_path = source_config_path.joinpath(f"{sink[0]}.json")
    existing_sink_config = {}
    if sink_config_path.exists():
        existing_sink_config = json.loads(sink_config_path.read_text())
    sink_config = {
        "sink_name": sink[1],
        "caption": caption,
        "filter": {
            "type": subscription_filter[0],
            "params": json.loads(subscription_filter[1]),
        },
    }
    if schedule:
        sink_config["schedule"] = schedule
    if start_message_id is not None:
        sink_config["start_message_id"] = start_message_id
    if batch != 1:
        sink_config["batch"] = batch
    # runtime state survives re-subscription unless schedule-defining options
    # changed: those start a fresh forwarding pointer
    if existing_sink_config.get("state") and (
        existing_sink_config.get("schedule") == sink_config.get("schedule")
        and existing_sink_config.get("start_message_id")
        == sink_config.get("start_message_id")
    ):
        sink_config["state"] = existing_sink_config["state"]
    elif schedule:
        # scheduler anchor: the next due time is the first cron occurrence
        # after this moment
        sink_config["state"] = {"last_run_at": datetime.now().isoformat()}
    _atomic_write(sink_config_path, json.dumps(sink_config))


def update_sink_state(
    user_id: int, source_channel_id: int, sink_channel_id: int, state: dict
):
    sink_config_path = (
        data_path.joinpath(str(user_id))
        .joinpath("subscriptions")
        .joinpath(str(source_channel_id))
        .joinpath(f"{sink_channel_id}.json")
    )
    sink_config = json.loads(sink_config_path.read_text())
    sink_config["state"] = state
    _atomic_write(sink_config_path, json.dumps(sink_config))


def remove_subscription(user_id: int, source_channel_id, sink_channel_id) -> bool:
    user_path = data_path.joinpath(str(user_id))
    if not user_path.exists() or not user_path.is_dir():
        raise Exception(f"No data folder for user {user_id}")
    user_subscriptions_dir = user_path.joinpath("subscriptions")
    source_config_path = user_subscriptions_dir.joinpath(str(source_channel_id))
    if (
        user_subscriptions_dir.exists()
        and user_subscriptions_dir.is_dir()
        and source_config_path.exists()
        and source_config_path.is_dir()
    ):
        sink_config_path = source_config_path.joinpath(f"{sink_channel_id}.json")
        sink_config_path.unlink(missing_ok=True)
    is_empty = source_config_path.exists() and not any(source_config_path.iterdir())
    if is_empty:
        source_config_path.rmdir()
    return is_empty


def get_allowed_to_use_user_ids() -> list[int]:
    whitelist_path = data_path.joinpath("user_whitelist")
    if not whitelist_path.exists():
        return []
    return [int(user.name) for user in whitelist_path.iterdir()]


def is_allowed_user(user_id: int) -> bool:
    return user_id == owner_user_id or user_id in get_allowed_to_use_user_ids()
