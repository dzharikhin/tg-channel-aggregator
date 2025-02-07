import json
import os
import pathlib
import re

from subscription import Sink

api_id = os.getenv("API_ID")
api_hash = os.getenv("API_HASH")
bot_token = os.getenv("BOT_TOKEN")
data_path = pathlib.Path("data")
qr_login_wait_seconds = 60
user_client_check_period_seconds = 10
dialog_list_page_size = 10
max_queue_workers = 3

owner_user_id = int(os.getenv("OWNER_USER_ID", "0"))


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
    sinks = [
        Sink(sink_file.stem, sink_file.read_text())
        for sink_file in subscription_path.iterdir()
    ]
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
):
    user_path = data_path.joinpath(str(user_id))
    if not user_path.exists() or not user_path.is_dir():
        raise Exception(f"No data folder for user {user_id}")

    user_subscriptions_dir = user_path.joinpath("subscriptions")
    user_subscriptions_dir.mkdir(exist_ok=True)
    source_config_path = user_subscriptions_dir.joinpath(str(source_channel_id))
    source_config_path.mkdir(exist_ok=True)
    sink_config_path = source_config_path.joinpath(f"{sink[0]}.json")
    sink_config = json.dumps(
        {
            "sink_name": sink[1],
            "filter": {
                "type": subscription_filter[0],
                "params": json.loads(subscription_filter[1]),
            },
        }
    )
    sink_config_path.write_text(sink_config)


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
