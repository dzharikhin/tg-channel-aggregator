import asyncio
import dataclasses
import itertools
import json
import logging
import pathlib
import re
from typing import Any, Optional

import qrcode
from ecies import decrypt, encrypt
from ecies.utils import generate_eth_key
from telethon import TelegramClient, events, Button
from telethon.errors import SessionPasswordNeededError
from telethon.events import CallbackQuery
from telethon.tl.custom import QRLogin, Dialog

import config

# commands to implement:
# - list-channels - shows user channels and ids
# - sink - shows current sink channel
# set-sink - sets sink channel
# list-subscriptions - shows current subscriptions for aggregation
# subscribe - add/update subscription
# unsubscribe - remove subscription
# sync - sync messages: mapping channel(may be "all") by date or by from_id

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _render_qr(data: str, file_path: pathlib.Path):
    qr = qrcode.main.QRCode(
        version=3,
        box_size=20,
        border=10,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(file_path)


@dataclasses.dataclass
class Keys:
    sk: str
    pk: str


def _generate_keys() -> Keys:
    eth_k = generate_eth_key()
    keys = Keys(eth_k.to_hex(), eth_k.public_key.to_hex())
    print(f"generated {keys=}")
    return keys


def _decode(encrypted_: str, sk: str):
    print(f"decoding {encrypted_=}")
    print(f"decoding {sk=}")
    return decrypt(sk, bytes.fromhex(encrypted_))


@dataclasses.dataclass
class TransitionStatus:
    new_state: "UserClientState"
    proceed_with_current_event: bool


class UserClientState:
    _bot_client: TelegramClient
    _user_client: TelegramClient

    async def transition(self, user_id: int, event) -> TransitionStatus:
        pass

    @classmethod
    async def get_or_create_client(
        cls,
        state_registry: dict[int, "UserClientState"],
        bot_client: TelegramClient,
        user_id: int,
        event=None,
    ) -> Optional[TelegramClient]:
        if event:
            user_id = event.sender_id

        if user_id != config.owner_user_id:
            user = await bot_client.get_entity(user_id)
            await bot_client.send_message(
                config.owner_user_id,
                f"User `{user_id}: {user.username}` tries to use bot",
            )
            return None

        current_state = state_registry.get(user_id)
        if not current_state:
            user_client = await init_user_client(user_id)
            state_registry[user_id] = NotAuthorizedClient(
                user_client=user_client, bot_client=bot_client
            )
        proceed_with_current_event = True
        while proceed_with_current_event:
            current_state = state_registry[user_id]
            transition_status = await current_state.transition(user_id, event)
            state_registry[user_id] = transition_status.new_state
            proceed_with_current_event = transition_status.proceed_with_current_event
        current_state = state_registry[user_id]
        return (
            current_state._user_client
            if type(current_state) == AuthorizedClient
            else None
        )


class NotAuthorizedClient(UserClientState):

    def __init__(
        self,
        *,
        from_state: Optional[UserClientState] = None,
        user_client: Optional[TelegramClient] = None,
        bot_client: Optional[TelegramClient] = None,
    ):
        if from_state:
            self._bot_client = from_state._bot_client
            self._user_client = from_state._user_client
        else:
            self._bot_client = bot_client
            self._user_client = user_client

    async def transition(self, user_id: int, event) -> TransitionStatus:
        if await self._user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(self), True)
        if not self._user_client.is_connected():
            await self._user_client.connect()
        qr_login = await self._user_client.qr_login()
        qr_img_path = config.data_path.joinpath(str(user_id)).joinpath("qr.png")
        _render_qr(qr_login.url, qr_img_path)
        await self._bot_client.send_file(user_id, qr_img_path)
        logging.debug(f"{qr_img_path=}")
        return TransitionStatus(QrAuthorizationWaitingClient(qr_login, self), True)


class AuthorizedClient(UserClientState):

    def __init__(self, from_state: UserClientState):
        self._user_client = from_state._user_client
        self._bot_client = from_state._bot_client

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if not self._user_client.is_connected():
            await self._user_client.connect()
        if await self._user_client.is_user_authorized():
            return TransitionStatus(self, False)
        return TransitionStatus(NotAuthorizedClient(from_state=self), True)


class QrAuthorizationWaitingClient(UserClientState):

    def __init__(self, qr_login: QRLogin, from_state: UserClientState):
        self._bot_client = from_state._bot_client
        self._user_client = from_state._user_client
        self._qr_login = qr_login

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if await self._user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(self), True)
        try:
            await self._qr_login.wait(config.qr_login_wait_seconds)
            return TransitionStatus(AuthorizedClient(self), True)
        except TimeoutError as e:
            logging.info("Qr auth timeout exception, recreating qr", e)
            return TransitionStatus(NotAuthorizedClient(from_state=self), True)
        except SessionPasswordNeededError as e:
            logging.info("2FA password required", e)
            return TransitionStatus(
                PasswordAuthorizationKeysPreparingClient(self), True
            )


class PasswordAuthorizationKeysPreparingClient(UserClientState):

    def __init__(self, from_state: UserClientState):
        self._user_client = from_state._user_client
        self._bot_client = from_state._bot_client

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if await self._user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(self), True)
        keys = _generate_keys()
        message = await self._bot_client.send_message(user_id, f"`{keys.pk}`")
        print(
            f"encrypted password: {encrypt(keys.pk, pathlib.Path("pwd").read_bytes()).hex()}"
        )
        return TransitionStatus(
            PasswordAuthorizationWaitingClient(keys.sk, keys.pk, message.id, self),
            False,
        )


class PasswordAuthorizationWaitingClient(UserClientState):

    def __init__(
        self,
        secret_key: str,
        public_key: str,
        message_with_public_key_id: int,
        from_state: UserClientState,
    ):
        self._user_client = from_state._user_client
        self._bot_client = from_state._bot_client
        self._secret_key = [secret_key]
        self.public_key = public_key
        self.public_key_msg_id = message_with_public_key_id

    async def transition(self, user_id: int, event) -> TransitionStatus:
        if await self._user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(self), True)
        encrypted_ = event.message.message.strip()
        await self._bot_client.delete_messages(
            user_id, [self.public_key_msg_id, event.message.id]
        )
        try:
            payload = _decode(encrypted_, self._secret_key.pop())
        except ValueError as e:
            logging.warning("Password input was not encrypted with current PK", e)
            await self._bot_client.send_message(
                user_id, "Password was not encrypted with public key. Lets try again"
            )
            return TransitionStatus(
                PasswordAuthorizationKeysPreparingClient(self), True
            )
        try:
            logged_in_user = await self._user_client.sign_in(
                password=payload.decode("utf-8")
            )
            logging.info(f"User {logged_in_user.id} logged in with password")
            return TransitionStatus(AuthorizedClient(from_state=self), True)
        except Exception as e:
            logging.error("Error on password login. Going to retry", e)
            return TransitionStatus(
                PasswordAuthorizationKeysPreparingClient(from_state=self), True
            )


async def new_message_in_target_channel_handler(event):
    # user_client.forward_messages(messages=[], )
    print(event.stringify())


async def init_user_client(user_id: int) -> TelegramClient:
    config_folder = config.data_path.joinpath(str(user_id))
    config_folder.mkdir(exist_ok=True)
    user_client = TelegramClient(
        config_folder.joinpath(config_folder.name), config.api_id, config.api_hash
    )
    user_config = get_user_config(config_folder.name)
    for channel in user_config.get("channels", []):
        user_client.add_event_handler(
            new_message_in_target_channel_handler, events.NewMessage(chats=[channel])
        )
    await user_client.connect()
    return user_client


def get_user_config(user_id: str) -> dict[str, Any]:
    config_path = config.data_path.joinpath(user_id).joinpath("config")
    if config_path.exists():
        return json.loads(config_path.read_text())
    return {}


async def check_clients_authorized(
    user_clients: dict[int, UserClientState], bot_client: TelegramClient
):
    while True:
        for user_id, state in list(user_clients.items()):
            if type(state) == AuthorizedClient:
                await state.get_or_create_client(user_clients, bot_client, user_id)
        await asyncio.sleep(config.user_client_check_period_seconds)


async def get_channels_page(
    user_client: TelegramClient, page: int
) -> tuple[list[Dialog], int | None, int | None]:
    channels = []
    async for dialog in user_client.iter_dialogs(archived=False, ignore_migrated=True):
        if dialog.is_channel and not dialog.is_group and not dialog.is_user:
            channels.append(dialog)

    chunks = list(itertools.batched(channels, config.dialog_list_page_size))
    return (
        list(chunks[page]),
        (page - 1 if page > 0 else None),
        (page + 1 if page < (len(chunks) - 1) else None),
    )


async def build_channel_response(
    user_client: TelegramClient, page: int = 0
) -> tuple[str, list[Button]]:
    channels_page, previous_page, next_page = await get_channels_page(user_client, page)
    previous_button = (
        Button.inline("Previous", f"ch({previous_page})")
        if previous_page is not None
        else None
    )
    next_button = (
        Button.inline("Next", f"ch({next_page})") if next_page is not None else None
    )
    channels_formatted = "\n".join(
        [f"- {channel.title}: `{channel.id}`" for channel in channels_page]
    )
    return channels_formatted, [b for b in [previous_button, next_button] if b]


async def main():
    bot_client = TelegramClient("bot", config.api_id, config.api_hash)
    bot_client = await bot_client.start(bot_token=config.bot_token)
    tasks = []
    async with bot_client:
        logging.debug(f"Started bot {await bot_client.get_me()}")
        user_client_registry = {}

        @bot_client.on(events.NewMessage(incoming=True, pattern="(?i)^/start"))
        async def list_channels_handler(event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            message_text, buttons = await build_channel_response(user_client)
            await event.respond(message_text, buttons=buttons)

        @bot_client.on(events.CallbackQuery(data=re.compile("^ch\\((\\d+)\\)")))
        async def channels_pagination_handler(event: CallbackQuery.Event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            page = int(event.pattern_match.group(1).decode("utf-8"))
            message_text, buttons = await build_channel_response(user_client, page)
            await event.edit(message_text, buttons=buttons)

        @bot_client.on(
            events.NewMessage(incoming=True, pattern="(?i)^/subscribe (-?\\d+)")
        )
        async def subscribe_handler(event):
            if not (
                user_client := await UserClientState.get_or_create_client(
                    user_client_registry, bot_client, event.sender_id, event
                )
            ):
                return
            channel_id = event.pattern_match.group(1).strip()
            print(f"{channel_id=}")
            user_client.add_event_handler(
                new_message_in_target_channel_handler,
                event=events.NewMessage(chats=[int(channel_id)]),
            )
            await event.respond(f"subscribed to channel {channel_id}")

        @bot_client.on(events.NewMessage(incoming=True, pattern="^[^/].+"))
        async def common_message_handler(event):
            await UserClientState.get_or_create_client(
                user_client_registry, bot_client, event.sender_id, event
            )

        tasks.append(
            asyncio.create_task(
                check_clients_authorized(user_client_registry, bot_client)
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
