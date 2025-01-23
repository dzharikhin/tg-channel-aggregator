import asyncio
import dataclasses
import json
import logging
import pathlib
from typing import Any, Optional

import qrcode
from ecies import decrypt, encrypt
from ecies.utils import generate_eth_key
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError
from telethon.tl.custom import QRLogin

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
    async def get_client(
        cls,
        state_registry: dict[int, "UserClientState"],
        bot_client: TelegramClient,
        event,
    ) -> Optional[TelegramClient]:
        current_state = state_registry.get(event.sender_id)
        if not current_state:
            user_client = await init_user_client(event.sender_id)
            state_registry[event.sender_id] = NotAuthorizedClient(
                user_client=user_client, bot_client=bot_client
            )
        proceed_with_current_event = True
        while proceed_with_current_event:
            current_state = state_registry[event.sender_id]
            transition_status = await current_state.transition(event.sender_id, event)
            state_registry[event.sender_id] = transition_status.new_state
            proceed_with_current_event = transition_status.proceed_with_current_event
        current_state = state_registry[event.sender_id]
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


async def main():
    bot_client = TelegramClient("bot", config.api_id, config.api_hash)
    bot_client = await bot_client.start(bot_token=config.bot_token)
    async with bot_client:
        logging.debug(f"Started bot {await bot_client.get_me()}")
        user_clients = {}

        @bot_client.on(events.NewMessage(incoming=True, pattern="(?i)^/start"))
        async def list_channels_handler(event):
            if not (
                user_client := await UserClientState.get_client(
                    user_clients, bot_client, event
                )
            ):
                return
            channels = []
            async for dialog in user_client.iter_dialogs(
                archived=False, limit=config.dialog_list_limit
            ):
                if dialog.is_channel:
                    channels.append(f"- {dialog.title}: `{dialog.id}`")
            await event.respond("\n".join(channels), parse_mode="md")

        @bot_client.on(
            events.NewMessage(incoming=True, pattern="(?i)^/subscribe (-?\\d+)")
        )
        async def subscribe_handler(event):
            if not (
                user_client := await UserClientState.get_client(
                    user_clients, bot_client, event
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
            await UserClientState.get_client(user_clients, bot_client, event)

        await bot_client.run_until_disconnected()


# api_id = os.getenv("API_ID")
# api_hash = os.getenv("API_HASH")
# bot_token = os.getenv("BOT_TOKEN")
if __name__ == "__main__":
    asyncio.run(main())
