import dataclasses
import datetime
import io
import logging
import pathlib
from typing import Optional

import persistqueue.serializers.json
import qrcode
from ecies import decrypt, encrypt
from ecies.utils import generate_eth_key
from persistqueue import SQLiteAckQueue
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.custom import QRLogin
from telethon.tl.types import Message

import config
from common import is_debug

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)


def _render_qr(data: str, user_id: int) -> tuple[bytes, int]:
    qr = qrcode.main.QRCode(
        version=3,
        box_size=20,
        border=10,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if is_debug():
        img.save(config.data_path.joinpath(str(user_id)).joinpath("qr.png"))
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return buf.read(), img.width


@dataclasses.dataclass
class Keys:
    sk: str
    pk: str


def _generate_keys() -> Keys:
    eth_k = generate_eth_key()
    keys = Keys(eth_k.to_hex(), eth_k.public_key.to_hex())
    return keys


def _decode(encrypted_: str, sk: str):
    return decrypt(sk, bytes.fromhex(encrypted_))


@dataclasses.dataclass
class TransitionStatus:
    new_state: "UserClientState"
    proceed_with_current_event: bool


class UserClientState:
    _bot_client: TelegramClient
    user_client: TelegramClient
    queue: SQLiteAckQueue | None

    async def transition(self, user_id: int, event) -> TransitionStatus:
        pass

    @classmethod
    async def get_or_create_client(
        cls,
        state_registry: dict[int, "UserClientState"],
        bot_client: TelegramClient,
        user_id: int,
        event=None,
    ) -> Optional["UserClientState"]:
        if event:
            user_id = event.sender_id

        if (
            user_id != config.owner_user_id
            and user_id not in config.get_allowed_to_use_user_ids()
        ):
            user = await bot_client.get_entity(user_id)
            await bot_client.send_message(
                config.owner_user_id,
                f"User `{user_id}`: {user.username} tries to use bot",
            )
            return None

        user_client = None
        try:
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
                proceed_with_current_event = (
                    transition_status.proceed_with_current_event
                )
            current_state = state_registry[user_id]
            return (
                current_state if isinstance(current_state, AuthorizedClient) else None
            )
        except Exception as e:
            logger.error(
                f"Logging at auth user {user_id}, resetting to unauthorized", e
            )
            if not user_client:
                user_client = await init_user_client(user_id)
            state_registry[user_id] = NotAuthorizedClient(
                user_client=user_client, bot_client=bot_client
            )
            await bot_client.send_message(
                user_id,
                "auth failed with unexpected exception. Please, wait and try again",
            )
            return None


class NotAuthorizedClient(UserClientState):

    def __init__(
        self,
        auth_message: Optional[Message] = None,
        *,
        from_state: Optional[UserClientState] = None,
        user_client: Optional[TelegramClient] = None,
        bot_client: Optional[TelegramClient] = None,
    ):
        self.auth_message = auth_message
        if from_state:
            self._bot_client = from_state._bot_client
            self.user_client = from_state.user_client
        else:
            self._bot_client = bot_client
            self.user_client = user_client

    async def transition(self, user_id: int, event) -> TransitionStatus:
        if await self.user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(user_id, self), True)
        if not self.user_client.is_connected():
            await self.user_client.connect()
        qr_login = await self.user_client.qr_login()
        created_at = datetime.datetime.now().astimezone()
        img_bytes, _ = _render_qr(qr_login.url, user_id)
        file = await self._bot_client.upload_file(img_bytes, file_name="login_qr.png")
        if not self.auth_message:
            self.auth_message = await self._bot_client.send_message(
                user_id,
                f"created at {created_at:%H-%M-%S%Z}. Actual for {config.qr_login_wait_seconds} seconds. "
                f"Open the image on a device that can be scanned with mobile Telegram scanner: Settings > Devices > Link Device",
                file=file,
            )
        else:
            await self._bot_client.edit_message(
                user_id,
                self.auth_message,
                f"created at {created_at:%H-%M-%S%Z}. Actual for {config.qr_login_wait_seconds} seconds. "
                f"Open the image on a device that can be scanned with mobile Telegram scanner: Settings > Devices > Link Device",
                file=file,
            )
        return TransitionStatus(
            QrAuthorizationWaitingClient(qr_login, self.auth_message, self), True
        )


class AuthorizedClient(UserClientState):

    def __init__(self, user_id: int, from_state: UserClientState):
        self.user_client = from_state.user_client
        self._bot_client = from_state._bot_client
        self.queue = SQLiteAckQueue(
            config.data_path.joinpath(str(user_id)),
            serializer=persistqueue.serializers.json,
            multithreading=True,
            auto_commit=True,
            db_file_name="queue.db",
        )

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if not self.user_client.is_connected():
            await self.user_client.connect()
        if await self.user_client.is_user_authorized():
            return TransitionStatus(self, False)
        return TransitionStatus(NotAuthorizedClient(from_state=self), True)


class QrAuthorizationWaitingClient(UserClientState):

    def __init__(
        self, qr_login: QRLogin, auth_message: Message, from_state: UserClientState
    ):
        self._bot_client = from_state._bot_client
        self.user_client = from_state.user_client
        self._qr_login = qr_login
        self._auth_message = auth_message

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if await self.user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(user_id, self), True)
        try:
            await self._qr_login.wait(config.qr_login_wait_seconds)
            await self._bot_client.delete_messages(
                user_id, message_ids=[self._auth_message.id]
            )
            return TransitionStatus(AuthorizedClient(user_id, self), True)
        except TimeoutError as e:
            logger.info("Qr auth timeout exception, recreating qr", e)
            return TransitionStatus(
                NotAuthorizedClient(self._auth_message, from_state=self), True
            )
        except SessionPasswordNeededError as e:
            logger.info("2FA password required", e)
            await self._bot_client.delete_messages(
                user_id, message_ids=[self._auth_message.id]
            )
            return TransitionStatus(
                PasswordAuthorizationKeysPreparingClient(self), True
            )


class PasswordAuthorizationKeysPreparingClient(UserClientState):

    def __init__(self, from_state: UserClientState):
        self.user_client = from_state.user_client
        self._bot_client = from_state._bot_client

    async def transition(self, user_id: int, event=None) -> TransitionStatus:
        if await self.user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(user_id, self), True)
        keys = _generate_keys()
        message = await self._bot_client.send_message(
            user_id,
            f"Password is required. DO NOT ENTER IN PLAIN TEXT. Encrypt via https://dzharikhin.github.io/ecies/index.html with public key `{keys.pk}` and send crypto message here",
        )
        if is_debug() and (path := pathlib.Path("pwd")).exists():
            logger.error(
                f"encrypted password: {encrypt(keys.pk, path.read_bytes()).hex()}"
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
        self.user_client = from_state.user_client
        self._bot_client = from_state._bot_client
        self._secret_key = [secret_key]
        self.public_key = public_key
        self.public_key_msg_id = message_with_public_key_id

    async def transition(self, user_id: int, event) -> TransitionStatus:
        if await self.user_client.is_user_authorized():
            return TransitionStatus(AuthorizedClient(user_id, self), True)
        encrypted_ = event.message.message.strip()
        await self._bot_client.delete_messages(
            user_id, [self.public_key_msg_id, event.message.id]
        )
        try:
            payload = _decode(encrypted_, self._secret_key.pop())
        except ValueError as e:
            logger.warning("Password input was not encrypted with current PK", e)
            await self._bot_client.send_message(
                user_id, "Password was not encrypted with public key. Lets try again"
            )
            return TransitionStatus(
                PasswordAuthorizationKeysPreparingClient(self), True
            )
        logged_in_user = await self.user_client.sign_in(
            password=payload.decode("utf-8")
        )
        logger.info(f"User {logged_in_user.id} logged in with password")
        return TransitionStatus(AuthorizedClient(user_id, self), True)


async def init_user_client(user_id: int) -> TelegramClient:
    config_folder = config.data_path.joinpath(str(user_id))
    config_folder.mkdir(exist_ok=True)
    user_client = TelegramClient(
        config_folder.joinpath(config_folder.name), config.api_id, config.api_hash
    )
    await user_client.connect()
    return user_client
