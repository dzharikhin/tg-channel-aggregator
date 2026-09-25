import asyncio
import dataclasses
import io
import logging
import pathlib
from typing import Optional

import qrcode
from persistqueue import SQLiteAckQueue
from statemachine import State, StateChart
from telethon import TelegramClient
from telethon.errors import (
    PasswordHashInvalidError,
    RPCError,
    SessionExpiredError,
    SessionPasswordNeededError,
)
from telethon.events import NewMessage
from telethon.tl.custom import QRLogin
from telethon.tl.types import Message

import config
import ecies_compat
from common import is_debug
from ecies_compat import Keys
from queues import get_or_create_sync_queue

logger = logging.getLogger(__name__)

# errors worth keeping the current state for, to be retried on the next tick
TRANSIENT_ERRORS = (RPCError, ConnectionError, TimeoutError)


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
class UserSession:
    """Resources of one user's client, created once and shared by every state."""

    user_id: int
    bot_client: TelegramClient
    user_client: TelegramClient
    queue: SQLiteAckQueue


class UserAuthMachine(StateChart):
    """Declarative auth pipeline: QR login -> optional 2FA password -> authorized.

    All Telegram I/O happens in (async) entry/exit actions. The machine never
    blocks on waiting: ``qr_login.wait()`` runs in a background task that
    dispatches follow-up events. Unknown events are silently discarded
    (StateChart default), so driving events from several entry points is safe.
    """

    # propagate action errors to the caller (AuthManager classifies them)
    catch_errors_as_events = False
    # commit the whole transition only if all actions succeeded,
    # so a failed side effect leaves the state retryable on the next tick
    atomic_configuration_update = True
    # the flow is cyclic (auth can be lost at any time), no final state
    validate_final_reachability = False

    idle = State("Idle", initial=True)
    qr_sent = State("Qr sent")
    password_wait = State("Password wait")
    authorized = State("Authorized")

    auth_ok = (
        idle.to(authorized) | qr_sent.to(authorized) | password_wait.to(authorized)
    )
    auth_missing = authorized.to(idle)
    start_auth = idle.to(qr_sent)
    qr_expired = qr_sent.to(qr_sent)
    password_needed = qr_sent.to(password_wait)
    password_bad = password_wait.to(password_wait)
    reset = (
        idle.to(idle) | qr_sent.to(idle) | password_wait.to(idle) | authorized.to(idle)
    )

    def __init__(self, session: UserSession):
        super().__init__()
        self.session = session
        self._qr_login: Optional[QRLogin] = None
        self._auth_message: Optional[Message] = None
        self._qr_task: Optional[asyncio.Task] = None
        self._pending_keys: Optional[Keys] = None
        self._pk_message_id: Optional[int] = None

    @property
    def is_authorized(self) -> bool:
        return self.authorized in self.configuration

    async def on_enter_qr_sent(self) -> None:
        user_id = self.session.user_id
        if not self.session.user_client.is_connected():
            await self.session.user_client.connect()
        if self._qr_login is None:
            self._qr_login = await self.session.user_client.qr_login()
        else:
            await self._qr_login.recreate()
        img_bytes, _ = _render_qr(self._qr_login.url, user_id)
        file = await self.session.bot_client.upload_file(
            img_bytes, file_name="login_qr.png"
        )
        text = (
            f"Actual until {self._qr_login.expires:%H-%M-%S%Z}. "
            f"Then new code is generated.\n\n"
            f"Open the image on a device that can be scanned with mobile Telegram "
            f"scanner: Settings > Devices > Link Device"
        )
        if self._auth_message is None:
            self._auth_message = await self.session.bot_client.send_message(
                user_id, text, file=file
            )
        else:
            await self.session.bot_client.edit_message(
                user_id, self._auth_message, text, file=file
            )
        self._qr_task = asyncio.ensure_future(self._await_qr_scan())

    def on_exit_qr_sent(self) -> None:
        # the qr_* outcome events are dispatched by the waiter task itself:
        # never cancel the task that is running the current transition
        task, self._qr_task = self._qr_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _await_qr_scan(self) -> None:
        try:
            await self._qr_login.wait()
            outcome = "auth_ok"
        except TimeoutError:
            logger.info("Qr auth timeout exception, recreating qr", exc_info=True)
            outcome = "qr_expired"
        except SessionPasswordNeededError:
            logger.info("2FA password required", exc_info=True)
            outcome = "password_needed"
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                f"qr wait failed unexpectedly for user {self.session.user_id}, "
                f"recreating qr"
            )
            outcome = "qr_expired"
        try:
            await self.send(outcome)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # the waiter task is nobody's awaited future: log here, otherwise
            # the traceback would surface only via the loop's exception handler
            logger.error(
                f"failed to dispatch auth outcome {outcome} for user "
                f"{self.session.user_id}",
                exc_info=e,
            )

    async def on_auth_ok(self, previous_configuration, new_configuration) -> None:
        if self.qr_sent in previous_configuration or (
            self.password_wait in previous_configuration
        ):
            await self._delete_auth_message()

    async def on_password_needed(self) -> None:
        await self._delete_auth_message()

    async def on_enter_password_wait(self) -> None:
        keys = ecies_compat.generate_keys()
        self._pending_keys = keys
        message = await self.session.bot_client.send_message(
            self.session.user_id,
            f"Password is required. DO NOT ENTER IN PLAIN TEXT. Encrypt via "
            f"https://dzharikhin.github.io/ecies/index.html with public key "
            f"`{keys.pk}` and send crypto message here",
        )
        self._pk_message_id = message.id
        if is_debug() and (path := pathlib.Path("pwd")).exists():
            logger.error(
                f"encrypted password: {ecies_compat.encrypt(keys.pk, path.read_bytes()).hex()}"
            )

    async def _delete_auth_message(self) -> None:
        if self._auth_message is None:
            return
        message_id, self._auth_message = self._auth_message.id, None
        await self.session.bot_client.delete_messages(
            self.session.user_id, message_ids=[message_id]
        )


class AuthManager:
    """Owns per-user auth machines. Single entry point for command handlers.

    Replaces UserClientState.get_or_create_client: access control, lazy
    client/session creation, event dispatch, and error classification live
    here instead of inside the states.
    """

    def __init__(self, bot_client: TelegramClient):
        self._bot_client = bot_client
        self._machines: dict[int, UserAuthMachine] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    async def bootstrap(self) -> None:
        for user_id in config.get_existing_users():
            await self._machine_for(user_id)

    def tracked_users(self) -> list[int]:
        return list(self._machines)

    async def ensure_authorized(self, user_id: int) -> Optional[UserSession]:
        if not await self._check_access(user_id):
            return None
        try:
            machine = await self._machine_for(user_id)
            if await self._authorize_if_possible(machine):
                return machine.session

            # auth can be lost at any time: stale 'authorized' goes back to idle
            await self._dispatch(machine, "auth_missing")
            if machine.idle in machine.configuration:
                await self._dispatch(machine, "start_auth")
            elif machine.qr_sent in machine.configuration:
                task = machine._qr_task
                if task is None or task.done():
                    # enter-action failed earlier (network) or waiter died
                    await self._dispatch(machine, "qr_expired")
            return None
        except TRANSIENT_ERRORS as e:
            logger.warning(
                f"transient error ensuring auth for user {user_id}, state kept",
                exc_info=e,
            )
            return None
        except Exception as e:
            logger.error(
                f"unexpected error ensuring auth for user {user_id}, resetting",
                exc_info=e,
            )
            await self._fail_and_reset(user_id)
            return None

    async def feed_message(
        self, user_id: int, event: NewMessage.Event
    ) -> Optional[UserSession]:
        """Delivers a plain (non-command) user message to the auth pipeline."""
        if not await self._check_access(user_id):
            return None
        try:
            machine = await self._machine_for(user_id)
            if await self._authorize_if_possible(machine):
                return machine.session
            if machine.password_wait not in machine.configuration:
                return None
            return await self._handle_password_input(machine, event)
        except TRANSIENT_ERRORS as e:
            logger.warning(
                f"transient error feeding message for user {user_id}, state kept",
                exc_info=e,
            )
            return None
        except Exception as e:
            logger.error(
                f"unexpected error feeding message for user {user_id}, resetting",
                exc_info=e,
            )
            await self._fail_and_reset(user_id)
            return None

    async def disconnect_clients(self) -> None:
        for machine in self._machines.values():
            if machine._qr_task is not None:
                machine._qr_task.cancel()
            await machine.session.user_client.disconnect()

    async def _authorize_if_possible(self, machine: UserAuthMachine) -> bool:
        session = machine.session
        if not session.user_client.is_connected():
            await session.user_client.connect()
        if not await session.user_client.is_user_authorized():
            return False
        await self._dispatch(machine, "auth_ok")
        return True

    async def _handle_password_input(
        self, machine: UserAuthMachine, event: NewMessage.Event
    ) -> Optional[UserSession]:
        session = machine.session
        keys, machine._pending_keys = machine._pending_keys, None
        if keys is None:
            await self._dispatch(machine, "password_bad")
            return None

        encrypted = event.message.message.strip()
        await session.bot_client.delete_messages(
            session.user_id, [machine._pk_message_id, event.message.id]
        )
        try:
            payload = ecies_compat.decrypt(keys.sk, bytes.fromhex(encrypted))
        except ValueError:
            logger.warning("Password input was not encrypted with current PK")
            await session.bot_client.send_message(
                session.user_id,
                "Password was not encrypted with public key. Lets try again",
            )
            await self._dispatch(machine, "password_bad")
            return None

        try:
            logged_in_user = await session.user_client.sign_in(
                password=payload.decode("utf-8")
            )
        except PasswordHashInvalidError:
            logger.info(f"Wrong password from user {session.user_id}")
            await session.bot_client.send_message(
                session.user_id, "Password is not correct. Lets try again"
            )
            # keys are still valid, let the user resend without re-registration
            machine._pending_keys = keys
            return None
        except SessionExpiredError:
            # the qr session behind this sign_in is gone: restart the flow
            logger.info(f"Auth session expired for user {session.user_id}")
            await self._dispatch(machine, "reset")
            return None
        except TRANSIENT_ERRORS:
            machine._pending_keys = keys
            raise

        logger.info(f"User {logged_in_user.id} logged in with password")
        await self._dispatch(machine, "auth_ok")
        return session if machine.is_authorized else None

    async def _dispatch(self, machine: UserAuthMachine, event: str) -> None:
        await machine.send(event)

    async def _machine_for(self, user_id: int) -> UserAuthMachine:
        if user_id in self._machines:
            return self._machines[user_id]
        lock = self._locks.setdefault(user_id, asyncio.Lock())
        async with lock:
            if user_id in self._machines:
                return self._machines[user_id]
            session = UserSession(
                user_id=user_id,
                bot_client=self._bot_client,
                user_client=await init_user_client(user_id),
                queue=get_or_create_sync_queue(user_id),
            )
            self._machines[user_id] = UserAuthMachine(session)
            return self._machines[user_id]

    async def _check_access(self, user_id: int) -> bool:
        if config.is_allowed_user(user_id):
            return True
        user = await self._bot_client.get_entity(user_id)
        await self._bot_client.send_message(
            config.owner_user_id,
            f"User `{user_id}`: {user.username} tries to use bot",
        )
        return False

    async def _fail_and_reset(self, user_id: int) -> None:
        machine = self._machines.get(user_id)
        if machine is not None:
            try:
                await machine.send("reset")
            except Exception as e:
                logger.error(f"auth reset failed for user {user_id}", exc_info=e)
        try:
            await self._bot_client.send_message(
                user_id,
                "auth failed with unexpected exception. Please, wait and try again",
            )
        except Exception as e:
            logger.error(
                f"failed to notify user {user_id} about auth failure", exc_info=e
            )


async def init_user_client(user_id: int) -> TelegramClient:
    config_folder = config.data_path.joinpath(str(user_id))
    config_folder.mkdir(exist_ok=True)
    user_client = TelegramClient(
        config_folder.joinpath(config_folder.name),
        config.api_id,
        config.api_hash,
        connection_retries=None,
        retry_delay=10,
        catch_up=True,
    )
    await user_client.connect()
    return user_client
