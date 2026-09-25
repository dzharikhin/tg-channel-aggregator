import asyncio
import datetime

import pytest
from telethon.errors import SessionPasswordNeededError

from auth import UserAuthMachine, UserSession


class FakeQRLogin:
    def __init__(self, wait_result=None, wait_error=None, hang=False, error_times=1):
        self.url = "tg://login?token=fake"
        self.expires = datetime.datetime(2026, 1, 1, 12, 0, 0)
        self.recreated = 0
        self._wait_result = wait_result
        self._wait_error = wait_error
        self._error_times = error_times
        self._hang = hang

    async def recreate(self):
        self.recreated += 1

    async def wait(self):
        if self._wait_error is not None and self._error_times > 0:
            self._error_times -= 1
            raise self._wait_error
        if self._wait_error is not None or self._hang:
            await asyncio.sleep(3600)  # hang until cancelled
        return self._wait_result


class FakeUserClient:
    def __init__(self, qr_login=None, authorized=False):
        self.authorized = authorized
        self.qr_login_result = qr_login or FakeQRLogin(hang=True)
        self.connect_calls = 0

    def is_connected(self):
        return True

    async def connect(self):
        self.connect_calls += 1

    async def is_user_authorized(self):
        return self.authorized

    async def qr_login(self):
        return self.qr_login_result

    async def sign_in(self, password=None):
        self.authorized = True

        class U:
            id = 42

        return U()


class FakeMessage:
    def __init__(self, message_id, text=""):
        self.id = message_id
        self.message = text


class FakeBotClient:
    def __init__(self):
        self.sent = []
        self.edited = []
        self.deleted = []
        self._next_id = 1

    async def upload_file(self, data, file_name=None):
        return f"file:{file_name}"

    async def send_message(self, user_id, text, file=None):
        message = FakeMessage(self._next_id, text)
        self._next_id += 1
        self.sent.append(message)
        return message

    async def edit_message(self, user_id, message, text, file=None):
        self.edited.append(message.id)

    async def delete_messages(self, user_id, message_ids=None, ids=None):
        self.deleted.extend(message_ids if message_ids is not None else ids)


async def eventually(condition, what, timeout=2.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if condition():
            return
        await asyncio.sleep(0.01)
    pytest.fail(f"condition not met within {timeout}s: {what}")


def states(machine):
    return set(machine.configuration_values)


@pytest.fixture
def session():
    return UserSession(
        user_id=7,
        bot_client=FakeBotClient(),
        user_client=FakeUserClient(),
        queue=object(),
    )


async def test_start_auth_sends_qr_and_spawns_waiter(session):
    machine = UserAuthMachine(session)
    await machine.send("start_auth")

    assert states(machine) == {"qr_sent"}
    assert len(session.bot_client.sent) == 1
    assert "Actual until" in session.bot_client.sent[0].message
    assert machine._qr_login is session.user_client.qr_login_result
    assert machine._qr_task is not None and not machine._qr_task.done()


async def test_qr_expired_regenerates_edits_and_respawns_waiter(session):
    qr = FakeQRLogin(wait_error=TimeoutError())
    session.user_client.qr_login_result = qr
    machine = UserAuthMachine(session)
    await machine.send("start_auth")

    await eventually(
        lambda: qr.recreated == 1 and len(session.bot_client.edited) == 1,
        "waiter should recreate qr and edit the message",
    )
    assert states(machine) == {"qr_sent"}
    assert machine._qr_task is not None and not machine._qr_task.done()
    # the qr_expired self-transition must NOT cancel the running waiter chain
    machine._qr_task.cancel()


async def test_waiter_fires_auth_ok_and_deletes_qr_message(session):
    session.user_client.qr_login_result = FakeQRLogin(wait_result=object())
    machine = UserAuthMachine(session)
    await machine.send("start_auth")

    await eventually(lambda: machine.is_authorized, "waiter should fire auth_ok")
    assert session.bot_client.deleted == [1]
    assert machine._qr_task is None  # cleared on exit


async def test_password_needed_flow(session):
    session.user_client.qr_login_result = FakeQRLogin(
        wait_error=SessionPasswordNeededError(request=None)
    )
    machine = UserAuthMachine(session)
    await machine.send("start_auth")

    await eventually(
        lambda: "password_wait" in states(machine), "waiter should fire password_needed"
    )
    assert session.bot_client.deleted == [1]  # QR message removed
    assert machine._pending_keys is not None
    assert len(session.bot_client.sent) == 2
    assert "Password is required" in session.bot_client.sent[1].message
    assert session.bot_client.sent[1].message.count(machine._pending_keys.pk) == 1


async def test_password_bad_regenerates_keys(session):
    machine = UserAuthMachine(session)
    await machine.send("start_auth")
    await machine.send("password_needed")
    first_keys = machine._pending_keys

    await machine.send("password_bad")

    assert states(machine) == {"password_wait"}
    assert machine._pending_keys is not None
    assert machine._pending_keys.pk != first_keys.pk
    assert len(session.bot_client.sent) == 3


async def test_steady_authorized_discards_unmatched_events(session):
    machine = UserAuthMachine(session)
    await machine.send("auth_ok")
    assert machine.is_authorized

    await machine.send("auth_ok")  # already there: discarded
    await machine.send("start_auth")  # not applicable: discarded
    await machine.send("password_needed")  # not applicable: discarded
    assert states(machine) == {"authorized"}


async def test_auth_missing_and_reset(session):
    machine = UserAuthMachine(session)
    await machine.send("auth_ok")
    await machine.send("auth_missing")
    assert states(machine) == {"idle"}

    await machine.send("start_auth")
    await machine.send("reset")
    assert states(machine) == {"idle"}
    assert machine._qr_task is None


async def test_reset_from_qr_sent_cancels_waiter(session):
    machine = UserAuthMachine(session)
    await machine.send("start_auth")
    waiter = machine._qr_task

    await machine.send("reset")

    assert waiter.cancelled() or waiter.done()
    assert states(machine) == {"idle"}


async def test_failed_qr_send_leaves_flow_retryable(session):
    class BrokenBot(FakeBotClient):
        def __init__(self):
            super().__init__()
            self.broken = True

        async def upload_file(self, data, file_name=None):
            if self.broken:
                raise RuntimeError("upload down")
            return await super().upload_file(data, file_name)

    bot = BrokenBot()
    session.bot_client = bot
    machine = UserAuthMachine(session)

    with pytest.raises(RuntimeError):
        await machine.send("start_auth")

    # whichever state the machine lands in, ticking must recover:
    # idle -> start_auth, qr_sent with dead waiter -> qr_expired
    bot.broken = False
    if machine.idle in machine.configuration:
        await machine.send("start_auth")
    else:
        await machine.send("qr_expired")
    assert states(machine) == {"qr_sent"}
