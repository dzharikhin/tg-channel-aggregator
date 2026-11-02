import os
from typing import Optional

from telethon.tl.types import Chat
from telethon.tl.types.messages import Chats


def is_debug():
    return "true" == os.getenv("DEBUG", "False").lower()


def unwrap_single_chat(chat: Chats) -> Optional[Chat]:
    if not chat or not chat.chats:
        return None
    return chat.chats[0]
