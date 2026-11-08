#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tg_top_posts.py
===============

Print the posts of a Telegram channel for a given year, ranked by
reactions (primary key) and view count (secondary key), both descending —
so the most reacted / most viewed posts of the year are at the top.

Messages with zero reactions AND zero views are skipped
(service messages, silent posts nobody saw, etc.).

For audio posts (mp3 documents) the preview shows the audio attributes:
    [mp3] Title — Performer (3:10)
falling back to the file name when the title attribute is missing.
For other posts the preview is the first line of the message text.

Accepted channel references (same rules as tg_track_forwarder.py):
    @username, t.me/username, t.me/c/1234 (private channel),
    numeric id (-100... for channels/supergroups) or "me" (= Saved Messages).

Usage examples
--------------
    export TELEGRAM_API_ID=123456
    export TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef

    # all posts of 2026, ranked:
    python3 tg_top_posts.py @jrxpodcastdislike 2026

    # only the top 25:
    python3 tg_top_posts.py @jrxpodcastdislike 2026 --limit 25

    # private channel by id:
    python3 tg_top_posts.py -1001111111111 2025

    # login by scanning a QR code instead of typing phone/code:
    python3 tg_top_posts.py @mychannel 2026 --qr

Dependencies:
    pip install telethon
    pip install qrcode        # optional, for terminal QR login (--qr)
"""

import argparse
import asyncio
import getpass
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

try:
    from telethon import TelegramClient, errors
    from telethon.sessions import StringSession
    from telethon.tl.types import (
        DocumentAttributeAudio,
        DocumentAttributeFilename,
        PeerChannel,
    )

    TELETHON_AVAILABLE = True
except ImportError:  # allows --help without telethon installed
    TELETHON_AVAILABLE = False

PREVIEW_WIDTH = 60


# ----------------------------------------------------------------------------
# Message attributes / preview
# ----------------------------------------------------------------------------


def fmt_dur(s: Optional[int]) -> str:
    if s is None:
        return "?"
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return "%d:%02d:%02d" % (h, m, sec) if h else "%d:%02d" % (m, sec)


def audio_attrs(msg):
    """Inspect the document attributes list of a message.

    NOTE: same as in tg_track_forwarder.py — title/performer/duration live in
    ``document.attributes`` on the ``DocumentAttributeAudio`` element, the
    file name on ``DocumentAttributeFilename``.

    Returns (is_music, title, performer, duration_s, file_name).
    """
    doc = getattr(msg, "document", None)
    if doc is None:
        return False, None, None, None, None
    is_audio = False
    title = performer = None
    dur = None
    fname = None
    for attr in getattr(doc, "attributes", None) or []:
        if isinstance(attr, DocumentAttributeAudio):
            is_audio = not bool(getattr(attr, "voice", False))
            title = getattr(attr, "title", None)
            performer = getattr(attr, "performer", None)
            if getattr(attr, "duration", None):
                dur = int(attr.duration)
        elif isinstance(attr, DocumentAttributeFilename):
            fname = getattr(attr, "file_name", None)
    return is_audio, title, performer, dur, fname


def truncate(s: str, width: int = PREVIEW_WIDTH) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > width:
        s = s[: width - 1] + "…"
    return s


def msg_preview(msg) -> str:
    """One-line preview: mp3 attributes for audio posts, else message text."""
    is_audio, title, performer, dur, fname = audio_attrs(msg)
    if is_audio:
        if not fname:
            f = getattr(msg, "file", None)
            if f is not None and getattr(f, "name", None):
                fname = f.name
        base = title or (os.path.splitext(fname)[0] if fname else "?")
        parts = [base]
        if performer:
            parts.append(performer)
        s = " — ".join(parts)
        if dur:
            s = "%s (%s)" % (s, fmt_dur(dur))
        return truncate("[mp3] " + s)
    text = (getattr(msg, "text", None) or getattr(msg, "message", None) or "").strip()
    return truncate(text) or "(no text)"


def msg_reactions(msg) -> int:
    """Total reaction count over all reaction types (0 if none)."""
    reactions = getattr(msg, "reactions", None)
    results = getattr(reactions, "results", None) or []
    return sum(int(getattr(r, "count", 0) or 0) for r in results)


def msg_link(entity, msg) -> Optional[str]:
    username = getattr(entity, "username", None)
    if username:
        return "https://t.me/%s/%d" % (username, msg.id)
    if getattr(entity, "title", None):  # private channel: t.me/c/<raw id>/<msg id>
        return "https://t.me/c/%d/%d" % (entity.id, msg.id)
    return None  # e.g. Saved Messages


# ----------------------------------------------------------------------------
# Telegram I/O
# ----------------------------------------------------------------------------


async def resolve_entity(client, ref: str, label: str):
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("%s: empty chat reference" % label)
    low = ref.lower()
    if low in ("me", "self", "saved", "saved messages", "savedmessages"):
        return await client.get_me()  # Saved Messages
    m = re.match(r"^(?:https?://)?t\.me/(?:c/)?([A-Za-z0-9_]+)/?$", ref)
    if m:
        handle = m.group(1)
        if handle.isdigit():  # t.me/c/1234567 (private)
            return await client.get_entity(PeerChannel(int(handle)))
        return await client.get_entity("@" + handle)
    if re.fullmatch(r"-?\d+", ref):  # numeric id
        v = int(ref)
        try:
            return await client.get_entity(v)
        except Exception:
            if v > 0:  # raw channel id w/o -100 prefix
                return await client.get_entity(PeerChannel(v))
            raise
    return await client.get_entity(ref)


def display(e) -> str:
    t = getattr(e, "title", None)
    if t:
        return "%s (id %s)" % (t, e.id)
    name = " ".join(
        x for x in (getattr(e, "first_name", None), getattr(e, "last_name", None)) if x
    )
    return "%s (id %s)" % (name or getattr(e, "username", None) or "?", e.id)


async def fetch_year(client, channel, year: int) -> Tuple[list, int]:
    """Collect (msg, reactions, views) tuples for the calendar year.

    Iterates newest-first starting from Jan 1 of year+1 (offset_date is
    documented as 'only messages with a lower date are retrieved') and stops
    once messages older than Jan 1 of the year appear.
    """
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    collected: List[tuple] = []
    seen = set()
    fetched = 0
    min_id = None

    while True:
        kwargs = {"offset_date": end}
        if min_id is not None:
            kwargs["min_id"] = min_id
        try:
            async for msg in client.iter_messages(channel, **kwargs):
                fetched += 1
                if fetched % 50 == 0:
                    print("\r  fetched %d message(s)..." % fetched, end="", flush=True)
                if msg.date < start:
                    break
                if msg.id in seen:  # dedupe after a FloodWait restart
                    continue
                seen.add(msg.id)
                if min_id is None or msg.id < min_id:
                    min_id = msg.id
                reactions = msg_reactions(msg)
                views = int(getattr(msg, "views", 0) or 0)
                if reactions == 0 and views == 0:
                    continue
                collected.append((msg, reactions, views))
            print("\r" + " " * 40 + "\r", end="")
            return collected, fetched
        except errors.FloodWaitError as e:
            wait = int(getattr(e, "seconds", None) or getattr(e, "value", None) or 15)
            print("\n  ! FloodWait %ds — sleeping, then continuing" % wait)
            await asyncio.sleep(wait + 1)


# ----------------------------------------------------------------------------
# Credentials / session (same conventions as tg_track_forwarder.py)
# ----------------------------------------------------------------------------


def phone_prompt() -> str:
    return input(
        "Enter your phone in international format (e.g. +79991234567): "
    ).strip()


def resolve_phone(args):
    p = args.phone or os.getenv("TELEGRAM_PHONE")
    if p:
        p = str(p).strip()
        if not re.fullmatch(r"\+?\d{6,15}", p.replace(" ", "")):
            die(
                "phone must be in international format, e.g. +79991234567 (got: %r)" % p
            )
        return p
    return phone_prompt  # callable; Telethon calls it only if login is needed


def resolve_creds(args) -> Tuple[int, str]:
    api_id = args.api_id or os.getenv("TELEGRAM_API_ID")
    api_hash = args.api_hash or os.getenv("TELEGRAM_API_HASH")
    if not api_id:
        api_id = input("Enter api_id from my.telegram.org: ").strip()
    if not api_hash:
        api_hash = getpass.getpass(
            "Enter api_hash from my.telegram.org (hidden): "
        ).strip()
    api_id = str(api_id).strip()
    api_hash = str(api_hash).strip()
    if not api_id.isdigit():
        die("api_id must be an integer (see my.telegram.org -> API development tools)")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        die("api_hash must be 32 hex characters (see my.telegram.org)")
    return int(api_id), api_hash


def chmod_session(session_name: str) -> None:
    path = (
        session_name if session_name.endswith(".session") else session_name + ".session"
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def render_qr_terminal(url: str) -> bool:
    try:
        import qrcode
    except ImportError:
        return False
    code = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    code.add_data(url)
    code.make(fit=True)
    code.print_ascii(invert=True)
    return True


async def qr_login_flow(client, overall_timeout: float = 300.0):
    deadline = time.monotonic() + overall_timeout
    qr = await client.qr_login()
    while True:
        if time.monotonic() > deadline:
            die(
                "QR login timed out after %ds — run the script again and scan promptly"
                % int(overall_timeout)
            )
        print()
        print("Scan the QR below with the Telegram app:")
        print("  Telegram -> Settings -> Devices -> Link Desktop Device")
        if not render_qr_terminal(qr.url):
            print("  [tip] pip install qrcode   <- enables a scannable QR right here")
            print(
                "  Or encode this URL with any QR generator / open it on a logged-in device:"
            )
            print("    %s" % qr.url)
        print(
            "Waiting for the scan... (QR refreshes automatically on expiry, Ctrl+C to abort)"
        )
        try:
            user = await qr.wait()
        except asyncio.TimeoutError:
            print("QR expired — generating a fresh one...")
            qr = await qr.recreate()
            continue
        except errors.SessionPasswordNeededError:
            pw = getpass.getpass("2FA password (hidden): ")
            await client.sign_in(password=pw)
            user = await client.get_me()
        return user


# ----------------------------------------------------------------------------
# CLI / main
# ----------------------------------------------------------------------------


def die(msg: str) -> None:
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Rank a Telegram channel's posts of a year by reactions "
        "(then views), both descending.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="channel reference: @username | t.me/link | numeric id | "
        '"me" (Saved Messages)',
    )
    p.add_argument("channel", help="channel id/username to analyze")
    p.add_argument("year", type=int, help="calendar year, e.g. 2026")
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="show only the top N posts (default: all)",
    )
    p.add_argument(
        "--api-id", help="telegram api_id (else TELEGRAM_API_ID env or prompt)"
    )
    p.add_argument(
        "--api-hash", help="telegram api_hash (else TELEGRAM_API_HASH env or prompt)"
    )
    p.add_argument("--phone", help="phone number for login (else prompted if needed)")
    p.add_argument(
        "--qr",
        action="store_true",
        help="login by scanning a QR code in the terminal (no phone/code input)",
    )
    p.add_argument(
        "--session",
        default="user",
        help="session file name (default: user)",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()

    year = args.year
    if not 2000 <= year <= datetime.now(timezone.utc).year + 1:
        die(
            "year must be a sane calendar year (2000..%d), got: %d"
            % (
                datetime.now(timezone.utc).year + 1,
                year,
            )
        )

    if not TELETHON_AVAILABLE:
        die("telethon is not installed:  pip install telethon")
    api_id, api_hash = resolve_creds(args)

    used_string_session = bool(os.getenv("TELEGRAM_SESSION_STRING"))
    if used_string_session:
        client = TelegramClient(
            StringSession(os.environ["TELEGRAM_SESSION_STRING"]), api_id, api_hash
        )
    else:
        client = TelegramClient(args.session, api_id, api_hash)
    client.flood_sleep_threshold = 60  # auto-sleep on small FloodWaits

    if args.qr:
        await client.connect()
        if not await client.is_user_authorized():
            await qr_login_flow(client)
    else:
        await client.start(phone=resolve_phone(args))
    if not used_string_session:
        chmod_session(args.session)

    me = await client.get_me()
    print("Authorized as: %s" % display(me))

    try:
        channel = await resolve_entity(client, args.channel, "channel")
    except errors.ChannelPrivateError:
        die("channel is private / not accessible for this account")
    print("Channel: %s" % display(channel))
    print("Year:    %d" % year)
    print("-" * 72)

    collected, fetched = await fetch_year(client, channel, year)
    collected.sort(key=lambda t: (-t[1], -t[2]))  # reactions desc, views desc
    shown = collected if args.limit is None else collected[: max(args.limit, 0)]

    if not shown:
        print(
            "No posts with reactions/views found for %d (fetched %d messages)."
            % (year, fetched)
        )
        await client.disconnect()
        return

    print("%4s  %-10s  %8s  %8s  %s" % ("#", "date", "react", "views", "preview"))
    print("-" * 72)
    for i, (msg, reactions, views) in enumerate(shown, 1):
        when = msg.date.astimezone(tz=None).strftime("%Y-%m-%d")
        print(
            "%4d  %-10s  %8d  %8d  %s" % (i, when, reactions, views, msg_preview(msg))
        )
        link = msg_link(channel, msg)
        if link:
            print("      %s" % link)
    print("-" * 72)
    print(
        "Shown: %d / kept: %d / fetched: %d message(s) for %d."
        % (len(shown), len(collected), fetched, year)
    )

    await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
