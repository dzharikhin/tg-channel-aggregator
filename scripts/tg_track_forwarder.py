#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tg_track_forwarder.py
=====================

Search audio tracks from a tracklist in one Telegram chat/channel ("source")
and forward the found audio messages into another chat/channel ("destination").

Tracklist format (UTF-8 text file, one track per line):

    Title — Artist (m:ss)

  * Title / artist separator: a dash surrounded by spaces
    (em dash '—', en dash '–' or plain ' - ' are all accepted).
  * Duration in brackets at the end of the line is used to pick the correct
    version when the search returns several candidates.
  * Titles truncated by the Telegram UI (ending with '…' or '...') are
    supported: the script automatically falls back to shorter queries.

Search / matching rules
-----------------------
  1. Search is done by the track TITLE (first part of the line) only,
    restricted to music messages (InputMessagesFilterMusic).
  2. A candidate counts as a title match if its audio title (or file name)
    contains the normalized query, or is very similar to it. Truncated
    titles ('…') therefore match their full versions.
  3. Among title matches, only messages whose audio duration is within
    --tolerance seconds (default 2) of the tracklist duration are accepted.
  4. If several accepted candidates exist, the FRESHEST one (newest date)
    is forwarded.
  5. Tracks with no acceptable match are reported at the end
    (and optionally written to a report file).

Safe authorization
------------------
  * api_id / api_hash are taken from --api-id/--api-hash, or from the
    TELEGRAM_API_ID / TELEGRAM_API_HASH environment variables, or asked
    interactively (api_hash input is hidden via getpass).
  * Login uses the official interactive flow: phone number, login code and
    2FA password are prompted by Telethon; nothing is printed to the console
    and nothing is stored except the local session file.
  * The session file permissions are tightened to 0600 after login.
    Alternatively, set TELEGRAM_SESSION_STRING to use a string session
    instead of a file (handy for servers/CI).

Accepted chat references (source / dest):
    @username, t.me/username, t.me/c/1234 (private channel),
    numeric id (-100... for channels/supergroups) or "me" (= Saved Messages).

Usage examples
--------------
    export TELEGRAM_API_ID=123456
    export TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef

    # search in Saved Messages, forward into a channel by username:
    python3 tg_track_forwarder.py tracklist_saved_messages.txt me @jrxpodcastdislike

    # by numeric channel ids:
    python3 tg_track_forwarder.py tracklist_jrxpodcastdislike.txt -1001111111111 -1002222222222

    # rehearsal (search + matching only, nothing is forwarded):
    python3 tg_track_forwarder.py tracklist.txt me @mychannel --dry-run

    # login by scanning a QR code instead of typing phone/code:
    python3 tg_track_forwarder.py tracklist.txt me @mychannel --qr --dry-run

    # offline parser/matcher self-test (no network):
    python3 tg_track_forwarder.py --selftest

Dependencies:
    pip install telethon
    pip install qrcode        # optional, for terminal QR login (--qr)
"""

import argparse
import asyncio
import difflib
import getpass
import os
import re
import sys
import time
import types as pytypes
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

try:
    from telethon import TelegramClient, errors
    from telethon.sessions import StringSession
    from telethon.tl.types import (
        DocumentAttributeAudio,
        DocumentAttributeFilename,
        InputMessagesFilterMusic,
        PeerChannel,
    )

    TELETHON_AVAILABLE = True
except ImportError:  # allows --selftest / parsing without telethon installed
    TELETHON_AVAILABLE = False

# ----------------------------------------------------------------------------
# Tracklist parsing
# ----------------------------------------------------------------------------

DUR_RE = re.compile(r"[(\[]\s*(\d{1,3}:\d{2}(?::\d{2})?)\s*[)\]]\s*$")
DASH_RE = re.compile(r"\s+[—–―]\s+|\s+-\s+")
TRUNC_TAIL_RE = re.compile(r"(…|\.\.\.)\s*([)\]])?\s*$")


def strip_trunc_tail(s: str) -> Tuple[str, bool]:
    """Remove trailing truncation marker ('…' / '...'), also before a closing
    bracket: 'Thank You (Felmax & V…)' -> 'Thank You (Felmax & V', True."""
    m = TRUNC_TAIL_RE.search(s)
    if not m:
        return s.rstrip(), False
    return s[: m.start()].rstrip(), True


@dataclass
class Track:
    raw: str
    title: str
    artist: Optional[str]
    duration_s: Optional[int]
    duration_str: Optional[str]
    truncated: bool

    @property
    def key(self) -> Tuple[str, Optional[int]]:
        return (norm(self.title), self.duration_s)


def parse_duration(s: str) -> Optional[int]:
    """'3:10' -> 190, '1:02:03' -> 3723."""
    parts = s.strip().split(":")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    secs = 0
    for p in parts:
        secs = secs * 60 + int(p)
    return secs


def fmt_dur(s: Optional[int]) -> str:
    if s is None:
        return "?"
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return "%d:%02d:%02d" % (h, m, sec) if h else "%d:%02d" % (m, sec)


def parse_track_line(line: str) -> Optional[Track]:
    """Parse one 'Title — Artist (m:ss)' line. Returns None for blanks/comments."""
    line = line.strip()
    if not line:
        return None
    m = DUR_RE.search(line)
    dur_str = dur_s = None
    rest = line
    if m:
        dur_str = m.group(1)
        dur_s = parse_duration(dur_str)
        rest = line[: m.start()].rstrip()

    parts = DASH_RE.split(rest, maxsplit=1)
    if len(parts) == 2:
        title, artist = parts[0].strip(), parts[1].strip() or None
    else:
        title, artist = rest.strip(), None

    title, truncated = strip_trunc_tail(title)
    if artist:
        artist, _ = strip_trunc_tail(artist)

    if not title:
        return None
    return Track(
        raw=line,
        title=title,
        artist=artist,
        duration_s=dur_s,
        duration_str=dur_str,
        truncated=truncated,
    )


def load_tracklist(path: str) -> List[Track]:
    tracks: List[Track] = []
    with open(path, encoding="utf-8-sig") as fh:
        for i, line in enumerate(fh, 1):
            t = parse_track_line(line)
            if t:
                tracks.append(t)
                continue
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith("==="):
                print(
                    "  ! line %d: cannot parse, skipped: %r" % (i, s), file=sys.stderr
                )
    return tracks


def dedupe(tracks: List[Track]) -> List[Track]:
    seen, out = set(), []
    for t in tracks:
        if t.key in seen:
            print("  = duplicate skipped: %s" % t.raw)
            continue
        seen.add(t.key)
        out.append(t)
    return out


# ----------------------------------------------------------------------------
# Normalization / matching
# ----------------------------------------------------------------------------


def norm(s: Optional[str]) -> str:
    """lowercase, strip accents/punctuation; keeps latin + cyrillic letters."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower().replace("ё", "е")
    return re.sub(r"[^0-9a-zа-я]+", "", s)


def title_matches(query_title: str, cand_title: str) -> bool:
    nq, nt = norm(query_title), norm(cand_title)
    if not nq or not nt:
        return False
    if nq in nt:  # covers truncated queries: 'thegirlsaremakingridd' in '...riddim'
        return True
    return difflib.SequenceMatcher(None, nq, nt).ratio() >= 0.85


def build_queries(track: Track) -> List[str]:
    """Query cascade: full title -> title w/o last (partial) word ->
    title + first artist token -> first 3 words."""
    qs: List[str] = [track.title]
    words = track.title.split()
    if track.truncated and len(words) > 1:
        qs.append(" ".join(words[:-1]))
    if track.artist:
        first = re.split(r"[,/&]", track.artist)[0].strip()
        if first and norm(first):
            qs.append("%s %s" % (track.title, first))
    if len(words) > 3:
        qs.append(" ".join(words[:3]))
    out, seen = [], set()
    for q in qs:
        k = norm(q)
        if len(k) < 2 or k in seen:
            continue
        seen.add(k)
        out.append(q)
    return out


# ----------------------------------------------------------------------------
# Candidate evaluation
# ----------------------------------------------------------------------------


@dataclass
class Cand:
    msg: object
    cand_title: str
    performer: Optional[str]
    dur: Optional[int]
    fname: Optional[str]


def audio_attrs(msg):
    """Inspect the document attributes list of a message.

    NOTE: Message.audio in Telethon returns the *Document* media object —
    title/performer/duration live in ``document.attributes`` on the
    ``DocumentAttributeAudio`` element (duration in seconds), and the file
    name on ``DocumentAttributeFilename``.

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


def audio_is_music(msg) -> bool:
    """True if the message carries an audio document (voice notes excluded)."""
    return audio_attrs(msg)[0]


def audio_info(msg) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
    """(display title, performer, duration sec, file name) of an audio message."""
    is_audio, title, performer, dur, fname = audio_attrs(msg)
    if not fname:
        f = getattr(msg, "file", None)
        if f is not None and getattr(f, "name", None):
            fname = f.name
    cand_title = title or (os.path.splitext(fname)[0] if fname else "")
    return cand_title, performer, dur, fname


def evaluate(cands: List[Cand], track: Track, tol: int) -> Tuple[Optional[Cand], str]:
    """Return (best_candidate_or_None, human_reason).

    best = freshest candidate that (a) title-matches and (b) duration-matches.
    """
    title_matched = [c for c in cands if title_matches(track.title, c.cand_title)]
    if not title_matched:
        return None, "no title matches among %d search result(s)" % len(cands)

    if track.duration_s is None:
        best = max(title_matched, key=lambda c: (c.msg.date, c.msg.id))
        return best, "no duration in tracklist — picked freshest title match"

    dur_matched = [
        c
        for c in title_matched
        if c.dur is not None and abs(c.dur - track.duration_s) <= tol
    ]
    if not dur_matched:
        found = sorted({fmt_dur(c.dur) for c in title_matched if c.dur is not None})
        return None, (
            "title matched %d msg(s) but none with duration %s (+/-%ds); "
            "durations found: %s"
            % (
                len(title_matched),
                track.duration_str,
                tol,
                ", ".join(found) or "unknown",
            )
        )
    best = max(dur_matched, key=lambda c: (c.msg.date, c.msg.id))
    return best, "ok"


# ----------------------------------------------------------------------------
# Telegram I/O
# ----------------------------------------------------------------------------


def flood_secs(e) -> int:
    v = getattr(e, "seconds", None) or getattr(e, "value", None) or 15
    return int(v)


async def search_query(client, src, q: str, limit: int) -> list:
    """One server-side search, music filter, with a single FloodWait retry."""
    for attempt in (1, 2):
        try:
            res = []
            async for m in client.iter_messages(
                src, search=q, filter=InputMessagesFilterMusic, limit=limit
            ):
                if not audio_is_music(m):
                    continue
                res.append(m)
            return res
        except errors.FloodWaitError as e:
            if attempt == 2:
                raise
            wait = flood_secs(e)
            print("  ! FloodWait %ds on search — sleeping, then retrying" % wait)
            await asyncio.sleep(wait + 1)
    return []


async def search_and_pick(
    client, src, track: Track, args
) -> Tuple[List[Cand], Optional[Cand], str]:
    cands: List[Cand] = []
    seen = set()
    last_reason = "no search results (0 queries produced messages)"
    for q in build_queries(track):
        msgs = await search_query(client, src, q, args.limit)
        for m in msgs:
            if m.id in seen:
                continue
            seen.add(m.id)
            ct, perf, dur, fname = audio_info(m)
            cands.append(Cand(m, ct, perf, dur, fname))
        best, reason = evaluate(cands, track, args.tolerance)
        if best is not None:
            return cands, best, reason
        last_reason = reason
        await asyncio.sleep(args.delay)
    return cands, None, last_reason


async def do_forward(client, dest, msg, src):
    for attempt in (1, 2):
        try:
            return await client.forward_messages(dest, msg.id, src)
        except errors.FloodWaitError as e:
            if attempt == 2:
                raise
            wait = flood_secs(e)
            print("  ! FloodWait %ds on forward — sleeping, then retrying" % wait)
            await asyncio.sleep(wait + 1)


async def resolve_entity(client, ref: str, label: str):
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("%s: empty chat reference" % label)
    low = ref.lower()
    if low in ("me", "self", "saved", "saved messages", "savedmessages"):
        return await client.get_me()  # forwarding to "me" == Saved Messages
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


# ----------------------------------------------------------------------------
# Credentials / session
# ----------------------------------------------------------------------------


def phone_prompt() -> str:
    """Callback for Telethon start(): asks for the phone once needed."""
    return input(
        "Enter your phone in international format (e.g. +79991234567): "
    ).strip()


def resolve_phone(args):
    """--phone arg > TELEGRAM_PHONE env > interactive callback.

    NOTE: recent Telethon does NOT prompt for the phone itself and raises
    'No phone number or bot token provided.' when phone is None — so we must
    always provide a value (string or callable).
    """
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
    """Render a scannable QR into the terminal. False if qrcode lib is missing."""
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
    """QR login: show a scannable QR, auto-refresh it on expiry, wait for
    the user to confirm on the phone. Returns the authorized user.

    On the phone: Telegram -> Settings -> Devices -> Link Desktop Device.
    2FA is confirmed on the phone while approving the login; if the server
    still demands a password here, it is asked via a hidden prompt.
    """
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
# Self-test (offline)
# ----------------------------------------------------------------------------


def run_selftest() -> None:
    # --- parser ---
    t = parse_track_line("Dimension — COSTA (3:10)")
    assert t.title == "Dimension" and t.artist == "COSTA" and t.duration_s == 190, t
    t = parse_track_line("THE GIRLS ARE MAKING RIDD… — Zingara & Gardella (2:57)")
    assert (
        t.truncated and t.title == "THE GIRLS ARE MAKING RIDD" and t.duration_s == 177
    ), t
    t = parse_track_line("Energy (S.P.Y Remix) — Flava D & Stush (3:10)")
    assert t.title == "Energy (S.P.Y Remix)" and t.artist == "Flava D & Stush", t
    t = parse_track_line("4AM (Phrva & Klo Flip) — Kaskade x Adam K & Soha (3:48)")
    assert (
        t.title == "4AM (Phrva & Klo Flip)" and t.artist == "Kaskade x Adam K & Soha"
    ), t
    t = parse_track_line("Thank You (Felmax & V…) — Dido (3:46)")
    assert t.truncated and t.title == "Thank You (Felmax & V", t
    t = parse_track_line("Just Smoak It. - Smoakland & Pretty Sweet (2:23)")
    assert t.title == "Just Smoak It." and t.duration_s == 143, t
    t = parse_track_line("Grant Us Eyes — Seven Lions, Kill The Nois… (4:06)")
    assert t.title == "Grant Us Eyes" and t.artist == "Seven Lions, Kill The Nois", t
    assert parse_duration("1:02:03") == 3723
    assert fmt_dur(317) == "5:17" and fmt_dur(3723) == "1:02:03"

    # --- matching ---
    assert title_matches("CALL ME BABY (SAY M", "CALL ME BABY (SAY MY NAME)")
    assert title_matches(
        "THE GIRLS ARE MAKING RIDD", "THE GIRLS ARE MAKING RIDDIM (feat. X)"
    )
    assert title_matches("If The Sun Burns Out T", "If The Sun Burns Out Tonight")
    assert title_matches("blur", "Blur")
    assert not title_matches("BLUR", "ECHOES")

    # --- evaluate: freshest among duration-matching ---
    from datetime import timezone

    def mk(i, day, dur, title):
        msg = pytypes.SimpleNamespace(
            id=i, date=datetime(2026, 1, day, tzinfo=timezone.utc)
        )
        return Cand(msg, title, None, dur, None)

    tr = parse_track_line("X — Y (3:10)")
    c1 = mk(1, 1, 190, "X")
    c2 = mk(2, 2, 250, "X (Extended Mix)")  # too long -> ignored
    c3 = mk(3, 3, 189, "X")  # freshest valid -> winner
    best, reason = evaluate([c1, c2, c3], tr, 2)
    assert best is not None and best.msg.id == 3 and reason == "ok", (best, reason)

    best, reason = evaluate([c2], tr, 2)
    assert best is None and "duration" in reason, (best, reason)

    q = build_queries(
        parse_track_line("THE GIRLS ARE MAKING RIDD… — Zingara & Gardella (2:57)")
    )
    assert q[0] == "THE GIRLS ARE MAKING RIDD" and q[1] == "THE GIRLS ARE MAKING", q

    # --- audio metadata extraction (regression: msg.audio is the Document;
    #     title/performer/duration live in document.attributes -> DocumentAttributeAudio) ---
    if TELETHON_AVAILABLE:
        from telethon.tl.types import (
            DocumentAttributeAudio as DAA,
        )
        from telethon.tl.types import (
            DocumentAttributeFilename as DAF,
        )

        doc = pytypes.SimpleNamespace(
            attributes=[
                DAF(file_name="01 - Dimension.mp3"),
                DAA(duration=190, title="Dimension", performer="COSTA", voice=False),
            ]
        )
        msg_stub = pytypes.SimpleNamespace(document=doc, file=None)
        ct, perf, d, fn = audio_info(msg_stub)
        assert ct == "Dimension" and perf == "COSTA" and d == 190, (ct, perf, d)
        assert fn == "01 - Dimension.mp3", fn
        assert audio_is_music(msg_stub) is True
        voice_doc = pytypes.SimpleNamespace(attributes=[DAA(duration=5, voice=True)])
        assert (
            audio_is_music(pytypes.SimpleNamespace(document=voice_doc, file=None))
            is False
        )
        assert (
            audio_is_music(pytypes.SimpleNamespace(document=None, file=None)) is False
        )

    print("selftest OK: parser, matcher and selection rules all passed")


# ----------------------------------------------------------------------------
# CLI / main
# ----------------------------------------------------------------------------


def die(msg: str) -> None:
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Find tracks from a tracklist in a Telegram source chat and "
        "forward them into a destination chat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="tracklist line format:  Title — Artist (m:ss)\n"
        'chat reference: @username | t.me/link | numeric id | "me" (Saved Messages)',
    )
    p.add_argument(
        "tracklist_pos", nargs="?", help="path to tracklist .txt (one track per line)"
    )
    p.add_argument(
        "source_pos", nargs="?", help="source chat id/username (where to search)"
    )
    p.add_argument(
        "dest_pos", nargs="?", help="destination chat id/username (where to forward)"
    )
    p.add_argument(
        "--tracklist", dest="tracklist_opt", help="same as positional (override)"
    )
    p.add_argument("--source", dest="source_opt", help="same as positional (override)")
    p.add_argument("--dest", dest="dest_opt", help="same as positional (override)")
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
        help="login by scanning a QR code in the terminal "
        "(no phone/code input; ignores --phone/--sms)",
    )
    p.add_argument(
        "--sms",
        action="store_true",
        help="force login code delivery via SMS instead of in-app message",
    )
    p.add_argument(
        "--session",
        default="user",
        help="session file name (default: user)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=100,
        help="max messages fetched per search query (default: 100)",
    )
    p.add_argument(
        "--tolerance",
        type=int,
        default=2,
        help="allowed duration difference in seconds (default: 2)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="pause between tracks/queries in seconds (default: 1.0)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="search and report only, do not forward anything",
    )
    p.add_argument(
        "--no-dedupe",
        action="store_true",
        help="process duplicate tracklist lines instead of skipping them",
    )
    p.add_argument(
        "--report", help="write not-found tracks (with reasons) to this file"
    )
    p.add_argument(
        "--selftest",
        action="store_true",
        help="run offline parser/matcher self-test and exit",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()

    if args.selftest:
        run_selftest()
        return

    tracklist = args.tracklist_opt or args.tracklist_pos
    source = args.source_opt or args.source_pos
    dest = args.dest_opt or args.dest_pos
    if not tracklist or not source or not dest:
        die("usage: tg_track_forwarder.py TRACKLIST SOURCE DEST  (or --selftest)")

    tracks = load_tracklist(tracklist)
    if not tracks:
        die("no tracks parsed from %s" % tracklist)
    if not args.no_dedupe:
        tracks = dedupe(tracks)
    print("Tracklist: %d track(s) loaded from %s" % (len(tracks), tracklist))

    api_id, api_hash = resolve_creds(args)
    if not TELETHON_AVAILABLE:
        die("telethon is not installed:  pip install telethon")

    used_string_session = bool(os.getenv("TELEGRAM_SESSION_STRING"))
    if used_string_session:
        client = TelegramClient(
            StringSession(os.environ["TELEGRAM_SESSION_STRING"]), api_id, api_hash
        )
    else:
        client = TelegramClient(args.session, api_id, api_hash)
    client.flood_sleep_threshold = 60  # auto-sleep on small FloodWaits

    if args.qr:
        # QR login: connect and authorize via scanned code (no phone/code prompts)
        await client.connect()
        if not await client.is_user_authorized():
            await qr_login_flow(client)
    else:
        await client.start(
            phone=resolve_phone(args), force_sms=args.sms
        )  # phone is required by Telethon 1.45+
    if not used_string_session:
        chmod_session(args.session)

    me = await client.get_me()
    print("Authorized as: %s" % display(me))  # phone number is never printed

    src = await resolve_entity(client, source, "source")
    dest_e = await resolve_entity(client, dest, "dest")
    print("Source: %s" % display(src))
    print("Dest:   %s" % display(dest_e))
    if args.dry_run:
        print("DRY RUN — nothing will be forwarded")
    print("-" * 72)

    forwarded, missed = 0, []
    for idx, track in enumerate(tracks, 1):
        print("\n[%d/%d] %s" % (idx, len(tracks), track.raw))
        try:
            cands, best, reason = await search_and_pick(client, src, track, args)
        except errors.ChannelPrivateError:
            die("source chat is private / not accessible for this account")
        if best is None:
            print("  [MISS] %s" % reason)
            missed.append((track, reason))
            await asyncio.sleep(args.delay)
            continue

        m = best.msg
        when = m.date.astimezone(tz=None).strftime("%Y-%m-%d %H:%M")
        print(
            "  [ok] match: %s — %s [%s] msg %s from %s"
            % (
                best.cand_title or "?",
                best.performer or "?",
                fmt_dur(best.dur),
                m.id,
                when,
            )
        )
        if args.dry_run:
            print("  [ok] (dry run) would forward this message")
            continue
        try:
            sent = await do_forward(client, dest_e, m, src)
        except errors.ChatWriteForbiddenError:
            die("no post rights in destination chat %s" % display(dest_e))
        except errors.ChannelPrivateError:
            die("destination chat is private / not accessible for this account")
        except errors.RPCError as e:
            print("  [FAIL] forward failed: %s: %s" % (type(e).__name__, e))
            missed.append((track, "forward failed: %s" % e))
            await asyncio.sleep(args.delay)
            continue
        forwarded += 1
        print("  [ok] forwarded -> msg id %s" % getattr(sent, "id", "?"))
        await asyncio.sleep(args.delay)

    print("\n" + "=" * 72)
    print(
        "Done. Forwarded: %d / %d. Not found / failed: %d."
        % (forwarded, len(tracks), len(missed))
    )
    for t, r in missed:
        print("  [MISS] %s\n         %s" % (t.raw, r))
    if missed and args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            for t, r in missed:
                fh.write("%s    # %s\n" % (t.raw, r))
        print("Not-found report written to %s" % args.report)

    await client.disconnect()


async def count_avg() -> None:
    args = parse_args()

    api_id, api_hash = resolve_creds(args)
    client = TelegramClient(args.session, api_id, api_hash)
    client.flood_sleep_threshold = 60  # auto-sleep on small FloodWaits

    if args.qr:
        # QR login: connect and authorize via scanned code (no phone/code prompts)
        await client.connect()
        if not await client.is_user_authorized():
            await qr_login_flow(client)
    else:
        await client.start(
            phone=resolve_phone(args), force_sms=args.sms
        )  # phone is required by Telethon 1.45+

    me = await client.get_me()
    print("Authorized as: %s" % display(me))  # phone number is never printed

    src = await resolve_entity(client, '-1001895123874', "source")
    print("Target channel: %s" % display(src))

    data = defaultdict(list)
    message_count = 0
    async for message in client.iter_messages(src, reverse=True):
        message_count += 1
        data[f"{message.date.year}-{message.date.month}"].append(message)
        print(message.date)

    print(f"Average: {message_count /len(data):.3f}: {message_count=}, {len(data)=}")


    await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(count_avg())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
