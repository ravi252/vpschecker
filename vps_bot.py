#!/usr/bin/env python3
"""
vps_bot.py — Telegram bot that checks a VPS list you upload.

Flow
----
  /start  ->  send a .txt with ip:port:user:pass lines (or paste the text)
  the bot replies with:
      * a short summary (checked / working / dead counts)
      * working.txt  (ONLY the working VPS, as a plain text file)
  (dead/failed servers are still logged on the server under bot_runs/)

Setup
-----
  1. Create a bot with @BotFather on Telegram and copy the token.
  2. Put the token in env  VPSBOT_TOKEN  (or BOT_TOKEN)
     OR write it to a file  bot_token.txt  next to this script.
  3. pip install python-telegram-bot paramiko
  4. python vps_bot.py

File size
---------
Telegram only lets a bot download files up to 20 MB (hard platform limit).
Files bigger than that are rejected with a short message. The bot itself
streams downloads to disk, so any file up to 20 MB works even on small VPSes.
"""
import asyncio
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from telegram import Update, InputFile
from telegram.error import BadRequest
from telegram.request import HTTPXRequest
from telegram.ext import (
    Application, CommandHandler,
    MessageHandler, filters,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("vps_bot")

# HTTP request timeout for the Bot API. Generous, because big file
# downloads/uploads stream through it. Per-operation seconds.
REQUEST_TIMEOUT = 180.0

# --- paths & tuning ------------------------------------------------------- #
BASE_DIR  = Path(__file__).resolve().parent
CHECKER   = str(BASE_DIR / "vps_checker.py")
RUNS_DIR  = BASE_DIR / "bot_runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

WORKERS         = 100    # parallel SSH checks per checker subprocess
PARALLEL_RUNS   = 4      # checker subprocesses at the same time (total concurrency = WORKERS x PARALLEL_RUNS)
TIMEOUT         = 8.0    # per-connection timeout (seconds)
SUBPROC_TIMEOUT = 1800   # hard cap on a whole run (seconds)
DEADLINE        = max(120, SUBPROC_TIMEOUT - 120)  # checker must finish before the cap
PING_ONLY       = False  # True = TCP-only, skip the SSH login (faster)

# Optional: Local Bot API Server URL. Leave empty to use the normal cloud API
# (20 MB download cap). Set only if you run one:  http://127.0.0.1:8081
LOCAL_API_URL = os.environ.get("VPSBOT_LOCAL_API", "").strip().rstrip("/")

MAX_CLOUD_DOWNLOAD = 20 * 1024 * 1024  # cloud Bot API download cap (bytes)

CHECK_LOCK = asyncio.Lock()  # only one heavy check at a time


# --- helpers -------------------------------------------------------------- #
def load_token():
    tok = os.environ.get("VPSBOT_TOKEN") or os.environ.get("BOT_TOKEN")
    if tok and tok.strip():
        return tok.strip()
    p = BASE_DIR / "bot_token.txt"
    if p.exists():
        t = p.read_text(encoding="utf-8").strip()
        if t:
            return t
    return None


def parse_json_line(line):
    """Parse ONE line of checker output. Progress lines are compact JSON
    objects; anything else (noise/stderr) is returned as None."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


async def _run_check_streaming(cmd, on_progress):
    """Run the checker, reading stdout as raw chunks and splitting lines
    ourselves (the final summary is ONE huge line, so asyncio's built-in
    readline() would blow past its 64 KiB buffer limit and crash with
    'Separator is not found'). Returns (final_payload, stderr_text)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=str(BASE_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        limit=2 * 1024 * 1024)
    payload = None
    noise = []
    start = time.monotonic()
    last_update = 0.0
    buf = b""

    async def handle_line(line: bytes) -> None:
        nonlocal payload, last_update
        text = line.decode("utf-8", "replace").strip()
        if not text:
            return
        obj = parse_json_line(text)
        if obj is None:
            noise.append(text[:2000])
            return
        if obj.get("progress"):
            now = time.monotonic()
            # throttle Telegram edits to ~1/sec so we never get rate-limited
            if obj.get("done", 0) == 0 or now - last_update >= 1.0:
                await on_progress(obj)
                last_update = now
        elif obj.get("results") is not None:
            payload = obj  # final summary

    try:
        while True:
            remaining = SUBPROC_TIMEOUT - (time.monotonic() - start)
            if remaining <= 0:
                raise TimeoutError(
                    f"The run did not finish within {SUBPROC_TIMEOUT}s and "
                    f"was cancelled. The list is too large and/or too many "
                    f"servers are hanging. Try a smaller file, or on the "
                    f"server raise SUBPROC_TIMEOUT / WORKERS in vps_bot.py.")
            try:
                chunk = await asyncio.wait_for(proc.stdout.read(65536),
                                               timeout=remaining)
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"The run did not finish within {SUBPROC_TIMEOUT}s and "
                    f"was cancelled. Try a smaller file, or on the server "
                    f"raise SUBPROC_TIMEOUT / WORKERS in vps_bot.py.") from None
            if not chunk:
                break  # checker exited -> EOF
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                await handle_line(buf[:nl])
                buf = buf[nl + 1:]
    finally:
        if proc.returncode is None:
            proc.kill()
    if buf:
        await handle_line(buf)  # tail after the last newline (final summary)
    await proc.wait()
    return payload, "\n".join(noise)


def working_line(r):
    specs = [p for p in (
        r.get("os"), r.get("cpu"),
        (f"{r['ram']} RAM" if r.get("ram") else None),
        (f"{r['disk']} disk" if r.get("disk") else None),
        (f"up {r['uptime']}" if r.get("uptime") else None),
        r.get("hostname"),
        (f"{r['latency_ms']} ms" if r.get("latency_ms") is not None else None),
    ) if p]
    spec  = ", ".join(specs) if specs else "working"
    creds = f"{r['ip']}:{r['port']}:{r['user']}:{r.get('password') or ''}"
    return f"{creds}   |   {spec}"


def dead_line(r):
    return (f"{r['ip']}:{r['port']}:{r['user']}   |   "
            f"{r.get('status', '?')}  {r.get('detail', '')}".rstrip())


def write_working(path, working):
    lines = [working_line(r) for r in working] or ["# no working VPSes found"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_dead(path, dead):
    lines = [dead_line(r) for r in dead] or ["# no dead VPSes -- all working"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def chunk_text(text, size=4000, max_parts=4):
    """Split text into Telegram-safe chunks (each < 4096 chars, never mid-line)."""
    parts, cur = [], text
    while len(cur) > size:
        cut = cur.rfind("\n", 0, size)
        cut = cut if cut > 0 else size
        parts.append(cur[:cut])
        cur = cur[cut:].lstrip("\n")
        if len(parts) >= max_parts:
            parts[-1] += "\n…(truncated — the full list is in working.txt)"
            return parts
    parts.append(cur)
    return parts


def new_run_dir(user_id):
    d = RUNS_DIR / f"{int(time.time())}_{user_id}_{uuid.uuid4().hex[:6]}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _count_lines(path):
    """Count non-blank lines without loading the file into memory."""
    n = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            if ln.strip():
                n += 1
    return n


def _stream_split(path, out_dir, n, prefix="part_"):
    """Split a (possibly huge) text file into ``n`` round-robin part files by
    streaming it line-by-line. Returns the list of created paths."""
    n = max(1, n)
    parts = [out_dir / f"{prefix}{i}.txt" for i in range(n)]
    handles = [open(p, "w", encoding="utf-8") for p in parts]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            idx = 0
            for ln in fh:
                if ln.strip():
                    handles[idx % n].write(ln)
                    idx += 1
    finally:
        for h in handles:
            h.close()
    return parts


def cleanup_old_runs(max_age=3600):
    now = time.time()
    for d in RUNS_DIR.iterdir():
        try:
            if d.is_dir() and now - d.stat().st_mtime > max_age:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


# --- Telegram handlers ---------------------------------------------------- #
async def _edit_skip_unchanged(msg, text):
    """edit_text() but quietly ignore Telegram's 'message is not modified'
    error (happens when a button is double-tapped or an edit repeats)."""
    try:
        await msg.edit_text(text)
    except BadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return
        raise


async def cmd_start(update, context):
    await update.message.reply_text(
        "👋 Send me a .txt with  ip:port:user:pass  lines, "
        "or paste the list as a message.\n\n"
        "I'll check each server and send back the working ones.")


async def cmd_help(update, context):
    await update.message.reply_text(
        "1. /start\n"
        "2. Send a .txt file (or just paste the text)\n"
        "3. You get the working VPS — as a working.txt file AND as a "
        "message you can read/copy right here\n\n"
        f"Settings: workers={WORKERS * PARALLEL_RUNS}, timeout={TIMEOUT:g}s")


async def _run_check(update, context, input_path, status_msg, run_dir):
    t0 = time.time()
    total_lines = _count_lines(input_path)

    n_runs = max(1, min(PARALLEL_RUNS, (total_lines + 15) // 16))

    def base_cmd(path):
        cmd = [sys.executable, CHECKER, str(path),
               "--json", "--no-persist",
               "--workers", str(WORKERS), "--timeout", str(TIMEOUT),
               "--deadline", str(DEADLINE), "--progress-json"]
        if PING_ONLY:
            cmd.append("--ping-only")
        return cmd

    if n_runs == 1:
        chunk_files = [input_path]
    else:
        chunk_files = _stream_split(input_path, run_dir, n_runs)

    cmds = [base_cmd(str(p)) for p in chunk_files]

    await _edit_skip_unchanged(
        status_msg,
        f"🚀 Checking {total_lines} line(s)… "
        f"{n_runs} runner(s) × {WORKERS} workers, "
        f"timeout {TIMEOUT:g}s")

    runs = {}          # runner index -> its latest progress object
    events = asyncio.Queue()
    last_label = ""

    async def on_event(idx, obj):
        await events.put((idx, obj))

    async def run_one(idx, cmd):
        async def ev(o):
            await on_event(idx, o)
        payload, err = await _run_check_streaming(cmd, ev)
        return idx, payload, err

    gather_task = asyncio.ensure_future(
        asyncio.gather(*[run_one(i, c) for i, c in enumerate(cmds)],
                       return_exceptions=True))

    def aggregate():
        done  = sum(int(r.get("done", 0)) for r in runs.values())
        total = sum(int(r.get("total", 0)) for r in runs.values())
        work  = sum(int(r.get("working", 0)) for r in runs.values())
        dead  = sum(int(r.get("dead", 0)) for r in runs.values())
        auth  = sum(int(r.get("auth", 0)) for r in runs.values())
        skpd  = sum(int(r.get("skipped", 0)) for r in runs.values())
        return done, total, work, dead, auth, skpd

    async def progress_text():
        done, total, work, dead, auth, skpd = aggregate()
        left = max(0, total - done)
        invalid = max(0, total_lines - total)
        lines = []
        if len(runs) == n_runs:
            lines.append(f"📄 {total_lines} lines → {total} valid, "
                         f"{invalid} invalid")
        lines.append(f"🔎 Checked {done}/{total} — {left} left, "
                     f"{skpd} skipped")
        lines.append(f"🟢 Working {work} · 🔴 Dead/Fail {dead} · "
                     f"⚠️ Auth {auth}")
        if last_label and done > 0:
            lines.append(f"Last: {last_label}")
        return "\n".join(lines)

    last_text = ""

    async def safe_edit(text):
        # Telegram rejects edits whose content is identical to the current
        # message; throttled progress updates can easily collide, so skip
        # same-text edits and swallow the "not modified" race quietly.
        nonlocal last_text
        if text == last_text:
            return
        try:
            await status_msg.edit_text(text)
        except BadRequest as exc:
            if "message is not modified" in str(exc).lower():
                return  # already shows this exact content — fine
            raise
        last_text = text

    # Consumer: fold every runner's progress into ONE message (~1 edit/sec).
    last_edit = 0.0
    while not gather_task.done() or not events.empty():
        try:
            idx, obj = await asyncio.wait_for(events.get(), timeout=0.4)
        except asyncio.TimeoutError:
            continue
        runs[idx] = obj
        if obj.get("last"):
            last_label = obj["last"]
        now = time.monotonic()
        if now - last_edit >= 1.0 and runs:
            await safe_edit(await progress_text())
            last_edit = now
    while not events.empty():
        idx, obj = events.get_nowait()
        runs[idx] = obj
        if obj.get("last"):
            last_label = obj["last"]
    if runs:
        await safe_edit(await progress_text())

    results = await gather_task

    # Merge every subprocess's results into one list.
    all_results = []
    any_error = None
    for res in results:
        if isinstance(res, BaseException):
            if isinstance(res, TimeoutError):
                any_error = res
            continue
        _idx, payload, _err = res
        if payload:
            all_results.extend(payload.get("results") or [])

    if any_error is not None:
        await safe_edit(f"❌ {any_error}")
        return

    if not all_results:
        await safe_edit("❌ Checker failed.")
        return

    working = [r for r in all_results if r.get("status") == "OK"]
    dead    = [r for r in all_results if r.get("status") != "OK"]
    wpath, dpath = run_dir / "working.txt", run_dir / "dead.txt"
    write_working(wpath, working)
    write_dead(dpath, dead)
    elapsed = time.time() - t0

    total = len(all_results)
    invalid = max(0, total_lines - total)
    skipped = sum(1 for r in all_results if r.get("status") == "SKIPPED")
    note = ""
    if skipped:
        note = (f"\n⚠️ Ran out of time — {skipped} server(s) were NOT checked. "
                f"Try a smaller file next time.")
    await safe_edit(
        f"✅ Done in {elapsed:.1f}s\n"
        f"📄 {total_lines} lines ({total} valid, {invalid} invalid)\n"
        f"🔢 Checked   : {total}\n"
        f"🟢 Working  : {len(working)}\n"
        f"🔴 Dead/Fail : {len(dead)}{note}\n\n📎 Sending working.txt + the list below…")

    # 1) The .txt file — upload the raw BYTES via BytesIO with an explicit
    #    filename so Telegram sends the real file, not the path as text.
    await update.message.reply_document(
        document=InputFile(io.BytesIO(wpath.read_bytes()), filename="working.txt"),
        caption=f"🟢 Working VPS ({len(working)}) — if the file won't open, "
                f"the exact same list is in the message right below.")

    # 2) The SAME list as plain chat text, so it's always readable/copyable.
    body = "\n".join(working_line(r) for r in working) or "No working VPSes found."
    for part in chunk_text(body):
        await update.message.reply_text(part, disable_web_page_preview=True)


async def on_document(update, context):
    message, doc = update.message, update.message.document
    if not doc:
        await message.reply_text("Please send a .txt file (or paste the text).")
        return
    if CHECK_LOCK.locked():
        await message.reply_text("⏳ A check is already running. Wait, then send it again.")
        return
    async with CHECK_LOCK:
        try:
            size = doc.file_size or 0
            if not LOCAL_API_URL and size > MAX_CLOUD_DOWNLOAD:
                await message.reply_text(
                    "❌ File is too big. Telegram only lets bots download "
                    "files up to 20 MB. Please send a file up to 20 MB.")
                return
            run_dir    = new_run_dir(update.effective_user.id)
            input_path = run_dir / "input.txt"
            status = await message.reply_text(
                f"📥 Downloading your file… ({size / (1024*1024):.1f} MB)")
            tg_file = await context.bot.get_file(doc.file_id)
            try:
                await tg_file.download_to_drive(custom_path=str(input_path))
            except BadRequest as exc:
                if "too big" in str(exc).lower():
                    await _edit_skip_unchanged(
                        status,
                        "❌ File is too big. Telegram only lets bots "
                        "download files up to 20 MB. Please send a file "
                        "up to 20 MB.")
                    return
                raise
            await _run_check(update, context, input_path, status, run_dir)
        except Exception as exc:
            log.exception("document handler failed")
            await message.reply_text(f"❌ Error: {exc}")


async def on_text(update, context):
    message = update.message
    text = message.text or ""
    if not text.strip():
        return
    if CHECK_LOCK.locked():
        await message.reply_text("⏳ A check is already running. Wait, then send it again.")
        return
    async with CHECK_LOCK:
        try:
            run_dir    = new_run_dir(update.effective_user.id)
            input_path = run_dir / "input.txt"
            input_path.write_text(text, encoding="utf-8")
            status = await message.reply_text(
                f"🧮 {len(text.splitlines())} line(s). Working…")
            await _run_check(update, context, input_path, status, run_dir)
        except Exception as exc:
            log.exception("text handler failed")
            await message.reply_text(f"❌ Error: {exc}")


# --- entry point ---------------------------------------------------------- #
def main():
    token = load_token()
    if not token:
        print("No bot token found.\n"
              "Create one with @BotFather, then set env VPSBOT_TOKEN "
              f"or write it to:  {BASE_DIR / 'bot_token.txt'}\n")
        sys.exit(1)
    cleanup_old_runs()

    builder = Application.builder().token(token)
    builder = builder.request(HTTPXRequest(timeout=REQUEST_TIMEOUT))
    if LOCAL_API_URL:
        builder = (builder
                   .base_url(LOCAL_API_URL + "/bot")
                   .base_file_url(LOCAL_API_URL + "/file/bot"))
        print(f"Using Local Bot API Server: {LOCAL_API_URL} "
              f"(uploads/downloads up to ~2 GB)")
    app = builder.build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    print(f"VPS Checker bot starting… (workers={WORKERS}, timeout={TIMEOUT:g}s)")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
