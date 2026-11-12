#!/usr/bin/env python3
"""Run reactive chat and scheduled room rotation with one unlocked identity."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import fcntl
except ImportError:  # Windows: no flock; the single-runner lock is skipped there.
    fcntl = None

import airdrop_watch
import technocore_agent as agent


ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
RUNNER_LOCK_PATH = Path(__file__).resolve().parent / ".technocore-runner.lock"
KEYRING_LOOKUP_TIMEOUT_SECONDS = 60.0
# A worker that stops with one of these is misconfigured and will not self-heal;
# restarting it would just spin. Anything else is treated as transient.
FATAL_WORKER_ERRORS = (agent.IdentityError, agent.ProtocolError)
WORKER_RESTART_BASE_SECONDS = 5.0
WORKER_RESTART_CAP_SECONDS = 300.0
WORKER_HEALTHY_SECONDS = 300.0

DEAL_SCRIPT = Path(__file__).resolve().parent / "deal.mjs"
DEALS_LOG_NAME = ".technocore-deals.jsonl"  # next to DEAL_SCRIPT, where deal.mjs writes it
DEAL_MIN_INTERVAL_SECONDS = 300.0
DEAL_SUBPROCESS_TIMEOUT_SECONDS = 240.0
DEAL_REASON_MAX_CHARS = 500


def load_env_file(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE entries without executing shell syntax."""
    if not path.exists():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise agent.LocalFileError(f"cannot read environment file {path}: {error}") from error
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise agent.ProtocolError(f"{path}:{line_number}: expected NAME=VALUE")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if ENV_NAME.fullmatch(name) is None:
            raise agent.ProtocolError(f"{path}:{line_number}: invalid variable name")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(name, value)


def acquire_runner_lock(path: Path = RUNNER_LOCK_PATH):
    """Take the one-runner-per-checkout lock and return its handle.

    Two runners would double every post, reply and deal under one identity —
    e.g. ``npm start`` while the systemd service is already up. The kernel drops
    the lock when the process exits, crash included, so it never goes stale.
    Keep the returned handle referenced for the life of the process.
    """
    try:
        handle = open(path, "a+", encoding="utf-8")
    except OSError as error:
        raise agent.LocalFileError(f"cannot open runner lock {path}: {error}") from error
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.seek(0)
            holder = handle.read().strip() or "unknown"
            handle.close()
            raise agent.LocalFileError(
                f"another Technocore runner is already running (pid {holder}); "
                "stop it first — if it is the service: systemctl --user stop technocore"
            ) from None
    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()
    return handle


def keyring_attributes(key: Path) -> list[str]:
    """The Secret Service attributes the identity passphrase is stored under."""
    return ["service", "technocore", "key", key.name]


def identity_from_keyring(environ) -> bool:
    try:
        return agent.environment_bool(environ.get("TECHNOCORE_IDENTITY_KEYRING", "false"))
    except ValueError:
        raise agent.ProtocolError("TECHNOCORE_IDENTITY_KEYRING must be true or false") from None


def keyring_passphrase(key: Path) -> bytes:
    """Fetch the identity passphrase from the login keyring (Secret Service).

    For unattended starts (the systemd unit), where there is no terminal to
    prompt on. The secret goes from ``secret-tool``'s stdout straight into the
    key loader and is never placed in the environment, so child processes such
    as the deal loop's ``node`` never inherit it.
    """
    store = (
        "secret-tool store --label='Technocore identity passphrase' "
        + " ".join(keyring_attributes(key))
    )
    secret_tool = shutil.which("secret-tool")
    if secret_tool is None:
        raise agent.IdentityError(
            "TECHNOCORE_IDENTITY_KEYRING is on but secret-tool is not installed "
            "(sudo apt install libsecret-tools)"
        )
    try:
        done = subprocess.run(
            [secret_tool, "lookup", *keyring_attributes(key)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=KEYRING_LOOKUP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise agent.IdentityError(
            "keyring lookup timed out — is the login keyring locked?"
        ) from None
    # secret-tool adds a newline only on a tty, but `echo … | secret-tool store`
    # stores one; getpass never yields a trailing newline, so dropping it matches.
    secret = done.stdout.rstrip(b"\r\n")
    if done.returncode != 0 or not secret:
        raise agent.IdentityError(
            f"no identity passphrase in the login keyring; store it once with: {store}"
        )
    return secret


def supervise(
    name: str,
    operation: Callable[[], int],
    shutdown: threading.Event,
    outcomes: dict[str, str],
) -> None:
    """Keep one worker running: restart it with capped backoff after a crash.

    A clean return ends the worker. A misconfiguration (``FATAL_WORKER_ERRORS``)
    disables just this worker without touching the other. Any other exception is
    transient: log it and restart after ``WORKER_RESTART_BASE_SECONDS`` doubling
    to ``WORKER_RESTART_CAP_SECONDS``, reset once the worker has run healthily.
    """
    backoff = WORKER_RESTART_BASE_SECONDS
    while not shutdown.is_set():
        started = time.monotonic()
        try:
            code = operation()
        except FATAL_WORKER_ERRORS as error:
            print(
                f"error: {name} disabled (fix the configuration and restart): {error}",
                file=sys.stderr,
                flush=True,
            )
            outcomes[name] = "fatal"
            return
        except BaseException as error:  # noqa: BLE001 - a supervisor must catch all
            if shutdown.is_set():
                return
            if time.monotonic() - started >= WORKER_HEALTHY_SECONDS:
                backoff = WORKER_RESTART_BASE_SECONDS
            print(
                f"warning: {name} crashed after "
                f"{time.monotonic() - started:.0f}s: {error!r}; "
                f"restarting in {backoff:.0f}s",
                file=sys.stderr,
                flush=True,
            )
            if shutdown.wait(backoff):
                return
            backoff = min(backoff * 2, WORKER_RESTART_CAP_SECONDS)
        else:
            print(f"{name} finished cleanly (exit {code})", file=sys.stderr, flush=True)
            outcomes[name] = "done"
            return


HOME_ROOM_DISABLED = frozenset({"none", "off", "-", "0"})


def resolve_home_room(config: dict, environ: object) -> str:
    """The room every deployment of this tool should keep active, or "".

    ``TECHNOCORE_HOME_ROOM`` wins over ``auto_chat.home_room`` in the JSON config;
    set the env var to ``none`` to opt out of a room the shipped config names.
    """
    raw = (
        environ.get("TECHNOCORE_HOME_ROOM", "")
        or config.get("auto_chat", {}).get("home_room", "")
        or ""
    )
    room = str(raw).strip()
    if not room or room.lower() in HOME_ROOM_DISABLED:
        return ""
    return agent.validate_name(room)


def home_state_path(chat_state: Path, home_room: str) -> Path:
    """A cursor file for the home-room watcher that never collides with the main one."""
    return Path(chat_state).expanduser().parent / f".technocore-home-{home_room}.json"


def deal_loop_plan(environ: object) -> tuple[float, str] | None:
    """(interval_seconds, room) when a scheduled tclk deal loop is configured.

    Off unless ``TECHNOCORE_DEAL_INTERVAL`` is set. The room defaults to the
    shared ``tclk-offers`` venue, where deals belong and anyone can audit them.
    """
    raw = str(environ.get("TECHNOCORE_DEAL_INTERVAL", "")).strip()
    if not raw:
        return None
    try:
        interval = float(raw)
    except ValueError as error:
        raise agent.ProtocolError(
            "TECHNOCORE_DEAL_INTERVAL must be a number of seconds"
        ) from error
    if interval < DEAL_MIN_INTERVAL_SECONDS:
        raise agent.ProtocolError(
            f"TECHNOCORE_DEAL_INTERVAL must be at least "
            f"{DEAL_MIN_INTERVAL_SECONDS:.0f} seconds"
        )
    room = str(environ.get("TECHNOCORE_DEAL_ROOM", "")).strip() or "tclk-offers"
    return interval, agent.validate_name(room)


def watch_loop_interval(environ: object) -> float | None:
    """Seconds between passes of the read-only airdrop watcher, or None when off."""
    raw = str(environ.get("TECHNOCORE_WATCH_INTERVAL", "")).strip()
    if not raw:
        return None
    try:
        interval = float(raw)
    except ValueError as error:
        raise agent.ProtocolError(
            "TECHNOCORE_WATCH_INTERVAL must be a number of seconds"
        ) from error
    if interval < airdrop_watch.MIN_INTERVAL_SECONDS:
        raise agent.ProtocolError(
            f"TECHNOCORE_WATCH_INTERVAL must be at least "
            f"{airdrop_watch.MIN_INTERVAL_SECONDS:.0f} seconds"
        )
    return interval


def utc_timestamp(now: float | None = None) -> str:
    """ISO-8601 UTC with milliseconds and a Z, the shape deal.mjs's toISOString() writes."""
    moment = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def last_deal_time(path: Path) -> float | None:
    """Unix time of the newest record (completed or failed) in the deals log, or None."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            stamp = json.loads(line).get("ts")
            return datetime.fromisoformat(stamp).timestamp()
        except (ValueError, TypeError, AttributeError):
            continue
    return None


def first_deal_delay(path: Path, interval: float, now: float | None = None) -> float:
    """Seconds until the next deal is due, judged from the newest record.

    Without this every runner start (each login, each crash restart) ran a deal
    immediately, on top of the interval cadence. Clamped to ``interval`` so a
    record stamped in the future (clock stepped back) cannot stall the loop.
    """
    last = last_deal_time(path)
    if last is None:
        return 0.0
    current = time.time() if now is None else now
    return min(interval, max(0.0, last + interval - current))


def record_failed_deal(path: Path, room: str, reason: str) -> None:
    """Append a failure record, so failed attempts are visible and count for cadence.

    deal.mjs writes the completed records; the runner writes failures because it
    also sees the ones the script cannot report itself (a timeout, a crash).
    """
    entry = {
        "ts": utc_timestamp(),
        "room": room,
        "outcome": "failed",
        "reason": reason[:DEAL_REASON_MAX_CHARS],
    }
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as error:
        print(f"warning: cannot record the failed deal in {path}: {error}",
              file=sys.stderr, flush=True)


def deal_failure_reason(done: subprocess.CompletedProcess) -> str:
    lines = [ln.strip() for ln in (done.stderr or done.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return f"exit status {done.returncode}"
    return lines[-1].removeprefix("deal failed:").strip() or lines[-1]


def run_deal_loop(interval: float, room: str) -> int:
    """Run one tclk PaperRail deal rehearsal per interval, forever.

    Each rehearsal is a full offer/accept/lock/reveal/receipt choreography by the
    disposable pair in ``parties.json``, self-audited and appended to
    ``.technocore-deals.jsonl``. A missing prerequisite (node, the script, the
    package) is fatal; a failed rehearsal is transient — recorded, logged, retried
    next tick. The first deal waits for whatever is left of the interval since the
    newest record, so restarts don't add deals.
    """
    node = shutil.which("node")
    if node is None:
        raise agent.ProtocolError("node is not on PATH; cannot run the tclk deal loop")
    for required in (DEAL_SCRIPT, DEAL_SCRIPT.parent / "tclk-signing.mjs"):
        if not required.exists():
            raise agent.ProtocolError(f"{required.name} is missing")
    if not (DEAL_SCRIPT.parent / "node_modules" / "@flop-labs" / "tclk").is_dir():
        raise agent.ProtocolError(
            "@flop-labs/tclk is not installed; run `npm install` in the project"
        )
    deals_log = DEAL_SCRIPT.parent / DEALS_LOG_NAME
    delay = first_deal_delay(deals_log, interval)
    if delay > 0:
        print(
            f"tclk deal loop: newest record is recent; next deal in {delay / 60:.0f} min",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(delay)
    while True:
        started = time.monotonic()
        try:
            done = subprocess.run(
                [node, str(DEAL_SCRIPT), room],
                cwd=str(DEAL_SCRIPT.parent),
                capture_output=True,
                text=True,
                timeout=DEAL_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            reason = f"timed out after {DEAL_SUBPROCESS_TIMEOUT_SECONDS:.0f}s"
            record_failed_deal(deals_log, room, reason)
            print(
                f"warning: tclk deal in {room} {reason}; retrying next tick",
                file=sys.stderr,
                flush=True,
            )
        else:
            if done.returncode == 0:
                tail = [ln for ln in (done.stdout or "").splitlines() if ln.strip()]
                print(
                    f"tclk deal in {room}: {tail[-1].strip() if tail else 'ok'}",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                reason = deal_failure_reason(done)
                record_failed_deal(deals_log, room, reason)
                print(
                    f"warning: tclk deal in {room} failed ({reason}); retrying next tick",
                    file=sys.stderr,
                    flush=True,
                )
        elapsed = time.monotonic() - started
        if elapsed < interval:
            time.sleep(interval - elapsed)


def main() -> int:
    agent.configure_output_streams()
    try:
        load_env_file()
        send = agent.environment_bool(os.environ.get("TECHNOCORE_SEND", "false"))
        parser = agent.build_parser()
        chat_args = parser.parse_args(["auto-chat"])
        post_args = parser.parse_args(["auto-post"])
        chat_args.send = send
        post_args.send = send
        home_room = resolve_home_room(agent.load_config(), os.environ)
        home_args = None
        if home_room:
            existing = list(post_args.rooms) if post_args.rooms else []
            if home_room not in existing:
                post_args.rooms = [*existing, home_room]
            if home_room != chat_args.room:
                home_args = parser.parse_args(["auto-chat"])
                home_args.send = send
                home_args.room = home_room
                home_args.state = home_state_path(chat_args.state, home_room)
        deal_plan = deal_loop_plan(os.environ)
        watch_interval = watch_loop_interval(os.environ)
        # Before the identity, so a second runner fails fast instead of prompting.
        runner_lock = acquire_runner_lock()  # noqa: F841 — held until exit
        passphrase = (
            keyring_passphrase(chat_args.key) if identity_from_keyring(os.environ) else None
        )
        private_key = agent.load_identity(chat_args.key, passphrase)
        del passphrase
    except (agent.IdentityError, agent.LocalFileError, agent.NetworkError,
            agent.ProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("cancelled", file=sys.stderr)
        return 130

    mode = "LIVE signed posting" if send else "DRY RUN (nothing will be published)"
    print(f"starting Technocore automation: {mode}", file=sys.stderr, flush=True)
    if home_room:
        extra = "" if home_args is None else " + dedicated auto-chat"
        print(
            f"home room: {home_room} (in auto-post rotation{extra})",
            file=sys.stderr,
            flush=True,
        )
    plan = [("auto-chat", lambda: agent.run_auto_chat(private_key, chat_args))]
    if home_args is not None:
        plan.append(
            (f"auto-chat:{home_room}", lambda: agent.run_auto_chat(private_key, home_args))
        )
    plan.append(("auto-post", lambda: agent.run_auto_post(private_key, post_args)))
    if deal_plan is not None:
        deal_interval, deal_room = deal_plan
        plan.append(
            (f"tclk-deals:{deal_room}", lambda: run_deal_loop(deal_interval, deal_room))
        )
        print(
            f"tclk deal loop: one PaperRail rehearsal in {deal_room} every "
            f"{deal_interval / 3600:.1f}h (disposable keys from parties.json)",
            file=sys.stderr,
            flush=True,
        )
    if watch_interval is not None:
        plan.append(("airdrop-watch", lambda: airdrop_watch.run_watch_loop(watch_interval)))
        print(
            f"airdrop watch: read-only check of official FLOP/Technocore sources "
            f"every {watch_interval / 60:.0f} min (alerts appear here as [watch])",
            file=sys.stderr,
            flush=True,
        )
    shutdown = threading.Event()
    outcomes: dict[str, str] = {}
    threads = [
        threading.Thread(
            name=name,
            target=supervise,
            args=(name, operation, shutdown, outcomes),
            daemon=True,
        )
        for name, operation in plan
    ]
    for thread in threads:
        thread.start()
    try:
        while any(thread.is_alive() for thread in threads):
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("cancelled; stopping workers", file=sys.stderr, flush=True)
        shutdown.set()
        for thread in threads:
            thread.join(timeout=5.0)
        return 130
    if "fatal" in outcomes.values():
        return 1
    print("all workers stopped", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
