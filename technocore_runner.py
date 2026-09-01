#!/usr/bin/env python3
"""Run reactive chat and scheduled room rotation with one unlocked identity."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable

import technocore_agent as agent


ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A worker that stops with one of these is misconfigured and will not self-heal;
# restarting it would just spin. Anything else is treated as transient.
FATAL_WORKER_ERRORS = (agent.IdentityError, agent.ProtocolError)
WORKER_RESTART_BASE_SECONDS = 5.0
WORKER_RESTART_CAP_SECONDS = 300.0
WORKER_HEALTHY_SECONDS = 300.0


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
        private_key = agent.load_identity(chat_args.key)
    except (agent.IdentityError, agent.LocalFileError, agent.NetworkError,
            agent.ProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("cancelled", file=sys.stderr)
        return 130

    mode = "LIVE signed posting" if send else "DRY RUN (nothing will be published)"
    print(f"starting Technocore automation: {mode}", file=sys.stderr, flush=True)
    shutdown = threading.Event()
    outcomes: dict[str, str] = {}
    threads = [
        threading.Thread(
            name=name,
            target=supervise,
            args=(name, operation, shutdown, outcomes),
            daemon=True,
        )
        for name, operation in (
            ("auto-chat", lambda: agent.run_auto_chat(private_key, chat_args)),
            ("auto-post", lambda: agent.run_auto_post(private_key, post_args)),
        )
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
