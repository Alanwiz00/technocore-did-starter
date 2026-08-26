#!/usr/bin/env python3
"""Run reactive chat and scheduled room rotation with one unlocked identity."""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
from pathlib import Path
from typing import Callable

import technocore_agent as agent


ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


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


def run_worker(
    name: str, operation: Callable[[], int], results: queue.Queue[tuple[str, BaseException | None]]
) -> None:
    try:
        code = operation()
        if code != 0:
            raise RuntimeError(f"worker returned exit code {code}")
    except BaseException as error:
        results.put((name, error))
    else:
        results.put((name, None))


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
        mode = "LIVE signed posting" if send else "DRY RUN (nothing will be published)"
        print(f"starting Technocore automation: {mode}", file=sys.stderr, flush=True)
        results: queue.Queue[tuple[str, BaseException | None]] = queue.Queue()
        workers = [
            threading.Thread(
                name="auto-chat",
                target=run_worker,
                args=("auto-chat", lambda: agent.run_auto_chat(private_key, chat_args), results),
                daemon=True,
            ),
            threading.Thread(
                name="auto-post",
                target=run_worker,
                args=("auto-post", lambda: agent.run_auto_post(private_key, post_args), results),
                daemon=True,
            ),
        ]
        for worker in workers:
            worker.start()
        name, error = results.get()
        if error is None:
            print(f"{name} stopped", file=sys.stderr)
            return 0
        raise RuntimeError(f"{name} failed: {error}") from error
    except (agent.IdentityError, agent.LocalFileError, agent.NetworkError,
            agent.ProtocolError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
