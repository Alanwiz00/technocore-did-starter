#!/usr/bin/env python3
"""Read-only monitor for official FLOP / Technocore signals.

Polls a fixed allowlist of official sources (the flop-labs GitHub org, the live
technocore.chat protocol documents, flop.finance), diffs each against its last
snapshot, and reports what changed, flagging anything that mentions a faucet,
testnet, airdrop, snapshot or claim. It never writes to any of those services
and never touches a key, seed or passphrase.

    python airdrop_watch.py --once           # one pass (first run = baseline)
    python airdrop_watch.py --interval 1800  # keep watching

X/Twitter is not readable without an account, so @flop_labs itself is NOT
covered here: turn on notifications for it separately.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

import technocore_agent as agent

DEFAULT_STATE_PATH = Path(".technocore-watch.json")
DEFAULT_EVENTS_PATH = Path(".technocore-watch-events.jsonl")
MIN_INTERVAL_SECONDS = 300.0
FETCH_TIMEOUT_SECONDS = 25.0
MAX_FETCH_BYTES = 3 * 1024 * 1024
MAX_SHOWN_LINES = 10
FAILURE_WARNING_AFTER = 3
# What matters for the airdrop: anything new that talks about the faucet, the
# testnet, an eligibility snapshot or a claim path.
PRIORITY_PATTERN = re.compile(
    r"faucet|testnet|airdrop|snapshot|eligib|claim|genesis|mainnet|\bTGE\b|allocation",
    re.IGNORECASE,
)

GITHUB_API = "https://api.github.com"
TECHNOCORE = "https://technocore.chat"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    kind: str  # repos | releases | commits | text | html


SOURCES: tuple[Source, ...] = (
    Source("github flop-labs repos", f"{GITHUB_API}/orgs/flop-labs/repos?sort=pushed&per_page=50", "repos"),
    Source("technocore-chat releases", f"{GITHUB_API}/repos/flop-labs/technocore-chat/releases?per_page=5", "releases"),
    Source("yellowpaper commits", f"{GITHUB_API}/repos/flop-labs/yellowpaper/commits?per_page=5", "commits"),
    Source("tclk commits", f"{GITHUB_API}/repos/flop-labs/tclk/commits?per_page=5", "commits"),
    Source("sonnet-challenge commits", f"{GITHUB_API}/repos/flop-labs/technocore-sonnet-challenge/commits?per_page=5", "commits"),
    Source("technocore llms.txt", f"{TECHNOCORE}/llms.txt", "text"),
    Source("technocore skill.md", f"{TECHNOCORE}/skill.md", "text"),
    Source("technocore patterns.md", f"{TECHNOCORE}/patterns.md", "text"),
    Source("technocore interop.md", f"{TECHNOCORE}/interop.md", "text"),
    Source("technocore auth.md", f"{TECHNOCORE}/auth.md", "text"),
    Source("technocore agent.json", f"{TECHNOCORE}/.well-known/agent.json", "text"),
    Source("technocore config", f"{TECHNOCORE}/config", "text"),
    Source("flop.finance", "https://flop.finance/", "html"),
    Source("flop.finance teaser", "https://flop.finance/teaser/", "html"),
)


class _VisibleText(HTMLParser):
    """Collect the text a reader would see, dropping scripts and styles."""

    def __init__(self) -> None:
        super().__init__()
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def fetch_text(url: str, *, token: str | None = None) -> str:
    """GET one allowlisted https URL with a size cap; the token only goes to GitHub."""
    if not url.startswith("https://"):
        raise ValueError("only https sources are watched")
    headers = {
        "User-Agent": f"technocore-did-starter/{agent.APP_VERSION} (+read-only watcher)",
        "Accept": "application/json, text/plain;q=0.9, text/html;q=0.8",
    }
    if token and url.startswith(GITHUB_API + "/"):
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(url, headers=headers), timeout=FETCH_TIMEOUT_SECONDS) as response:
        raw = response.read(MAX_FETCH_BYTES + 1)
    if len(raw) > MAX_FETCH_BYTES:
        raise ValueError("response exceeded the size limit")
    return raw.decode("utf-8", errors="replace")


def _json_list(body: str) -> list[Any]:
    data = json.loads(body)
    if not isinstance(data, list):  # GitHub errors and rate limits are objects
        raise ValueError(str(data.get("message", "unexpected response"))[:120] if isinstance(data, dict) else "unexpected response")
    return data


def normalise(kind: str, body: str) -> list[str]:
    """Reduce a response to stable, comparable lines."""
    if kind == "repos":
        lines = sorted(f"repo {item['name']}" for item in _json_list(body))
    elif kind == "releases":
        lines = []
        for item in _json_list(body):
            lines.append(
                f"release {item.get('tag_name')} {str(item.get('published_at', ''))[:10]} "
                f"{item.get('name') or ''}".strip()
            )
            lines.extend(
                f"  {text.strip()}" for text in str(item.get("body") or "").splitlines() if text.strip()
            )
    elif kind == "commits":
        lines = [
            f"{item['sha'][:7]} {str(item['commit']['author']['date'])[:10]} "
            f"{str(item['commit']['message']).splitlines()[0] if item['commit']['message'] else ''}"
            for item in _json_list(body)
        ]
    elif kind == "html":
        parser = _VisibleText()
        parser.feed(body)
        text = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()
        lines = [chunk for chunk in re.split(r"(?<=[.!?])\s+", text) if chunk]
    else:
        lines = [line.rstrip() for line in body.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty response")
    return lines


def diff_lines(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    """(added, removed) lines between two snapshots."""
    added: list[str] = []
    removed: list[str] = []
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            removed.extend(old[i1:i2])
        if tag in {"replace", "insert"}:
            added.extend(new[j1:j2])
    return added, removed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def check_source(
    source: Source, state: dict[str, Any], fetch: Callable[[str], str]
) -> dict[str, Any] | None:
    """Fetch one source; return a change event, or None (baseline/unchanged/failed)."""
    entry = state.setdefault(source.name, {})
    try:
        lines = normalise(source.kind, fetch(source.url))
    except (URLError, OSError, ValueError, KeyError, TypeError, IndexError) as error:
        entry["fails"] = int(entry.get("fails", 0)) + 1
        if entry["fails"] == FAILURE_WARNING_AFTER:
            print(
                f"warning: watch source '{source.name}' has failed "
                f"{FAILURE_WARNING_AFTER} times in a row: {error}",
                file=sys.stderr,
                flush=True,
            )
        return None
    entry["fails"] = 0
    entry["checked_at"] = _now()
    previous = entry.get("lines")
    entry["lines"] = lines
    if previous is None or previous == lines:
        return None
    added, removed = diff_lines(previous, lines)
    keywords = sorted({m.group(0).lower() for line in added for m in PRIORITY_PATTERN.finditer(line)})
    return {
        "ts": _now(),
        "source": source.name,
        "url": source.url,
        "priority": bool(keywords),
        "keywords": keywords,
        "added_total": len(added),
        "removed_total": len(removed),
        "added": [line[:300] for line in added[:MAX_SHOWN_LINES]],
        "removed": [line[:300] for line in removed[:MAX_SHOWN_LINES]],
    }


def load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}  # a corrupt snapshot just means a fresh baseline
    return data if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    target = Path(path)
    temporary = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, separators=(",", ":"))
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def notify_desktop(title: str, body: str, *, urgent: bool) -> None:
    """Best-effort desktop popup; silently skipped where notify-send is absent."""
    binary = shutil.which("notify-send")
    if binary is None:
        return
    try:
        subprocess.run(
            [binary, "-u", "critical" if urgent else "normal", "-a", "technocore-watch", title, body],
            timeout=5,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def report(event: dict[str, Any], events_path: Path, *, notify: bool) -> None:
    label = "PRIORITY" if event["priority"] else "changed"
    keywords = f" [{', '.join(event['keywords'])}]" if event["keywords"] else ""
    print(
        f"[watch] {label}: {event['source']} "
        f"(+{event['added_total']}/-{event['removed_total']}){keywords}  {event['url']}",
        file=sys.stderr,
        flush=True,
    )
    for line in event["added"][:5]:
        print(f"    + {line[:180]}", file=sys.stderr, flush=True)
    with open(events_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    if notify:
        first = event["added"][0][:140] if event["added"] else event["url"]
        notify_desktop(f"FLOP watch: {event['source']}", first, urgent=event["priority"])


def run_once(
    state_path: Path = DEFAULT_STATE_PATH,
    events_path: Path = DEFAULT_EVENTS_PATH,
    *,
    fetch: Callable[[str], str] = fetch_text,
    notify: bool = False,
    sources: tuple[Source, ...] = SOURCES,
) -> list[dict[str, Any]]:
    """One full pass over every source; returns the change events found."""
    fresh = not Path(state_path).exists()
    state = load_state(state_path)
    events = [event for source in sources if (event := check_source(source, state, fetch))]
    save_state(state_path, state)
    if fresh:
        recorded = sum(1 for entry in state.values() if entry.get("lines"))
        print(
            f"[watch] baseline recorded for {recorded}/{len(sources)} sources; "
            f"changes will be reported from the next pass",
            file=sys.stderr,
            flush=True,
        )
    for event in events:
        report(event, Path(events_path), notify=notify)
    return events


def run_watch_loop(
    interval: float,
    state_path: Path = DEFAULT_STATE_PATH,
    events_path: Path = DEFAULT_EVENTS_PATH,
) -> int:
    """Watch forever, one pass per ``interval`` seconds."""
    if interval < MIN_INTERVAL_SECONDS:
        raise agent.ProtocolError(
            f"watch interval must be at least {MIN_INTERVAL_SECONDS:.0f} seconds"
        )
    token = os.environ.get("TECHNOCORE_WATCH_GITHUB_TOKEN", "").strip() or None
    notify = agent.environment_bool(os.environ.get("TECHNOCORE_WATCH_NOTIFY", "true"))

    def fetch(url: str) -> str:
        return fetch_text(url, token=token)

    while True:
        started = time.monotonic()
        run_once(state_path, events_path, fetch=fetch, notify=notify)
        time.sleep(max(1.0, interval - (time.monotonic() - started)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    parser.add_argument("--interval", type=float, default=1800.0, help="seconds between passes")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    parser.add_argument("--no-notify", action="store_true", help="skip desktop notifications")
    args = parser.parse_args(argv)
    token = os.environ.get("TECHNOCORE_WATCH_GITHUB_TOKEN", "").strip() or None
    try:
        if args.once:
            events = run_once(
                args.state,
                args.events,
                fetch=lambda url: fetch_text(url, token=token),
                notify=not args.no_notify,
            )
            print(f"[watch] {len(events)} change(s) since the last pass", file=sys.stderr)
            return 0
        return run_watch_loop(args.interval, args.state, args.events)
    except (agent.ProtocolError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
