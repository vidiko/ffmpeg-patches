#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require exactly one Signed-off-by matching Git's configured identity.

Exit status: 0 for a valid message, 1 for a refused message, 2 when undecidable.
Git parses trailers for both message files and introduced commits, including merges.

A commit counts as introduced when it is not reachable from every considered
remote's tracking references and from the locally known advertised remote head.
When no remote is considered, only the known advertised head limits history.
Passing no considered-remote list checks against every configured remote;
a stale remote missing origin history can refuse until that remote is fetched
or removed.

In the path-on-stdin mode the reader accepts only the file Git names as its commit
message file or merge message file; any other path, a truncated prefix included,
is undecidable (message-path allow-list).

Under deadline_scope every Git call gets the time left on one total deadline
(SIGNOFF_DEADLINE seconds), at most GIT_TIMEOUT, and none starts once it has
passed; outside a scope each call has GIT_TIMEOUT alone.
"""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import os
import subprocess  # nosec B404 - fixed local Git argv, no shell, explicit timeouts.
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

MAX_COMMITS = 1000
MAX_TRAILERS = 1000
MAX_MESSAGE_CHARS = 1024 * 1024
MAX_STDIN_PATH_BYTES = 4096
MAX_REMOTES = 1000
GIT_TIMEOUT = 10
SIGNOFF_DEADLINE = 120
SEPARATOR_PIN = ("trailer.separators=:",)
IDENTITY_PIN = ("user.useConfigOnly=true",)
REASON_MISSING = "no Signed-off-by trailer"
REPAIR_MISSING = (
    "amend with the sign-off option (git commit --amend --signoff); "
    "an in-progress merge concludes with a commit given the sign-off option "
    "(git commit --signoff)"
)
REPAIR_EDIT = (
    "edit the message so exactly one Signed-off-by trailer with the expected identity remains"
)
# The active total deadline of one sign-off check: (clock, start, limit), else None.
_DEADLINE: contextvars.ContextVar[tuple[Callable[[], float], float, float] | None] = (
    contextvars.ContextVar("signoff_deadline", default=None)
)


def seconds_left(
    clock: Callable[[], float], start: float, limit: float, label: str, *, zero_ok: bool = False
) -> float:
    """Return the seconds left of a deadline, raising once it has passed (or is just used up)."""
    left = limit - (clock() - start)
    if left < 0 or (left == 0 and not zero_ok):
        raise ValueError(f"{label} deadline of {limit} s passed")
    return left


@contextlib.contextmanager
def deadline_scope(
    limit: float = SIGNOFF_DEADLINE, clock: Callable[[], float] = time.monotonic
) -> Iterator[None]:
    """Run the Git calls inside under one total deadline that starts now, on its own clock."""
    token = _DEADLINE.set((clock, clock(), limit))
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def call_timeout() -> float:
    """Return GIT_TIMEOUT, or the smaller time left on the active deadline, failing closed."""
    active = _DEADLINE.get()
    if active is None:
        return GIT_TIMEOUT
    clock, start, limit = active
    return min(GIT_TIMEOUT, seconds_left(clock, start, limit, "sign-off check"))


def git(
    args: list[str],
    text: str | None = None,
    cwd: str | None = None,
    *,
    missing_ok: bool = False,
    config: tuple[str, ...] = (),
) -> str:
    """Run local Git without replacement objects, with a deadline, failing closed on errors."""
    argv = ["git", "--no-replace-objects"]
    for entry in config:
        argv.extend(["-c", entry])
    argv.extend(args)
    timeout = call_timeout()
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed Git executable, argv data, no shell.
            argv,
            input=text if text is not None else "",
            cwd=cwd,
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"git {args[0]} failed: {type(exc).__name__}") from exc
    if result.returncode == 1 and missing_ok:
        return ""
    if result.returncode:
        raise ValueError(f"git {args[0]} exited {result.returncode}")
    return result.stdout


def identity(cwd: str | None = None) -> str:
    """Read the committer identity the sign-off option writes, never an autodetected one."""
    unset = "Git identity unset or empty (committer name and email required)"
    try:
        ident = git(["var", "GIT_COMMITTER_IDENT"], cwd=cwd, config=IDENTITY_PIN)
    except ValueError as exc:
        raise ValueError(f"{unset}: {exc}") from exc
    name_email = ident.removesuffix("\n").rsplit(" ", 2)[0]
    name, separator, rest = name_email.partition(" <")
    if not separator or not rest.endswith(">") or not name.strip() or not rest[:-1].strip():
        raise ValueError(unset)
    return name_email


def trailer_values(text: str) -> list[str]:
    """Extract Signed-off-by values from formatted trailer lines, empty values included."""
    lines = text.split("\n")
    if len(lines) > MAX_TRAILERS:
        raise ValueError(f"more than {MAX_TRAILERS} trailers")
    values = []
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key.casefold() == "signed-off-by":
            values.append(value.strip())
    return values


def message_values(message: str, cwd: str | None = None) -> list[str]:
    """Extract Signed-off-by values through Git's trailer parser, including unfolding."""
    command = ["interpret-trailers", "--parse", "--no-divider"]
    return trailer_values(git(command, message, cwd, config=SEPARATOR_PIN))


def repair_text(reason: str) -> str:
    """Map a judge reason, also behind a commit prefix, to the repair that fixes it."""
    return REPAIR_MISSING if REASON_MISSING in reason else REPAIR_EDIT


def judge(values: list[str], expected: str) -> str | None:
    """Accept exactly one trailer whose value equals the configured identity."""
    if not values:
        return REASON_MISSING
    if len(values) != 1:
        return "more than one Signed-off-by trailer"
    if values[0] != expected:
        return f"Signed-off-by has other identity; expected {expected}"
    return None


def configured_remotes(cwd: str | None = None) -> list[str]:
    """List configured remote names from one bounded git remote call."""
    names = git(["remote"], cwd=cwd).splitlines()
    if len(names) > MAX_REMOTES:
        raise ValueError(f"more than {MAX_REMOTES} remotes")
    return names


def read_message_path_stdin() -> str:
    """Read exactly one message-file path line from standard input with a byte cap."""
    data = sys.stdin.read(MAX_STDIN_PATH_BYTES + 1)
    if len(data) > MAX_STDIN_PATH_BYTES:
        raise ValueError(f"message path stdin exceeds {MAX_STDIN_PATH_BYTES} bytes")
    if not data.strip():
        raise ValueError("empty message path stdin")
    body = data.rstrip("\n")
    if "\n" in body:
        raise ValueError("message path stdin must be exactly one line")
    if not body:
        raise ValueError("empty message path stdin")
    return body


def is_git_message_file(path: str) -> bool:
    """Tell whether the path names Git's own commit message file or merge message file."""
    for name in ("COMMIT_EDITMSG", "MERGE_MSG"):
        known = git(["rev-parse", "--git-path", name]).removesuffix("\n")
        try:
            if os.path.samefile(path, known):
                return True
        except OSError:
            continue
    return False


def _rev_list_introduced(
    local_sha: str, remote_sha: str, not_remotes: list[str] | None, cwd: str | None
) -> list[str]:
    """List commits absent from the given remote histories and the known advertised head."""
    args = ["rev-list", f"--max-count={MAX_COMMITS + 1}", local_sha]
    exclusions: list[str] = []
    if not_remotes is not None:
        for remote in not_remotes:
            exclusions.append(f"--remotes={remote}")
    if set(remote_sha) != {"0"}:
        known = git(
            ["rev-parse", "--verify", "--quiet", f"{remote_sha}^{{commit}}"],
            cwd=cwd,
            missing_ok=True,
        )
        if known.strip():
            exclusions.append(remote_sha)
    if exclusions:
        args.extend(["--not", *exclusions])
    commits = git(args, cwd=cwd).splitlines()
    if len(commits) > MAX_COMMITS:
        raise ValueError(f"more than {MAX_COMMITS} introduced commits")
    return commits


def introduced_commits(
    local_sha: str,
    remote_sha: str,
    cwd: str | None = None,
    *,
    considered_remotes: list[str] | None = None,
) -> list[str]:
    """Union introduced commits absent from each considered remote's tracking history."""
    remotes = configured_remotes(cwd) if considered_remotes is None else considered_remotes
    if len(remotes) > MAX_REMOTES:
        raise ValueError(f"more than {MAX_REMOTES} remotes")
    if not remotes:
        return _rev_list_introduced(local_sha, remote_sha, None, cwd)
    union: list[str] = []
    seen: set[str] = set()
    for remote in remotes:
        introduced = _rev_list_introduced(local_sha, remote_sha, [remote], cwd)
        for commit in introduced:
            if commit in seen:
                continue
            seen.add(commit)
            union.append(commit)
            if len(union) > MAX_COMMITS:
                raise ValueError(f"more than {MAX_COMMITS} introduced commits")
    return union


def check_commits(
    local_sha: str,
    remote_sha: str,
    cwd: str | None = None,
    *,
    considered_remotes: list[str] | None = None,
) -> str | None:
    """Return the first invalid introduced commit and reason using one bounded log read."""
    commits = introduced_commits(local_sha, remote_sha, cwd, considered_remotes=considered_remotes)
    if not commits:
        return None
    expected = identity(cwd)
    raw = git(
        [
            "log",
            "--no-walk=unsorted",
            "--no-show-signature",
            "--no-patch",
            "--no-notes",
            "-z",
            "--format=%H%x00%(trailers:key=Signed-off-by,unfold,separator=%x0a)",
            "--stdin",
        ],
        "\n".join(commits) + "\n",
        cwd,
        config=SEPARATOR_PIN,
    )
    fields = raw.split("\0")
    if len(fields) != 2 * len(commits) + 1 or fields[-1] != "":
        raise ValueError("cannot parse Git commit trailer records")
    for index in range(MAX_COMMITS):
        if index == len(commits):
            break
        sha, value = fields[2 * index : 2 * index + 2]
        if sha != commits[index]:
            raise ValueError("Git returned unexpected commit order")
        reason = judge(trailer_values(value), expected)
        if reason:
            return f"commit {sha}: {reason}"
    return None


def read_message(args: argparse.Namespace) -> str:
    """Read the message file named by the option or, on stdin, by Git's own message path."""
    if args.message_path_stdin:
        path = read_message_path_stdin()
        if not is_git_message_file(path):
            raise ValueError(
                f"message path {path!r} is not Git's commit message file or merge message "
                "file (message-path allow-list)"
            )
    else:
        path = args.message_file
    with Path(path).open(encoding="utf-8") as handle:
        message = handle.read(MAX_MESSAGE_CHARS + 1)
    if len(message) > MAX_MESSAGE_CHARS:
        raise ValueError(f"message exceeds {MAX_MESSAGE_CHARS} characters")
    return message


def main(argv: list[str] | None = None) -> int:
    """Validate a commit-msg file and report a corrective command on refusal."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--message-file", type=Path)
    group.add_argument("--message-path-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        reason = judge(message_values(read_message(args)), identity())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"signoff: cannot decide: {exc}; refusing (fail closed)", file=sys.stderr)
        return 2
    if reason:
        print(f"signoff: refusing: {reason}; {repair_text(reason)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
