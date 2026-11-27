#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Require exactly one literal Signed-off-by matching Git's configured identity.

Exit status: 0 for a valid message, 1 for a refused message, 2 when undecidable.
Git parses trailers for both message files and introduced commits (merges included)
through interpret-trailers --parse --no-divider with configuration isolated from
system, global, repository and environment sources so trailer.<token>.key aliases
never rewrite keys. Introduced commit messages are read in one UTF-8 git log call
and judged by the same isolated parser.

Tracking references of a configured remote R limit introduced commits only when
every configured remote uses its default fetch refspec (+refs/heads/*:refs/remotes/<name>/*),
R is not nested under another configured remote's name, and R's push destination
equals its fetch URL (REMOTE_URL in named mode, or a single push URL equal to its
fetch URL in configuration mode); otherwise only the locally known advertised head
limits history. When R's tracking history counts, refs of configured remotes nested
under R's name are excluded so only refs owned by R count. Passing no considered
remote list unions introduced commits across every configured remote, so any remote
that fails the destination proof or lacks origin history widens the union.

Refusal repair text follows the refusal site (commit-msg vs pre-push) and whether a
rejected pushed commit equals the checked-out HEAD.

In the path-on-stdin mode the reader accepts only the file Git names as its commit
message file or merge message file; any other path, a truncated prefix included,
is undecidable (message-path allow-list).

Under deadline_scope every call gets the time left on one total deadline
(SIGNOFF_DEADLINE seconds), capped by its per-call timeout, and nested scopes keep
the outer clock, start and limit; outside a scope each Git call has GIT_TIMEOUT alone.
"""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import os
import subprocess  # nosec B404 - fixed local Git argv, no shell, explicit timeouts.
import sys
import time
from collections.abc import Callable, Iterator, Sequence
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
REPAIR_COMMIT_MSG_MISSING = (
    "retry the refused git commit command with the sign-off option (git commit --signoff); "
    "an in-progress merge also concludes with git commit --signoff"
)
REPAIR_COMMIT_MSG_EDIT = (
    "edit the message so exactly one Signed-off-by trailer with the expected identity remains, "
    "then retry the refused git commit command"
)
REPAIR_MISSING = "amend with the sign-off option (git commit --amend --signoff)"
REPAIR_EDIT = (
    "amend the message (git commit --amend) so exactly one Signed-off-by trailer with the "
    "expected identity remains"
)
# The active total deadline of one sign-off check: (clock, start, limit), else None.
_DEADLINE: contextvars.ContextVar[tuple[Callable[[], float], float, float] | None] = (
    contextvars.ContextVar("signoff_deadline", default=None)
)
_EXCLUDED_REMOTES: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "signoff_excluded_remotes", default=()
)


@contextlib.contextmanager
def excluded_remotes_scope(excluded: tuple[str, ...]) -> Iterator[None]:
    """Bind nested configured remote exclusions across one pre-push sign-off check."""
    token = _EXCLUDED_REMOTES.set(excluded)
    try:
        yield
    finally:
        _EXCLUDED_REMOTES.reset(token)


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
    """Run calls inside under one total deadline, keeping any outer active deadline."""
    if _DEADLINE.get() is not None:
        yield
        return
    token = _DEADLINE.set((clock, clock(), limit))
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def call_timeout(cap: float = GIT_TIMEOUT) -> float:
    """Return cap, or the smaller time left on the active deadline, failing closed."""
    active = _DEADLINE.get()
    if active is None:
        return cap
    clock, start, limit = active
    return min(cap, seconds_left(clock, start, limit, "sign-off check"))


def _isolated_git_env() -> dict[str, str]:
    """Build an environment that hides system, global, repository and env Git config."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_DIR=os.path.join(os.devnull, "git"),
    )
    return env


def _run_git(
    args: list[str],
    text: str | None = None,
    cwd: str | None = None,
    *,
    missing_ok: bool = False,
    env: dict[str, str] | None = None,
) -> str:
    """Execute git --no-replace-objects with call_timeout and strict UTF-8 decoding."""
    subcommand = args[2] if len(args) > 2 and args[0] == "-c" else args[0]
    timeout = call_timeout()
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed Git executable, argv data, no shell.
            ["git", "--no-replace-objects", *args],
            input=text if text is not None else "",
            cwd=cwd,
            env=env,
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"git {subcommand} failed: {type(exc).__name__}") from exc
    if result.returncode == 1 and missing_ok:
        return ""
    if result.returncode:
        raise ValueError(f"git {subcommand} exited {result.returncode}")
    return result.stdout


def git(
    args: list[str],
    text: str | None = None,
    cwd: str | None = None,
    *,
    missing_ok: bool = False,
    config: tuple[str, ...] = (),
) -> str:
    """Run local Git without replacement objects, with a deadline, failing closed on errors."""
    configured = [item for entry in config for item in ("-c", entry)]
    configured.extend(args)
    return _run_git(configured, text, cwd, missing_ok=missing_ok)


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
    """Extract literal Signed-off-by values through Git's config-isolated trailer parser."""
    command = ["-c", *SEPARATOR_PIN, "interpret-trailers", "--parse", "--no-divider"]
    return trailer_values(_run_git(command, message, cwd, env=_isolated_git_env()))


def checked_out_head(cwd: str | None = None) -> str | None:
    """Return the commit SHA of HEAD, or None when HEAD is unborn or unreadable."""
    call_timeout()
    try:
        sha = git(
            ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
            cwd=cwd,
            missing_ok=True,
        ).strip()
    except ValueError:
        call_timeout()
        return None
    return sha or None


def _rejected_commit_sha(reason: str) -> str:
    """Extract the commit SHA prefix added by check_commits, if present."""
    prefix, separator, _ = reason.partition(": ")
    if separator and prefix.startswith("commit "):
        return prefix.removeprefix("commit ")
    return ""


def repair_text(
    reason: str,
    *,
    site: str = "pre-push",
    branch: str | None = None,
    head_sha: str | None = None,
) -> str:
    """Choose the corrective instruction by refusal site and rejected commit position."""
    missing = REASON_MISSING in reason
    if site == "commit-msg":
        return REPAIR_COMMIT_MSG_MISSING if missing else REPAIR_COMMIT_MSG_EDIT
    sha = _rejected_commit_sha(reason)
    if branch is not None and (not sha or sha != head_sha):
        return (
            f"commit {sha} is not the checked-out HEAD, so amend does not reach it; "
            f"rewrite it in the history of branch {branch} (for example an interactive "
            "rebase from its parent that stops at it), give it exactly one Signed-off-by "
            "trailer with the expected identity, then push again"
        )
    return REPAIR_MISSING if missing else REPAIR_EDIT


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
    raw = git(["remote"], cwd=cwd)
    names = raw.removesuffix("\n").split("\n") if raw else []
    if len(names) > MAX_REMOTES:
        raise ValueError(f"more than {MAX_REMOTES} remotes")
    return names


def remote_fetch_url(name: str, cwd: str | None = None) -> str:
    """Return the expanded fetch URL Git reports for one configured remote."""
    return git(["remote", "get-url", name], cwd=cwd).removesuffix("\n")


def remote_push_urls(name: str, cwd: str | None = None) -> list[str]:
    """Return bounded expanded push URLs Git reports for one configured remote."""
    raw = git(["remote", "get-url", "--push", "--all", name], cwd=cwd)
    urls = raw.removesuffix("\n").split("\n") if raw else []
    if len(urls) > MAX_REMOTES:
        raise ValueError(f"more than {MAX_REMOTES} remote push URLs")
    return urls


def has_default_fetch_refspecs(names: Sequence[str], cwd: str | None = None) -> bool:
    """Tell whether every configured remote fetches only into its own tracking namespace."""
    for name in names:
        expected = f"+refs/heads/*:refs/remotes/{name}/*\n"
        actual = git(["config", "--get-all", f"remote.{name}.fetch"], cwd=cwd, missing_ok=True)
        if actual != expected:
            return False
    return True


def _is_nested_remote(name: str, names: Sequence[str]) -> bool:
    """Tell whether name sits under another configured remote's slash-delimited prefix."""
    return any(name.startswith(f"{other}/") for other in names)


def _nested_remotes(name: str, names: Sequence[str]) -> tuple[str, ...]:
    """Return configured remotes whose tracking namespaces sit under name."""
    return tuple(other for other in names if other.startswith(f"{name}/"))


def _all_remotes_match_push_url(names: Sequence[str], cwd: str | None) -> bool:
    """Tell whether every configured remote is top-level with push URL equal to fetch URL."""
    for name in names:
        if _is_nested_remote(name, names):
            return False
        if remote_push_urls(name, cwd) != [remote_fetch_url(name, cwd)]:
            return False
    return True


def attributable_remotes(
    cwd: str | None = None,
    destination: tuple[str, str] | None = None,
) -> tuple[list[str], tuple[str, ...]]:
    """Prove which configured remotes limit history and list nested remotes to exclude."""
    names = configured_remotes(cwd)
    if not names:
        return [], ()
    if destination is not None:
        remote_name, remote_url = destination
        if (
            remote_name not in names
            or _is_nested_remote(remote_name, names)
            or not has_default_fetch_refspecs(names, cwd)
            or remote_fetch_url(remote_name, cwd) != remote_url
        ):
            return [], ()
        return [remote_name], _nested_remotes(remote_name, names)
    # In --from-config mode the introduced set stays the union over every configured remote.
    # Any remote that fails the destination proof contributes the advertised-head-only set,
    # and because the advertised-head-only set contains every per-remote set, one unproved
    # remote makes the union equal to the advertised-head-only set.
    if not has_default_fetch_refspecs(names, cwd) or not _all_remotes_match_push_url(names, cwd):
        return [], ()
    nested = tuple(child for name in names for child in _nested_remotes(name, names))
    return names, nested


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
    local_sha: str,
    remote_sha: str,
    not_remotes: list[str] | None,
    cwd: str | None,
    excluded_remotes: Sequence[str] = (),
) -> list[str]:
    """List commits absent from the owned remote histories and the known advertised head."""
    args = ["rev-list", f"--max-count={MAX_COMMITS + 1}", local_sha]
    exclusions: list[str] = []
    if not_remotes is not None:
        for remote in not_remotes:
            for nested in excluded_remotes:
                if nested.startswith(f"{remote}/"):
                    exclusions.append(f"--exclude={nested}/*")
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
    excluded_remotes: Sequence[str] = (),
) -> list[str]:
    """Union introduced commits absent from each attributable remote's owned tracking refs."""
    if considered_remotes is None:
        remotes, nested = attributable_remotes(cwd)
    else:
        remotes = considered_remotes
        active_excluded = _EXCLUDED_REMOTES.get()
        if len(remotes) > MAX_REMOTES or len(excluded_remotes) > MAX_REMOTES:
            raise ValueError(f"more than {MAX_REMOTES} remotes")
        nested = tuple(
            sorted(
                {
                    *excluded_remotes,
                    *active_excluded,
                    *(r for name in remotes for r in _nested_remotes(name, remotes)),
                }
            )
        )
    if len(remotes) > MAX_REMOTES or len(nested) > MAX_REMOTES:
        raise ValueError(f"more than {MAX_REMOTES} remotes")
    if not remotes:
        return _rev_list_introduced(local_sha, remote_sha, None, cwd)
    union: list[str] = []
    seen: set[str] = set()
    for remote in remotes:
        introduced = _rev_list_introduced(local_sha, remote_sha, [remote], cwd, nested)
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
    excluded_remotes: Sequence[str] = (),
) -> str | None:
    """Return the first invalid introduced commit and reason using one bounded log read."""
    commits = introduced_commits(
        local_sha,
        remote_sha,
        cwd,
        considered_remotes=considered_remotes,
        excluded_remotes=excluded_remotes,
    )
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
            "--encoding=UTF-8",
            "-z",
            "--format=%H%x00%B",
            "--stdin",
        ],
        "\n".join(commits) + "\n",
        cwd,
    )
    fields = raw.split("\0")
    if len(fields) != 2 * len(commits) + 1 or fields[-1] != "":
        raise ValueError("cannot parse Git commit trailer records")
    for index in range(MAX_COMMITS):
        if index == len(commits):
            break
        sha, message = fields[2 * index : 2 * index + 2]
        if sha != commits[index]:
            raise ValueError("Git returned unexpected commit order")
        if len(message) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message exceeds {MAX_MESSAGE_CHARS} characters")
        reason = judge(message_values(message, cwd), expected)
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
        print(
            f"signoff: refusing: {reason}; {repair_text(reason, site='commit-msg')}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
