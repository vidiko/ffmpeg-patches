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
"""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 - fixed local Git argv, no shell, explicit timeouts.
import sys
from pathlib import Path

MAX_COMMITS = 1000
MAX_TRAILERS = 1000
MAX_MESSAGE_CHARS = 1024 * 1024
MAX_STDIN_PATH_BYTES = 4096
MAX_REMOTES = 1000
GIT_TIMEOUT = 10
FIX = (
    "amend with the sign-off option (git commit --amend --signoff), "
    "or merge with the sign-off option (git merge --signoff)"
)


def git(
    args: list[str], text: str | None = None, cwd: str | None = None, *, missing_ok: bool = False
) -> str:
    """Run local Git with a fixed executable and deadline, failing closed on errors."""
    try:
        result = subprocess.run(  # nosec B603 B607 - fixed Git executable, argv data, no shell.
            ["git", *args],
            input=text if text is not None else "",
            cwd=cwd,
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=GIT_TIMEOUT,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"git {args[0]} failed: {type(exc).__name__}") from exc
    if result.returncode == 1 and missing_ok:
        return ""
    if result.returncode:
        raise ValueError(f"git {args[0]} exited {result.returncode}")
    return result.stdout


def identity(cwd: str | None = None) -> str:
    """Read the exact sign-off identity from the effective Git configuration."""
    name = git(["config", "user.name"], cwd=cwd, missing_ok=True).removesuffix("\n")
    email = git(["config", "user.email"], cwd=cwd, missing_ok=True).removesuffix("\n")
    if not name.strip() or not email.strip():
        raise ValueError("Git identity unset or empty (user.name and user.email required)")
    return f"{name} <{email}>"


def message_values(message: str, cwd: str | None = None) -> list[str]:
    """Extract Signed-off-by values through Git's trailer parser, including unfolding."""
    parsed = git(["interpret-trailers", "--parse"], message, cwd).splitlines()
    if len(parsed) > MAX_TRAILERS:
        raise ValueError(f"more than {MAX_TRAILERS} trailers")
    values = []
    for index in range(MAX_TRAILERS):
        if index == len(parsed):
            break
        key, separator, value = parsed[index].partition(":")
        if separator and key.casefold() == "signed-off-by":
            values.append(value.strip())
    return values


def judge(values: list[str], expected: str) -> str | None:
    """Accept exactly one trailer whose value equals the configured identity."""
    if not values:
        return "no Signed-off-by trailer"
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
            "--format=%H%x00%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x0a)",
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
        sha, value = fields[2 * index : 2 * index + 2]
        if sha != commits[index]:
            raise ValueError("Git returned unexpected commit order")
        reason = judge(value.split("\n") if value else [], expected)
        if reason:
            return f"commit {sha}: {reason}"
    return None


def main(argv: list[str] | None = None) -> int:
    """Validate a commit-msg file and report a corrective command on refusal."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--message-file", type=Path)
    group.add_argument("--message-path-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        path = Path(read_message_path_stdin() if args.message_path_stdin else args.message_file)
        with path.open(encoding="utf-8") as handle:
            message = handle.read(MAX_MESSAGE_CHARS + 1)
        if len(message) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message exceeds {MAX_MESSAGE_CHARS} characters")
        reason = judge(message_values(message), identity())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"signoff: cannot decide: {exc}; refusing (fail closed)", file=sys.stderr)
        return 2
    if reason:
        print(f"signoff: refusing: {reason}; {FIX}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
