# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Exercise Git's trailer parser and bounded introduced-commit sign-off checks."""

from __future__ import annotations

import os
import subprocess  # nosec B404 - fixed local Git/Python argv in isolated fixture repositories.
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from scripts import signoff
from tests.helpers import capture_main

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "Signoff Fixture <signoff@example.invalid>"
TRAILER = f"Signed-off-by: {IDENTITY}"
ZERO = "0" * 40


class GitFixture(unittest.TestCase):
    """Provide disposable repositories with fixture-owned identity and isolated configuration."""

    def setUp(self) -> None:
        """Strip every inherited Git variable before configuring a temporary repository."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        isolation = unittest.mock.patch.dict(os.environ, self.env, clear=True)
        isolation.start()
        self.addCleanup(isolation.stop)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Signoff Fixture")
        self.git("config", "user.email", "signoff@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", str(self.root / "empty-hooks"))

    def git(self, *args: str, text: str = "") -> str:
        """Run bounded local Git commands only against the isolated fixture."""
        return subprocess.run(  # nosec B603 B607 - local fixture argv, no shell, timeout set.
            ["git", *args],
            input=text,
            cwd=self.root,
            env=self.env,
            capture_output=True,
            encoding="utf-8",
            check=True,
            timeout=30,
        ).stdout.strip()

    def commit(self, subject: str = "fixture", signed: bool = True) -> str:
        """Create an empty commit with an optional sign-off using the fixture identity."""
        self.git("commit", "--allow-empty", "-qm", subject, *(["--signoff"] if signed else []))
        return self.git("rev-parse", "HEAD")

    def merge(self, signed: bool) -> str:
        """Plant a two-parent merge with signed parents and an optional merge sign-off."""
        self.commit("base")
        self.git("checkout", "-qb", "topic")
        self.commit("topic")
        self.git("checkout", "-q", "main")
        self.commit("main")
        self.git(
            "merge", "--no-ff", "-m", "merge fixture", "topic", *(["--signoff"] if signed else [])
        )
        return self.git("rev-parse", "HEAD")


class MessageTest(GitFixture):
    """Compare real Git trailer parsing with the configured fixture identity."""

    def test_one_correct_trailer_and_comments(self) -> None:
        """Accept an ordinary trailer with trailing commit-message comment lines."""
        for message in (f"Subject\n\n{TRAILER}\n", f"Subject\n\n{TRAILER}\n# comment\n"):
            with self.subTest(message=message):
                values = signoff.message_values(message, str(self.root))
                self.assertEqual(values, [IDENTITY])
                self.assertIsNone(signoff.judge(values, signoff.identity(str(self.root))))

    def test_invalid_message_cases(self) -> None:
        """Refuse missing, duplicate, foreign, body-only and comment-only sign-offs."""
        cases = (
            ("", "no Signed-off-by"),
            ("Subject\n", "no Signed-off-by"),
            (f"Subject\n\n{TRAILER}\n{TRAILER}\n", "more than one"),
            ("Subject\n\nSigned-off-by: Other <other@example.invalid>\n", "other identity"),
            (f"Subject\n\n{TRAILER}\n\nA non-trailer paragraph.\n", "no Signed-off-by"),
            (f"Subject\n\n# {TRAILER}\n", "no Signed-off-by"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                reason = signoff.judge(signoff.message_values(message, str(self.root)), IDENTITY)
                self.assertIsNotNone(reason)
                self.assertIn(expected, reason)

    def test_folded_value(self) -> None:
        """Unfold a continuation line before comparing the complete identity."""
        message = "Subject\n\nSigned-off-by: Signoff Fixture\n <signoff@example.invalid>\n"
        self.assertEqual(signoff.message_values(message, str(self.root)), [IDENTITY])

    def test_identity_unset_or_empty(self) -> None:
        """Refuse to decide without both configured identity fields."""
        for key in ("user.name", "user.email"):
            with self.subTest(key=key):
                self.git("config", key, "")
                with self.assertRaisesRegex(ValueError, "identity unset or empty"):
                    signoff.identity(str(self.root))
                self.git("config", "--unset", key)
                with self.assertRaisesRegex(ValueError, "identity unset or empty"):
                    signoff.identity(str(self.root))
                self.git("config", "user.name", "Signoff Fixture")
                self.git("config", "user.email", "signoff@example.invalid")

    def test_cli_pass_refusal_and_unreadable_file(self) -> None:
        """Exercise the actual script with valid, missing, empty and absent message files."""
        message = self.root / "message with spaces.txt"
        for text, expected in ((f"Subject\n\n{TRAILER}\n", 0), ("merge fixture\n", 1), ("", 1)):
            with self.subTest(expected=expected, text=text):
                message.write_text(text, encoding="utf-8")
                result = self.cli(message)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertIn("no Signed-off-by", result.stderr)
                    self.assertIn(
                        "retry the refused git commit command with the sign-off option",
                        result.stderr,
                    )
                    self.assertIn("in-progress merge", result.stderr)
                    self.assertNotIn("merge with the sign-off option", result.stderr)
                    self.assertNotIn("git merge", result.stderr)
        message.unlink()
        self.assertEqual(self.cli(message).returncode, 2)

    def cli(self, message: Path) -> subprocess.CompletedProcess[str]:
        """Invoke the script from a fixture repository with its own Git configuration."""
        return subprocess.run(  # nosec B603 - fixed Python argv, fixture path, no shell.
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts/signoff.py"),
                "--message-file",
                str(message),
            ],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=30,
        )

    def test_cli_identity_missing(self) -> None:
        """Return cannot-decide for a valid message when the Git identity is missing."""
        message = self.root / "message"
        message.write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
        self.git("config", "--unset", "user.name")
        result = self.cli(message)
        self.assertEqual(result.returncode, 2)
        self.assertIn("identity unset or empty", result.stderr)

    def test_git_missing_timeout_and_failure(self) -> None:
        """Convert missing Git, timeout and failed parser calls to cannot-decide."""
        message = self.root / "message"
        message.write_text("fixture\n", encoding="utf-8")
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("git", 10), UnicodeError()):
            with (
                self.subTest(error=type(error).__name__),
                unittest.mock.patch.object(signoff.subprocess, "run", side_effect=error),
            ):
                status, _, err = capture_main(signoff.main, "--message-file", str(message))
                self.assertEqual(status, 2)
                self.assertIn("cannot decide", err)
        with unittest.mock.patch.object(signoff.subprocess, "run") as run:
            run.return_value.returncode = 128
            with self.assertRaisesRegex(ValueError, "exited 128"):
                signoff.message_values("fixture")

    def test_repair_text_per_reason(self) -> None:
        """Give each refusal its own repair text on the message-file entrypoint."""
        message = self.root / "message"
        other = "Signed-off-by: Other <other@example.invalid>"
        cases = (
            (
                "Subject\n",
                "retry the refused git commit command with the sign-off option",
                "exactly one",
            ),
            (f"Subject\n\n{TRAILER}\n{TRAILER}\n", "exactly one", "amend with"),
            (f"Subject\n\n{other}\n", "exactly one", "amend with"),
        )
        for text, present, absent in cases:
            with self.subTest(text=text):
                message.write_text(text, encoding="utf-8")
                result = self.cli(message)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(present, result.stderr)
                self.assertNotIn(absent, result.stderr)
                self.assertNotIn("git merge", result.stderr)

    def test_repair_text_maps_reasons(self) -> None:
        """Map each judge reason, also behind a commit prefix, to one repair text."""
        missing = signoff.judge([], IDENTITY)
        many = signoff.judge([IDENTITY, IDENTITY], IDENTITY)
        other = signoff.judge(["Other <other@example.invalid>"], IDENTITY)
        self.assertIn("amend with the sign-off option", signoff.repair_text(missing))
        self.assertIn("amend with the sign-off option", signoff.repair_text(f"commit x: {missing}"))
        for reason in (many, other, f"commit x: {many}"):
            with self.subTest(reason=reason):
                self.assertIn("exactly one Signed-off-by", signoff.repair_text(reason))

    def test_committer_identity_is_the_expected_identity(self) -> None:
        """Accept the committer-email trailer and refuse the user-email trailer."""
        self.git("config", "committer.email", "committer@example.invalid")
        message = self.root / "message"
        committer = "Signoff Fixture <committer@example.invalid>"
        for trailer, expected in ((committer, 0), (IDENTITY, 1)):
            with self.subTest(trailer=trailer):
                message.write_text(f"Subject\n\nSigned-off-by: {trailer}\n", encoding="utf-8")
                self.assertEqual(self.cli(message).returncode, expected)
        self.assertEqual(signoff.identity(str(self.root)), committer)

    def test_environment_committer_wins_and_email_alone_is_unset(self) -> None:
        """Follow GIT_COMMITTER_EMAIL and refuse the EMAIL variable without configuration."""
        with unittest.mock.patch.dict(os.environ, {"GIT_COMMITTER_EMAIL": "env@example.invalid"}):
            self.assertEqual(
                signoff.identity(str(self.root)), "Signoff Fixture <env@example.invalid>"
            )
        self.git("config", "--unset", "user.name")
        self.git("config", "--unset", "user.email")
        with (
            unittest.mock.patch.dict(os.environ, {"EMAIL": "auto@example.invalid"}),
            self.assertRaisesRegex(ValueError, "identity unset or empty"),
        ):
            signoff.identity(str(self.root))

    def test_literal_divider_line_in_plain_message(self) -> None:
        """Count the sign-off that follows a literal divider line in a plain message."""
        message = f"Subject\n\nBody\n---\nmore text\n\n{TRAILER}\n"
        values = signoff.message_values(message, str(self.root))
        self.assertEqual(values, [IDENTITY])
        self.assertIsNone(signoff.judge(values, IDENTITY))

    def test_verbose_commit_message_counts_only_real_trailer(self) -> None:
        """Ignore the diff and the foreign sign-off below the scissors line."""
        scissors = "# ------------------------ >8 ------------------------"
        diff = "diff --git a/f b/f\n--- a/f\n+++ b/f\n---\nSigned-off-by: F <f@example.invalid>\n"
        message = f"Subject\n\n{TRAILER}\n{scissors}\n{diff}"
        self.assertEqual(signoff.message_values(message, str(self.root)), [IDENTITY])

    def test_trailer_separator_config_does_not_change_the_policy(self) -> None:
        """Accept a colon sign-off and refuse a percent sign-off whatever separators are set."""
        self.git("config", "trailer.separators", "%:")
        message = self.root / "message"
        percent = f"Subject\n\nSigned-off-by% {IDENTITY}\n"
        for text, expected in ((f"Subject\n\n{TRAILER}\n", 0), (percent, 1)):
            with self.subTest(text=text):
                message.write_text(text, encoding="utf-8")
                result = self.cli(message)
                self.assertEqual(result.returncode, expected, result.stderr)
        self.assertEqual(signoff.message_values(percent, str(self.root)), [])

    def test_trailer_key_alias_is_not_counted(self) -> None:
        """Ignore trailer.<token>.key aliases from repo, environment and global config."""
        aliased = f"Subject\n\nApproved-by: {IDENTITY}\n"
        self.git("config", "trailer.Approved-by.key", "Signed-off-by")
        self.assertEqual(signoff.message_values(aliased, str(self.root)), [])
        literal = f"Subject\n\nOne\nTwo\nThree\n{TRAILER}\n"
        folded = "Subject\n\nSigned-off-by: Signoff Fixture\n <signoff@example.invalid>\n"
        self.assertEqual(signoff.message_values(literal, str(self.root)), [IDENTITY])
        self.assertEqual(signoff.message_values(folded, str(self.root)), [IDENTITY])
        self.git("config", "--unset", "trailer.Approved-by.key")
        param = "'trailer.Approved-by.key=Signed-off-by'"
        with unittest.mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": param}):
            self.assertEqual(signoff.message_values(aliased, str(self.root)), [])
        count_env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "trailer.Approved-by.key",
            "GIT_CONFIG_VALUE_0": "Signed-off-by",
        }
        with unittest.mock.patch.dict(os.environ, count_env):
            self.assertEqual(signoff.message_values(aliased, str(self.root)), [])
        global_cfg = self.root / "global.gitconfig"
        global_cfg.write_text('[trailer "Approved-by"]\n\tkey = Signed-off-by\n', encoding="utf-8")
        with unittest.mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_cfg)}):
            self.assertEqual(signoff.message_values(aliased, str(self.root)), [])

    def test_main_commit_msg_repair_texts_never_advise_amend(self) -> None:
        """Print commit-msg retry and edit instructions without advising --amend."""
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        message = self.root / "COMMIT_MSG"
        message.write_text("Subject without signoff\n", encoding="utf-8")
        status, _, err = capture_main(signoff.main, "--message-file", str(message))
        self.assertEqual(status, 1, err)
        self.assertIn(
            "retry the refused git commit command with the sign-off option (git commit --signoff); "
            "an in-progress merge also concludes with git commit --signoff",
            err,
        )
        self.assertNotIn("--amend", err)
        message.write_text(f"Subject\n\n{TRAILER}\n{TRAILER}\n", encoding="utf-8")
        status, _, err = capture_main(signoff.main, "--message-file", str(message))
        self.assertEqual(status, 1, err)
        self.assertIn(
            "edit the message so exactly one Signed-off-by trailer with the expected identity "
            "remains, then retry the refused git commit command",
            err,
        )
        self.assertNotIn("--amend", err)


class CommitRangeTest(GitFixture):
    """Check ordinary and merge commits through real bounded Git history reads."""

    def test_signed_ordinary_commit(self) -> None:
        """Accept one correctly signed-off ordinary commit on a new branch."""
        sha = self.commit()
        self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))

    def test_merge_signoff_required(self) -> None:
        """Reject the planted unsigned-off merge even when both parents comply."""
        sha = self.merge(False)
        self.assertEqual(len(self.git("show", "-s", "--format=%P", sha).split()), 2)
        self.assertEqual(
            signoff.check_commits(sha, ZERO, str(self.root)),
            f"commit {sha}: no Signed-off-by trailer",
        )
        self.git("commit", "--amend", "--no-edit", "--signoff")
        self.assertIsNone(
            signoff.check_commits(self.git("rev-parse", "HEAD"), ZERO, str(self.root))
        )

    def test_merge_with_signoff_option(self) -> None:
        """Accept a two-parent merge created with the sign-off option."""
        self.assertIsNone(signoff.check_commits(self.merge(True), ZERO, str(self.root)))

    def test_commit_duplicate_and_foreign_trailers(self) -> None:
        """Preserve duplicate and foreign trailer values in the single Git log read."""
        for suffix, reason in (
            (f"{TRAILER}\n{TRAILER}", "more than one"),
            ("Signed-off-by: Other <other@example.invalid>", "other identity"),
        ):
            with self.subTest(reason=reason):
                sha = self.commit(f"fixture\n\n{suffix}", signed=False)
                self.assertIn(reason, signoff.check_commits(sha, ZERO, str(self.root)))

    def test_commit_folded_value(self) -> None:
        """Unfold commit trailers consistently with the message-file parser."""
        sha = self.commit(
            "Subject\n\nSigned-off-by: Signoff Fixture\n <signoff@example.invalid>", signed=False
        )
        self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))

    def test_remote_tracking_history_is_excluded(self) -> None:
        """Exclude already-published history even if it contains an invalid old sign-off."""
        self.git("remote", "add", "origin", "https://example.invalid/origin.git")
        old = self.commit("published without signoff", signed=False)
        self.git("update-ref", "refs/remotes/origin/main", old)
        self.assertEqual(signoff.introduced_commits(old, ZERO, str(self.root)), [])
        self.assertIsNone(signoff.check_commits(old, ZERO, str(self.root)))
        sha = self.commit("new signed work")
        self.assertEqual(signoff.introduced_commits(sha, ZERO, str(self.root)), [sha])
        self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))

    def test_remote_head_is_excluded_when_locally_known(self) -> None:
        """Exclude an advertised remote head even without any remote-tracking reference."""
        old = self.commit("published", signed=False)
        sha = self.commit("introduced")
        self.assertEqual(signoff.introduced_commits(sha, old, str(self.root)), [sha])
        self.assertIsNone(signoff.check_commits(sha, old, str(self.root)))

    def test_unknown_remote_head_does_not_fetch(self) -> None:
        """Check available local history when the remote's advertised object is absent."""
        sha = self.commit()
        self.assertEqual(signoff.introduced_commits(sha, "f" * 40, str(self.root)), [sha])

    def test_exact_cap_and_one_above(self) -> None:
        """Accept exactly MAX_COMMITS real commits and refuse one above the fixed cap."""
        tree = self.git("mktree")
        parent = []
        for index in range(signoff.MAX_COMMITS + 1):
            sha = self.git("commit-tree", tree, *parent, text=f"commit {index}\n\n{TRAILER}\n")
            parent = ["-p", sha]
            if index == signoff.MAX_COMMITS - 1:
                self.assertEqual(
                    len(signoff.introduced_commits(sha, ZERO, str(self.root))), signoff.MAX_COMMITS
                )
                self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))
        with self.assertRaisesRegex(ValueError, "more than 1000 introduced commits"):
            signoff.check_commits(sha, ZERO, str(self.root))

    def test_one_log_call_per_nonempty_update(self) -> None:
        """Read all selected commits in one log call and skip log reads for an empty range."""
        sha = self.commit()
        self.commit("second")
        with unittest.mock.patch.object(signoff, "git", wraps=signoff.git) as git:
            self.assertIsNone(
                signoff.check_commits(self.git("rev-parse", "HEAD"), ZERO, str(self.root))
            )
        logs = [call for call in git.call_args_list if call.args[0][0] == "log"]
        self.assertEqual(len(logs), 1)
        self.git("remote", "add", "origin", "https://example.invalid/origin.git")
        self.git("update-ref", "refs/remotes/origin/main", sha)
        with unittest.mock.patch.object(signoff, "git", wraps=signoff.git) as git:
            self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))
        self.assertFalse(any(call.args[0][0] == "log" for call in git.call_args_list))

    def test_malformed_log_fails_closed(self) -> None:
        """Refuse incomplete or unexpected commit records instead of trusting partial output."""
        sha = self.commit()
        for raw in ("", f"{sha}\0{IDENTITY}", f"{'f' * 40}\0{IDENTITY}\0"):
            with (
                self.subTest(raw=raw),
                unittest.mock.patch.object(
                    signoff,
                    "git",
                    side_effect=[
                        "",
                        f"{sha}\n",
                        "Signoff Fixture\n",
                        "signoff@example.invalid\n",
                        raw,
                    ],
                ),
                self.assertRaises(ValueError),
            ):
                signoff.check_commits(sha, ZERO, str(self.root))

    def test_replacement_object_does_not_hide_unsigned_commit(self) -> None:
        """Refuse an unsigned commit even when a local replacement names a signed copy."""
        tree = self.git("mktree")
        unsigned = self.git("commit-tree", tree, text="unsigned\n")
        signed = self.git("commit-tree", tree, text=f"unsigned\n\n{TRAILER}\n")
        self.git("replace", unsigned, signed)
        self.assertEqual(
            signoff.check_commits(unsigned, ZERO, str(self.root)),
            f"commit {unsigned}: no Signed-off-by trailer",
        )

    def test_commit_committer_identity_is_the_expected_identity(self) -> None:
        """Accept a commit signed with the committer email and refuse the user-email one."""
        self.git("config", "committer.email", "committer@example.invalid")
        accepted = self.commit("fixture")
        self.assertIn("committer@example.invalid", self.git("show", "-s", "--format=%B", accepted))
        self.assertIsNone(signoff.check_commits(accepted, ZERO, str(self.root)))
        refused = self.commit(f"fixture\n\n{TRAILER}", signed=False)
        self.assertIn("other identity", signoff.check_commits(refused, ZERO, str(self.root)))

    def test_commit_with_literal_divider_counts_its_trailer(self) -> None:
        """Count the commit sign-off after a literal divider line in the log read."""
        sha = self.commit(f"fixture\n\nbody\n---\nmore\n\n{TRAILER}", signed=False)
        self.assertIsNone(signoff.check_commits(sha, ZERO, str(self.root)))

    def test_commit_trailer_separator_config_does_not_change_the_policy(self) -> None:
        """Accept a signed commit and refuse a percent sign-off commit under trailer.separators."""
        self.git("config", "trailer.separators", "%:")
        self.assertIsNone(signoff.check_commits(self.commit("fixture"), ZERO, str(self.root)))
        percent = self.commit(f"fixture\n\nSigned-off-by% {IDENTITY}", signed=False)
        reason = signoff.check_commits(percent, ZERO, str(self.root))
        self.assertIsNotNone(reason)
        self.assertIn("no Signed-off-by", reason)

    def test_empty_signoff_trailer_is_counted(self) -> None:
        """Refuse an empty sign-off before or after a valid one and accept a single valid one."""
        tree = self.git("mktree")
        for text, valid in (
            (f"Signed-off-by:\n{TRAILER}", False),
            (f"{TRAILER}\nSigned-off-by:", False),
            (TRAILER, True),
        ):
            with self.subTest(text=text):
                sha = self.git("commit-tree", tree, text=f"fixture\n\n{text}\n")
                reason = signoff.check_commits(sha, ZERO, str(self.root))
                if valid:
                    self.assertIsNone(reason)
                else:
                    self.assertIn("more than one", reason or "")

    def test_malformed_log_after_identity_fails_closed(self) -> None:
        """Refuse malformed log records once the committer identity read succeeded."""
        sha = self.commit()
        ident = f"{IDENTITY} 1700000000 +0000\n"
        for raw in ("", f"{sha}\0{TRAILER}", f"{'f' * 40}\0{TRAILER}\0"):
            with (
                self.subTest(raw=raw),
                unittest.mock.patch.object(
                    signoff, "git", side_effect=["", f"{sha}\n", ident, raw]
                ),
                self.assertRaises(ValueError),
            ):
                signoff.check_commits(sha, ZERO, str(self.root))

    def test_commit_trailer_key_alias_is_not_counted(self) -> None:
        """Refuse an Approved-by commit aliased to Signed-off-by in repo or env config."""
        aliased = self.commit(f"Subject\n\nApproved-by: {IDENTITY}", signed=False)
        self.git("config", "trailer.Approved-by.key", "Signed-off-by")
        self.assertEqual(
            signoff.check_commits(aliased, ZERO, str(self.root)),
            f"commit {aliased}: no Signed-off-by trailer",
        )
        signed = self.commit("signed with alias configured", signed=True)
        self.assertIsNone(signoff.check_commits(signed, aliased, str(self.root)))
        self.git("config", "--unset", "trailer.Approved-by.key")
        param = "'trailer.Approved-by.key=Signed-off-by'"
        with unittest.mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": param}):
            self.assertEqual(
                signoff.check_commits(aliased, ZERO, str(self.root)),
                f"commit {aliased}: no Signed-off-by trailer",
            )

    def test_log_output_encoding_requests_utf8(self) -> None:
        """Decode non-ASCII sign-off identities as UTF-8 despite i18n.logOutputEncoding."""
        self.git("config", "user.name", "José Fixture")
        self.git("config", "i18n.logOutputEncoding", "ISO-8859-1")
        sha = self.commit("utf8 signoff", signed=True)
        try:
            reason = signoff.check_commits(sha, ZERO, str(self.root))
        except ValueError as exc:
            self.fail(f"UTF-8 commit failed under logOutputEncoding: {exc}")
        self.assertIsNone(reason)


class MessagePathStdinTest(GitFixture):
    """Exercise the hook message-path channel that reads one path line from stdin."""

    def _run_signoff_stdin(
        self, path_line: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run signoff with --message-path-stdin and the given path line on stdin."""
        return subprocess.run(  # nosec B603 - fixed Python argv, fixture paths, no shell.
            [sys.executable, "-B", str(ROOT / "scripts/signoff.py"), "--message-path-stdin"],
            input=path_line,
            cwd=cwd or self.root,
            env=self.env,
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=30,
        )

    def test_message_path_stdin_signed_and_unsigned(self) -> None:
        """Accept a signed message file path and refuse an unsigned one through stdin."""
        relative = self.git("rev-parse", "--git-path", "COMMIT_EDITMSG")
        message = self.root / relative
        message.write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
        signed = self._run_signoff_stdin(relative + "\n")
        self.assertEqual(signed.returncode, 0, signed.stderr)
        message.write_text("Subject without trailer\n", encoding="utf-8")
        refused = self._run_signoff_stdin(relative + "\n")
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertIn("no Signed-off-by", refused.stderr)

    def test_message_path_stdin_fail_closed_inputs(self) -> None:
        """Refuse empty stdin, two lines and a missing file with exit status two."""
        message = self.root / "present.txt"
        message.write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
        for path_line, label in (
            ("", "empty"),
            (f"{message}\nsecond\n", "two lines"),
            (str(self.root / "absent.txt") + "\n", "missing file"),
        ):
            with self.subTest(label=label):
                result = self._run_signoff_stdin(path_line)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("cannot decide", result.stderr)

    def test_message_path_stdin_allow_list_accepts_git_message_files(self) -> None:
        """Accept the commit and merge message files in relative and absolute form."""
        for name in ("COMMIT_EDITMSG", "MERGE_MSG"):
            relative = self.git("rev-parse", "--git-path", name)
            (self.root / relative).write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
            for form in (relative, str(self.root / relative)):
                with self.subTest(name=name, form=form):
                    result = self._run_signoff_stdin(form + "\n")
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_message_path_stdin_allow_list_accepts_linked_worktree_file(self) -> None:
        """Accept the commit message file of a linked worktree read from that worktree."""
        self.commit("base")
        linked = self.root / "linked-worktree"
        self.git("worktree", "add", "-q", "-b", "side", str(linked))
        named = subprocess.run(  # nosec B603 B607 - fixture Git argv, no shell, timeout set.
            ["git", "rev-parse", "--git-path", "COMMIT_EDITMSG"],
            cwd=linked,
            env=self.env,
            capture_output=True,
            encoding="utf-8",
            check=True,
            timeout=30,
        ).stdout.strip()
        self.assertTrue(Path(named).is_absolute(), named)
        Path(named).write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
        result = self._run_signoff_stdin(named + "\n", cwd=linked)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_message_path_stdin_allow_list_refuses_other_signed_file(self) -> None:
        """Refuse a signed file elsewhere in the work tree as cannot decide."""
        elsewhere = self.root / "elsewhere.txt"
        elsewhere.write_text(f"Subject\n\n{TRAILER}\n", encoding="utf-8")
        for form in ("elsewhere.txt", str(elsewhere)):
            with self.subTest(form=form):
                result = self._run_signoff_stdin(form + "\n")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("cannot decide", result.stderr)
                self.assertIn("allow-list", result.stderr)


class ConsideredRemotesTest(GitFixture):
    """Check introduced commits against per-remote tracking history."""

    def test_fork_only_unsigned_refused_for_origin_scope(self) -> None:
        """Refuse a fork-only unsigned commit when only origin is the considered remote."""
        self.git("remote", "add", "origin", "https://example.invalid/origin.git")
        self.git("remote", "add", "fork", "https://example.invalid/fork.git")
        base = self.commit("origin base", signed=True)
        self.git("update-ref", "refs/remotes/origin/main", base)
        unsigned = self.commit("unsigned on fork", signed=False)
        self.git("update-ref", "refs/remotes/fork/topic", unsigned)
        signed_sha = self.commit("signed tip")
        reason_origin = signoff.check_commits(
            signed_sha, base, str(self.root), considered_remotes=["origin"]
        )
        self.assertIsNotNone(reason_origin)
        self.assertIn(unsigned, reason_origin)
        reason_all = signoff.check_commits(signed_sha, base, str(self.root))
        self.assertIsNotNone(reason_all)
        self.assertIn(unsigned, reason_all)

    def test_unsigned_on_origin_tracking_passes(self) -> None:
        """Pass when the unsigned commit is also reachable from origin tracking refs."""
        self.git("remote", "add", "origin", "https://example.invalid/origin.git")
        self.git("remote", "add", "fork", "https://example.invalid/fork.git")
        unsigned = self.commit("unsigned", signed=False)
        self.git("update-ref", "refs/remotes/fork/topic", unsigned)
        self.git("update-ref", "refs/remotes/origin/main", unsigned)
        signed_sha = self.commit("signed", signed=True)
        self.assertIsNone(
            signoff.check_commits(
                signed_sha, unsigned, str(self.root), considered_remotes=["origin"]
            )
        )
        self.assertIsNone(signoff.check_commits(signed_sha, unsigned, str(self.root)))

    def test_stale_second_remote_causes_documented_false_refusal(self) -> None:
        """Refuse when a stale remote lacks unsigned history that origin already published."""
        self.git("remote", "add", "origin", "https://example.invalid/origin.git")
        self.git("remote", "add", "stale", "https://example.invalid/stale.git")
        base = self.commit("stale base", signed=True)
        self.git("update-ref", "refs/remotes/stale/main", base)
        old_unsigned = self.commit("old unsigned", signed=False)
        self.git("update-ref", "refs/remotes/origin/main", old_unsigned)
        signed_sha = self.commit("new signed")
        self.assertIsNone(
            signoff.check_commits(
                signed_sha, old_unsigned, str(self.root), considered_remotes=["origin"]
            )
        )
        refused = signoff.check_commits(signed_sha, ZERO, str(self.root))
        self.assertIsNotNone(refused)
        self.assertIn(old_unsigned, refused)

    def test_no_remote_counts_every_commit_against_advertised_head(self) -> None:
        """Treat every local commit as introduced with no remote and an unknown head."""
        old_unsigned = self.commit("local unsigned", signed=False)
        signed_sha = self.commit("local signed", signed=True)
        refused = signoff.check_commits(signed_sha, ZERO, str(self.root))
        self.assertIsNotNone(refused)
        self.assertIn(old_unsigned, refused)
        self.assertIsNone(signoff.check_commits(signed_sha, old_unsigned, str(self.root)))

    def test_remote_count_above_cap_fails_closed(self) -> None:
        """Refuse when the considered-remote list exceeds the fixed remote cap."""
        cap = signoff.MAX_REMOTES
        names = [f"r{index}" for index in range(cap + 1)]
        with self.assertRaisesRegex(ValueError, str(cap)):
            signoff.check_commits(self.commit(), ZERO, str(self.root), considered_remotes=names)

    def test_configured_remotes_list_refuses_above_cap_without_git_config(self) -> None:
        """Raise from configured_remotes when a mocked remote list exceeds MAX_REMOTES."""
        cap = signoff.MAX_REMOTES
        output = "\n".join(f"r{index}" for index in range(cap + 1))
        with (
            unittest.mock.patch.object(signoff, "git", return_value=output + "\n"),
            self.assertRaisesRegex(ValueError, str(cap)),
        ):
            signoff.configured_remotes(str(self.root))

    def test_leftover_remote_tracking_ref_refused_without_configured_remote(self) -> None:
        """Refuse an unsigned commit hidden only by a stale remote-tracking ref."""
        unsigned = self.commit("stale unsigned", signed=False)
        self.git("update-ref", "refs/remotes/gone/main", unsigned)
        signed_sha = self.commit("signed tip", signed=True)
        refused = signoff.check_commits(signed_sha, ZERO, str(self.root))
        self.assertIsNotNone(refused)
        self.assertIn(unsigned, refused)


class FakeClock:
    """A settable clock standing in for time.monotonic."""

    def __init__(self) -> None:
        """Start at zero seconds."""
        self.now = 0.0

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now


def empty_run(clock: FakeClock | None = None, step: float = 0.0) -> unittest.mock.Mock:
    """Stub subprocess.run: empty Git output, advancing the clock by step seconds per call."""

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        """Serve one empty Git answer."""
        if clock is not None:
            clock.now += step
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    return unittest.mock.Mock(side_effect=run)


class SignoffDeadlineTest(unittest.TestCase):
    """Run the sign-off Git calls under one total deadline."""

    def test_per_call_timeout_is_the_time_left_capped(self) -> None:
        """Give each call the time left on the deadline, never more than GIT_TIMEOUT."""
        for used, expected in ((115, 5), (30, 10)):
            with self.subTest(used=used):
                clock = FakeClock()
                run = empty_run()
                with (
                    unittest.mock.patch("scripts.signoff.subprocess.run", run),
                    signoff.deadline_scope(clock=clock),
                ):
                    clock.now = used
                    signoff.git(["remote"])
                self.assertEqual(run.call_args.kwargs["timeout"], expected)

    def test_boundary_just_before_the_deadline_still_runs(self) -> None:
        """Make the call with the half second left at 119.5 s used."""
        clock = FakeClock()
        run = empty_run()
        with (
            unittest.mock.patch("scripts.signoff.subprocess.run", run),
            signoff.deadline_scope(clock=clock),
        ):
            clock.now = 119.5
            try:
                signoff.git(["remote"])
            except ValueError as exc:
                self.fail(f"call refused with half a second left: {exc}")
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["timeout"], 0.5)

    def test_passed_deadline_makes_no_call(self) -> None:
        """Refuse before the next Git call at 120 s and 121 s used."""
        for used in (120, 121):
            with self.subTest(used=used):
                clock = FakeClock()
                run = empty_run()
                with (
                    unittest.mock.patch("scripts.signoff.subprocess.run", run),
                    signoff.deadline_scope(clock=clock),
                ):
                    clock.now = used
                    with self.assertRaises(ValueError) as caught:
                        signoff.check_commits("a" * 40, ZERO, considered_remotes=["origin"])
                self.assertIn("sign-off check deadline of 120 s passed", str(caught.exception))
                run.assert_not_called()

    def test_one_deadline_spans_every_call_of_a_check(self) -> None:
        """Refuse the third remote read once two reads used the whole deadline."""
        clock = FakeClock()
        run = empty_run(clock, 60)
        with (
            unittest.mock.patch("scripts.signoff.subprocess.run", run),
            signoff.deadline_scope(clock=clock),
            self.assertRaisesRegex(ValueError, "sign-off check deadline of 120 s passed"),
        ):
            signoff.check_commits("a" * 40, ZERO, considered_remotes=["one", "two", "three"])
        self.assertEqual(run.call_count, 2)

    def test_default_keeps_the_fixed_timeout_on_every_call(self) -> None:
        """Pass GIT_TIMEOUT to every call of a check that runs without a deadline."""
        run = empty_run()
        with unittest.mock.patch("scripts.signoff.subprocess.run", run):
            signoff.check_commits("a" * 40, ZERO, considered_remotes=["one", "two"])
        timeouts = [call.kwargs["timeout"] for call in run.call_args_list]
        self.assertEqual(timeouts, [signoff.GIT_TIMEOUT] * 2)

    def test_deadline_ends_with_its_scope(self) -> None:
        """Return to GIT_TIMEOUT for calls made after the scope ended."""
        clock = FakeClock()
        run = empty_run()
        with unittest.mock.patch("scripts.signoff.subprocess.run", run):
            with signoff.deadline_scope(clock=clock):
                clock.now = 115
            clock.now = 200
            signoff.git(["remote"])
        self.assertEqual(run.call_args.kwargs["timeout"], signoff.GIT_TIMEOUT)

    def test_nested_deadline_scope_keeps_outer_deadline(self) -> None:
        """Keep the outer clock, start and limit when entering a nested deadline_scope."""
        clock = FakeClock()
        with signoff.deadline_scope(limit=5, clock=clock):
            clock.now = 4.0
            with signoff.deadline_scope():
                self.assertLessEqual(signoff.call_timeout(), 1.0)
            self.assertLessEqual(signoff.call_timeout(), 1.0)


if __name__ == "__main__":
    unittest.main()
