# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Unit tests for base-commit claim parsing and live merge-base checks."""

from __future__ import annotations

import contextlib
import io
import json
import re
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from scripts import base_claims

MERGE_BASE = "c" * 40

DEPENDENCY_ALLOWLIST_CASES: tuple[tuple[str, list[tuple[int, str]] | None, str], ...] = (
    ("r1-or", None, "Depends on #12 ~ head aaaaaaa or #13 (head bbbbbbb)."),
    ("r1-comma-or", None, "Depends on #12 ~ head aaaaaaa, or #13 (head bbbbbbb)."),
    ("r1-plus", None, "Depends on #12 ~ head aaaaaaa plus #13 (head bbbbbbb)."),
    ("r1-as-well-as", None, "Depends on #12 ~ head aaaaaaa as well as #13 (head bbbbbbb)."),
    ("r1-along-with", None, "Depends on #12 ~ head aaaaaaa along with #13 (head bbbbbbb)."),
    ("r1-slash", None, "Depends on #12 ~ head aaaaaaa / #13 (head bbbbbbb)."),
    ("r1-and-or", None, "Depends on #12 ~ head aaaaaaa and/or #13 (head bbbbbbb)."),
    ("r1-plus-sign", None, "Depends on #12 ~ head aaaaaaa + #13 (head bbbbbbb)."),
    ("r1-then", None, "Depends on #12 ~ head aaaaaaa then #13 (head bbbbbbb)."),
    ("r1-full-or", None, "Depends on #12 (head aaaaaaa) or #13 (head bbbbbbb)."),
    ("r1-prose-or", None, "Depends on #12 (head aaaaaaa), or #13 (head bbbbbbb)."),
    ("r1-prose-plus", None, "Depends on #12 (head aaaaaaa), plus #13 (head bbbbbbb)."),
    ("r1-prose-bracket", None, "Depends on #12 (head aaaaaaa), (and #13, head bbbbbbb)."),
    ("r1-prose-words", None, "Depends on #12 (head aaaaaaa), for details see #14."),
    ("r1-keep-see", [(12, "aaaaaaa")], "Depends on #12 (head aaaaaaa), see #14 for benchmarks."),
    (
        "r1-keep-and-see",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa) and see #14 for benchmarks.",
    ),
    (
        "r1-keep-see-chain",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa), see #14 and #15 for benchmarks.",
    ),
    (
        "r1-keep-unrelated",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        "Depends on #12 (head aaaaaaa), #13 (head bbbbbbb), unrelated #14 head ccccccc.",
    ),
    ("r1-keep-historical", [], "Previously stacked on #12 ~ head aaaaaaa, #13 (head bbbbbbb)."),
    (
        "r2-and-previously",
        None,
        "Depends on #12 (head aaaaaaa) and previously stacked on #13 (head bbbbbbb).",
    ),
    (
        "r2-previously-comma",
        None,
        "Depends on #12 (head aaaaaaa), previously, stacked on #13 (head bbbbbbb).",
    ),
    ("r2-formerly", None, "Depends on #12 (head aaaaaaa), formerly stacked on #13 (head bbbbbbb)."),
    (
        "r2-originally",
        None,
        "Depends on #12 (head aaaaaaa), originally stacked on #13 (head bbbbbbb).",
    ),
    (
        "r2-no-longer",
        None,
        "Depends on #12 (head aaaaaaa) and no longer depends on #13 (head bbbbbbb).",
    ),
    ("r2-dash", None, "Depends on #12 (head aaaaaaa) - previously stacked on #13 (head bbbbbbb)."),
    ("r2-which", None, "Depends on #12 (head aaaaaaa) which builds on #13 (head bbbbbbb)."),
    ("r2-empty-gap", None, "Depends on #12 (head aaaaaaa), based on #13 (head bbbbbbb)."),
    ("r2-truncated", None, "Depends on #12 ~ head aaaaaaa then depends on #13 (head bbbbbbb)."),
    (
        "r2-keep-and-now",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        "Depends on #12 (head aaaaaaa), and now depends on #13 (head bbbbbbb).",
    ),
    (
        "r2-keep-previously",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa), previously stacked on #13 (head bbbbbbb).",
    ),
    (
        "r2-keep-historical-first",
        [(13, "bbbbbbb")],
        "Previously stacked on #12 and now depends on #13 (head bbbbbbb).",
    ),
    (
        "r2-keep-used-to",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa); it used to depend on #13 (head bbbbbbb).",
    ),
    (
        "r3-in-brackets",
        None,
        "Depends on #12 (head aaaaaaa; previously stacked on #13, head bbbbbbb).",
    ),
    ("r3-semicolon", None, "Depends on #12 (previous head aaaaaaa; now head bbbbbbb)."),
    ("r3-period", None, "Depends on #12 (old head aaaaaaa. New head bbbbbbb)."),
    ("r3-bang", None, "Depends on #12 (old head aaaaaaa! new head bbbbbbb)."),
    ("r3-question", None, "Depends on #12 (old head aaaaaaa? new head bbbbbbb)."),
    ("r3-see", None, "Depends on #12 (head aaaaaaa; see #13)."),
    ("r3-abbreviation", None, "Depends on #12 (head aaaaaaa, e.g. rebased)."),
    (
        "r3-keep-depth-zero",
        [(13, "bbbbbbb")],
        "Depends on #13 - head bbbbbbb! Then unrelated head ccccccc.",
    ),
    ("control-plain", [(12, "aaaaaaa")], "Depends on #12 (head aaaaaaa)."),
    (
        "control-two",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb).",
    ),
    ("r1-sibling-with", None, "Depends on #12 ~ head aaaaaaa with #13 (head bbbbbbb)."),
    ("r1-sibling-via", None, "Depends on #12 (head aaaaaaa) via #13 (head bbbbbbb)."),
    ("r1-sibling-see-or", None, "Depends on #12 (head aaaaaaa), see #14 or #15 for benchmarks."),
    (
        "r2-sibling-historically",
        None,
        "Depends on #12 (head aaaaaaa), historically stacked on #13 (head bbbbbbb).",
    ),
    (
        "r2-sibling-currently",
        None,
        "Depends on #12 (head aaaaaaa), currently depends on #13 (head bbbbbbb).",
    ),
    ("r2-sibling-nospace-gap", None, "Depends on #12 (head aaaaaaa),based on #13 (head bbbbbbb)."),
    (
        "r3-sibling-square-semicolon",
        None,
        "Depends on #12 [previous head aaaaaaa; now head bbbbbbb].",
    ),
    ("r3-sibling-square-period", None, "Depends on #12 [old head aaaaaaa. New head bbbbbbb]."),
    ("r3-sibling-nested-brackets", None, "Depends on #12 (head aaaaaaa [e.g. rebased])."),
)

DEPENDENCY_ATTRIBUTION_CASES: tuple[tuple[str, list[tuple[int, str]] | None, str], ...] = (
    (
        "s-keep-345",
        [],
        "It builds on #344, so until #344 lands this pull request also shows that commit.",
    ),
    (
        "s-keep-345-line",
        [],
        (
            "Part of #340 (second of two stacked pull requests). It builds on #344, "
            "so until #344 lands this pull request also shows that commit; after #344 "
            "lands, main is merged in and only the commit below remains."
        ),
    ),
    (
        "s-keep-head",
        [(344, "aaaaaaa")],
        "Depends on #344 (head aaaaaaa), so until #344 lands this shows that commit.",
    ),
    (
        "s-keep-second",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), so once #13 lands this rebases.",
    ),
    (
        "s-keep-first",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), so until #12 lands this shows both.",
    ),
    (
        "s-keep-which",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa), which means #12 must land first.",
    ),
    (
        "s-keep-bracket-note",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa), so until #12 (the parser change) lands this waits.",
    ),
    (
        "s-keep-historical",
        [],
        "Previously stacked on #12 (head aaaaaaa), so until #12 lands this showed that commit.",
    ),
    (
        "s-control-see-same",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa), see #12 for the plan.",
    ),
    (
        "s-refuse-new-head",
        None,
        "Depends on #12 (head aaaaaaa), so until #12 (head bbbbbbb) lands this waits.",
    ),
    (
        "s-refuse-same-head",
        None,
        "Depends on #12 (head aaaaaaa), so until #12 at head aaaaaaa lands this waits.",
    ),
    (
        "s-refuse-chain-and",
        None,
        "Depends on #12 (head aaaaaaa), so until #12 and #13 land this waits.",
    ),
    (
        "s-refuse-chain-comma",
        None,
        "Depends on #12 (head aaaaaaa), so until #12, #13 land this waits.",
    ),
    (
        "s-refuse-other",
        None,
        "Depends on #12 (head aaaaaaa), so until #13 lands this shows that commit.",
    ),
    ("s-refuse-depth", None, "Depends on #12 (head aaaaaaa), so until it (#12) lands this waits."),
    ("s-refuse-dedupe", None, "Depends on #12 (head aaaaaaa) or #13, see #13."),
    ("c-refuse-semicolon", None, "Depends on #12 {head aaaaaaa; now head bbbbbbb}."),
    ("c-refuse-period", None, "Depends on #12 {old head aaaaaaa. New head bbbbbbb}."),
    ("c-refuse-member", None, "Depends on #12 (head aaaaaaa) {and #13 head bbbbbbb}."),
    ("c-keep-plain", [(12, "aaaaaaa")], "Depends on #12 {head aaaaaaa}."),
    ("c-keep-nested", [(12, "aaaaaaa")], "Depends on #12 (head aaaaaaa {rebased})."),
    (
        "c-keep-next-sentence",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa). {Draft} notes follow.",
    ),
    ("h-refuse-pull", None, "Depends on #12 (head aaaaaaa) and pull 13 (head bbbbbbb)."),
    ("h-refuse-pr-nospace", None, "Depends on #12 (head aaaaaaa) and PR13 (head bbbbbbb)."),
    ("h-refuse-then", None, "Depends on #12 (head aaaaaaa), then head bbbbbbb after the rebase."),
    ("h-refuse-lone-pull", None, "Depends on #12 and pull 13 (head bbbbbbb)."),
    ("h-refuse-gh", None, "Depends on #12 and GH-13 at head bbbbbbb."),
    ("h-refuse-date", None, "Depends on #12, rebased on 2026-11-20, now at head 5d6e7f8."),
    (
        "h-keep-ending",
        [(25664, "c35b0e1fce")],
        (
            "Depends on #25664: the first three commits are that PR's series, "
            "currently ending at c35b0e1fce."
        ),
    ),
    (
        "h-keep-hist-now",
        [(12, "bbbbbbb")],
        "Depends on #12, previously at head aaaaaaa, now head bbbbbbb",
    ),
    (
        "h-keep-hist-hex",
        [(12, "5d6e7f8")],
        "Depends on #12, previously at head 1a2b3c4, now head 5d6e7f8",
    ),
    ("h-keep-tilde", [(12, "aaaaaaa")], "Depends on #12 ~ head aaaaaaa."),
    ("h-keep-at", [(12, "aaaaaaa")], "Depends on #12 at head aaaaaaa."),
    (
        "h-keep-annotation-hist",
        [(12, "aaaaaaa")],
        "Depends on #12 (head aaaaaaa, previously head bbbbbbb).",
    ),
    ("h-keep-version", [(12, "aaaaaaa")], "Depends on #12 (v2, head aaaaaaa)."),
    (
        "s-sibling-word-repeat",
        [(12, "aaaaaaa")],
        "Stacked on PR 12 (head aaaaaaa), so once pull request #12 merges this rebases.",
    ),
    (
        "s-sibling-chain-ampersand",
        None,
        "Depends on #12 (head aaaaaaa), so until #12 & PR 13 land this waits.",
    ),
    (
        "s-sibling-see-chain-break",
        None,
        "Depends on #12 (head aaaaaaa), see #14 and #12 and #15 for context.",
    ),
    ("c-sibling-bang", None, "Depends on #12 {old head aaaaaaa! new head bbbbbbb}."),
    ("c-sibling-question", None, "Depends on #12 {old head aaaaaaa? new head bbbbbbb}."),
    (
        "c-sibling-old-brace-scope",
        [(12, "bbbbbbb")],
        "Depends on #12 {old head aaaaaaa} at head bbbbbbb.",
    ),
    ("h-sibling-two-tips", None, "Builds on PR 12 (tip aaaaaaa, now tip bbbbbbb)."),
    ("h-sibling-pulls-slash", None, "Stacked on PR 12 and pulls/13 (ending at bbbbbbb)."),
    ("h-sibling-issue-ref", None, "Based on pull request 12 and issue 13, ends at 5d6e7f8."),
)

DEPENDENCY_SCOPE_CASES: tuple[
    tuple[str, str, list[tuple[int, str]] | None, list[int] | None, str], ...
] = (
    ("b-refuse-cr", "refuse", None, None, "Depends on #12 [note). head bbbbbbb]"),
    ("b-refuse-paren", "refuse", None, None, "Depends on #12 (note]. head bbbbbbb)"),
    ("b-refuse-brace", "refuse", None, None, "Depends on #12 {note). head bbbbbbb}"),
    ("b-refuse-semicolon", "refuse", None, None, "Depends on #12 [note); head bbbbbbb]"),
    (
        "b-refuse-list",
        "refuse",
        None,
        None,
        "Depends on #12 [note). head aaaaaaa], #13 (head bbbbbbb)",
    ),
    ("b-refuse-hidden", "refuse", None, None, "Depends on #12 (note], #13 head bbbbbbb)"),
    ("b-keep-outside", "ok", [], [], "Depends on #12 [note]. Head bbbbbbb"),
    ("b-keep-stray-closer", "ok", [(12, "bbbbbbb")], [12], "Depends on #12 [head bbbbbbb)]"),
    ("b-keep-matched", "ok", [(12, "bbbbbbb")], [12], "Depends on #12 [head bbbbbbb]"),
    ("b-keep-nested", "ok", [(12, "bbbbbbb")], [12], "Depends on #12 [head bbbbbbb (rebased)]"),
    ("l-two", "ok", [], [1, 2], "Depends on #1 (old head aaaaaaa), #2"),
    (
        "l-mixed",
        "ok",
        [(2, "bbbbbbb")],
        [1, 2],
        "Depends on #1 (old head aaaaaaa), #2 (head bbbbbbb)",
    ),
    (
        "l-over",
        "limit",
        None,
        None,
        "Depends on #1 (old head aaaaaaa), #2, #3, #4, #5, #6, #7, #8, #9, #10",
    ),
    (
        "l-over-head",
        "limit",
        None,
        None,
        "Depends on #1 (old head aaaaaaa), #2 (head bbbbbbb), #3, #4, #5, #6, #7, #8, #9",
    ),
    (
        "l-eight",
        "ok",
        [],
        [1, 2, 3, 4, 5, 6, 7, 8],
        "Depends on #1 (old head aaaaaaa), #2, #3, #4, #5, #6, #7, #8",
    ),
    ("l-and", "ok", [], [12, 13], "Depends on #12 (old head aaaaaaa) and #13"),
    (
        "l-square",
        "ok",
        [(13, "bbbbbbb")],
        [12, 13],
        "Depends on #12 [old head aaaaaaa], #13 [head bbbbbbb]",
    ),
    (
        "l-member-words",
        "ok",
        [(12, "aaaaaaa")],
        [12, 13],
        "Depends on #12 (head aaaaaaa), #13 from an earlier series (head bbbbbbb)",
    ),
    ("l-trailing-hist", "ok", [], [12, 13], "Depends on #12 and #13 (previous head bbbbbbb)"),
    (
        "l-trailing-mixed",
        "refuse",
        None,
        None,
        "Depends on #12 and #13 (previous head aaaaaaa, now head bbbbbbb)",
    ),
    ("l-keep-lead-hist", "ok", [], [], "Previously depends on #12 and #13 (head bbbbbbb)"),
    (
        "l-keep-lead-hist-over",
        "ok",
        [],
        [],
        "Previously depends on #1, #2, #3, #4, #5, #6, #7, #8, #9, #10",
    ),
    ("l-keep-single-hist", "ok", [], [], "Depends on #12 (old head aaaaaaa)"),
    ("l-keep-control-over", "limit", None, None, "Depends on #2, #3, #4, #5, #6, #7, #8, #9, #10"),
    (
        "l-keep-two-current",
        "ok",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        [12, 13],
        "Depends on #12 (head aaaaaaa), #13 (head bbbbbbb)",
    ),
    (
        "o-colon",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Depends on #12: previous head aaaaaaa, now head bbbbbbb",
    ),
    (
        "o-dash",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Depends on #12 - previous head aaaaaaa, now head bbbbbbb",
    ),
    (
        "o-stacked",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Stacked on #12: old head aaaaaaa, now head bbbbbbb",
    ),
    (
        "o-list",
        "ok",
        [(13, "bbbbbbb")],
        [12, 13],
        "Depends on #12: old head aaaaaaa, #13 (head bbbbbbb)",
    ),
    ("o-keep-lead-hist-colon", "ok", [], [], "Previously stacked on #12: head bbbbbbb"),
    ("o-keep-lead-hist", "ok", [], [], "Previously stacked on #12 (head bbbbbbb)"),
    (
        "o-keep-words-unbracketed",
        "ok",
        [],
        [],
        "Depends on #12 from an earlier series head aaaaaaa",
    ),
    (
        "o-words-bracketed",
        "ok",
        [(13, "bbbbbbb")],
        [12, 13],
        "Depends on #12 from an earlier series (head aaaaaaa), #13 (head bbbbbbb)",
    ),
    (
        "o-words-unbracketed",
        "ok",
        [(13, "bbbbbbb")],
        [12, 13],
        "Depends on #12 from an earlier series head aaaaaaa, #13 (head bbbbbbb)",
    ),
    (
        "o-keep-comma",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Depends on #12, previously at head aaaaaaa, now head bbbbbbb",
    ),
    ("o-keep-old-only", "ok", [], [], "Depends on #12: old head aaaaaaa"),
    ("o-keep-colon-current", "ok", [(12, "bbbbbbb")], [12], "Depends on #12: head bbbbbbb"),
    (
        "o-keep-bracketed",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Depends on #12 (previous head aaaaaaa, now head bbbbbbb)",
    ),
    ("a-refuse-cr", "refuse", None, None, "Depends on #12 head (aaaaaaa and #13 head bbbbbbb)"),
    ("a-refuse-comma", "refuse", None, None, "Depends on #12 head (aaaaaaa, #13 head bbbbbbb)"),
    ("a-refuse-square", "refuse", None, None, "Depends on #12 head [aaaaaaa and #13 head bbbbbbb]"),
    (
        "a-keep",
        "ok",
        [(12, "aaaaaaa"), (13, "bbbbbbb")],
        [12, 13],
        "Depends on #12 head (aaaaaaa) and #13 head bbbbbbb",
    ),
    ("a-keep-plain", "ok", [], [12, 13], "Depends on #12 and #13"),
    (
        "b-sibling-nested-extent",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Depends on #12 [(note]) old] at head bbbbbbb",
    ),
    ("b-sibling-brace-bang", "refuse", None, None, "Stacked on PR 12 {note]! tip bbbbbbb}"),
    (
        "l-sibling-both-hist",
        "ok",
        [],
        [12, 13],
        "Stacked on PR 12 (prior head aaaaaaa) & PR 13 (former tip bbbbbbb)",
    ),
    (
        "l-sibling-trailing-three",
        "ok",
        [],
        [12, 13, 14],
        "Builds on PR 12, PR 13, and PR 14 [earlier tip bbbbbbb]",
    ),
    (
        "o-sibling-builds-prior-tip",
        "ok",
        [(12, "bbbbbbb")],
        [12],
        "Builds on PR 12: prior tip aaaaaaa, now tip bbbbbbb",
    ),
    (
        "o-sibling-and-former-list",
        "ok",
        [(13, "bbbbbbb")],
        [12, 13],
        "Based on PR 12 - former head aaaaaaa and PR 13 [tip bbbbbbb]",
    ),
    (
        "a-sibling-ampersand",
        "refuse",
        None,
        None,
        "Stacked on PR 12 tip (aaaaaaa & PR 13 tip bbbbbbb)",
    ),
    (
        "a-sibling-oxford-comma",
        "refuse",
        None,
        None,
        "On top of pull request 12 ending at (aaaaaaa, and PR #13 ending at bbbbbbb)",
    ),
)


class BaseClaimsTest(unittest.TestCase):
    """Verify base-claim extraction, filtering, staleness checks and CLI exit codes."""

    def setUp(self) -> None:
        """Create a temporary fixture directory registered for cleanup."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)

    def write_fixture(self, name: str, content: str) -> Path:
        """Write UTF-8 fixture text inside the temporary directory."""
        path = self.tmp / name
        path.write_text(content, encoding="utf-8")
        return path

    def run_cli(self, *argv: str) -> tuple[int, str]:
        """Execute base_claims.main with captured stderr."""
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = base_claims.main(list(argv))
        return rc, stderr.getvalue()

    def test_find_base_claims_matches_supported_forms(self) -> None:
        """Supported base-claim phrasings return lowercased hex hashes in order."""
        forty_a = "a" * 40
        self.assertEqual(
            base_claims.find_base_claims("Base: FFmpeg master 46f23be8b197."),
            ["46f23be8b197"],
        )
        self.assertEqual(base_claims.find_base_claims(f"base: {forty_a}"), [forty_a])
        self.assertEqual(
            base_claims.find_base_claims("proposed base master abc1234"),
            ["abc1234"],
        )
        self.assertEqual(
            base_claims.find_base_claims("Base: FFmpeg commit 46F23BE8B197"),
            ["46f23be8b197"],
        )

    def test_find_base_claims_ignores_non_claims_and_boundaries(self) -> None:
        """Unrelated words, quotes, fences, history markers and 6-hex values are ignored."""
        fenced = "```text\nBase: master 46f23be8b197\n```\n"
        for sample in (
            "database 1234567",
            "base64 abcdef1",
            "parent a88838af4821",
            "> Base: master 46f23be8b197",
            fenced,
            "Previous base: 46f23be8b197",
            "base abc123",
        ):
            with self.subTest(sample=sample):
                self.assertEqual(base_claims.find_base_claims(sample), [])

    def test_stale_claims_checks_merge_base_prefixes(self) -> None:
        """Prefixes of merge_base pass while non-matching hashes are returned."""
        self.assertEqual(
            base_claims.stale_claims(f"Base: FFmpeg master {MERGE_BASE[:12]}.", MERGE_BASE),
            [],
        )
        self.assertEqual(
            base_claims.stale_claims("Base: FFmpeg master 46f23be8b197.", MERGE_BASE),
            ["46f23be8b197"],
        )
        self.assertEqual(
            base_claims.stale_claims(f"base: {MERGE_BASE[:7]}", MERGE_BASE.upper()),
            [],
        )

    def test_main_with_merge_base_and_body_file(self) -> None:
        """CLI --merge-base rejects stale claims and accepts current or absent claims."""
        stale_file = self.write_fixture("stale.md", "Base: FFmpeg master 46f23be8b197.\n")
        rc, err = self.run_cli("--merge-base", MERGE_BASE, str(stale_file))
        self.assertEqual(rc, 1)
        self.assertIn(
            f"{stale_file}: names base 46f23be8b197, the live merge base is {MERGE_BASE}",
            err,
        )

        current_file = self.write_fixture("current.md", f"Base: {MERGE_BASE[:12]}\n")
        rc, err = self.run_cli("--merge-base", MERGE_BASE, str(current_file))
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

        plain_file = self.write_fixture("plain.md", "No base commit mentioned here.\n")
        rc, err = self.run_cli("--merge-base", MERGE_BASE, str(plain_file))
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_main_with_pull_json_and_live_body(self) -> None:
        """CLI --pull-json validates merge_base presence and optional live PR body claims."""
        missing_base = self.write_fixture("missing.json", json.dumps({"body": ""}))
        claim_file = self.write_fixture("claim.md", "Base: FFmpeg master 46f23be8b197.\n")
        plain_file = self.write_fixture("plain.md", "Unrelated text.\n")

        rc, err = self.run_cli("--pull-json", str(missing_base), str(claim_file))
        self.assertEqual(rc, 2)
        self.assertNotEqual(err, "")

        rc, err = self.run_cli("--pull-json", str(missing_base), str(plain_file))
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

        stale_pull = self.write_fixture(
            "stale.json",
            json.dumps({"merge_base": MERGE_BASE, "body": "Base: FFmpeg master 46f23be8b197.\n"}),
        )
        rc, err = self.run_cli("--pull-json", str(stale_pull), "--live-body")
        self.assertEqual(rc, 1)
        self.assertIn("live PR body", err)

        rc, err = self.run_cli("--pull-json", str(stale_pull))
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_main_stdin_and_input_errors(self) -> None:
        """CLI stdin reading works and unreadable inputs or bad merge bases return 2."""
        payload = json.dumps(
            {"merge_base": MERGE_BASE, "body": "Base: FFmpeg master 46f23be8b197.\n"}
        )
        with unittest.mock.patch("sys.stdin", io.StringIO(payload)):
            rc, err = self.run_cli("--pull-json", "-", "--live-body")
        self.assertEqual(rc, 1)
        self.assertIn("live PR body: names base 46f23be8b197", err)

        rc, err = self.run_cli("--merge-base", MERGE_BASE, str(self.tmp / "nonexistent.md"))
        self.assertEqual(rc, 2)
        self.assertNotEqual(err, "")

        claim_file = self.write_fixture("claim.md", "Base: FFmpeg master 46f23be8b197.\n")
        rc, err = self.run_cli("--merge-base", "short", str(claim_file))
        self.assertEqual(rc, 2)
        self.assertNotEqual(err, "")

    def test_find_base_claims_commonmark_fences(self) -> None:
        """CommonMark backtick and tilde fences track marker, length, indent and info strings."""
        cases = (
            ("````text\n```\n````\nBase: aaaaaaa.\n", ["aaaaaaa"]),
            ("~~~\nBase: aaaaaaa.\n~~~\n", []),
            ("```\nBase: aaaaaaa.\n````  \nBase: bbbbbbb.\n", ["bbbbbbb"]),
            ("```\n``` text\nBase: aaaaaaa.\n```\n", []),
            ("~~~\n```\nBase: aaaaaaa.\n~~~\nBase: bbbbbbb.\n", ["bbbbbbb"]),
            ("    ```\nBase: aaaaaaa.\n", ["aaaaaaa"]),
            ("``` a`b\nBase: aaaaaaa.\n", ["aaaaaaa"]),
        )
        for sample, expected in cases:
            with self.subTest(sample=sample):
                self.assertEqual(base_claims.find_base_claims(sample), expected)

    def test_find_base_claims_clause_scoped_history_words(self) -> None:
        """History markers drop only claims in their own clause and keep later current claims."""
        compound = "Previous base: ccccccc; current base: aaaaaaa."
        self.assertEqual(base_claims.find_base_claims(compound), ["aaaaaaa"])
        self.assertEqual(base_claims.stale_claims(compound, "c" * 40), ["aaaaaaa"])
        self.assertEqual(
            base_claims.find_base_claims("Previous base: ccccccc, now base aaaaaaa"),
            ["aaaaaaa"],
        )
        self.assertEqual(
            base_claims.find_base_claims("rebased from the previous base abc1234"),
            [],
        )

    def test_main_head_option(self) -> None:
        """CLI --head checks exact 40-hex pull head.sha and rejects short or invalid heads."""
        pull_file = self.write_fixture(
            "pull.json",
            json.dumps({"head": {"sha": "a" * 40}, "merge_base": "c" * 40}),
        )
        rc, err = self.run_cli("--pull-json", str(pull_file), "--head", "a" * 40)
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

        rc, err = self.run_cli("--pull-json", str(pull_file), "--head", "A" * 40)
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

        rc, err = self.run_cli("--pull-json", str(pull_file), "--head", "b" * 40)
        self.assertEqual(rc, 3)
        self.assertIn("pull head", err)

        no_head = self.write_fixture("no_head.json", json.dumps({"merge_base": "c" * 40}))
        rc, err = self.run_cli("--pull-json", str(no_head), "--head", "a" * 40)
        self.assertEqual(rc, 2)
        self.assertNotEqual(err, "")

        rc, err = self.run_cli("--merge-base", "c" * 40, "--head", "a" * 40)
        self.assertEqual(rc, 2)
        self.assertNotEqual(err, "")

        rc, err = self.run_cli("--pull-json", str(pull_file), "--head", "xyz")
        self.assertEqual(rc, 2)
        self.assertIn("full 40-hex", err)

        rc, err = self.run_cli("--pull-json", str(pull_file), "--head", "aaaaaaa")
        self.assertEqual(rc, 2)
        self.assertIn("full 40-hex", err)

    def test_main_label_option(self) -> None:
        """CLI --label replaces the file path in stale-claim diagnostic messages."""
        stale_file = self.write_fixture("stale.md", "Base: FFmpeg master 46f23be8b197.\n")
        rc, err = self.run_cli("--merge-base", MERGE_BASE, "--label", "shown-name", str(stale_file))
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("shown-name:"), err)

    def test_dependency_examples(self) -> None:
        """Review examples and uppercase heads yield normalized dependency claims."""
        cases = (
            (
                (
                    "Depends on #25664: the first three commits are that PR's series, "
                    "currently ending at c35b0e1fce."
                ),
                [(25664, "c35b0e1fce")],
            ),
            (
                (
                    "This branch is stacked on pull request 25726 (head edd7328845e3); "
                    "only the last three commits are new here."
                ),
                [(25726, "edd7328845e3")],
            ),
            ("on top of PR #12 (head: ABCDEF1)", [(12, "abcdef1")]),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(base_claims.find_dependency_claims(text), expected)

    def test_dependency_list_pairs_each_members_own_head(self) -> None:
        """Each list reference owns only the head inside its member span."""
        for verb in ("depends on", "stacked on", "on top of", "builds on", "based on"):
            for reference in ("#13", "PR #13", "PR 13", "pull request #13", "pull request 13"):
                text = f"{verb.upper()} #12 (head AAAAAAA) and {reference.upper()} (tip bbbbbbb)"
                with self.subTest(text=text):
                    self.assertEqual(
                        base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
                    )

    def test_dependency_comma_list_pairs_each_members_own_head(self) -> None:
        """Comma and Oxford-comma lists pair each member with its own head."""
        for separator in (", ", ", and "):
            with self.subTest(separator=separator):
                self.assertEqual(
                    base_claims.find_dependency_claims(
                        f"Depends on #12 (head aaaaaaa){separator}PR #13 (head bbbbbbb)"
                    ),
                    [(12, "aaaaaaa"), (13, "bbbbbbb")],
                )

    def test_dependency_ampersand_list_pairs_each_members_own_head(self) -> None:
        """Ampersand lists pair each member with its own head."""
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12 (head aaaaaaa) & #13 (head bbbbbbb)"
            ),
            [(12, "aaaaaaa"), (13, "bbbbbbb")],
        )

    def test_dependency_list_headless_member_is_listed_without_claim(self) -> None:
        """A headless final member is listed without borrowing another member's head."""
        text = "Depends on #12 (head aaaaaaa) and #13"
        self.assertEqual(base_claims.find_dependency_claims(text), [(12, "aaaaaaa")])
        body = self.write_fixture("body.md", text)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli("--merge-base", MERGE_BASE, "--list-dependencies", str(body))
        self.assertEqual((rc, err, stdout.getvalue()), (0, "", "12\n13\n"))

    def test_dependency_list_trailing_head_is_ambiguous(self) -> None:
        """A lone trailing list head fails closed with numbers and repair instructions."""
        message = (
            r"ambiguous.*#12.*#13.*bbbbbbb.*head right after each reference"
            r".*one dependency per sentence"
        )
        for separator in (" and ", ", ", ", and ", " & "):
            with self.subTest(separator=separator), self.assertRaisesRegex(ValueError, message):
                base_claims.find_dependency_claims(f"Depends on #12{separator}#13 (head bbbbbbb)")

    def test_dependency_cli_ambiguous_list_refuses_check_and_listing(self) -> None:
        """Both CLI modes return two and explain an ambiguous trailing list head."""
        body = self.write_fixture("body.md", "Depends on #12 and #13 (head bbbbbbb)")
        dependency = self.dependency_json({"head": {"sha": "b" * 40}})
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc, err = self.run_cli(
                        "--merge-base",
                        MERGE_BASE,
                        "--dependency-json",
                        f"12={dependency}",
                        *flags,
                        str(body),
                    )
                self.assertEqual(rc, 2)
                for detail in (
                    "ambiguous",
                    "#12",
                    "#13",
                    "bbbbbbb",
                    "head right after each reference",
                    "one dependency per sentence",
                ):
                    self.assertIn(detail, err)
                self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_headless_members_count_toward_limit(self) -> None:
        """Every list member counts toward the shared distinct dependency limit."""
        text = "Depends on " + ", ".join(
            f"#{number}" for number in range(1, base_claims.MAX_DEPENDENCIES + 2)
        )
        message = f"more than {base_claims.MAX_DEPENDENCIES} distinct dependency PR numbers"
        with self.assertRaisesRegex(ValueError, message):
            base_claims.find_dependency_claims(text)
        body = self.write_fixture("body.md", text)
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                rc, err = self.run_cli("--merge-base", MERGE_BASE, *flags, str(body))
                self.assertEqual(rc, 2)
                self.assertIn(message, err)

    def test_dependency_list_lead_history_applies_to_every_member(self) -> None:
        """Lead-clause history suppresses every member's head across list commas."""
        for history in ("Previous", "prior", "earlier", "former", "old", "previously"):
            text = f"{history} dependency: depends on #12 (head aaaaaaa), #13 (head bbbbbbb)"
            with self.subTest(history=history):
                self.assertEqual(base_claims.find_dependency_claims(text), [])
                self.assertEqual(base_claims._dependency_numbers([("body", text)]), [])

    def test_dependency_list_first_member_after_history_stays_local(self) -> None:
        """History after the first member reference drops only its head and lists both members."""
        for history in ("Previous", "prior", "earlier", "former", "old", "previously"):
            text = f"Depends on #12 {history} (head aaaaaaa), #13 (head bbbbbbb)"
            with self.subTest(history=history):
                try:
                    claims = base_claims.find_dependency_claims(text)
                    numbers = base_claims._dependency_numbers([("body", text)])
                except ValueError as error:
                    self.fail(f"unexpected ValueError: {error}")
                self.assertEqual(claims, [(13, "bbbbbbb")])
                self.assertEqual(numbers, [12, 13])

    def test_dependency_list_history_is_local_to_each_members_clauses(self) -> None:
        """Member history stays local and ordinary clause breaks retain their meaning."""
        cases = (
            ("Depends on #12 (old head aaaaaaa), #13 (head bbbbbbb)", [(13, "bbbbbbb")]),
            (
                "Depends on #12 (head aaaaaaa), #13 from an earlier series (head bbbbbbb)",
                [(12, "aaaaaaa")],
            ),
            (
                "Depends on #12 (head aaaaaaa), #13 (previous head bbbbbbb, now head ccccccc)",
                [(12, "aaaaaaa"), (13, "ccccccc")],
            ),
            (
                "Previous dependency, depends on #12 (head aaaaaaa), #13 (head bbbbbbb)",
                [(12, "aaaaaaa"), (13, "bbbbbbb")],
            ),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(base_claims.find_dependency_claims(text), expected)

    def test_dependency_cli_second_list_members_stale_head_names_its_number(self) -> None:
        """A matching first head cannot hide a stale head belonging to the second member."""
        body = self.write_fixture("body.md", "Depends on #12 (head bbbbbbb) and #13 (head aaaaaaa)")
        dependency = self.dependency_json({"head": {"sha": "b" * 40}})
        rc, err = self.run_cli(
            "--merge-base",
            MERGE_BASE,
            "--dependency-json",
            f"12={dependency}",
            "--dependency-json",
            f"13={dependency}",
            str(body),
        )
        self.assertEqual(rc, 1)
        self.assertEqual(
            err, f"{body}: names head aaaaaaa of #13, the live head of #13 is {'b' * 40}\n"
        )

    def test_dependency_list_stops_before_unrelated_text(self) -> None:
        """Unrelated prose terminates list membership and its members' own head spans."""
        text = "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), unrelated #14 head ccccccc"
        self.assertEqual(
            base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
        )

    def test_dependency_list_nonmember_owns_unsupported_head(self) -> None:
        """A nearest nonmember reference owns its head even with an unsupported opener."""
        for reference in ("#14", "PR 14", "pull request 14"):
            for annotation in ("head ccccccc", "~ head ccccccc", "{head ccccccc}"):
                text = (
                    "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), "
                    f"see {reference} {annotation}"
                )
                with self.subTest(text=text):
                    self.assertEqual(
                        base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
                    )

    def test_dependency_list_unpaired_head_names_nearest_member_and_hex(self) -> None:
        """Unsupported member annotations fail closed and identify their reference and head."""
        for reference in ("#13", "PR 13", "pull request 13"):
            for annotation in ("~ head bbbbbbb", "{head bbbbbbb}"):
                text = f"Depends on #12 (head aaaaaaa) and {reference} {annotation}"
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, r"#13.*bbbbbbb"):
                    base_claims.find_dependency_claims(text)

    def test_dependency_cli_unpaired_head_names_nearest_member_and_hex(self) -> None:
        """Both CLI modes identify unpaired member heads even when both live heads match."""
        first = self.dependency_json()
        second = self.write_fixture("second.json", json.dumps({"head": {"sha": "b" * 40}}))
        for annotation in ("~ head bbbbbbb", "{head bbbbbbb}"):
            body = self.write_fixture(
                "body.md", f"Depends on #12 (head aaaaaaa) and #13 {annotation}"
            )
            for flags in ((), ("--list-dependencies",)):
                with self.subTest(annotation=annotation, flags=flags):
                    rc, err = self.run_cli(
                        "--merge-base",
                        MERGE_BASE,
                        "--dependency-json",
                        f"12={first}",
                        "--dependency-json",
                        f"13={second}",
                        *flags,
                        str(body),
                    )
                    self.assertEqual(rc, 2)
                    self.assertRegex(err, r"#13.*bbbbbbb")

    def test_dependency_list_colon_heads_belong_to_their_own_members(self) -> None:
        """A colon on either list member preserves both reference and head pairs."""
        for text in (
            "Depends on #12: head aaaaaaa and #13 (head bbbbbbb)",
            "Depends on #12 (head aaaaaaa) and #13: head bbbbbbb",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
                )

    def test_dependency_cli_colon_heads_list_both_members(self) -> None:
        """Listing prints both dependency numbers with a colon on either member."""
        for text in (
            "Depends on #12: head aaaaaaa and #13 (head bbbbbbb)",
            "Depends on #12 (head aaaaaaa) and #13: head bbbbbbb",
        ):
            with self.subTest(text=text):
                body = self.write_fixture("body.md", text)
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc, err = self.run_cli(
                        "--merge-base", MERGE_BASE, "--list-dependencies", str(body)
                    )
                self.assertEqual((rc, err, stdout.getvalue()), (0, "", "12\n13\n"))

    def test_dependency_cli_colon_heads_reject_stale_second_member(self) -> None:
        """A matching first head cannot hide stale member thirteen across a colon."""
        dependency = self.dependency_json()
        for text in (
            "Depends on #12: head aaaaaaa and #13 (head bbbbbbb)",
            "Depends on #12 (head aaaaaaa) and #13: head bbbbbbb",
        ):
            with self.subTest(text=text):
                body = self.write_fixture("body.md", text)
                rc, err = self.run_cli(
                    "--merge-base",
                    MERGE_BASE,
                    "--dependency-json",
                    f"12={dependency}",
                    "--dependency-json",
                    f"13={dependency}",
                    str(body),
                )
                self.assertEqual(rc, 1)
                self.assertEqual(
                    err, f"{body}: names head bbbbbbb of #13, the live head of #13 is {'a' * 40}\n"
                )

    def test_dependency_single_colon_head_is_preserved(self) -> None:
        """A single colon-separated dependency head retains its original pairing."""
        self.assertEqual(
            base_claims.find_dependency_claims("Depends on #12: head aaaaaaa"), [(12, "aaaaaaa")]
        )

    def test_dependency_single_dash_and_bracket_heads_are_preserved(self) -> None:
        """Single dash and bracket heads retain their existing reference pairing."""
        for annotation in ("- head bbbbbbb", "[head bbbbbbb]"):
            with self.subTest(annotation=annotation):
                self.assertEqual(
                    base_claims.find_dependency_claims(f"Depends on #13 {annotation}"),
                    [(13, "bbbbbbb")],
                )

    def test_dependency_list_member_openers_pair_both_positions(self) -> None:
        """Every supported opener attributes heads to its own member in either position."""
        for annotation in (
            ": head {}",
            "- head {}",
            "\u2013 head {}",
            "\u2014 head {}",
            "[head {}]",
        ):
            for text in (
                "Depends on #12 (head aaaaaaa) and #13 " + annotation.format("bbbbbbb"),
                "Depends on #12 " + annotation.format("aaaaaaa") + " and #13 (head bbbbbbb)",
            ):
                with self.subTest(text=text):
                    self.assertEqual(
                        base_claims._dependency_records(text),
                        [(12, None), (12, "aaaaaaa"), (13, None), (13, "bbbbbbb")],
                    )

    def test_dependency_list_dash_first_does_not_borrow_second_head(self) -> None:
        """A first-member dash cannot consume the following member's distinct head."""
        text = "Depends on #12 - head aaaaaaa and #13 (head ccccccc)"
        self.assertEqual(
            base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "ccccccc")]
        )
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12, 13])

    def test_dependency_cli_member_openers_list_both_members(self) -> None:
        """Listing preserves both members with dash or bracket annotations."""
        for annotation in ("- head {}", "\u2013 head {}", "\u2014 head {}", "[head {}]"):
            for text in (
                "Depends on #12 (head aaaaaaa) and #13 " + annotation.format("bbbbbbb"),
                "Depends on #12 " + annotation.format("aaaaaaa") + " and #13 (head ccccccc)",
            ):
                with self.subTest(text=text):
                    body = self.write_fixture("body.md", text)
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        rc, err = self.run_cli(
                            "--merge-base", MERGE_BASE, "--list-dependencies", str(body)
                        )
                    self.assertEqual((rc, err, stdout.getvalue()), (0, "", "12\n13\n"))

    def test_dependency_cli_member_openers_reject_stale_second_head(self) -> None:
        """A current first member cannot hide a stale dash or bracket second member."""
        dependency = self.dependency_json()
        for annotation in ("- head bbbbbbb", "\u2013 head bbbbbbb", "[head bbbbbbb]"):
            with self.subTest(annotation=annotation):
                body = self.write_fixture(
                    "body.md", f"Depends on #12 (head aaaaaaa) and #13 {annotation}"
                )
                rc, err = self.run_cli(
                    "--merge-base",
                    MERGE_BASE,
                    "--dependency-json",
                    f"12={dependency}",
                    "--dependency-json",
                    f"13={dependency}",
                    str(body),
                )
                self.assertEqual(rc, 1)
                self.assertIn("names head bbbbbbb of #13", err)

    def test_dependency_list_dash_members_count_toward_limit(self) -> None:
        """A dash on the first member cannot hide eight members from the bound."""
        members = "Depends on #1 - head aaaaaaa, " + ", ".join(f"#{n}" for n in range(2, 9))
        self.assertEqual(base_claims._dependency_numbers([("body", members)]), list(range(1, 9)))
        text = members + ", #9"
        message = "more than 8 distinct dependency PR numbers"
        with self.assertRaisesRegex(ValueError, message):
            base_claims.find_dependency_claims(text)
        body = self.write_fixture("body.md", text)
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                rc, err = self.run_cli("--merge-base", MERGE_BASE, *flags, str(body))
                self.assertEqual(rc, 2)
                self.assertIn(message, err)

    def test_dependency_list_unpaired_current_heads_fail_closed(self) -> None:
        """Unknown tilde and brace openers cannot silently discard current list heads."""
        for annotation in ("~ head bbbbbbb", "{head bbbbbbb}"):
            text = f"Depends on #12 (head aaaaaaa) and #13 {annotation}"
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, r"#12.*#13"):
                base_claims.find_dependency_claims(text)

    def test_dependency_cli_unpaired_current_heads_fail_closed(self) -> None:
        """Both CLI modes refuse unpaired current heads even with matching live heads."""
        dependency = self.dependency_json()
        for annotation in ("~ head aaaaaaa", "{head aaaaaaa}"):
            body = self.write_fixture(
                "body.md", f"Depends on #12 (head aaaaaaa) and #13 {annotation}"
            )
            for flags in ((), ("--list-dependencies",)):
                with self.subTest(annotation=annotation, flags=flags):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        rc, err = self.run_cli(
                            "--merge-base",
                            MERGE_BASE,
                            "--dependency-json",
                            f"12={dependency}",
                            "--dependency-json",
                            f"13={dependency}",
                            *flags,
                            str(body),
                        )
                    self.assertEqual(rc, 2)
                    self.assertIn("#12", err)
                    self.assertIn("#13", err)
                    self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_hidden_members_fail_closed(self) -> None:
        """A single-member fallback rejects separator-led references hidden by an opener."""
        text = "Depends on #12 ~ head aaaaaaa, #13"
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims(text)

    def test_dependency_cli_hidden_members_fail_closed(self) -> None:
        """Hidden fallback members return two in both CLI modes with matching live heads."""
        body = self.write_fixture("body.md", "Depends on #12 ~ head aaaaaaa, #13")
        dependency = self.dependency_json()
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc, err = self.run_cli(
                        "--merge-base",
                        MERGE_BASE,
                        "--dependency-json",
                        f"12={dependency}",
                        *flags,
                        str(body),
                    )
                self.assertEqual(rc, 2)
                self.assertIn("#12", err)
                self.assertIn("#13", err)
                self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_first_annotation_rejects_hidden_word_members(self) -> None:
        """Word-form members inside the first annotation cannot be silently discarded."""
        for annotation in (
            "(head aaaaaaa, and PR 13 head bbbbbbb)",
            "(head aaaaaaa, PR 13 head bbbbbbb)",
            "[head aaaaaaa, and pull request 13 head bbbbbbb]",
            "(head aaaaaaa, and PR 13)",
        ):
            with (
                self.subTest(annotation=annotation),
                self.assertRaisesRegex(ValueError, r"#12.*#13"),
            ):
                base_claims.find_dependency_claims(f"Depends on #12 {annotation}.")

    def test_dependency_cli_first_annotation_rejects_hidden_word_members(self) -> None:
        """Both modes reject hidden first-annotation members with empty stdout."""
        dependency = self.dependency_json()
        options = [
            arg for number in (12, 13) for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        for annotation in (
            "(head aaaaaaa, and PR 13 head bbbbbbb)",
            "(head aaaaaaa, PR 13 head bbbbbbb)",
            "[head aaaaaaa, and pull request 13 head bbbbbbb]",
            "(head aaaaaaa, and PR 13)",
        ):
            body = self.write_fixture("body.md", f"Depends on #12 {annotation}.")
            for flags in ((), ("--list-dependencies",)):
                with self.subTest(annotation=annotation, flags=flags):
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        rc, err = self.run_cli(
                            "--merge-base", MERGE_BASE, *options, *flags, str(body)
                        )
                    self.assertEqual(rc, 2)
                    self.assertRegex(err, r"#12.*#13")
                    self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_later_annotation_rejects_hidden_word_member(self) -> None:
        """A word-form member hidden in a later annotation names all window references."""
        text = "Depends on #12 (head aaaaaaa), #13 (head bbbbbbb, and PR 14 head ccccccc)."
        with self.assertRaisesRegex(ValueError, r"#12.*#13.*#14"):
            base_claims.find_dependency_claims(text)

    def test_dependency_cli_later_annotation_rejects_hidden_word_member(self) -> None:
        """Both modes reject hidden later-annotation members with empty stdout."""
        body = self.write_fixture(
            "body.md",
            "Depends on #12 (head aaaaaaa), #13 (head bbbbbbb, and PR 14 head ccccccc).",
        )
        dependency = self.dependency_json()
        options = [
            arg
            for number in (12, 13, 14)
            for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc, err = self.run_cli("--merge-base", MERGE_BASE, *options, *flags, str(body))
                self.assertEqual(rc, 2)
                self.assertRegex(err, r"#12.*#13.*#14")
                self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_truncated_middle_member_rejects_hidden_tail(self) -> None:
        """A truncated multi-member list rejects later members with their full attribution."""
        for annotation in (": aaaaaaa", " ~ previous head aaaaaaa"):
            text = f"Depends on #12 (head aaaaaaa), #13{annotation}, #14 (head bbbbbbb)"
            with (
                self.subTest(annotation=annotation),
                self.assertRaisesRegex(ValueError, r"#12.*#13.*#14"),
            ):
                base_claims.find_dependency_claims(text)

    def test_dependency_cli_truncated_middle_member_rejects_hidden_tail(self) -> None:
        """Both modes reject hidden tails even when all supplied live heads match."""
        dependency = self.dependency_json()
        options = [
            arg
            for number in (12, 13, 14)
            for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        for annotation in (": aaaaaaa", " ~ previous head aaaaaaa"):
            for head in ("aaaaaaa", "bbbbbbb"):
                body = self.write_fixture(
                    "body.md", f"Depends on #12 (head aaaaaaa), #13{annotation}, #14 (head {head})"
                )
                for flags in ((), ("--list-dependencies",)):
                    with self.subTest(annotation=annotation, head=head, flags=flags):
                        stdout = io.StringIO()
                        with contextlib.redirect_stdout(stdout):
                            rc, err = self.run_cli(
                                "--merge-base", MERGE_BASE, *options, *flags, str(body)
                            )
                        self.assertEqual(rc, 2)
                        self.assertRegex(err, r"#12.*#13.*#14")
                        self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_truncated_nine_members_fail_closed(self) -> None:
        """A truncated second member cannot hide a list beyond the eight-member bound."""
        text = "Depends on #1 (head aaaaaaa), #2: aaaaaaa, " + ", ".join(
            f"#{number} (head bbbbbbb)" for number in range(3, 10)
        )
        with self.assertRaisesRegex(ValueError, r"#1.*#2.*#9"):
            base_claims.find_dependency_claims(text)

    def test_dependency_cli_truncated_nine_members_fail_closed(self) -> None:
        """Both modes reject hidden excess members instead of listing only the first two."""
        text = "Depends on #1 (head aaaaaaa), #2: aaaaaaa, " + ", ".join(
            f"#{number} (head bbbbbbb)" for number in range(3, 10)
        )
        body = self.write_fixture("body.md", text)
        dependency = self.dependency_json()
        options = [
            arg for number in (1, 2) for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc, err = self.run_cli("--merge-base", MERGE_BASE, *options, *flags, str(body))
                self.assertEqual(rc, 2)
                self.assertRegex(err, r"#1.*#2.*#9")
                self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_marked_middle_member_preserves_third_claim(self) -> None:
        """A supported middle annotation keeps all three members paired with their heads."""
        text = "Depends on #12 (head aaaaaaa), #13: head aaaaaaa, #14 (head bbbbbbb)"
        self.assertEqual(
            base_claims.find_dependency_claims(text),
            [(12, "aaaaaaa"), (13, "aaaaaaa"), (14, "bbbbbbb")],
        )

    def test_dependency_cli_marked_middle_member_checks_stale_third(self) -> None:
        """Check mode still names the stale third member after a supported middle annotation."""
        body = self.write_fixture(
            "body.md", "Depends on #12 (head aaaaaaa), #13: head aaaaaaa, #14 (head bbbbbbb)"
        )
        dependency = self.dependency_json()
        options = [
            arg
            for number in (12, 13, 14)
            for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli("--merge-base", MERGE_BASE, *options, str(body))
        self.assertEqual(rc, 1)
        self.assertIn("head bbbbbbb of #14", err)
        self.assertEqual(stdout.getvalue(), "")

    def test_dependency_list_nonmember_prose_keeps_two_claims(self) -> None:
        """Separator-led prose without a leading member remains a nonmember boundary."""
        for tail in ("unrelated #14 head ccccccc", "see #14 ~ head ccccccc", "unrelated text"):
            text = f"Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), {tail}"
            with self.subTest(tail=tail):
                self.assertEqual(
                    base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
                )

    def test_dependency_list_history_precedes_trailing_head_ambiguity(self) -> None:
        """Historical reference and head clauses are ignored before ambiguity checks."""
        for text in (
            "Previously depends on #12 and #13 (head bbbbbbb)",
            "Depends on #12 and #13 (previous head bbbbbbb)",
        ):
            with self.subTest(text=text):
                self.assertEqual(base_claims.find_dependency_claims(text), [])

    def test_dependency_list_see_prose_does_not_hide_later_and_members(self) -> None:
        """Unrelated prose after parsed members ends the hidden-member scan at , see."""
        text = (
            "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), see #14 and #15 for benchmarks."
        )
        self.assertEqual(
            base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
        )

    def test_dependency_list_hidden_member_before_see_prose_still_raises(self) -> None:
        """A hidden truncated member before see prose still fails closed."""
        text = (
            "Depends on #12 (head aaaaaaa), #13: aaaaaaa, #14 (head bbbbbbb), see #15 for context."
        )
        with self.assertRaisesRegex(ValueError, r"#12.*#13.*#14"):
            base_claims.find_dependency_claims(text)

    def test_dependency_list_historical_lead_skips_hidden_truncated_members(self) -> None:
        """A Previously lead is historical first; truncated list yields no claims or numbers."""
        text = "Previously stacked on #12 ~ head aaaaaaa, #13 (head bbbbbbb)."
        self.assertEqual(base_claims.find_dependency_claims(text), [])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [])

    def test_dependency_list_historical_lead_without_heads_yields_no_member_numbers(self) -> None:
        """Headless historical lists emit no claims and no numbers to fetch."""
        text = "Previously stacked on #12 and #13."
        self.assertEqual(base_claims.find_dependency_claims(text), [])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [])

    def test_dependency_list_truncated_without_historical_lead_still_raises(self) -> None:
        """The truncated middle form without Previously still fails closed."""
        text = "Depends on #12 ~ head aaaaaaa, #13 (head bbbbbbb)."
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims(text)

    def test_dependency_list_bracketed_old_is_local_to_one_member(self) -> None:
        """Bracketed old on one member drops only that head and keeps later members."""
        text = "Depends on #12 [old head aaaaaaa], #13 [head bbbbbbb]"
        self.assertEqual(base_claims.find_dependency_claims(text), [(13, "bbbbbbb")])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12, 13])

    def test_dependency_bracket_history_drops_previous_keeps_now_head(self) -> None:
        """Bracket history stops at an inner comma and the later head stays current."""
        text = "Depends on #12 [previous head aaaaaaa, now head bbbbbbb]."
        self.assertEqual(base_claims.find_dependency_claims(text), [(12, "bbbbbbb")])

    def test_dependency_bracketed_historical_lead_yields_no_claims(self) -> None:
        """A bracketed historical lead still yields no dependency claims."""
        text = "Previously stacked on #12 [head aaaaaaa]."
        self.assertEqual(base_claims.find_dependency_claims(text), [])

    def test_dependency_split_lead_claims_only_the_current_depends_on(self) -> None:
        """A later depends-on lead keeps its head without inheriting Earlier lead history."""
        text = "Previously stacked on #12 and now depends on #13 (head bbbbbbb)."
        self.assertEqual(base_claims.find_dependency_claims(text), [(13, "bbbbbbb")])

    def test_dependency_split_historical_and_without_heads_is_quiet(self) -> None:
        """Previously stacked on two members without heads still emits nothing."""
        text = "Previously stacked on #12 and #13."
        self.assertEqual(base_claims.find_dependency_claims(text), [])

    def test_dependency_and_lists_both_numbers_without_heads(self) -> None:
        """Depends on #12 and #13 still records both members with no head claims."""
        text = "Depends on #12 and #13."
        self.assertEqual(base_claims.find_dependency_claims(text), [])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12, 13])

    def test_dependency_hidden_member_inside_annotation_raises(self) -> None:
        """A member number inside another member's annotation fails closed."""
        text = "Depends on #12 (head aaaaaaa, rebased, and #13 head bbbbbbb)."
        with self.assertRaisesRegex(ValueError, r"#13"):
            base_claims.find_dependency_claims(text)

    def test_dependency_see_prose_outside_annotation_lists_both_heads(self) -> None:
        """Closed annotations and see-prose tails keep two explicit member heads."""
        text = (
            "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb), see #14 and #15 for benchmarks."
        )
        self.assertEqual(
            base_claims.find_dependency_claims(text), [(12, "aaaaaaa"), (13, "bbbbbbb")]
        )

    def test_dependency_bracket_depths_nested_brackets(self) -> None:
        """Bracket depth increases inside nested openers and returns after closes."""
        depths = base_claims._dependency_bracket_depths("a[(b)c]")
        self.assertEqual(depths[3], 2)
        self.assertEqual(depths[len("a[(b)c]")], 0)

    def test_dependency_bracket_depths_unclosed_bracket(self) -> None:
        """An unclosed opener keeps depth past an inner comma through sentence end."""
        text = "open (still, more"
        depths = base_claims._dependency_bracket_depths(text)
        comma = text.index(",")
        self.assertEqual(depths[comma + 1], 1)
        self.assertGreater(depths[len(text)], 0)

    def test_dependency_bracket_depths_stray_close(self) -> None:
        """A stray closer does not drive depth below zero."""
        depths = base_claims._dependency_bracket_depths("x)y")
        self.assertEqual(depths[2], 0)

    def test_dependency_nested_bracket_annotation_rejects_hidden_member(self) -> None:
        """An inner bracket inside an annotation does not shorten hidden-member rejection."""
        text = "Depends on #12 ([notes], and #13 head bbbbbbb)."
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims(text)
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims._dependency_numbers([("body", text)])

    def test_dependency_closed_nested_annotation_stops_at_see_prose(self) -> None:
        """A closed nested annotation keeps its claim while flat hidden prose still fails."""
        boundary = "Depends on #12 (head aaaaaaa [rebased]), see #14 for benchmarks."
        self.assertEqual(base_claims.find_dependency_claims(boundary), [(12, "aaaaaaa")])
        self.assertEqual(base_claims._dependency_numbers([("body", boundary)]), [12])
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims("Depends on #12 (notes, and #13 head bbbbbbb).")

    def test_dependency_truncated_list_joined_by_and_raises(self) -> None:
        """A truncated list joined by and rejects the hidden following member."""
        text = "Depends on #12 ~ head aaaaaaa and #13 (head bbbbbbb)."
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims(text)
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims._dependency_numbers([("body", text)])

    def test_dependency_truncated_list_joined_by_ampersand_raises(self) -> None:
        """A truncated list joined by ampersand rejects the hidden following member."""
        text = "Depends on #12 ~ head aaaaaaa & #13 (head bbbbbbb)."
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims.find_dependency_claims(text)
        with self.assertRaisesRegex(ValueError, r"#12.*#13"):
            base_claims._dependency_numbers([("body", text)])

    def test_dependency_truncated_list_continuation_without_brackets_raises(self) -> None:
        """Truncated continuations across and or ampersand fail without outer brackets."""
        cases = (
            ("Depends on #12 ~ head aaaaaaa and #13.", r"#12.*#13"),
            ("Depends on #12 ~ head aaaaaaa & #13.", r"#12.*#13"),
            ("Depends on #12 (head aaaaaaa), #13: aaaaaaa and #14 (head bbbbbbb).", r"#12.*#14"),
            ("Depends on #12 ~ [notes, see more] and #13 (head bbbbbbb).", r"#12.*#13"),
        )
        for text, pattern in cases:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, pattern):
                base_claims.find_dependency_claims(text)

    def test_dependency_separator_prose_stops_and_valid_and_member(self) -> None:
        """Prose after comma or and stops the list while valid and members claim both."""
        for text in (
            "Depends on #12 (head aaaaaaa), see #14 for benchmarks.",
            "Depends on #12 (head aaaaaaa) and see #14 for benchmarks.",
        ):
            with self.subTest(text=text):
                self.assertEqual(base_claims.find_dependency_claims(text), [(12, "aaaaaaa")])
                self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12])
        both = "Depends on #12 (head aaaaaaa) and #13 (head bbbbbbb)."
        self.assertEqual(
            base_claims.find_dependency_claims(both), [(12, "aaaaaaa"), (13, "bbbbbbb")]
        )
        self.assertEqual(base_claims._dependency_numbers([("body", both)]), [12, 13])

    def test_dependency_separated_member_helper(self) -> None:
        """The shared separator helper distinguishes members, prose, brackets and empty tails."""
        for separator in (", ", " and ", " & ", ", and "):
            sample = f"Depends on #12{separator}#13"
            depths = base_claims._dependency_bracket_depths(sample)
            match = base_claims._dependency_separated_member(sample, depths, 14, len(sample))
            self.assertEqual(None if match is None else match.group(1), "13")
        for prose in ("Depends on #12, see #14 and #15", "Depends on #12 and see #14"):
            depths = base_claims._dependency_bracket_depths(prose)
            self.assertIsNone(
                base_claims._dependency_separated_member(prose, depths, 14, len(prose))
            )
        bracketed = "Depends on #12 (notes, and #13"
        depths = base_claims._dependency_bracket_depths(bracketed)
        self.assertIsNone(
            base_claims._dependency_separated_member(bracketed, depths, 14, len(bracketed))
        )
        empty = "Depends on #12"
        depths = base_claims._dependency_bracket_depths(empty)
        self.assertIsNone(
            base_claims._dependency_separated_member(empty, depths, len(empty), len(empty))
        )

    def test_dependency_comma_previously_before_later_lead_is_historical(self) -> None:
        """A comma-separated previously marker before a later lead suppresses its head."""
        text = "Depends on #12 (head aaaaaaa), previously stacked on #13 (head bbbbbbb)."
        self.assertEqual(base_claims.find_dependency_claims(text), [(12, "aaaaaaa")])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12])

    def test_dependency_semicolon_previously_before_later_lead_is_historical(self) -> None:
        """A semicolon-separated previously marker before a later lead suppresses its head."""
        text = "Depends on #12 (head aaaaaaa); previously stacked on #13 (head bbbbbbb)."
        self.assertEqual(base_claims.find_dependency_claims(text), [(12, "aaaaaaa")])
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12])
        self.assertEqual(base_claims._sentence_dependencies(text), [(12, "aaaaaaa")])

    def test_dependency_later_current_lead_keeps_claim_after_first_lead(self) -> None:
        """Later coordinated current leads keep their claims without inheriting first history."""
        both = "Depends on #12 (head aaaaaaa), and now depends on #13 (head bbbbbbb)."
        self.assertEqual(
            base_claims.find_dependency_claims(both), [(12, "aaaaaaa"), (13, "bbbbbbb")]
        )
        self.assertEqual(base_claims._dependency_numbers([("body", both)]), [12, 13])
        split = "Previously stacked on #12 and now depends on #13 (head bbbbbbb)."
        self.assertEqual(base_claims.find_dependency_claims(split), [(13, "bbbbbbb")])
        self.assertEqual(base_claims._dependency_numbers([("body", split)]), [13])

    def test_dependency_list_current_depends_on_two_members_unchanged(self) -> None:
        """Depends on #12 and #13 still lists both numbers without a historical lead."""
        text = "Depends on #12 and #13."
        self.assertEqual(base_claims._dependency_numbers([("body", text)]), [12, 13])

    def test_dependency_cli_historical_lists_need_no_dependency_json(self) -> None:
        """Historical lists pass check mode without any live dependency JSON mappings."""
        for text in ("Previously depends on #12 and #13 (head bbbbbbb)",):
            with self.subTest(text=text):
                body = self.write_fixture("body.md", text)
                rc, err = self.run_cli("--merge-base", MERGE_BASE, str(body))
                self.assertEqual((rc, err), (0, ""))

    def test_dependency_cli_trailing_historical_head_lists_members(self) -> None:
        """A trailing historical head still requires dependency JSON and lists both members."""
        body = self.write_fixture("body.md", "Depends on #12 and #13 (previous head bbbbbbb)")
        self.assertEqual(
            self.run_cli("--merge-base", MERGE_BASE, str(body)),
            (2, "base_claims: missing --dependency-json for #12\n"),
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli("--merge-base", MERGE_BASE, "--list-dependencies", str(body))
        self.assertEqual((rc, err, stdout.getvalue()), (0, "", "12\n13\n"))

    def test_dependency_list_limit_boundary_and_duplicate_members(self) -> None:
        """Exactly the distinct limit and repeated list members remain accepted."""
        references = [f"#{number}" for number in range(1, base_claims.MAX_DEPENDENCIES + 1)]
        text = "Depends on " + ", ".join([*references, "#1"])
        body = self.write_fixture("body.md", text)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli("--merge-base", MERGE_BASE, "--list-dependencies", str(body))
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(stdout.getvalue(), "".join(f"{n}\n" for n in range(1, 9)))

    def test_dependency_list_head_markers_and_parenthesized_hashes(self) -> None:
        """List annotations accept every head marker and parenthesized uppercase hashes."""
        for marker in ("head", "ending at", "ends at", "tip"):
            for span in (f"{marker}: (AAAAAAA)", f"({marker}: (AAAAAAA))"):
                with self.subTest(span=span):
                    self.assertEqual(
                        base_claims.find_dependency_claims(
                            f"Depends on #12 {span}, #13 (head bbbbbbb)"
                        ),
                        [(12, "aaaaaaa"), (13, "bbbbbbb")],
                    )

    def test_dependency_exclamation_sentence_break(self) -> None:
        """An exclamation sentence break prevents associating a later unrelated head."""
        self.assertEqual(
            base_claims.find_dependency_claims("Depends on #12! This PR has head bbbbbbb."), []
        )

    def test_dependency_question_sentence_break(self) -> None:
        """A question sentence break prevents associating a later unrelated head."""
        self.assertEqual(
            base_claims.find_dependency_claims("Depends on #12? This PR has head bbbbbbb."), []
        )

    def test_dependency_head_before_exclamation_break(self) -> None:
        """A head inside the dependency sentence survives a later exclamation break."""
        self.assertEqual(
            base_claims.find_dependency_claims("Depends on #12 (head abcdef1)! Next sentence."),
            [(12, "abcdef1")],
        )

    def test_dependency_current_head_after_previous_clause(self) -> None:
        """A previous head clause does not suppress a current head after a comma."""
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12 (previous head aaaaaaa, now head bbbbbbb)"
            ),
            [(12, "bbbbbbb")],
        )

    def test_dependency_current_head_after_old_parenthesis(self) -> None:
        """An old parenthesized head does not suppress a later current head."""
        self.assertEqual(
            base_claims.find_dependency_claims("Depends on #12 (old head aaaaaaa) at head bbbbbbb"),
            [(12, "bbbbbbb")],
        )

    def test_dependency_historical_reference(self) -> None:
        """A historical reference suppresses a head in the same clause."""
        self.assertEqual(
            base_claims.find_dependency_claims("previously stacked on #12 at head abcdef1"), []
        )

    def test_dependency_history_after_reference_before_parenthesis(self) -> None:
        """History after the reference suppresses a head in a later parenthesized clause."""
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12 from an earlier series (head abcdef1)"
            ),
            [],
        )

    def test_dependency_current_head_after_previously_clause(self) -> None:
        """Previously in an intermediate head clause does not suppress the current head."""
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12, previously at head aaaaaaa, now head bbbbbbb"
            ),
            [(12, "bbbbbbb")],
        )

    def test_dependency_cli_current_head_after_history(self) -> None:
        """The CLI checks the current head after history against the live dependency head."""
        body = self.write_fixture(
            "body.md", "Depends on #12 (previous head aaaaaaa, now head bbbbbbb)."
        )
        for live_head, expected_rc in (("a" * 40, 1), ("b" * 40, 0)):
            with self.subTest(live_head=live_head):
                dependency = self.dependency_json({"head": {"sha": live_head}})
                rc, err = self.run_cli(
                    "--merge-base", MERGE_BASE, "--dependency-json", f"12={dependency}", str(body)
                )
                self.assertEqual(rc, expected_rc)
                if expected_rc:
                    self.assertIn("names head bbbbbbb of #12", err)
                else:
                    self.assertEqual(err, "")

    def test_dependency_reference_and_head_forms(self) -> None:
        """All dependency verbs, reference forms and head markers are recognized."""
        for verb in ("depends on", "stacked on", "on top of", "builds on", "based on"):
            for reference in ("#12", "PR 12", "PR #12", "pull request 12", "pull request #12"):
                for marker in ("head", "ending at", "ends at", "tip"):
                    text = f"{verb.upper()} {reference} {marker}: (ABCDEF1)"
                    with self.subTest(text=text):
                        self.assertEqual(
                            base_claims.find_dependency_claims(text), [(12, "abcdef1")]
                        )

    def test_dependency_exclusions(self) -> None:
        """Sentence boundaries, missing markers, fences, quotes and history exclude claims."""
        cases = (
            "Depends on #12. Head abcdef1",
            "Depends on #12; head abcdef1",
            "Depends on #12\nhead abcdef1",
            "Depends on #12 at abcdef1",
            "```text\nDepends on #12 head abcdef1\n```",
            "~~~\nDepends on #12 head abcdef1\n~~~",
            "> Depends on #12 head abcdef1",
            "previously stacked on #12 at head abcdef1",
            "Previous dependency: stacked on #12 (head abcdef1)",
            "depends on #12 at old head abcdef1",
            "depends on #12345678 head abcdef1",
            "depends on #0 head abcdef1",
            "depends on #12 head abcdef",
            "depends on #12 head " + "a" * 41,
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(base_claims.find_dependency_claims(text), [])

    def test_dependency_and_base_extraction_share_filtering(self) -> None:
        """Both claim kinds share fence tracking without changing base extraction."""
        text = (
            "````text\n```\nDepends on #1 head aaaaaaa; base aaaaaaa\n````\n"
            "> Depends on #2 head bbbbbbb; base bbbbbbb\n"
            "Depends on #12 head abcdef1; base ccccccc\n"
            "Previous base aaaaaaa, now base ddddddd\n"
        )
        self.assertEqual(base_claims.find_dependency_claims(text), [(12, "abcdef1")])
        self.assertEqual(base_claims.find_base_claims(text), ["ccccccc", "ddddddd"])

    def dependency_json(self, payload: object | None = None) -> Path:
        """Write a dependency pull fixture with a full head unless overridden."""
        return self.write_fixture(
            "dependency.json",
            json.dumps({"head": {"sha": "a" * 40}} if payload is None else payload),
        )

    def test_dependency_cli_stale_head(self) -> None:
        """A stale dependency prefix reports both claimed and live heads with exit one."""
        body = self.write_fixture("body.md", "Depends on #12 head bbbbbbb")
        dependency = self.dependency_json()
        rc, err = self.run_cli(
            "--merge-base", MERGE_BASE, "--dependency-json", f"12={dependency}", str(body)
        )
        self.assertEqual(rc, 1)
        self.assertEqual(
            err, f"{body}: names head bbbbbbb of #12, the live head of #12 is {'a' * 40}\n"
        )

    def test_dependency_cli_current_prefix(self) -> None:
        """A dependency prefix matches a full uppercase live head with exit zero."""
        body = self.write_fixture("body.md", "stacked on pull request #12 (head AAAAAAA)")
        dependency = self.dependency_json({"head": {"sha": "A" * 40}})
        rc, err = self.run_cli(
            "--merge-base", MERGE_BASE, "--dependency-json", f"12={dependency}", str(body)
        )
        self.assertEqual((rc, err), (0, ""))

    def test_dependency_cli_missing_pull(self) -> None:
        """A dependency claim without supplied pull JSON fails closed and names its PR."""
        body = self.write_fixture("body.md", "Depends on #12 head aaaaaaa")
        rc, err = self.run_cli("--merge-base", MERGE_BASE, str(body))
        self.assertEqual(rc, 2)
        self.assertIn("#12", err)

    def test_dependency_cli_missing_json_file_names_path(self) -> None:
        """A supplied dependency JSON path that does not exist returns two with its path."""
        body = self.write_fixture("body.md", "Depends on #12 head aaaaaaa")
        missing = self.tmp / "missing-dependency.json"
        rc, err = self.run_cli(
            "--merge-base", MERGE_BASE, "--dependency-json", f"12={missing}", str(body)
        )
        self.assertEqual(rc, 2)
        self.assertIn(str(missing), err)

    def test_dependency_cli_json_directory_names_path(self) -> None:
        """A directory supplied as dependency JSON returns two and identifies the path."""
        body = self.write_fixture("body.md", "Depends on #12 head aaaaaaa")
        rc, err = self.run_cli(
            "--merge-base", MERGE_BASE, "--dependency-json", f"12={self.tmp}", str(body)
        )
        self.assertEqual(rc, 2)
        self.assertIn(str(self.tmp), err)

    def test_dependency_cli_malformed_option(self) -> None:
        """Malformed dependency mappings and stdin paths return input errors."""
        for value in ("12", "x=file", "0=file", "-1=file", "12345678=file", "12=", "12=-"):
            with self.subTest(value=value):
                rc, err = self.run_cli("--merge-base", MERGE_BASE, f"--dependency-json={value}")
                self.assertEqual(rc, 2)
                self.assertIn("N=PATH", err)
        with self.subTest(separated="x=file"):
            rc, err = self.run_cli("--merge-base", MERGE_BASE, "--dependency-json", "x=file")
            self.assertEqual(rc, 2)
            self.assertIn("N=PATH", err)

    def test_dependency_cli_repeated_number(self) -> None:
        """Repeated dependency PR options are rejected even for the same file."""
        dependency = self.dependency_json()
        rc, err = self.run_cli(
            "--merge-base",
            MERGE_BASE,
            "--dependency-json",
            f"12={dependency}",
            "--dependency-json",
            f"012={dependency}",
        )
        self.assertEqual(rc, 2)
        self.assertIn("repeated", err)
        self.assertIn("#12", err)

    def test_dependency_cli_bad_head(self) -> None:
        """Missing, nonstring, short and nonhex dependency heads fail closed."""
        payloads = [{}, {"head": []}, {"head": {}}] + [
            {"head": {"sha": value}} for value in (None, 123, "a" * 7, "g" * 40, "a" * 41)
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                dependency = self.dependency_json(payload)
                rc, err = self.run_cli(
                    "--merge-base", MERGE_BASE, "--dependency-json", f"12={dependency}"
                )
                self.assertEqual(rc, 2)
                self.assertIn("#12", err)

    def test_dependency_cli_non_object_json(self) -> None:
        """A dependency pull JSON array is an input error even without claims."""
        dependency = self.dependency_json([])
        rc, err = self.run_cli("--merge-base", MERGE_BASE, "--dependency-json", f"12={dependency}")
        self.assertEqual(rc, 2)
        self.assertIn("object", err)

    def test_dependency_cli_list_sorted_unique(self) -> None:
        """Dependency listing merges live and file bodies in sorted unique order."""
        body = self.write_fixture(
            "body.md", "Depends on #12 head aaaaaaa\nBuilds on PR 2 tip bbbbbbb"
        )
        pull = self.write_fixture(
            "pull.json",
            json.dumps(
                {
                    "head": {"sha": "d" * 40},
                    "body": "Based on #3 ends at ccccccc\nDepends on #12 head aaaaaaa",
                }
            ),
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli(
                "--pull-json",
                str(pull),
                "--head",
                "d" * 40,
                "--live-body",
                "--list-dependencies",
                str(body),
            )
        self.assertEqual((rc, err, stdout.getvalue()), (0, "", "2\n3\n12\n"))

    def test_dependency_cli_list_head_mismatch(self) -> None:
        """Dependency listing still refuses a mismatched tested pull head."""
        pull = self.write_fixture("pull.json", json.dumps({"head": {"sha": "d" * 40}}))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc, err = self.run_cli(
                "--pull-json", str(pull), "--head", "a" * 40, "--list-dependencies"
            )
        self.assertEqual(rc, 3)
        self.assertIn("pull head", err)
        self.assertEqual(stdout.getvalue(), "")

    def test_dependency_cli_list_input_error(self) -> None:
        """Dependency listing validates live body input before emitting numbers."""
        pull = self.write_fixture("pull.json", json.dumps({"body": []}))
        rc, err = self.run_cli("--pull-json", str(pull), "--live-body", "--list-dependencies")
        self.assertEqual(rc, 2)
        self.assertIn("string body", err)

    def test_dependency_cli_combined_stale_claims(self) -> None:
        """One validation reports stale base and dependency claims together."""
        body = self.write_fixture("body.md", "Base bbbbbbb; depends on #12 head ddddddd")
        dependency = self.dependency_json()
        rc, err = self.run_cli(
            "--merge-base",
            MERGE_BASE,
            "--label",
            "body",
            "--dependency-json",
            f"12={dependency}",
            str(body),
        )
        self.assertEqual(rc, 1)
        self.assertIn(f"body: names base bbbbbbb, the live merge base is {MERGE_BASE}\n", err)
        self.assertIn(f"body: names head ddddddd of #12, the live head of #12 is {'a' * 40}\n", err)

    def test_dependency_cli_distinct_limit(self) -> None:
        """Nine distinct dependency claims exceed the bound during checking and listing."""
        body = self.write_fixture(
            "body.md", "\n".join(f"Depends on #{number} head aaaaaaa" for number in range(1, 10))
        )
        for flags in ((), ("--list-dependencies",)):
            with self.subTest(flags=flags):
                rc, err = self.run_cli("--merge-base", MERGE_BASE, *flags, str(body))
                self.assertEqual(rc, 2)
                self.assertIn("8", err)

    def test_dependency_cli_option_limit(self) -> None:
        """Nine dependency JSON options exceed the shared bound."""
        dependency = self.dependency_json()
        options = [
            arg
            for number in range(1, 10)
            for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        rc, err = self.run_cli("--merge-base", MERGE_BASE, *options)
        self.assertEqual(rc, 2)
        self.assertIn("8", err)

    def test_dependency_cli_limit_boundary(self) -> None:
        """Exactly eight dependency options and claims are accepted."""
        dependency = self.dependency_json()
        body = self.write_fixture(
            "body.md", "\n".join(f"Depends on #{number} head aaaaaaa" for number in range(1, 9))
        )
        options = [
            arg for number in range(1, 9) for arg in ("--dependency-json", f"{number}={dependency}")
        ]
        rc, err = self.run_cli("--merge-base", MERGE_BASE, *options, str(body))
        self.assertEqual((rc, err), (0, ""))

    def test_dependency_allowlist_cases(self) -> None:
        """Allow-listed continuations pass while unlisted joiners, gaps and breaks fail closed."""
        for label, want, sentence in DEPENDENCY_ALLOWLIST_CASES:
            with self.subTest(case=label):
                if want is None:
                    with self.assertRaises(ValueError) as caught:
                        base_claims.find_dependency_claims(sentence)
                    message = str(caught.exception)
                    self.assertTrue(message.startswith("ambiguous dependency"), message)
                    for match in base_claims.DEPENDENCY_MEMBER.finditer(sentence):
                        self.assertIn(f"#{match.group(1)}", message)
                    continue
                try:
                    actual = base_claims.find_dependency_claims(sentence)
                except ValueError as error:
                    self.fail(f"unexpected ValueError: {error}")
                self.assertEqual(actual, want)

    def test_dependency_allowlist_cli_and_chains(self) -> None:
        """Comma chains in see/unrelated prose pass while CLI modes reject unlisted shapes."""
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12 (head aaaaaaa), see #14, #15, and PR 16 & #17 for benchmarks."
            ),
            [(12, "aaaaaaa")],
        )
        self.assertEqual(
            base_claims.find_dependency_claims(
                "Depends on #12 (head aaaaaaa), now depends on #13 (head bbbbbbb)."
            ),
            [(12, "aaaaaaa"), (13, "bbbbbbb")],
        )
        hist_body = self.write_fixture(
            "hist.md", "Previously stacked on #12 ~ head aaaaaaa, #13 (head bbbbbbb)."
        )
        self.assertEqual(self.run_cli("--merge-base", MERGE_BASE, str(hist_body)), (0, ""))
        dependency = self.dependency_json()
        for sample in (
            "Depends on #12 (head aaaaaaa) or #13 (head bbbbbbb).",
            "Depends on #12 (head aaaaaaa), formerly stacked on #13 (head bbbbbbb).",
            "Depends on #12 (head aaaaaaa; see #13).",
        ):
            body = self.write_fixture("body.md", sample)
            for flags in ((), ("--list-dependencies",)):
                with self.subTest(sample=sample, flags=flags):
                    rc, err = self.run_cli(
                        "--merge-base",
                        MERGE_BASE,
                        "--dependency-json",
                        f"12={dependency}",
                        *flags,
                        str(body),
                    )
                    self.assertEqual(rc, 2)
                    self.assertIn("ambiguous dependency", err)
                    self.assertIn("#12", err)
                    self.assertIn("#13", err)

    def assert_ambiguous_dependency_refusal(self, sentence: str) -> None:
        """Assert a refusal starts with ambiguous dependency and names each member once."""
        with self.assertRaises(ValueError) as caught:
            base_claims.find_dependency_claims(sentence)
        message = str(caught.exception)
        self.assertTrue(message.startswith("ambiguous dependency"), message)
        for match in base_claims.DEPENDENCY_MEMBER.finditer(sentence):
            self.assertIn(f"#{match.group(1)}", message)
        listed = re.findall(r"#([0-9]{1,7})\b", message)
        self.assertEqual(len(listed), len(set(listed)), message)

    def test_dependency_attribution_cases(self) -> None:
        """Repeat references, brace annotations and head attribution match table cases."""
        for label, want, sentence in DEPENDENCY_ATTRIBUTION_CASES:
            with self.subTest(case=label):
                if want is None:
                    self.assert_ambiguous_dependency_refusal(sentence)
                    continue
                try:
                    actual = base_claims.find_dependency_claims(sentence)
                except ValueError as error:
                    self.fail(f"unexpected ValueError: {error}")
                self.assertEqual(actual, want)

    def test_dependency_allowlist_refusal_numbers_are_unique(self) -> None:
        """Every allow-list refusal names each member reference number at most once."""
        for label, want, sentence in DEPENDENCY_ALLOWLIST_CASES:
            if want is not None:
                continue
            with self.subTest(case=label):
                with self.assertRaises(ValueError) as caught:
                    base_claims.find_dependency_claims(sentence)
                message = str(caught.exception)
                listed = re.findall(r"#([0-9]{1,7})\b", message)
                self.assertEqual(len(listed), len(set(listed)), message)

    def assert_scope_refusal_message(self, message: str, sentence: str) -> None:
        """Verify an ambiguity error starts correctly and lists each member once."""
        self.assertTrue(message.startswith("ambiguous dependency"), message)
        for match in base_claims.DEPENDENCY_MEMBER.finditer(sentence):
            self.assertIn(f"#{match.group(1)}", message)
        listed = re.findall(r"#([0-9]{1,7})\b", message)
        self.assertEqual(len(listed), len(set(listed)), message)

    def assert_scope_non_ok_case(self, outcome: str, sentence: str) -> None:
        """Verify find_dependency_claims and _dependency_numbers fail with outcome."""
        limit = f"more than {base_claims.MAX_DEPENDENCIES} distinct dependency PR numbers"
        with self.assertRaises(ValueError) as claims_err:
            base_claims.find_dependency_claims(sentence)
        with self.assertRaises(ValueError) as numbers_err:
            base_claims._dependency_numbers([("body", sentence)])
        for caught in (claims_err, numbers_err):
            message = str(caught.exception)
            if outcome == "limit":
                self.assertEqual(message, limit)
            else:
                self.assertEqual(outcome, "refuse")
                self.assert_scope_refusal_message(message, sentence)

    def assert_scope_ok_case(
        self,
        claims: list[tuple[int, str]] | None,
        numbers: list[int] | None,
        sentence: str,
    ) -> None:
        """Verify find_dependency_claims and _dependency_numbers match expected lists."""
        try:
            actual_claims = base_claims.find_dependency_claims(sentence)
            actual_numbers = base_claims._dependency_numbers([("body", sentence)])
        except ValueError as error:
            self.fail(f"unexpected ValueError: {error}")
        self.assertEqual(actual_claims, claims)
        self.assertEqual(actual_numbers, numbers)

    def test_dependency_scope_cases(self) -> None:
        """Typed brackets, member-local history, lead windows and separators match table."""
        for label, outcome, claims, numbers, sentence in DEPENDENCY_SCOPE_CASES:
            with self.subTest(case=label):
                if outcome != "ok":
                    self.assert_scope_non_ok_case(outcome, sentence)
                    continue
                self.assert_scope_ok_case(claims, numbers, sentence)


if __name__ == "__main__":
    unittest.main()
