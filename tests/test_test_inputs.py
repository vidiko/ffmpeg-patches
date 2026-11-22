# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Reject test modules that quote filesystem paths under the git-ignored .lane tree."""

from __future__ import annotations

import ast
import io
import tempfile
import tokenize
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
_LANE_ROOT = "." + "lane"
_LANE_PREFIX = _LANE_ROOT + "/"
_FSTRING_START = getattr(tokenize, "FSTRING_START", None)
_FSTRING_MIDDLE = getattr(tokenize, "FSTRING_MIDDLE", None)
_FSTRING_END = getattr(tokenize, "FSTRING_END", None)


def _first_fstring_middle(tokens: list[tokenize.TokenInfo], start: int) -> str | None:
    """Return the first FSTRING_MIDDLE after START, or None when absent."""
    limit = len(tokens)
    for index in range(start + 1, limit):
        tok = tokens[index]
        if _FSTRING_MIDDLE is not None and tok.type == _FSTRING_MIDDLE:
            return tok.string
        if _FSTRING_END is not None and tok.type == _FSTRING_END:
            return None
    return None


def quoted_lane_path_hits(source: str) -> list[int]:
    """Return line numbers where a string literal names `.lane` or a `.lane/` path."""
    hits: list[int] = []
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    limit = len(tokens)
    for index in range(limit):
        tok = tokens[index]
        if tok.type == tokenize.STRING:
            try:
                value = ast.literal_eval(tok.string)
            except (SyntaxError, ValueError):
                continue
            if not isinstance(value, str):
                continue
            if value == _LANE_ROOT or value.startswith(_LANE_PREFIX):
                hits.append(tok.start[0])
            continue
        if _FSTRING_START is None or tok.type != _FSTRING_START:
            continue
        first_middle = _first_fstring_middle(tokens, index)
        if first_middle is None:
            continue
        if first_middle == _LANE_ROOT or first_middle.startswith(_LANE_PREFIX):
            hits.append(tok.start[0])
    return hits


def find_quoted_lane_paths(directory: Path) -> list[tuple[str, int]]:
    """Return (file name, line) pairs for quoted `.lane` segments in sorted test modules."""
    pairs: list[tuple[str, int]] = []
    py_files = sorted(directory.glob("*.py"))
    for path in py_files:
        if path.name == Path(__file__).name:
            continue
        for line in quoted_lane_path_hits(path.read_text(encoding="utf-8")):
            pairs.append((path.name, line))
    return pairs


class QuotedLanePathTest(unittest.TestCase):
    """Exercise quoted and f-string `.lane` path literals in tracked tests."""

    def test_repository_tests_directory_has_no_quoted_lane_paths(self) -> None:
        """Tracked tests must not embed `.lane` path segments in string literals."""
        self.assertEqual(find_quoted_lane_paths(TESTS_DIR), [])

    def test_planted_path_join_flags_lane_segment(self) -> None:
        """A module that joins through `.lane` is reported at that literal's line."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_join.py"
            path.write_text(
                "ROOT = Path(__file__).resolve().parent.parent\n"
                'DATA = ROOT / ".lane" / "input" / "x.json"\n',
                encoding="utf-8",
            )
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [("planted_join.py", 2)])

    def test_planted_lane_tmp_string_is_reported(self) -> None:
        """A quoted `.lane/tmp` path is reported on its own line."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_tmp.py"
            path.write_text('SCRATCH = ".lane/tmp"\n', encoding="utf-8")
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [("planted_tmp.py", 1)])

    def test_planted_fstring_lane_path_is_reported(self) -> None:
        """An f-string whose first segment is `.lane/` is reported on its start line."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_fstring.py"
            path.write_text('PATH = f".lane/{name}"\n', encoding="utf-8")
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [("planted_fstring.py", 1)])

    def test_planted_fstring_lane_subpath_is_ignored(self) -> None:
        """An f-string that only embeds `.lane` after an expression is not reported."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_fstring_sub.py"
            path.write_text('PATH = f"{root}/.lane/x"\n', encoding="utf-8")
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [])

    def test_longer_path_with_lane_segment_is_ignored(self) -> None:
        """A string that merely contains `.lane` mid-path is not a `.lane` root path."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_subpath.py"
            path.write_text('LOG = "/x/.lane/build"\n', encoding="utf-8")
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [])

    def test_lane_name_only_in_comment_is_ignored(self) -> None:
        """Comments must not be treated as quoted path literals."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "planted_comment.py"
            path.write_text('# use ROOT / ".lane" / "input"\nVALUE = "ok"\n', encoding="utf-8")
            self.assertEqual(find_quoted_lane_paths(Path(tmp)), [])


if __name__ == "__main__":
    unittest.main()
