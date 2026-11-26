# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Reject duplicate module-level name bindings in tracked Python sources."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.helpers import python_sources

ROOT = Path(__file__).resolve().parent.parent


def _bound_names(statement: ast.stmt) -> set[str]:
    """Return bare names bound directly by one plain or annotated assignment."""
    if isinstance(statement, ast.Assign):
        return {target.id for target in statement.targets if isinstance(target, ast.Name)}
    if (
        isinstance(statement, ast.AnnAssign)
        and statement.value is not None
        and isinstance(statement.target, ast.Name)
    ):
        return {statement.target.id}
    return set()


def find_module_rebindings(source: str, *, filename: str = "<unknown>") -> list[str]:
    """Return sorted bare names bound by two or more module-level assignments."""
    tree = ast.parse(source, filename=filename)
    seen: set[str] = set()
    rebound: set[str] = set()
    for statement in tree.body:
        for name in _bound_names(statement):
            if name in seen:
                rebound.add(name)
            else:
                seen.add(name)
    return sorted(rebound)


class ModuleBindingsTest(unittest.TestCase):
    """Verify module-level rebinding detection on planted inputs and repository sources."""

    def test_plain_rebinding_reported(self) -> None:
        """Two plain module-level assignments to the same bare name report that name."""
        self.assertEqual(find_module_rebindings("A = 1\nB = 2\nA = 3\n"), ["A"])

    def test_annotated_and_plain_rebinding_reported(self) -> None:
        """An annotated assignment followed by a plain assignment reports the name."""
        self.assertEqual(find_module_rebindings("A: int = 1\nA = 2\n"), ["A"])

    def test_nested_and_augmented_assignments_ignored(self) -> None:
        """Nested block bindings and augmented assignments do not count as rebindings."""
        self.assertEqual(find_module_rebindings("A = 1\nif B:\n    A = 2\nA += 1\n"), [])

    def test_repository_avoids_module_rebindings(self) -> None:
        """Tracked Python sources bind each module-level name at most once."""
        offenders = []
        for path in python_sources(ROOT):
            relative = path.relative_to(ROOT)
            source = path.read_text(encoding="utf-8")
            names = find_module_rebindings(source, filename=str(relative))
            if names:
                offenders.append(f"{relative}: {', '.join(names)}")
        self.assertEqual(offenders, [], "duplicate module bindings:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
