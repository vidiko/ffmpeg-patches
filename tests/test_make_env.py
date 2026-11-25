# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check Make environment isolation and require its reuse by Make fixtures."""

from __future__ import annotations

import ast
import os
import unittest
import unittest.mock
from pathlib import Path

from tests.make_env import make_environment


def _uses_make_lookup(tree: ast.Module) -> bool:
    """Return whether the AST names shutil.which with a make argument."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shutil"
            and node.func.attr == "which"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "make"
        ):
            return True
    return False


def _missing_make_env_import(source: str) -> bool:
    """Flag GNU Make fixture sources without an import of the shared isolation module."""
    tree = ast.parse(source)
    if not _uses_make_lookup(tree):
        return False
    return not any(
        isinstance(node, ast.ImportFrom) and node.module == "tests.make_env"
        for node in ast.walk(tree)
    )


class MakeEnvironmentTest(unittest.TestCase):
    """Exercise environment copying and source-level adoption checks."""

    def test_make_environment_copies_and_scrubs_channels_and_extra_names(self) -> None:
        """Every Make channel and extra name is removed without mutating the parent."""
        channels = (
            "MAKEFLAGS",
            "MFLAGS",
            "GNUMAKEFLAGS",
            "MAKELEVEL",
            "MAKEOVERRIDES",
            "MAKEFILES",
        )
        planted = dict.fromkeys((*channels, "FIXTURE_TREE"), "parent")
        planted["KEPT"] = "literal value"
        with unittest.mock.patch.dict(os.environ, planted):
            environment = make_environment("FIXTURE_TREE")
            self.assertEqual(set(environment), set(os.environ) - set(channels) - {"FIXTURE_TREE"})
            self.assertEqual(environment["KEPT"], "literal value")
            for name in (*channels, "FIXTURE_TREE"):
                self.assertEqual(os.environ[name], "parent")
            environment["KEPT"] = "child"
            self.assertEqual(os.environ["KEPT"], "literal value")

    def test_make_fixtures_import_shared_environment(self) -> None:
        """Every GNU Make fixture names the shared module, including planted sources."""
        for planted in (
            'import shutil\nmake = shutil.which("make")\n',
            "import shutil\nmake = shutil.which('make')\n",
        ):
            with self.subTest(planted=planted):
                self.assertTrue(_missing_make_env_import(planted))
                self.assertFalse(
                    _missing_make_env_import(
                        "from tests.make_env import make_environment\n" + planted
                    )
                )
        self.assertFalse(_missing_make_env_import("pass\n"))
        self.assertFalse(_missing_make_env_import('# shutil.which("make")\n'))
        offenders = [
            str(path.relative_to(Path(__file__).parent.parent))
            for path in sorted(Path(__file__).parent.glob("test_*.py"))
            if _missing_make_env_import(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [], "Make fixtures missing tests.make_env: " + repr(offenders))
