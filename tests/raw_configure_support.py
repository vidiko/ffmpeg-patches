# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Shared test fixtures and harness base for raw configure guard tests."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess  # nosec B404 - fixed guard and shell-hook commands, never configure.
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "raw_configure_guard.py"
CLIENTS = ("claude", "codex", "gemini", "opencode")
CONFIGS = {
    "claude": (ROOT / ".claude/settings.json", "PreToolUse", "Bash", 15),
    "codex": (ROOT / ".codex/hooks.json", "PreToolUse", "Bash", 15),
    "gemini": (ROOT / ".gemini/settings.json", "BeforeTool", "run_shell_command", 15000),
}
SPEC = importlib.util.spec_from_file_location("raw_configure_guard", GUARD)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load module from {GUARD}")
GUARD_MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD_MOD)


class RawConfigureGuardBase(unittest.TestCase):
    """Base fixture providing temporary trees and guard runner helper methods.

    all_clients: False runs one rotating client per case; True runs every client (guard suite).
    """

    all_clients: bool = False

    def setUp(self) -> None:
        """Create FFmpeg-shaped and unrelated trees without running configure."""
        self._guard_turn = 0
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tree = self.root / "tree"
        self.tree.mkdir()
        (self.tree / "libavcodec").mkdir()
        self.build = self.root / "build"
        self.build.mkdir()
        (self.root / "BUILD").mkdir()
        self.other = self.root / "other"
        self.other.mkdir()
        self.marker = self.root / "ran"
        for directory in (self.tree, self.other):
            script = directory / "configure"
            script.write_text(f"#!/bin/sh\ntouch '{self.marker}'\n", encoding="utf-8")
            script.chmod(0o755)

    def payload(self, client: str, command: str | None, cwd: Path) -> dict[str, object]:
        """Build the documented pre-tool shell input for one client."""
        if client == "opencode":
            return {"tool": "bash", "args": {"command": command}, "cwd": str(cwd)}
        tool = "run_shell_command" if client == "gemini" else "Bash"
        arguments = {} if command is None else {"command": command}
        return {"tool_name": tool, "tool_input": arguments, "cwd": str(cwd)}

    def run_guard(
        self, client: str, payload: object, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run only the guard with JSON on stdin and a short deadline."""
        data = payload if isinstance(payload, str) else json.dumps(payload)
        run_env = {"PATH": os.defpath, "LC_ALL": "C.UTF-8"} if env is None else env
        return subprocess.run(  # nosec B603 - fixed guard argv with explicit interpreter.
            [sys.executable, "-I", str(GUARD), "--client", client],
            input=data,
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=5,
            check=False,
            env=run_env,
        )

    def _next_client(self) -> str:
        """Advance per-test client rotation and return the client for the next guard run."""
        client = CLIENTS[self._guard_turn % len(CLIENTS)]
        self._guard_turn += 1
        return client

    def _case_clients(self) -> tuple[str, ...]:
        """Return all CLIENTS in order when all_clients is on, else one rotating client."""
        return CLIENTS if self.all_clients else (self._next_client(),)

    def _assert_refused(
        self,
        cases: tuple[tuple[str, Path], ...],
        env: dict[str, str] | None = None,
        remedy: str = "python3 scripts/ffmpeg_configure.py",
    ) -> tuple[subprocess.CompletedProcess[str], ...]:
        """Refuse each case under one rotating client, or every client when all_clients is on."""
        results: list[subprocess.CompletedProcess[str]] = []
        for command, cwd in cases:
            for client in self._case_clients():
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd), env=env)
                    results.append(result)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("configure", result.stderr)
                    self.assertIn(remedy, result.stderr)
                    self.assertFalse(self.marker.exists())
        return tuple(results)

    def _assert_allowed(
        self, cases: tuple[tuple[str, Path], ...], env: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], ...]:
        """Allow each case under one rotating client, or every client when all_clients is on."""
        results: list[subprocess.CompletedProcess[str]] = []
        for command, cwd in cases:
            for client in self._case_clients():
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd), env=env)
                    results.append(result)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(self.marker.exists())
        return tuple(results)

    def _check_parser_body(self, body: str, *, refused: bool, reason: str | None = None) -> None:
        """Inspect a fixture body across _case_clients without executing the script."""
        cfg = f'"{self.tree}/configure" --x'
        body = body.replace("<cfg>", cfg).replace("<tree>", str(self.tree))
        body = body.replace("<build>", str(self.build))
        script = self.root / "parser_body.sh"
        script.write_text(body, encoding="utf-8")
        (self.root / "inner.sh").write_text(cfg + "\n", encoding="utf-8")
        assertion = self._assert_refused if refused else self._assert_allowed
        results = assertion(((f"bash {script}", self.root),))
        if reason is not None:
            for result in results:
                self.assertIn(reason, result.stderr)
