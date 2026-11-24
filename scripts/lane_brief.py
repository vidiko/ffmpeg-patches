#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Render or check a lane brief against repository standards.

The check command with a runner first runs scripts/lane_isolation.py on the worktree.
Required entries must end at an allowed token boundary.
Refuses make-without-praetorctl, column-limit joins, file length checks, and missing 40-hex names.
Runner dependencies load on demand so copied validators can reuse the YAML reader.

Usage: lane_brief.py render --branch B --task T --finding F --fix X --tests S --paths P --modules M
       lane_brief.py check BRIEF [--config FILE] [--runner PATH] [--worktree DIR]
Exit status: 0 when valid, 1 for invalid briefs, 2 for usage or input errors.
"""

from __future__ import annotations

import argparse
import bisect
import importlib
import io
import os
import re
import shlex
import stat
import subprocess  # nosec B404 - runner precheck with explicit argv, no shell, bounded timeout.
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEMPLATE = ROOT / "scripts" / "lane_brief_template.md"
CONFIG = ROOT / ".config" / "lane-brief.yaml"
NAMES = ("task", "branch", "n", "r", "finding", "fix", "tests", "paths", "modules")
PLACEHOLDERS = re.compile(r"<(task|branch|n|r|finding|fix|tests|paths|modules)>")
MAX_SIZE = 1024 * 1024
MAX_LINES = 10000
MAX_LINE_SIZE = 65536
RUNNER_TIMEOUT = 120
RUNNER_OUTPUT_LIMIT = 65536
# Allow-list of characters that end a required entry; whitespace, end of text,
# and a period followed by whitespace or end of text also end it.
ENTRY_ENDINGS = '`"),:;'
NEVER_RUN_CLAUSE = re.compile(
    r"\bnever\s+run\b(?:[^\n;.]|\.(?!\s|$)|\n(?![ \t]*(?:$|[-*`]|\d+\.|\w+:)))*",
    re.IGNORECASE,
)
FORBIDDEN_PRAETORCTL = re.compile(r"\bpraetorctl\b(?!\s+(?:gate|admit)\b)", re.IGNORECASE)
ALLOWED_ADMIT = re.compile(r"\bexcept\b[^.;\n]*\badmit\b", re.IGNORECASE)
FORBIDDEN_MAKE = re.compile(r"\bmake\b(?!\s+verify-all\b)", re.IGNORECASE)
BACKTICK_SPAN = re.compile(r"(?<!`)`([^`]+)`(?!`)")
MAKE_INVOCATION = re.compile(r"(?<![.-])\bmake\b(?![/.-])(?!\s+(?i:verify-all)\b)")
COLUMN_LIMIT = re.compile(
    r"(?:\b(?:(?:longer|more)\s+than|over|at\s+most)\s+|<=\s*)\d{2,3}\s+col(?:umn)?s\b",
    re.IGNORECASE,
)
ONE_LINE_JOIN = re.compile(
    r"\b(?:"
    r"becomes?\s+(?:one|a\s+single)\s+line"
    r"|join(?:ed|ing|s)?(?:\s+(?:(?!\n\s*\n)[^.;]){1,80}?)?\s+"
    r"(?:into|onto)\s+(?:one|a\s+single)\s+line"
    r"|go(?:es)?\s+to\s+(?:one|a\s+single)\s+line"
    r")\b",
    re.IGNORECASE,
)
JOIN_NEGATION = re.compile(r"\b(?:not|never|no|don't)\b", re.IGNORECASE)
JOIN_BOUNDARY = re.compile(
    r"[;]|[.!?]\s+|\n[ \t]*(?:\n|[-*+#]|\d+[.)][ \t]|\w+:)"
    r"|\b(?:but|however)\b",
    re.IGNORECASE,
)
FINDING_PREFIX = re.compile(r"^[ \t]*(?:(?:[-*+]|\d+[.)])[ \t]+)*finding:", re.IGNORECASE)
WHOLE_FILE_LENGTH = re.compile(
    r"\b[gmn]?awk\b[\s\S]*?(?<![/.-])\blength\b(?:\s*\(\s*(?:\$0\s*)?\)|(?![/.-]|\s*\())"
    r"|\b(?:[ef]?grep|rg)\b[\s\S]*?(?<!\\)\.\\?\{\d{2,3}(?:,\d*)?\\?\}"
    r"|\bwc\s+(?:-[a-zA-Z]*L\b|--max-line-length\b)"
)
AWK_LENGTH_PROGRAM = re.compile(
    r"(?<![/.-])\blength\b(?:\s*\(\s*(?:\$0\s*)?\)|(?![/.-]|\s*\())",
    re.IGNORECASE,
)
GREP_COUNTED_DOT = re.compile(r"(?<!\\)\.\\?\{\d{2,3}(?:,\d*)?\\?\}")
LENGTH_TOOL_NAMES = frozenset({"wc", "awk", "gawk", "mawk", "nawk", "grep", "egrep", "fgrep", "rg"})
GIT_DIFF_COMMAND = re.compile(r"\bgit\b[^|;&]*\bdiff\b")
STANDALONE_OBJECT = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
NESTED_GIT_C = re.compile(r"""\bgit\s+-C\s+("[^"\n]+"|'[^'\n]+'|[^\s`'";,|&()<>]+)""")
MAX_NESTED_REPOS = 8
REDIRECT_CHARS = frozenset("<>&|")
COMMAND_SEPARATORS = frozenset({";", "&", "&&", "||"})
PIPE_SEPARATORS = frozenset({"|", "|&"})


def validate_lines(lines: list[bytes], label: str) -> None:
    """Reject content exceeding the byte size, line count, or line length limits."""
    if sum(map(len, lines)) > MAX_SIZE:
        raise ValueError(f"{label}: size exceeds 1 MiB")
    if len(lines) > MAX_LINES:
        raise ValueError(f"{label}: exceeds 10000 lines")
    if any(len(line) > MAX_LINE_SIZE for line in lines):
        raise ValueError(f"{label}: line exceeds 65536 bytes")


def bounded_lines(path: Path) -> list[str]:
    """Read bounded lines from a regular file of at most 1 MiB."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{path}: not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            lines = io.BytesIO(source.read(MAX_SIZE + 1)).readlines()
    finally:
        os.close(descriptor)
    validate_lines(lines, str(path))
    return [line.decode("utf-8") for line in lines]


def read_yaml(path: Path) -> object:
    """Read bounded safe YAML while rejecting duplicate mapping keys."""
    try:
        import yaml  # noqa: PLC0415 - optional parser dependency.
    except ImportError as error:
        raise ValueError(f"{path}: missing pyyaml; install requirements-dev.txt") from error

    class UniqueLoader(yaml.SafeLoader):
        """Reject duplicate mapping keys while loading safe YAML."""

        def construct_mapping(self, node: object, deep: bool = False) -> dict:
            """Construct a mapping only when each key is unique."""
            self.flatten_mapping(node)
            seen: set = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in seen
                    seen.add(key)
                except TypeError as error:
                    raise ValueError(f"{path}: invalid YAML: unhashable key") from error
                if duplicate:
                    message = (
                        "duplicate required key" if key == "required" else f"duplicate key {key}"
                    )
                    raise ValueError(f"{path}: {message}")
            return super().construct_mapping(node, deep=deep)

    try:
        loader = UniqueLoader("".join(bounded_lines(path)))
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as error:
        raise ValueError(f"{path}: invalid YAML: {error}") from error
    return document


def read_required(path: Path) -> list[str]:
    """Read and validate the required substrings from a bounded YAML document."""
    return validate_required(path, read_yaml(path))


def validate_required(path: Path, document: object) -> list[str]:
    """Validate and normalize the required list in a YAML document."""
    if not isinstance(document, dict) or not isinstance(document.get("required"), list):
        raise ValueError(f"{path}: missing or invalid required list")
    items = document["required"]
    if not items:
        raise ValueError(f"{path}: missing or empty required list")
    if len(items) > 32:
        raise ValueError(f"{path}: required list exceeds 32 items")
    result: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip() or "\n" in item or "\r" in item:
            raise ValueError(f"{path}: invalid required item")
        value = item.strip()
        if len(value) > 200:
            raise ValueError(f"{path}: required item exceeds 200 characters")
        result.append(value)
    return result


def ends_token(rest: str) -> bool:
    """Return whether text after an entry begins with an allowed token boundary."""
    if not rest or rest[0].isspace() or rest[0] in ENTRY_ENDINGS:
        return True
    return rest[0] == "." and (len(rest) == 1 or rest[1].isspace())


def has_entry(content: str, item: str) -> bool:
    """Return False for an empty entry or whether any occurrence ends at a token boundary."""
    if not item:
        return False
    start = 0
    for _ in range(len(content) - len(item) + 1):
        index = content.find(item, start)
        if index < 0:
            return False
        end = index + len(item)
        if ends_token(content[end : end + 2]):
            return True
        start = index + 1
    return False


def check(content: str, label: str, required: list[str]) -> int:
    """Print each missing requirement and unfilled placeholder."""
    errors = [
        f"{label}: missing required line: {item}"
        for item in required
        if not has_entry(content, item)
    ]
    errors.extend(
        f"{label}: unfilled placeholder <{name}>" for name in NAMES if f"<{name}>" in content
    )
    for error in errors:
        print(error, file=sys.stderr)
    return int(bool(errors))


def parser_for_cli() -> argparse.ArgumentParser:
    """Define the render and check command arguments."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    for name in ("branch", "task", "finding", "fix", "tests", "paths", "modules"):
        render.add_argument(f"--{name}", required=True)
    render.add_argument("--issue", default="none")
    render.add_argument("--round", default="1")
    render.add_argument("-o", type=Path)
    verify = commands.add_parser("check")
    verify.add_argument("brief", type=Path)
    verify.add_argument("--config", type=Path, default=None)
    verify.add_argument("--runner", type=Path, default=os.environ.get("LANE_BRIEF_RUNNER") or None)
    verify.add_argument("--worktree", type=Path, default=ROOT)
    return parser


def render_brief(args: argparse.Namespace) -> int:
    """Render and validate before writing any output."""
    values = {
        name: getattr(args, name)
        for name in ("task", "branch", "finding", "fix", "tests", "paths", "modules")
    }
    values.update(n=args.issue, r=args.round)
    for name, value in values.items():
        if len(value) > 8192:
            argument = {"n": "issue", "r": "round"}.get(name, name)
            raise ValueError(f"--{argument}: exceeds 8192 characters")
    content = PLACEHOLDERS.sub(
        lambda match: values[match.group(1)], TEMPLATE.read_text(encoding="utf-8")
    )
    validate_lines(io.BytesIO(content.encode("utf-8")).readlines(), str(args.o or "stdout"))
    result = check(content, str(args.o) if args.o else "stdout", read_required(CONFIG))
    if result:
        return result
    if args.o:
        args.o.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
    return 0


def read_runner_output(process: subprocess.Popen[bytes], deadline: float) -> bytes:
    """Read runner output within the byte limit and monotonic deadline."""
    process_group = importlib.import_module("scripts.process_group")
    if process.stdout is None:
        raise OSError("runner stdout pipe unavailable")
    return process_group.read_bounded(
        process, (process.stdout,), deadline, RUNNER_OUTPUT_LIMIT, RUNNER_TIMEOUT
    )[0]


def run_runner(argv: list[str]) -> tuple[bytes, int]:
    """Run and reap a runner while collecting bounded combined output."""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    process_group = importlib.import_module("scripts.process_group")
    process = subprocess.Popen(  # nosec B603 - configured runner path, explicit argv, no shell.
        argv,
        env=lane_isolation.git_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    completed = False
    try:
        output = read_runner_output(process, time.monotonic() + RUNNER_TIMEOUT)
        completed = True
        return output, process.returncode
    finally:
        if not completed or process.poll() != 0:
            process_group.kill_process_group(process)
        try:
            process.wait(timeout=5)
        finally:
            if process.stdout is not None:
                process.stdout.close()


def check_runner(runner: Path, brief: Path, worktree: Path) -> int:
    """Run the lane runner precheck and report its output and result."""
    try:
        output, returncode = run_runner([str(runner), "--check-brief", str(brief), str(worktree)])
    except subprocess.TimeoutExpired:
        print(
            f"lane_brief: runner failed: timed out after {RUNNER_TIMEOUT} seconds", file=sys.stderr
        )
        return 2
    except (OSError, ValueError) as error:
        print(f"lane_brief: runner failed: {error}", file=sys.stderr)
        return 2
    sys.stderr.write(output.decode("utf-8", errors="replace"))
    if returncode:
        print(f"lane_brief: runner refused brief (rc {returncode})", file=sys.stderr)
        return 1
    return 0


def check_isolation(worktree: Path) -> int:
    """Refuse unsafe lane worktrees before the runner can start."""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    try:
        lines = lane_isolation.refusals(worktree)
    except (lane_isolation.IsolationError, OSError) as error:
        print(f"lane_brief: lane isolation failed: {error}", file=sys.stderr)
        return 2
    if lines:
        for line in lines[: lane_isolation.MAX_LISTED + 2]:
            print(line, file=sys.stderr)
        print(f"lane_brief: lane isolation refused worktree {worktree}", file=sys.stderr)
        return 1
    return 0


def line_slice(content: str, start: int, end: int) -> str:
    """Return the full line or lines spanning start through end in content."""
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    return content[line_start : len(content) if line_end < 0 else line_end]


def mask_backtick_inners(content: str) -> str:
    """Replace backtick span inners with neutral letters at the same offsets."""
    chars = list(content)
    for match in BACKTICK_SPAN.finditer(content):
        for offset in range(match.start(1), match.end(1)):
            chars[offset] = "x"
    return "".join(chars)


def never_run_clause_spans(content: str) -> list[tuple[int, int]]:
    """Return Never run clause spans using boundaries outside backtick inners."""
    masked = mask_backtick_inners(content)
    return [(match.start(), match.end()) for match in NEVER_RUN_CLAUSE.finditer(masked)]


def non_clause_spans(content: str) -> list[re.Match[str]]:
    """Return inline backtick matches that lie outside every Never run clause."""
    clauses = never_run_clause_spans(content)
    spans = list(BACKTICK_SPAN.finditer(content))
    if not clauses:
        return spans
    clause_ends = [end for _start, end in clauses]
    outside: list[re.Match[str]] = []
    for match in spans:
        clause_index = bisect.bisect_right(clause_ends, match.start())
        inside = (
            clause_index < len(clauses)
            and clauses[clause_index][0] <= match.start()
            and match.end() <= clauses[clause_index][1]
        )
        if not inside:
            outside.append(match)
    return outside


def conflict_make_without_praetorctl(content: str) -> str:
    """Report a brief that runs make while forbidding praetorctl in Never run."""
    clauses = [match.group(0) for match in NEVER_RUN_CLAUSE.finditer(content)]
    praetor_clause = next(
        (
            clause
            for clause in clauses
            if FORBIDDEN_PRAETORCTL.search(clause) and not ALLOWED_ADMIT.search(clause)
        ),
        "",
    )
    if not praetor_clause:
        return ""
    make_span = next(
        (
            match.group(1)
            for match in non_clause_spans(content)
            if "host ran" not in line_slice(content, match.start(), match.end()).lower()
            and MAKE_INVOCATION.search(match.group(1))
        ),
        "",
    )
    if not make_span:
        return ""
    span_text = " ".join(make_span.split())
    clause_text = " ".join(praetor_clause.split())
    return (
        f"`{span_text}` with `{clause_text}`: "
        "allow praetorctl admit for the make command or move the build to the host and forbid make"
    )


def join_is_excluded(content: str, match: re.Match[str]) -> bool:
    """Return whether a one-line join match is negated or sits on a record line."""
    line = line_slice(content, match.start(), match.end())
    if FINDING_PREFIX.match(line) or "host ran" in line.lower():
        return True
    earlier = JOIN_BOUNDARY.split(content[: match.start()])[-1]
    return bool(JOIN_NEGATION.search(earlier))


def conflict_join_under_column_limit(content: str) -> str:
    """Report a brief that sets a column limit and asks to join code onto one line."""
    limit_match = COLUMN_LIMIT.search(content)
    if not limit_match:
        return ""
    join_match = next(
        (
            match
            for match in ONE_LINE_JOIN.finditer(content)
            if not join_is_excluded(content, match)
        ),
        None,
    )
    if join_match is None:
        return ""
    limit_text = " ".join(limit_match.group(0).split())
    join_text = " ".join(join_match.group(0).split())
    return f'"{join_text}" under "{limit_text}": give the exact wrapped form instead of a join'


def is_redirect_operator(token: str) -> bool:
    """Return whether token is a shell redirect made only of redirection punctuation."""
    if not token:
        return False
    if any(char not in REDIRECT_CHARS for char in token):
        return False
    return "<" in token or ">" in token


def span_shell_tokens(span: str) -> list[str] | None:
    """Return punctuation-aware shell tokens for span or None when quoting is unclosed."""
    try:
        lexer = shlex.shlex(span, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def split_token_groups(tokens: list[str], separators: frozenset[str]) -> list[list[str]]:
    """Split token list on separator tokens while preserving empty groups."""
    groups: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in separators:
            groups.append(current)
            current = []
            continue
        current.append(token)
    groups.append(current)
    return groups


def span_token_command_groups(tokens: list[str]) -> list[list[list[str]]]:
    """Split shell tokens into command groups and pipeline stages."""
    command_groups = split_token_groups(tokens, COMMAND_SEPARATORS)
    return [split_token_groups(group, PIPE_SEPARATORS) for group in command_groups]


@dataclass(frozen=True)
class ToolSpec:
    """Describe option arity, program words, and unnamed-file flags for one tool."""

    short_no_arg: frozenset[str] = frozenset()
    short_arg: frozenset[str] = frozenset()
    short_opt_arg: frozenset[str] = frozenset()
    long_no_arg: frozenset[str] = frozenset()
    long_arg: frozenset[str] = frozenset()
    long_opt_arg: frozenset[str] = frozenset()
    program_opts: frozenset[str] = frozenset()
    file_program_opts: frozenset[str] = frozenset()
    program_words: int = 0
    unnamed_file_opts: frozenset[str] = frozenset()
    unnamed_file_opt_values: tuple[tuple[str, str], ...] = ()
    ignore_operands: bool = False


@dataclass(frozen=True)
class StageParse:
    """Hold parsed options, programs, operands, and redirects for one pipeline stage."""

    tool: str
    seen_opts: frozenset[str]
    programs: tuple[str, ...]
    uses_file: bool
    operands: tuple[str, ...]
    input_redirects: tuple[str, ...]
    refused: bool


@dataclass
class _StageState:
    """Accumulate mutable option, operand, and redirect state while scanning one stage."""

    seen_opts: set[str]
    opt_programs: list[str]
    uses_file: bool
    positionals: list[str]
    input_redirects: list[str]
    refused: bool


WC_SPEC = ToolSpec(
    short_no_arg=frozenset("cmlLw"),
    long_no_arg=frozenset(
        {
            "--bytes",
            "--chars",
            "--lines",
            "--debug",
            "--max-line-length",
            "--words",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset({"--files0-from", "--total"}),
    unnamed_file_opts=frozenset({"--files0-from"}),
)

GREP_SPEC = ToolSpec(
    short_no_arg=frozenset("EFGPiwxzsvVbnHhoqaIrRLlcTZU0123456789"),
    short_arg=frozenset("efmdDBAC"),
    long_no_arg=frozenset(
        {
            "--extended-regexp",
            "--fixed-strings",
            "--basic-regexp",
            "--perl-regexp",
            "--ignore-case",
            "--no-ignore-case",
            "--word-regexp",
            "--line-regexp",
            "--null-data",
            "--no-messages",
            "--invert-match",
            "--version",
            "--help",
            "--byte-offset",
            "--line-number",
            "--line-buffered",
            "--with-filename",
            "--no-filename",
            "--only-matching",
            "--quiet",
            "--silent",
            "--text",
            "--recursive",
            "--dereference-recursive",
            "--files-without-match",
            "--files-with-matches",
            "--count",
            "--initial-tab",
            "--null",
            "--no-group-separator",
            "--binary",
        }
    ),
    long_arg=frozenset(
        {
            "--regexp",
            "--file",
            "--max-count",
            "--label",
            "--binary-files",
            "--directories",
            "--devices",
            "--include",
            "--exclude",
            "--exclude-from",
            "--exclude-dir",
            "--before-context",
            "--after-context",
            "--context",
            "--group-separator",
        }
    ),
    long_opt_arg=frozenset({"--color", "--colour"}),
    program_opts=frozenset({"-e", "--regexp"}),
    file_program_opts=frozenset({"-f", "--file"}),
    program_words=1,
    unnamed_file_opts=frozenset({"-r", "-R", "--recursive", "--dereference-recursive"}),
    unnamed_file_opt_values=(("-d", "recurse"), ("--directories", "recurse")),
)

RG_SPEC = ToolSpec(
    short_no_arg=frozenset("zsFivxUPSawL.ubhnN0opqHIclV"),
    short_arg=frozenset("efEmjgdtTABCMr"),
    long_no_arg=frozenset(
        {
            "--auto-hybrid-regex",
            "--binary",
            "--block-buffered",
            "--byte-offset",
            "--case-sensitive",
            "--column",
            "--count",
            "--count-matches",
            "--crlf",
            "--debug",
            "--files",
            "--files-with-matches",
            "--files-without-match",
            "--fixed-strings",
            "--follow",
            "--glob-case-insensitive",
            "--heading",
            "--help",
            "--hidden",
            "--ignore",
            "--ignore-case",
            "--ignore-dot",
            "--ignore-exclude",
            "--ignore-file-case-insensitive",
            "--ignore-files",
            "--ignore-global",
            "--ignore-messages",
            "--ignore-parent",
            "--ignore-vcs",
            "--include-zero",
            "--invert-match",
            "--json",
            "--line-buffered",
            "--line-number",
            "--line-regexp",
            "--max-columns-preview",
            "--messages",
            "--mmap",
            "--multiline",
            "--multiline-dotall",
            "--no-auto-hybrid-regex",
            "--no-binary",
            "--no-block-buffered",
            "--no-byte-offset",
            "--no-column",
            "--no-config",
            "--no-context-separator",
            "--no-crlf",
            "--no-encoding",
            "--no-filename",
            "--no-fixed-strings",
            "--no-follow",
            "--no-glob-case-insensitive",
            "--no-heading",
            "--no-hidden",
            "--no-ignore",
            "--no-ignore-dot",
            "--no-ignore-exclude",
            "--no-ignore-file-case-insensitive",
            "--no-ignore-files",
            "--no-ignore-global",
            "--no-ignore-messages",
            "--no-ignore-parent",
            "--no-ignore-vcs",
            "--no-include-zero",
            "--no-invert-match",
            "--no-json",
            "--no-line-buffered",
            "--no-line-number",
            "--no-max-columns-preview",
            "--no-messages",
            "--no-mmap",
            "--no-multiline",
            "--no-multiline-dotall",
            "--no-one-file-system",
            "--no-pcre2",
            "--no-pcre2-unicode",
            "--no-pre",
            "--no-require-git",
            "--no-search-zip",
            "--no-sort-files",
            "--no-stats",
            "--no-text",
            "--no-trim",
            "--no-unicode",
            "--null",
            "--null-data",
            "--one-file-system",
            "--only-matching",
            "--passthrough",
            "--passthru",
            "--pcre2",
            "--pcre2-unicode",
            "--pcre2-version",
            "--pretty",
            "--quiet",
            "--require-git",
            "--search-zip",
            "--smart-case",
            "--sort-files",
            "--stats",
            "--stop-on-nonmatch",
            "--text",
            "--trace",
            "--trim",
            "--type-list",
            "--unicode",
            "--unrestricted",
            "--version",
            "--vimgrep",
            "--with-filename",
            "--word-regexp",
        }
    ),
    long_arg=frozenset(
        {
            "--after-context",
            "--before-context",
            "--color",
            "--colors",
            "--context",
            "--context-separator",
            "--dfa-size-limit",
            "--encoding",
            "--engine",
            "--field-context-separator",
            "--field-match-separator",
            "--file",
            "--generate",
            "--glob",
            "--hostname-bin",
            "--hyperlink-format",
            "--iglob",
            "--ignore-file",
            "--max-columns",
            "--max-count",
            "--max-depth",
            "--maxdepth",
            "--max-filesize",
            "--path-separator",
            "--pre",
            "--pre-glob",
            "--regex-size-limit",
            "--regexp",
            "--replace",
            "--sort",
            "--sortr",
            "--threads",
            "--type",
            "--type-add",
            "--type-clear",
            "--type-not",
        }
    ),
    program_opts=frozenset({"-e", "--regexp"}),
    file_program_opts=frozenset({"-f", "--file"}),
    program_words=1,
    unnamed_file_opts=frozenset({"--files"}),
)

AWK_SPEC = ToolSpec(
    short_no_arg=frozenset("bcCghIkMNnOPrsStV"),
    short_arg=frozenset("fFveEil"),
    short_opt_arg=frozenset("dDLop"),
    long_no_arg=frozenset(
        {
            "--characters-as-bytes",
            "--traditional",
            "--copyright",
            "--gen-pot",
            "--help",
            "--trace",
            "--csv",
            "--bignum",
            "--use-lc-numeric",
            "--non-decimal-data",
            "--optimize",
            "--posix",
            "--re-interval",
            "--no-optimize",
            "--sandbox",
            "--lint-old",
            "--version",
        }
    ),
    long_arg=frozenset(
        {
            "--file",
            "--field-separator",
            "--assign",
            "--source",
            "--exec",
            "--include",
            "--load",
        }
    ),
    long_opt_arg=frozenset(
        {"--dump-variables", "--debug", "--lint", "--pretty-print", "--profile"}
    ),
    program_opts=frozenset({"-e", "--source"}),
    file_program_opts=frozenset({"-f", "--file", "-E", "--exec"}),
    program_words=1,
)

SED_SPEC = ToolSpec(
    short_no_arg=frozenset("nErsuz"),
    short_arg=frozenset("efl"),
    short_opt_arg=frozenset("i"),
    long_no_arg=frozenset(
        {
            "--quiet",
            "--silent",
            "--debug",
            "--follow-symlinks",
            "--posix",
            "--regexp-extended",
            "--separate",
            "--sandbox",
            "--unbuffered",
            "--null-data",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset({"--expression", "--file", "--line-length"}),
    long_opt_arg=frozenset({"--in-place"}),
    program_opts=frozenset({"-e", "--expression"}),
    file_program_opts=frozenset({"-f", "--file"}),
    program_words=1,
)

CUT_SPEC = ToolSpec(
    short_no_arg=frozenset("nswz"),
    short_arg=frozenset("bcdfFO"),
    long_no_arg=frozenset(
        {
            "--complement",
            "--no-partial",
            "--only-delimited",
            "--zero-terminated",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset(
        {"--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"}
    ),
    long_opt_arg=frozenset({"--whitespace-delimited"}),
)

HEAD_SPEC = ToolSpec(
    short_no_arg=frozenset("qvz"),
    short_arg=frozenset("cn"),
    long_no_arg=frozenset(
        {"--quiet", "--silent", "--verbose", "--zero-terminated", "--help", "--version"}
    ),
    long_arg=frozenset({"--bytes", "--lines"}),
)

TAIL_SPEC = ToolSpec(
    short_no_arg=frozenset("fFqvz"),
    short_arg=frozenset("cns"),
    long_no_arg=frozenset(
        {
            "--debug",
            "--quiet",
            "--silent",
            "--retry",
            "--verbose",
            "--zero-terminated",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset(
        {"--bytes", "--lines", "--max-unchanged-stats", "--pid", "--sleep-interval"}
    ),
    long_opt_arg=frozenset({"--follow"}),
)

SORT_SPEC = ToolSpec(
    short_no_arg=frozenset("bdfgiMhnRrcCmsuzV"),
    short_arg=frozenset("koStT"),
    long_no_arg=frozenset(
        {
            "--ignore-leading-blanks",
            "--dictionary-order",
            "--ignore-case",
            "--general-numeric-sort",
            "--ignore-nonprinting",
            "--month-sort",
            "--human-numeric-sort",
            "--numeric-sort",
            "--random-sort",
            "--reverse",
            "--version-sort",
            "--debug",
            "--merge",
            "--stable",
            "--unique",
            "--zero-terminated",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset(
        {
            "--random-source",
            "--sort",
            "--batch-size",
            "--compress-program",
            "--files0-from",
            "--key",
            "--output",
            "--buffer-size",
            "--field-separator",
            "--temporary-directory",
            "--parallel",
        }
    ),
    long_opt_arg=frozenset({"--check"}),
    unnamed_file_opts=frozenset({"--files0-from"}),
)

UNIQ_SPEC = ToolSpec(
    short_no_arg=frozenset("cdDiuz"),
    short_arg=frozenset("fsw"),
    long_no_arg=frozenset(
        {
            "--count",
            "--repeated",
            "--ignore-case",
            "--unique",
            "--zero-terminated",
            "--help",
            "--version",
        }
    ),
    long_arg=frozenset({"--skip-fields", "--skip-chars", "--check-chars"}),
    long_opt_arg=frozenset({"--all-repeated", "--group"}),
)

TR_SPEC = ToolSpec(
    short_no_arg=frozenset("cCdst"),
    long_no_arg=frozenset(
        {
            "--complement",
            "--delete",
            "--squeeze-repeats",
            "--truncate-set1",
            "--help",
            "--version",
        }
    ),
    ignore_operands=True,
)

CAT_SPEC = ToolSpec(
    short_no_arg=frozenset("AbeEnstTuv"),
    long_no_arg=frozenset(
        {
            "--show-all",
            "--number-nonblank",
            "--show-ends",
            "--number",
            "--squeeze-blank",
            "--show-tabs",
            "--show-nonprinting",
            "--help",
            "--version",
        }
    ),
)

TOOL_SPECS: dict[str, ToolSpec] = {
    "wc": WC_SPEC,
    "grep": GREP_SPEC,
    "egrep": GREP_SPEC,
    "fgrep": GREP_SPEC,
    "rg": RG_SPEC,
    "awk": AWK_SPEC,
    "gawk": AWK_SPEC,
    "mawk": AWK_SPEC,
    "nawk": AWK_SPEC,
    "sed": SED_SPEC,
    "cut": CUT_SPEC,
    "head": HEAD_SPEC,
    "tail": TAIL_SPEC,
    "sort": SORT_SPEC,
    "uniq": UNIQ_SPEC,
    "tr": TR_SPEC,
    "cat": CAT_SPEC,
}

AWK_TOOL_NAMES = frozenset({"awk", "gawk", "mawk", "nawk"})
AWK_LOAD_OPTS = frozenset({"-i", "--include", "-l", "--load"})
AWK_FILE_CONSTRUCT = re.compile(r"\b(?:getline|system)\b|[<|]")
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SED_FILE_COMMANDS = frozenset({"r", "R", "w", "W", "e"})
SED_DELIMITED_COMMANDS = frozenset({"s", "y"})
SED_LINE_ARG_COMMANDS = frozenset({":", "b", "t", "T", "l", "q", "Q", "v"})
SED_TEXT_COMMANDS = frozenset({"a", "i", "c"})
SED_SIMPLE_COMMANDS = frozenset(
    {"d", "D", "g", "G", "h", "H", "n", "N", "p", "P", "x", "z", "=", "F"}
)


def length_tool_index(words: list[str]) -> int | None:
    """Return the index of the first non-redirect whole-file length program word."""
    limit = len(words)
    index = 0
    for _ in range(limit):
        if index >= limit:
            break
        redirect = length_redirect_operands(words, index, limit)
        if redirect is not None:
            index, _ = redirect
            continue
        if Path(words[index]).name in LENGTH_TOOL_NAMES:
            return index
        index += 1
    return None


def stage_command_index(words: list[str]) -> int | None:
    """Return the index of the command word of a stage after redirects and assignments."""
    limit = len(words)
    index = 0
    for _ in range(limit):
        if index >= limit:
            break
        redirect = length_redirect_operands(words, index, limit)
        if redirect is not None:
            index, _ = redirect
            continue
        if ENV_ASSIGNMENT.match(words[index]):
            index += 1
            continue
        return index
    return None


def collect_prefix_redirects(words: list[str], tool_index: int) -> tuple[list[str], bool]:
    """Collect input redirect targets and xargs presence before tool_index."""
    redirects: list[str] = []
    has_xargs = False
    index = 0
    for _ in range(tool_index):
        if index >= tool_index:
            break
        redirect = length_redirect_operands(words, index, tool_index)
        if redirect is not None:
            index, extra = redirect
            redirects.extend(extra)
            continue
        if Path(words[index]).name == "xargs":
            has_xargs = True
        index += 1
    return redirects, has_xargs


def record_option(spec: ToolSpec, opt: str, value: str | None, state: _StageState) -> None:
    """Record one parsed option and any program, file-program, or unnamed-file effect."""
    state.seen_opts.add(opt)
    if opt in spec.unnamed_file_opts:
        state.refused = True
    if value is not None and (opt, value) in spec.unnamed_file_opt_values:
        state.refused = True
    if opt in spec.program_opts and value is not None:
        state.opt_programs.append(value)
    if opt in spec.file_program_opts:
        state.uses_file = True


def parse_long_option(
    spec: ToolSpec, words: list[str], index: int, limit: int, state: _StageState
) -> int:
    """Parse one --long option token starting at index and return the next index."""
    name, has_eq, inline_value = words[index].partition("=")
    if name in spec.long_no_arg:
        if has_eq:
            state.refused = True
        record_option(spec, name, None, state)
        return index + 1
    if name in spec.long_opt_arg:
        record_option(spec, name, inline_value if has_eq else None, state)
        return index + 1
    if name in spec.long_arg:
        if has_eq:
            record_option(spec, name, inline_value, state)
            return index + 1
        if index + 1 < limit:
            record_option(spec, name, words[index + 1], state)
            return index + 2
        state.refused = True
        record_option(spec, name, None, state)
        return index + 1
    state.refused = True
    return index + 1


def parse_short_cluster(
    spec: ToolSpec, words: list[str], index: int, limit: int, state: _StageState
) -> int:
    """Parse one short-option cluster starting at index and return the next index."""
    cluster = words[index][1:]
    for offset, letter in enumerate(cluster):
        opt = f"-{letter}"
        rest = cluster[offset + 1 :]
        if letter in spec.short_no_arg:
            record_option(spec, opt, None, state)
            continue
        if letter in spec.short_opt_arg:
            record_option(spec, opt, rest or None, state)
            return index + 1
        if letter in spec.short_arg:
            if rest:
                record_option(spec, opt, rest, state)
                return index + 1
            if index + 1 < limit:
                record_option(spec, opt, words[index + 1], state)
                return index + 2
            state.refused = True
            record_option(spec, opt, None, state)
            return index + 1
        state.refused = True
    return index + 1


def step_stage_option(
    spec: ToolSpec, words: list[str], index: int, limit: int, state: _StageState
) -> int | None:
    """Advance past one option token when words[index] is an option, else return None."""
    token = words[index]
    if token.startswith("--"):
        return parse_long_option(spec, words, index, limit, state)
    if token.startswith("-") and token != "-":
        return parse_short_cluster(spec, words, index, limit, state)
    return None


def parse_stage_tokens(spec: ToolSpec, words: list[str], start: int, state: _StageState) -> None:
    """Scan tokens from start for redirects, options, --, and positional arguments."""
    limit = len(words)
    index = start
    options_ended = False
    for _ in range(limit):
        if index >= limit:
            break
        redirect = length_redirect_operands(words, index, limit)
        if redirect is not None:
            index, extra = redirect
            state.input_redirects.extend(extra)
            continue
        if not options_ended and words[index] == "--":
            options_ended = True
            index += 1
            continue
        next_index = None if options_ended else step_stage_option(spec, words, index, limit, state)
        if next_index is not None:
            index = next_index
            continue
        state.positionals.append(words[index])
        index += 1


def finalize_stage_parse(tool: str, spec: ToolSpec, state: _StageState) -> StageParse:
    """Build an immutable StageParse from accumulated options, operands, and redirects."""
    program_given = bool(state.opt_programs) or state.uses_file
    refused = state.refused
    if spec.ignore_operands:
        programs: tuple[str, ...] = ()
        operands: tuple[str, ...] = ()
    elif program_given:
        programs = tuple(state.opt_programs)
        operands = tuple(state.positionals)
    else:
        if len(state.positionals) < spec.program_words:
            refused = True
        programs = tuple(state.positionals[: spec.program_words])
        operands = tuple(state.positionals[spec.program_words :])
    return StageParse(
        tool=tool,
        seen_opts=frozenset(state.seen_opts),
        programs=programs,
        uses_file=state.uses_file,
        operands=operands,
        input_redirects=tuple(state.input_redirects),
        refused=refused,
    )


def parse_tool_stage(words: list[str], tool_index: int) -> StageParse:
    """Parse one stage around tool_index using the tool's getopt option spec."""
    tool = Path(words[tool_index]).name
    spec = TOOL_SPECS.get(tool)
    prefix_redirects, has_xargs = collect_prefix_redirects(words, tool_index)
    state = _StageState(
        seen_opts=set(),
        opt_programs=[],
        uses_file=False,
        positionals=[],
        input_redirects=prefix_redirects,
        refused=has_xargs or spec is None,
    )
    if spec is None:
        return finalize_stage_parse(tool, ToolSpec(), state)
    parse_stage_tokens(spec, words, tool_index + 1, state)
    return finalize_stage_parse(tool, spec, state)


def wc_is_length_check(words: list[str], tool_index: int) -> bool:
    """Return whether wc options request a max-line-length check."""
    parsed = parse_tool_stage(words, tool_index)
    return "-L" in parsed.seen_opts or "--max-line-length" in parsed.seen_opts


def strip_awk_double_quotes(program: str) -> str:
    """Remove double-quoted awk string literals while honoring backslash escapes."""
    kept: list[str] = []
    in_string = False
    escape = False
    for char in program:
        if in_string:
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        kept.append(char)
    return "".join(kept)


def awk_program_token(words: list[str], tool_index: int) -> tuple[str | None, bool]:
    """Return the inline awk program token and whether a program file option is present."""
    parsed = parse_tool_stage(words, tool_index)
    program = "\n".join(parsed.programs) if parsed.programs else None
    return program, parsed.uses_file


def awk_is_length_check(words: list[str], tool_index: int) -> bool:
    """Return whether an awk invocation measures whole-line length."""
    parsed = parse_tool_stage(words, tool_index)
    if parsed.uses_file:
        return True
    program = "\n".join(parsed.programs)
    if program and AWK_LENGTH_PROGRAM.search(strip_awk_double_quotes(program)):
        return True
    if parsed.refused:
        return any(
            AWK_LENGTH_PROGRAM.search(strip_awk_double_quotes(word)) for word in parsed.operands
        )
    return False


def grep_is_length_check(words: list[str], tool_index: int | None = None) -> bool:
    """Return whether grep or rg uses a pattern file or counted-dot column-width pattern."""
    resolved = length_tool_index(words) if tool_index is None else tool_index
    if resolved is None:
        return False
    parsed = parse_tool_stage(words, resolved)
    if parsed.uses_file:
        return True
    candidates = (*parsed.programs, *parsed.operands) if parsed.refused else parsed.programs
    return any(GREP_COUNTED_DOT.search(token) for token in candidates)


def command_is_length_check(words: list[str]) -> bool:
    """Return whether a parsed shell command performs a whole-file length check."""
    tool_index = length_tool_index(words)
    if tool_index is None:
        return False
    tool = Path(words[tool_index]).name
    if tool == "wc":
        return wc_is_length_check(words, tool_index)
    if tool in AWK_TOOL_NAMES:
        return awk_is_length_check(words, tool_index)
    return grep_is_length_check(words, tool_index)


def operand_is_lane_owned(operand: str) -> bool:
    """Return whether a file operand names a path under the worktree .lane/ tree."""
    if operand.startswith("\x00"):
        return False
    parts = operand.split("/")
    if ".." in parts:
        return False
    if operand.startswith(".lane/") or operand.startswith("./.lane/"):
        return True
    return operand.startswith("/") and "/.lane/" in operand


def length_redirect_advance(words: list[str], index: int, limit: int) -> tuple[list[str], int]:
    """Collect stdin operands and skip redirects starting at index."""
    found: list[str] = []
    token = words[index]
    if re.fullmatch(r"\d+", token) and index + 1 < limit and is_redirect_operator(words[index + 1]):
        index += 1
        token = words[index]
    if not is_redirect_operator(token):
        return found, index
    if token == "<" and index + 1 < limit:
        found.append(words[index + 1])
        return found, index + 2
    next_index = index + 1
    if (
        next_index < limit
        and words[next_index] not in COMMAND_SEPARATORS
        and token != "<"
        and not is_redirect_operator(words[next_index])
    ):
        next_index += 1
    return found, next_index


def length_redirect_operands(
    words: list[str], index: int, limit: int
) -> tuple[int, list[str]] | None:
    """Return redirect advance when index starts a paren or redirection token."""
    token = words[index]
    if token in ("(", ")"):
        return index + 1, []
    extra, advanced = length_redirect_advance(words, index, limit)
    if advanced == index:
        return None
    return advanced, extra


def command_file_operands(words: list[str]) -> list[str]:
    """Collect file operands for a parsed whole-file length command."""
    tool_index = length_tool_index(words)
    if tool_index is None:
        return []
    parsed = parse_tool_stage(words, tool_index)
    operands = [*parsed.operands, *parsed.input_redirects]
    if parsed.refused:
        operands.append("\x00refused")
    return operands


def awk_program_reads_files(source: str) -> bool:
    """Return whether an awk program uses getline, system, or pipe/input redirection."""
    return bool(AWK_FILE_CONSTRUCT.search(strip_awk_double_quotes(source)))


def skip_sed_delimited(script: str, start: int, delim: str) -> int | None:
    """Return index after the next unescaped delim in script, or None when unclosed."""
    escaped = False
    for index in range(start, len(script)):
        char = script[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == delim:
            return index + 1
    return None


def skip_sed_address_atom(script: str, index: int) -> int | None:
    """Advance past one sed address atom at index, returning None on unclosed regex."""
    limit = len(script)
    char = script[index]
    if char == "$":
        return index + 1
    if char == "/":
        return skip_sed_delimited(script, index + 1, "/")
    if char == "\\":
        if index + 1 >= limit:
            return None
        return skip_sed_delimited(script, index + 2, script[index + 1])
    if char.isdigit() or char in "+~":
        end = index + 1
        for pos in range(index + 1, limit):
            if not (script[pos].isdigit() or script[pos] in "+~"):
                break
            end = pos + 1
        return end
    return index


def skip_sed_line(script: str, start: int) -> int:
    """Return index of the newline ending the current sed line or len(script)."""
    newline = script.find("\n", start)
    return len(script) if newline < 0 else newline + 1


def skip_sed_prefix(script: str, start: int) -> int | None:
    """Skip sed separators, comments, blocks, and addresses before a command letter."""
    limit = len(script)
    index = start
    for _ in range(limit + 1):
        if index >= limit:
            return limit
        char = script[index]
        if char in " \t\r\n;{}!,":
            index += 1
            continue
        if char == "#":
            index = skip_sed_line(script, index + 1)
            continue
        advanced = skip_sed_address_atom(script, index)
        if advanced is None:
            return None
        if advanced == index:
            return index
        index = advanced
    return limit


def step_sed_delimited(script: str, index: int) -> tuple[int, bool]:
    """Advance past a sed s or y command and report whether its flags read or execute."""
    cmd = script[index]
    if index + 1 >= len(script):
        return len(script), True
    delim = script[index + 1]
    mid = skip_sed_delimited(script, index + 2, delim)
    end = None if mid is None else skip_sed_delimited(script, mid, delim)
    if end is None:
        return len(script), True
    if cmd == "y":
        return end, False
    for pos in range(end, len(script)):
        flag = script[pos]
        if flag in ";\n}#":
            return pos, False
        if flag in ("w", "e") or flag not in "gpiImM0123456789 \t\r":
            return len(script), True
    return len(script), False


def skip_sed_text_arg(script: str, start: int) -> int:
    """Advance past a sed a, i, or c text argument honoring backslash-continued lines."""
    escaped = False
    for pos in range(start, len(script)):
        char = script[pos]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "\n":
            return pos + 1
    return len(script)


def skip_sed_label_arg(script: str, start: int) -> int:
    """Advance past a sed label, branch, or line-arg command to the next boundary."""
    for pos in range(start, len(script)):
        if script[pos] in ";\n}":
            return pos
    return len(script)


def step_sed_other_command(program: str, index: int) -> int | None:
    """Return next index after a non-file, non-s/y sed command, or None when unknown."""
    cmd = program[index]
    if cmd in SED_SIMPLE_COMMANDS:
        return index + 1
    if cmd in SED_LINE_ARG_COMMANDS:
        return skip_sed_label_arg(program, index + 1)
    if cmd in SED_TEXT_COMMANDS:
        return skip_sed_text_arg(program, index + 1)
    return None


def sed_program_reads_files(program: str) -> bool:
    """Return whether a sed script uses a file or shell-execution command or s flag."""
    limit = len(program)
    index = 0
    for _ in range(limit + 1):
        next_index = skip_sed_prefix(program, index)
        if next_index is None:
            return True
        if next_index >= limit:
            return False
        cmd = program[next_index]
        if cmd in SED_FILE_COMMANDS:
            return True
        if cmd in SED_DELIMITED_COMMANDS:
            index, unsafe = step_sed_delimited(program, next_index)
            if unsafe:
                return True
            continue
        other_index = step_sed_other_command(program, next_index)
        if other_index is None:
            return True
        index = other_index
    return True


def intermediate_program_safe(parsed: StageParse) -> bool:
    """Return whether an intermediate awk or sed stage avoids external file constructs."""
    if parsed.tool in AWK_TOOL_NAMES:
        if parsed.uses_file or (parsed.seen_opts & AWK_LOAD_OPTS):
            return False
        return not any(awk_program_reads_files(prog) for prog in parsed.programs)
    if parsed.tool == "sed":
        if parsed.uses_file:
            return False
        return not any(sed_program_reads_files(prog) for prog in parsed.programs)
    return True


def stage_reads_only_pipe(words: list[str], *, is_final: bool) -> bool:
    """Return whether one pipeline stage reads exclusively from its stdin pipe."""
    cmd_index = stage_command_index(words)
    if cmd_index is None or Path(words[cmd_index]).name not in TOOL_SPECS:
        return False
    parsed = parse_tool_stage(words, cmd_index)
    if parsed.refused or parsed.input_redirects or any(op != "-" for op in parsed.operands):
        return False
    return True if is_final else intermediate_program_safe(parsed)


def length_command_allowed(words: list[str], pipeline: list[list[str]], command_index: int) -> bool:
    """Return whether a length command may read outside a git diff."""
    operands = command_file_operands(words)
    if operands and all(operand_is_lane_owned(operand) for operand in operands):
        return True
    if command_index == 0 or not GIT_DIFF_COMMAND.search(" ".join(pipeline[0])):
        return False
    return all(
        stage_reads_only_pipe(pipeline[idx], is_final=(idx == command_index))
        for idx in range(1, command_index + 1)
    )


def span_whole_file_length_refused(span: str) -> bool:
    """Return whether any parsed length command in the span must be refused."""
    tokens = span_shell_tokens(span)
    if tokens is None:
        return bool(WHOLE_FILE_LENGTH.search(span))
    for pipeline in span_token_command_groups(tokens):
        parsed = [stage for stage in pipeline if stage]
        for command_index, words in enumerate(parsed):
            if command_is_length_check(words) and not length_command_allowed(
                words, parsed, command_index
            ):
                return True
    return False


def conflict_whole_file_length_check(content: str) -> str:
    """Report a backtick line-length command that does not read a git diff."""
    for match in non_clause_spans(content):
        if "host ran" in line_slice(content, match.start(), match.end()).lower():
            continue
        span = match.group(1)
        if span_whole_file_length_refused(span):
            span_text = " ".join(span.split())
            return f"`{span_text}`: check only added lines of a git diff"
    return ""


def standalone_object_names(content: str) -> list[str]:
    """Collect unique standalone 40-hex names outside URL tokens in content order."""
    seen: dict[str, None] = {}
    for token in content.split():
        if "://" in token:
            continue
        for name in STANDALONE_OBJECT.findall(token):
            seen.setdefault(name.lower(), None)
    return list(seen)


def probe_repository_root(directory: Path) -> tuple[Path | None, str, str]:
    """Return resolved root, error message, and probe status ok, git, or not_root."""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    result = lane_isolation.run_git(["-C", str(directory), "rev-parse", "--show-toplevel"])
    toplevel = result.stdout.removesuffix("\n")
    if result.returncode != 0 or not toplevel:
        return None, result.stderr.strip() or f"{directory}: not a git worktree", "git"
    resolved = directory.resolve()
    if Path(toplevel).resolve() != resolved:
        return None, f"{directory}: not its own repository root", "not_root"
    return resolved, "", "ok"


def valid_nested_root(path: Path, worktree_root: Path) -> bool:
    """Return whether path is a repository root strictly inside worktree_root."""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    if path == worktree_root or not path.is_relative_to(worktree_root):
        return False
    if not path.is_dir():
        return False
    root, error, kind = probe_repository_root(path)
    if root is not None:
        return True
    if kind == "not_root":
        return False
    if kind == "git" and error:
        raise lane_isolation.IsolationError(error)
    return False


def nested_repositories(content: str, worktree_root: Path) -> list[Path]:
    """Collect up to 8 resolved nested repository roots named with git -C."""
    candidates: list[Path] = []
    for match in list(NESTED_GIT_C.finditer(content))[:MAX_LINES]:
        raw = match.group(1).strip("\"'")
        if Path(raw).is_absolute():
            continue
        resolved = (worktree_root / raw).resolve()
        if resolved not in candidates:
            candidates.append(resolved)
        if len(candidates) >= MAX_NESTED_REPOS:
            break
    return [path for path in candidates if valid_nested_root(path, worktree_root)]


def object_exists(repositories: list[Path], name: str) -> bool:
    """Return whether name exists in any repository, raising IsolationError on Git error."""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    for repository in repositories:
        probe = lane_isolation.run_git(["-C", str(repository), "cat-file", "-e", name])
        if probe.returncode == 0:
            return True
        if probe.returncode != 1:
            detail = probe.stderr.strip() or f"git cat-file exited {probe.returncode}"
            raise lane_isolation.IsolationError(detail)
    return False


def conflict_missing_object(content: str, worktree: Path) -> str:
    """Report a standalone 40-hex object name absent from the worktree and nested repos."""
    names = standalone_object_names(content)
    if not names:
        return ""
    lane_isolation = importlib.import_module("scripts.lane_isolation")
    current = names[0]
    try:
        worktree_root, root_error, _kind = probe_repository_root(worktree)
        if worktree_root is None:
            raise lane_isolation.IsolationError(root_error)
        repositories = [worktree_root, *nested_repositories(content, worktree_root)]
        for current in names:
            if not object_exists(repositories, current):
                return (
                    f"{current} not in {worktree}: write full names from git rev-parse, "
                    "never extend a short name by hand"
                )
    except (lane_isolation.IsolationError, OSError) as error:
        raise lane_isolation.IsolationError(f"could not resolve {current}: {error}") from error
    return ""


def check_conflicts(content: str, label: str, worktree: Path) -> int:
    """Print each brief conflict reason and return 1 on conflict or 2 on Git error."""
    reasons = [
        conflict_make_without_praetorctl(content),
        conflict_join_under_column_limit(content),
        conflict_whole_file_length_check(content),
    ]
    try:
        reasons.append(conflict_missing_object(content, worktree))
    except (OSError, ValueError) as error:
        print(f"lane_brief: {error}", file=sys.stderr)
        return 2
    reported = [reason for reason in reasons if reason]
    for reason in reported:
        print(f"{label}: conflict: {reason}", file=sys.stderr)
    return int(bool(reported))


def check_brief(args: argparse.Namespace) -> int:
    """Validate the brief locally and run the configured runner precheck."""
    content = "".join(bounded_lines(args.brief))
    config = (
        args.config if args.config is not None else args.worktree / ".config" / "lane-brief.yaml"
    )
    result = check(content, str(args.brief), read_required(config))
    conflict_result = check_conflicts(content, str(args.brief), args.worktree)
    if conflict_result == 2:
        return 2
    if result or conflict_result:
        return 1
    if not args.runner:
        print(
            "lane_brief: runner and lane isolation checks skipped: LANE_BRIEF_RUNNER unset",
            file=sys.stderr,
        )
        return 0
    result = check_isolation(args.worktree)
    if result:
        return result
    return check_runner(args.runner, args.brief, args.worktree)


def main(argv: list[str] | None = None) -> int:
    """Run the selected command and report input errors."""
    args = parser_for_cli().parse_args(argv)
    try:
        if args.command == "render":
            return render_brief(args)
        return check_brief(args)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"lane_brief: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
