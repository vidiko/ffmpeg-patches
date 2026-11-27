# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Shell tokenizer, substitution and heredoc scanners of the raw configure guard."""

from __future__ import annotations

import itertools
import re
import shlex
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

# Ensure repository root is on sys.path for test/tool imports
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.raw_configure_words import (  # noqa: E402
    MAX_COMMAND,
    MAX_SUBSHELL_DEPTH,
    MAX_TOKENS,
    REDIRECT_TARGET_OPS,
    SELF_REDIRECT,
    SEPARATORS,
)

_TAIL_WORD = re.compile(rb"[A-Za-z0-9_./:,=+\-]+")
_DQ_TAIL_INNER = re.compile(
    rb"^[A-Za-z0-9_ ./:,=+\-]*"
    rb"(?:\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*))*$"
)
_DESCRIPTOR_BOUNDARY = r"(?:\A|(?<=[ \t\n;|()])|(?<=(?<![<>])&))"
_DESCRIPTOR_BODY = r"([0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})"
_DESCRIPTOR_PREFIX_STR = _DESCRIPTOR_BOUNDARY + _DESCRIPTOR_BODY
_DESCRIPTOR_PREFIX = _DESCRIPTOR_PREFIX_STR.encode("ascii")
_DUP_OPERAND_END_STR = r"(?=\Z|[ \t\n;&|<>()])"
_DUP_OPERAND_END = _DUP_OPERAND_END_STR.encode("ascii")
_TAIL_MARK = re.compile(_DESCRIPTOR_PREFIX + rb"<<<")
_DUP_STDIN = re.compile(rf"(?:{_DESCRIPTOR_PREFIX_STR})?<&([0-9]+)-?{_DUP_OPERAND_END_STR}")
_DUP_STDIN_BYTES = re.compile(
    rb"(?:" + _DESCRIPTOR_PREFIX + rb")?<&\s*([0-9]+)-?" + _DUP_OPERAND_END
)
_HS_FD_TAG = re.compile(r"^__RCG_HS_FD([0-9]+)_([0-9]+)([VU]?)__$")
_HS_ZERO_TAG = re.compile(r"^__RCG_HS_0_([0-9]+)__$")
_DUP_OR_CLOSE_TOK = re.compile(
    rf"^(?:{_DESCRIPTOR_PREFIX_STR})?(<&|>&)([0-9]+-?|-){_DUP_OPERAND_END_STR}"
)
_FILE_REDIR_TOK = re.compile(r"^([0-9]*)(>>|<>|>\||<|>|&>|&>>)$")
_SEG_REDIR_BYTES = re.compile(
    rb"(?:"
    rb"(?P<hd>(?:" + _DESCRIPTOR_PREFIX + rb")?<<-?(?!<))"
    rb"|(?P<hs>(?P<hs_fd>" + _DESCRIPTOR_PREFIX + rb")?<<<)"
    rb"|(?P<dup>(?P<dup_fd>"
    + _DESCRIPTOR_PREFIX
    + rb")?(?P<dup_op><&|>&)\s*(?P<dup_rhs>[0-9]+-?|-)"
    + _DUP_OPERAND_END
    + rb")"
    rb"|(?P<amp>&>>|&>|>&)"
    rb"|(?P<file>(?P<file_fd>" + _DESCRIPTOR_PREFIX + rb")?(?P<file_op>>>|<>|>\||<|>)(?![<&>(]))"
    rb")"
)
_BYTE_SEP = re.compile(rb"\|\||\|&|\||&&|;;&|;;|;&|;|&|\n|\(|\)|`")


def _descriptor_fd(prefix: str | bytes | None) -> int | None:
    """Return integer descriptor for an empty or digit prefix, or None for brace names."""
    if not prefix:
        return 0
    text = prefix.decode("ascii") if isinstance(prefix, bytes) else prefix
    return int(text) if text.isdigit() else None


def _is_stdin_descriptor(prefix: str | bytes | None) -> bool:
    """Return whether an empty or digit descriptor prefix refers to fd 0."""
    return _descriptor_fd(prefix) == 0


def _dup_stdin_fd(left: str | bytes | None, right: str | bytes) -> int | None:
    """Return the duplicated descriptor number when left<&right targets fd 0."""
    if not _is_stdin_descriptor(left):
        return None
    text = right.decode("ascii") if isinstance(right, bytes) else right
    return int(text.removesuffix("-"))


def _apply_dup_or_close(
    fds: dict[int, Any], left: str | bytes | None, op: str | bytes, rhs: str | bytes
) -> Any | None:
    """Apply one N<&M, N>&M, N<&M-, N>&M-, N<&-, or N>&- operation; return resolved stdin."""
    is_in = op in ("<&", b"<&")
    target = (0 if is_in else 1) if not left else _descriptor_fd(left)
    rhs_text = rhs.decode("ascii") if isinstance(rhs, bytes) else rhs
    if target is None:
        if rhs_text != "-" and rhs_text.endswith("-"):
            fds.pop(int(rhs_text[:-1]), None)
        return None
    if rhs_text == "-":
        fds.pop(target, None)
        return None
    is_move = rhs_text.endswith("-")
    src_digits = rhs_text[:-1] if is_move else rhs_text
    src = int(src_digits)
    val = fds.get(src)
    if val is None:
        fds.pop(target, None)
    else:
        fds[target] = val
    if is_move:
        fds.pop(src, None)
    return fds.get(0) if is_in and _dup_stdin_fd(left, src_digits) is not None else None


def _apply_file_redirect(fds: dict[int, Any], left: str | bytes | None, op: str | bytes) -> None:
    """Remove any descriptor entry overwritten by a file redirection operator."""
    op_text = op.decode("ascii") if isinstance(op, bytes) else op
    if op_text in ("&>", "&>>", ">&"):
        fds.pop(1, None)
        fds.pop(2, None)
        return
    default_fd = 0 if op_text in ("<", "<>") else 1
    target = default_fd if not left else _descriptor_fd(left)
    if target is not None:
        fds.pop(target, None)


def _advance_unquoted_mask(raw: bytes, buf: bytearray, idx: int) -> tuple[int, int | None, bool]:
    """Advance one unquoted step and return next index, opened quote, and ANSI-C flag."""
    n = len(raw)
    b = raw[idx]
    if b == ord("\\"):
        if idx + 1 < n and raw[idx + 1] != ord("\n"):
            buf[idx] = buf[idx + 1] = 1
        return idx + 2, None, False
    if b == ord("#") and (idx == 0 or raw[idx - 1] in b" \t\r\n;&|()"):
        nl = raw.find(b"\n", idx)
        end = n if nl < 0 else nl
        buf[idx:end] = b"\x01" * (end - idx)
        return (n if nl < 0 else nl + 1), None, False
    if b in (ord("'"), ord('"')):
        ansi = b == ord("'") and idx > 0 and raw[idx - 1] == ord("$")
        return idx + 1, b, ansi
    return idx + 1, None, False


def _advance_quoted_mask(
    raw: bytes, buf: bytearray, idx: int, quote: int, ansi: bool
) -> tuple[int, int | None, bool]:
    """Advance one quoted step and mask non-newline interior bytes to SOH."""
    n = len(raw)
    b = raw[idx]
    if b == ord("\\") and (quote == ord('"') or ansi):
        buf[idx] = 1
        if idx + 1 < n and raw[idx + 1] != ord("\n"):
            buf[idx + 1] = 1
        return idx + 2, quote, ansi
    if b == quote:
        return idx + 1, None, False
    if b != ord("\n"):
        buf[idx] = 1
    return idx + 1, quote, ansi


def _mask_quoted_bytes(raw: bytes) -> bytes:
    """Replace quoted, escaped, and comment interior bytes with SOH."""
    buf = bytearray(raw)
    quote: int | None = None
    ansi = False
    idx = 0
    n = len(raw)
    for _ in range(n):
        if idx >= n:
            break
        if quote is None:
            idx, quote, ansi = _advance_unquoted_mask(raw, buf, idx)
        else:
            idx, quote, ansi = _advance_quoted_mask(raw, buf, idx, quote, ansi)
    return bytes(buf)


def _append_attached_op(op: str, tokens: list[str], left_ok: bool) -> None:
    """Append a redirection operator, merging it onto an adjacent leading fd token."""
    if left_ok:
        tokens[-1] += op
    else:
        tokens.append(op)


def _append_redirect_fd(
    punc: str,
    tokens: list[str],
    raw_tokens: list[str],
    idx: int,
    attach: tuple[bool, bool] = (True, True),
) -> int:
    """Attach a redirection operator to an adjacent left fd and any valid right fd target."""
    left_ok, right_ok = attach
    _append_attached_op(punc, tokens, left_ok and bool(tokens) and tokens[-1].isdigit())
    if right_ok and idx < len(raw_tokens):
        rhs = raw_tokens[idx]
        if rhs == "-" or rhs.removesuffix("-").isdigit():
            tokens[-1] += rhs
            return idx + 1
    return idx


def _step_punctuation(
    token: str,
    pos: int,
    tokens: list[str],
    ctx: tuple[list[str], int, bool],
) -> tuple[int, int]:
    """Consume one punctuation operator at pos and return updated (pos, raw_idx)."""
    raw_tokens, idx, attach_left = ctx
    left_ok = attach_left and pos == 0
    two = token[pos : pos + 2]
    if token[pos : pos + 3] == "&>>":
        tokens.append("&>>")
        return pos + 3, idx
    if two in (">&", "<&"):
        next_idx = _append_redirect_fd(
            two, tokens, raw_tokens, idx, (left_ok, pos + 2 == len(token))
        )
        return pos + 2, next_idx
    if two in (">>", "<>", ">|"):
        _append_attached_op(two, tokens, left_ok)
        return pos + 2, idx
    if two in ("&>", "&&", "||", "<<"):
        tokens.append(two)
        return pos + 2, idx
    if two == "|&":
        tokens.append("|")
        return pos + 2, idx
    _append_attached_op(token[pos], tokens, left_ok and token[pos] in ("<", ">"))
    return pos + 1, idx


def _append_punctuation(
    token: str,
    tokens: list[str],
    raw_tokens: list[str],
    idx: int,
    *,
    attach_left: bool = True,
) -> int:
    """Expand one punctuation run and merge shell redirect operators."""
    pos = 0
    for _ in range(len(token)):
        if pos >= len(token):
            break
        pos, idx = _step_punctuation(token, pos, tokens, (raw_tokens, idx, attach_left))
    return idx


def _update_quote(char: str, quote: str | None, allow_quotes: bool = True) -> str | None:
    """Update current quote state when encountering quote delimiters."""
    if not allow_quotes:
        return None
    if quote is None and char in ("'", '"'):
        return char
    if quote is not None and char == quote:
        return None
    return quote


def _scan_substitution_body(command: str, start: int) -> tuple[int, int] | None:
    """Find the closing parenthesis of a command substitution without recursion."""
    depth = 1
    idx = start
    quote: str | None = None
    cmd_len = len(command)
    for _ in range(cmd_len):
        if idx >= cmd_len:
            break
        char = command[idx]
        if char == "\\":
            idx += 2
            continue
        if quote is not None:
            quote = _update_quote(char, quote)
            idx += 1
            continue
        if char in ("'", '"'):
            quote = char
            idx += 1
            continue
        if command[idx : idx + 2] in ("$(", "<(", ">("):
            depth += 1
            if depth > MAX_SUBSHELL_DEPTH:
                return None
            idx += 2
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return start, idx
        idx += 1
    return None


def _scan_backtick(command: str, idx: int) -> int | None:
    """Find the closing backtick of a command substitution."""
    end_idx = command.find("`", idx + 1)
    return None if end_idx == -1 else end_idx


def _record_sub(full_sub: str, inner: str, reps: list[tuple[str, str]], inners: list[str]) -> str:
    """Record one substitution placeholder and inner command."""
    tag = f"__RCG_SUB_{len(reps)}__"
    reps.append((tag, full_sub))
    inners.append(inner)
    return tag


def _scan_substitutions(
    command: str,
    *,
    literal_quotes: bool = False,
) -> tuple[str, list[str], list[tuple[str, str]]] | None:
    """Find command and process substitutions before shlex parsing without recursion."""
    if len(command.encode("utf-8", "surrogatepass")) > MAX_COMMAND:
        return None
    pieces: list[str] = []
    inners: list[str] = []
    replacements: list[tuple[str, str]] = []
    idx = 0
    quote: str | None = None
    cmd_len = len(command)
    for _ in range(cmd_len):
        if idx >= cmd_len:
            break
        char = command[idx]
        if char == "\\":
            pieces.append(command[idx : idx + 2])
            idx += 2
            continue
        if quote != "'":
            if command[idx : idx + 2] in ("$(", "<(", ">("):
                b = _scan_substitution_body(command, idx + 2)
                if b is None:
                    return None
                tag = _record_sub(
                    command[idx : b[1] + 1], command[b[0] : b[1]], replacements, inners
                )
                pieces.append(tag)
                idx = b[1] + 1
                continue
            if char == "`":
                end_idx = _scan_backtick(command, idx)
                if end_idx is None:
                    return None
                tag = _record_sub(
                    command[idx : end_idx + 1], command[idx + 1 : end_idx], replacements, inners
                )
                pieces.append(tag)
                idx = end_idx + 1
                continue
        quote = _update_quote(char, quote, not literal_quotes)
        pieces.append(char)
        idx += 1
    return "".join(pieces), inners, replacements


def _restore_tokens(tokens: list[str], replacements: list[tuple[str, str]]) -> list[str]:
    """Restore command substitution placeholders in parsed tokens."""
    if not replacements:
        return tokens
    restored = list(tokens)
    for tag, full_sub in replacements:
        restored = [tok.replace(tag, full_sub) for tok in restored]
    return restored


def _read_delim(line: str, pos: int, line_len: int) -> tuple[str, int, str | None]:
    """Read a heredoc delimiter token starting at the given position."""
    if pos < line_len and line[pos] in ("'", '"'):
        q_char = line[pos]
        pos += 1
        start_q = pos
        for _ in range(line_len - pos + 1):
            if pos >= line_len or line[pos] == q_char:
                break
            pos += 1
        delim = line[start_q:pos]
        return delim, (pos + 1 if pos < line_len else pos), q_char
    quoted: str | None = None
    if pos < line_len and line[pos] == "\\":
        quoted = "\\"
        pos += 1
    start_d = pos
    for _ in range(line_len - pos + 1):
        if pos >= line_len or line[pos] in " \t;&|<>()\n\r":
            break
        if line[pos] in ("\\", "'", '"'):
            quoted = "\\"
        pos += 1
    return line[start_d:pos], pos, quoted


def _parse_heredoc_at(line: str, pos: int, line_len: int) -> tuple[int, str, bool, bool] | None:
    """Parse heredoc marker details starting after << operator."""
    tab_strip = pos < line_len and line[pos] == "-"
    pos += 1 if tab_strip else 0
    for _ in range(line_len - pos):
        if line[pos] not in " \t":
            break
        pos += 1
    delim, pos, q_delim = _read_delim(line, pos, line_len)
    if delim:
        return pos, delim, tab_strip, q_delim is not None
    return None


def _scan_heredoc_line(line: str, line_len: int) -> tuple[int, int, str, bool, bool] | None:
    """Find one heredoc marker and delimiter on a line outside quotes."""
    quote = None
    pos = 0
    for _ in range(line_len):
        if pos >= line_len:
            break
        ch = line[pos]
        if quote is None:
            if ch in ("'", '"'):
                quote = ch
            elif line[pos : pos + 3] == "<<<":
                pos += 3
                continue
            elif line[pos : pos + 2] == "<<":
                start_hd = pos
                parsed = _parse_heredoc_at(line, pos + 2, line_len)
                if parsed is not None:
                    end_pos, delim, tab_strip, is_quoted = parsed
                    return start_hd, end_pos, delim, tab_strip, is_quoted
        elif ch == quote:
            quote = None
        pos += 1
    return None


def _scan_heredocs(command: str) -> tuple[str, dict[str, str], set[str]] | None:
    """Extract heredocs outside quotes and replace declarations with placeholders."""
    if len(command) > MAX_COMMAND:
        return None
    lines = command.splitlines(keepends=True)
    out_lines: list[str] = []
    heredocs: dict[str, str] = {}
    expanding_tags: set[str] = set()
    idx = 0
    num_lines = len(lines)
    for _ in range(num_lines):
        if idx >= num_lines:
            break
        line = lines[idx]
        idx += 1
        found_hd = _scan_heredoc_line(line, len(line))
        if found_hd is None:
            out_lines.append(line)
            continue
        start_hd, end_hd, delim, tab_strip, is_quoted = found_hd
        tag = f"__RCG_HD_{len(heredocs)}__"
        if not is_quoted:
            expanding_tags.add(tag)
        out_lines.append(line[:start_hd] + tag + line[end_hd:])
        body: list[str] = []
        closed = False
        for _ in range(num_lines - idx + 1):
            if idx >= num_lines:
                break
            b_line = lines[idx]
            idx += 1
            check = b_line.lstrip("\t") if tab_strip else b_line
            if check.rstrip("\r\n") == delim:
                closed = True
                break
            body.append(b_line)
        if not closed:
            return None
        heredocs[tag] = "".join(body)
    return "".join(out_lines), heredocs, expanding_tags


def _char_byte_offsets(command: str, raw: bytes) -> tuple[int, ...] | None:
    """Build per-character UTF-8 byte offsets when command contains non-ASCII characters."""
    if len(raw) == len(command):
        return None
    return (0, *itertools.accumulate(len(ch.encode("utf-8", "surrogatepass")) for ch in command))


def _byte_offset(command: str, pos: int, offsets: tuple[int, ...] | None) -> int:
    """Return UTF-8 byte offset of char index pos in command."""
    return pos if offsets is None else offsets[pos]


def _herestring_opener(
    command: str,
    pos: int,
    precomputed: tuple[bytes, bytes, tuple[int, ...] | None] | None = None,
) -> tuple[int, str]:
    """Return char length and descriptor prefix of an unquoted here-string opener at pos."""
    if pos < 0 or pos >= len(command) or command[pos] in " \t\r\n":
        return 0, ""
    if precomputed is None:
        raw = command.encode("utf-8", "surrogatepass")
        masked = _mask_quoted_bytes(raw)
        offsets = _char_byte_offsets(command, raw)
    else:
        raw, masked, offsets = precomputed
    bpos = _byte_offset(command, pos, offsets)
    if masked[bpos] == 1:
        return 0, ""
    match = _TAIL_MARK.match(masked, bpos)
    if match is not None:
        prefix = raw[match.start(1) : match.end(1)].decode("ascii")
        return len(prefix) + 3, prefix
    if masked[bpos : bpos + 3] == b"<<<":
        return 3, ""
    return 0, ""


def _herestring_op_len(command: str, pos: int) -> int:
    """Return char length of a here-string opener at pos, or zero when none starts there."""
    return _herestring_opener(command, pos)[0]


def _herestring_tag(prefix: str, val: str, idx: int, herestrings: dict[str, str]) -> str:
    """Register one extracted here-string value and return its token placeholder."""
    if _is_stdin_descriptor(prefix):
        tag = f"__RCG_HS_0_{idx}__"
    elif (fd := _descriptor_fd(prefix)) is not None:
        tag = f"__RCG_HS_FD{fd}_{idx}{_word_class(val)}__"
        herestrings[f"__RCG_HS_0_{idx}__"] = val
    else:
        tag = f"__RCG_HS_BR_{idx}__"
    herestrings[tag] = val
    return tag


def _prepare_herestring_masks(
    command: str,
) -> tuple[bytes, bytes, tuple[int, ...] | None] | None:
    """Build UTF-8 bytes, quote mask, and char offsets when command contains <<<."""
    if "<<<" not in command:
        return None
    raw = command.encode("utf-8", "surrogatepass")
    return raw, _mask_quoted_bytes(raw), _char_byte_offsets(command, raw)


def _scan_herestrings(command: str) -> tuple[str, dict[str, str], list[str]]:
    """Extract here-strings outside quotes and replace with placeholders."""
    prepared = _prepare_herestring_masks(command)
    if prepared is None:
        return command, {}, []
    herestrings: dict[str, str] = {}
    hs_to_scan: list[str] = []
    pos = 0
    cmd_len = len(command)
    pieces: list[str] = []
    hs_count = 0
    for _ in range(cmd_len):
        if pos >= cmd_len:
            break
        if (opener := _herestring_opener(command, pos, prepared))[0] > 0:
            pos += opener[0]
            pos += len(command[pos:]) - len(command[pos:].lstrip(" \t"))
            val, pos, q_delim = _read_delim(command, pos, cmd_len)
            tag = _herestring_tag(opener[1], val, hs_count, herestrings)
            hs_count += 1
            if q_delim != "'":
                hs_to_scan.append(val)
            pieces.append(tag)
            continue
        pieces.append(command[pos])
        pos += 1
    return "".join(pieces), herestrings, hs_to_scan


def _is_redirect_word_op(tok: str) -> bool:
    """Return whether tok is a file redirection operator taking a following word."""
    return (
        tok in REDIRECT_TARGET_OPS
        or re.fullmatch(r"^\d*(?:>>|<>|>|<|&>|&>>|>\|)$", tok) is not None
    )


def _is_self_redirect_tok(tok: str) -> bool:
    """Return whether tok is a descriptor-duplication, move, or close redirection token."""
    return (
        tok in (">&", "<&")
        or SELF_REDIRECT.fullmatch(tok) is not None
        or _DUP_OR_CLOSE_TOK.fullmatch(tok) is not None
    )


def _dup_stdin_source(tok: str) -> int | None:
    """Return source fd when tok ends with a numeric descriptor dup onto fd 0."""
    match = _DUP_STDIN.search(tok)
    return _dup_stdin_fd(match.group(1), match.group(2)) if match is not None else None


class _Marker:
    """Table value naming why a descriptor binding cannot be resolved."""

    def __init__(self, reason: str) -> None:
        """Store the refusal reason carried by this marker."""
        self.reason = reason


_UNKNOWN = _Marker("descriptor binding unknown at duplication")
_STALE = _Marker("saved here-string word may change before its duplication")
_LEAD_WORDS = frozenset(
    (
        "if",
        "then",
        "elif",
        "else",
        "while",
        "until",
        "do",
        "{",
        "}",
        "!",
        "time",
        "fi",
        "done",
        "esac",
    )
)
_ASSIGN_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_FN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")
_NON_ASSIGNING = frozenset(("cat", "echo", "true", ":", "test", "[", "printf"))
_ARITH_MARKS = ("$((", "$[", "((", "${")
_PLAIN_EXPANSION = re.compile(
    r"\$(?:\{(?=[A-Za-z0-9_]*[a-z])[A-Za-z_][A-Za-z0-9_]*\}"
    r"|(?=[A-Za-z0-9_]*[a-z])[A-Za-z_][A-Za-z0-9_]*)"
)
_SUB_TAG = "__RCG_SUB_"
_TERM_KIND = {
    ";": ";",
    "\n": ";",
    "&&": ";",
    "||": ";",
    "|": "|",
    "&": "&",
    "(": "(",
    ")": ")",
}


class _Bound(NamedTuple):
    """One here-string word held by a descriptor; volatile when it expands an application name."""

    word: Any
    volatile: bool


class _Event(NamedTuple):
    """One stage with its payload, ending separator, separator kind and unchanged text."""

    payload: Any
    sep: Any
    kind: str
    echo: list[Any]


class _StageState:
    """Outputs of one command stage: rewritten parts, command words, table and refusal."""

    def __init__(self, table: dict[int, Any]) -> None:
        """Start a stage from a copy of the caller's descriptor table."""
        self.fds: dict[int, Any] = dict(table)
        self.out: list[Any] = []
        self.words: list[str] = []
        self.stripped = bytearray()
        self.refusal: str | None = None


class _Frame:
    """One open group: closer, table at the open, pipeline position and case depth."""

    def __init__(
        self, closer: str, snapshot: dict[int, Any], after_pipe: bool, case_level: int
    ) -> None:
        """Record one open group with the table to restore at its closer."""
        self.closer = closer
        self.snapshot = snapshot
        self.after_pipe = after_pipe
        self.case_level = case_level
        self.is_fn = False
        self.assigned = False


def _word_class(word: str | bytes) -> str:
    """Return empty for a literal word, V for plain application names only, U otherwise."""
    text = word.decode("utf-8", "surrogateescape") if isinstance(word, bytes) else word
    if "`" in text:
        return "U"
    if "$" not in text:
        return ""
    return "U" if "$" in _PLAIN_EXPANSION.sub("", text) else "V"


def _bound_word(word: Any, flag: str) -> Any:
    """Return the table value for a saved word: stale at once when its expansion is unstable."""
    return _STALE if flag == "U" else _Bound(word, bool(flag))


def _leading_words(words: list[str]) -> list[str]:
    """Return the run of reserved opening or closing words at the start of one stage."""
    lead: list[str] = []
    for word in words:
        if word not in _LEAD_WORDS:
            break
        lead.append(word)
    return lead


def _command_words(words: list[str]) -> tuple[list[str], bool]:
    """Return the words from the command name on and whether an assignment precedes it."""
    assigned = False
    for idx, word in enumerate(words):
        if word in _LEAD_WORDS:
            continue
        if _ASSIGN_WORD.match(word) is not None:
            assigned = True
            continue
        return words[idx:], assigned
    return [], assigned


def _stage_assigns(cmd: list[str], assigned: bool) -> bool:
    """Return whether one stage can assign a shell variable under the non-assigning allow-list."""
    if assigned:
        return True
    if not cmd or cmd == ["exec"]:
        return False
    if cmd[0] not in _NON_ASSIGNING:
        return True
    if cmd[0] == "printf" and any(word.startswith("-v") for word in cmd[1:]):
        return True
    return any(mark in word for word in cmd for mark in _ARITH_MARKS)


def _changed_fds(old: dict[int, Any], new: dict[int, Any]) -> set[int]:
    """Return the descriptors whose binding differs between two tables."""
    return {fd for fd in old.keys() | new.keys() if old.get(fd) != new.get(fd)}


def _stale_table(table: dict[int, Any]) -> dict[int, Any]:
    """Return a copy of table with every volatile here-string binding marked stale."""
    return {
        fd: (_STALE if isinstance(val, _Bound) and val.volatile else val)
        for fd, val in table.items()
    }


class _FdFlow:
    """Descriptor table, group stack and pipeline position shared by both surfaces."""

    def __init__(self, lastpipe: bool) -> None:
        """Start with an empty table and no open group."""
        self.fds: dict[int, Any] = {}
        self.frames: list[_Frame] = []
        self.after_pipe = False
        self.pending_fn = False
        self.lastpipe = lastpipe
        self.sticky: set[int] = set()
        self.case_level = 0
        self.broken = False
        self.volatile = False
        self.sub_tag = False
        self.refusal: str | None = None

    def isolated(self, kind: str) -> bool:
        """Return whether a stage ending in kind runs in a child of the caller."""
        return kind in ("|", "&") or (self.after_pipe and not self.lastpipe)

    def mark_assigned(self) -> None:
        """Mark every saved here-string word stale after a command that can assign."""
        if self.volatile:
            self.fds = _stale_table(self.fds)
            self.volatile = False
        if self.frames:
            self.frames[-1].assigned = True

    def break_model(self) -> None:
        """Mark every descriptor unknown from here on when a construct cannot be modelled."""
        self.broken = True
        self.fds = dict.fromkeys(self.fds, _UNKNOWN)

    def commit(self, local: dict[int, Any], kind: str) -> None:
        """Carry the table of an exec stage into the caller unless the stage is isolated."""
        if self.isolated(kind):
            return
        new = dict(local)
        if self.after_pipe:
            new.update(dict.fromkeys(_changed_fds(self.fds, new), _UNKNOWN))
        new.update(dict.fromkeys(self.sticky, _UNKNOWN))
        self.fds = dict.fromkeys(new, _UNKNOWN) if self.broken else new
        self.volatile = self.volatile or any(
            isinstance(val, _Bound) and val.volatile for val in new.values()
        )

    def open(self, closer: str) -> None:
        """Open a group, saving the table so an isolated group can restore it."""
        frame = _Frame(closer, dict(self.fds), self.after_pipe, self.case_level)
        frame.is_fn = self.pending_fn
        self.pending_fn = False
        self.frames.append(frame)
        self.after_pipe = False

    def close(self, closer: str, kind: str) -> None:
        """Close the innermost group opened for closer and restore its table when isolated."""
        top = self.frames[-1] if self.frames else None
        if top is None or top.closer != closer:
            self.stray(closer)
            return
        if top.case_level != self.case_level:
            self.mark_assigned()
            return
        self.frames.pop()
        now = self.fds
        isolated = closer == ")" or top.is_fn or kind in ("|", "&")
        isolated = isolated or (top.after_pipe and not self.lastpipe)
        if isolated:
            self.fds = dict(top.snapshot)
            self.volatile = True
        if top.is_fn:
            changed = _changed_fds(top.snapshot, now)
            self.sticky |= changed
            self.fds.update(dict.fromkeys(changed, _UNKNOWN))
        elif top.after_pipe and not isolated:
            self.fds.update(dict.fromkeys(_changed_fds(top.snapshot, now), _UNKNOWN))
        if top.assigned:
            self.mark_assigned()
        self.after_pipe = False

    def stray(self, closer: str) -> None:
        """Handle a closer without an opener: a case pattern or substitution tail, else unknown."""
        if closer == ")" and (self.case_level > 0 or self.sub_tag):
            self.mark_assigned()
        else:
            self.break_model()

    def end_stage(self, words: list[str], local: dict[int, Any], kind: str) -> None:
        """Fold one finished stage into the table under the execution-context rule."""
        lead = _leading_words(words)
        self.sub_tag = any(_SUB_TAG in word for word in words)
        for _ in range(lead.count("{")):
            self.open("}")
        cmd, assigned = _command_words(words)
        if cmd[:1] in (["function"], ["coproc"]):
            self.break_model()
        if cmd == ["exec"]:
            self.commit(local, kind)
        if _stage_assigns(cmd, assigned):
            self.mark_assigned()
        opens = 1 if cmd[:1] == ["case"] else 0
        self.case_level = max(0, self.case_level + opens - lead.count("esac"))
        for _ in range(lead.count("}")):
            self.close("}", kind)

    def advance(self, kind: str, fn_def: bool) -> None:
        """Apply the separator that ends a stage: group open or close, pipe position."""
        if kind == "(":
            if fn_def:
                self.pending_fn = True
            else:
                self.open(")")
        elif kind == ")":
            self.close(")", kind)
        else:
            self.after_pipe = kind == "|"


def _is_fn_def(words: list[str], events: list[_Event], idx: int) -> bool:
    """Return whether the stage is a bare function name followed by an empty ( ) pair."""
    cmd, _ = _command_words(words)
    if len(cmd) != 1 or _FN_NAME.match(cmd[0]) is None or idx + 1 >= len(events):
        return False
    nxt = events[idx + 1]
    return nxt.kind == ")" and not any(part.strip() for part in nxt.echo)


def _drive_stages(
    events: list[_Event], run: Callable[[Any, _FdFlow], _StageState], flow: _FdFlow
) -> list[list[Any]]:
    """Run every stage in source order under the execution-context rule; return stage outputs."""
    results: list[list[Any]] = []
    skip = False
    for idx, event in enumerate(events):
        if skip:
            skip = False
            results.append(event.echo)
            continue
        stage = run(event.payload, flow)
        results.append(stage.out)
        flow.refusal = flow.refusal or stage.refusal
        flow.end_stage(stage.words, stage.fds, event.kind)
        skip = event.kind == "(" and _is_fn_def(stage.words, events, idx)
        flow.advance(event.kind, skip)
    return results


def _dup_token(resolved: Any, tok: str, stage: _StageState) -> str:
    """Return the token for a dup: the bound tag, or the dup itself when unresolved or refused."""
    if isinstance(resolved, _Marker):
        stage.refusal = stage.refusal or resolved.reason
        return tok
    if isinstance(resolved, _Bound):
        return str(resolved.word)
    return resolved if resolved is not None else tok


def _step_stage_token(stage: list[str], idx: int, state: _StageState) -> int:
    """Process one command-stage token or redirection in source order and return next index."""
    tok = stage[idx]
    if tok.startswith(("__RCG_HD_", "__RCG_HS_")):
        if (fd_match := _HS_FD_TAG.fullmatch(tok)) is not None:
            tag = f"__RCG_HS_0_{fd_match.group(2)}__"
            state.fds[int(fd_match.group(1))] = _bound_word(tag, fd_match.group(3))
        elif _HS_ZERO_TAG.fullmatch(tok) is not None:
            state.fds[0] = tok
        elif tok.startswith("__RCG_HD_"):
            state.fds.pop(0, None)
        state.out.append(tok)
        return idx + 1
    if (
        (fmatch := _FILE_REDIR_TOK.fullmatch(tok)) is not None
        and idx + 1 < len(stage)
        and stage[idx + 1] not in SEPARATORS
    ):
        _apply_file_redirect(state.fds, fmatch.group(1), fmatch.group(2))
        state.out.extend(stage[idx : idx + 2])
        return idx + 2
    if (dmatch := _DUP_OR_CLOSE_TOK.fullmatch(tok)) is not None:
        resolved = _apply_dup_or_close(state.fds, dmatch.group(1), dmatch.group(2), dmatch.group(3))
        state.out.append(_dup_token(resolved, tok, state))
        return idx + 1
    state.words.append(tok)
    state.out.append(tok)
    return idx + 1


def _run_token_stage(stage: list[str], flow: _FdFlow) -> _StageState:
    """Resolve descriptor dups across one token stage against the flow table."""
    state = _StageState(flow.fds)
    idx = 0
    for _ in range(len(stage)):
        if idx >= len(stage):
            break
        idx = _step_stage_token(stage, idx, state)
    return state


def _token_events(tokens: list[str]) -> list[_Event]:
    """Split tokens into stages, each ended by a separator token."""
    events: list[_Event] = []
    stage: list[str] = []
    for tok in tokens:
        if tok in SEPARATORS:
            events.append(_Event(stage, tok, _TERM_KIND[tok], stage))
            stage = []
        else:
            stage.append(tok)
    events.append(_Event(stage, "", ";", stage))
    return events


def _resolve_token_flow(tokens: list[str]) -> tuple[list[str], str | None]:
    """Resolve descriptor here-string dups across commands; return tokens and a refusal."""
    events = _token_events(tokens)
    flow = _FdFlow(any("lastpipe" in tok or tok == "shopt" for tok in tokens))
    results = _drive_stages(events, _run_token_stage, flow)
    out: list[str] = []
    for event, res in zip(events, results, strict=True):
        out.extend(res)
        if event.sep:
            out.append(event.sep)
    return out, flow.refusal


def _resolve_herestring_dups(tokens: list[str]) -> list[str] | None:
    """Resolve descriptor here-string dups onto fd 0 across simple commands; None when refused."""
    out, refusal = _resolve_token_flow(tokens)
    return None if refusal is not None else out


def _step_word_char(command: str, idx: int, quote: str | None) -> tuple[int, str | None] | None:
    """Advance one char or escape in a shlex word, or return None at word boundary."""
    ch = command[idx]
    if quote is None:
        if ch in " \t\r;&|<>()\n":
            return None
        if ch == "\\":
            return idx + 2, None
        return idx + 1, (ch if ch in ("'", '"') else None)
    if quote == "'":
        return idx + 1, (None if ch == "'" else "'")
    if ch == '"':
        return idx + 1, None
    step = 2 if ch == "\\" and idx + 1 < len(command) and command[idx + 1] in ("\\", '"') else 1
    return idx + step, '"'


def _advance_word_span(command: str, start: int) -> int:
    """Return end index in command of one shlex word token starting at start."""
    n = len(command)
    idx = start
    quote: str | None = None
    for _ in range(n - start + 1):
        if idx >= n:
            break
        step = _step_word_char(command, idx, quote)
        if step is None:
            break
        idx, quote = step
    return min(idx, n)


def _raw_token_spans(command: str, limit: int) -> list[tuple[int, int]]:
    """Return (start, end) character spans in command for up to limit shlex tokens."""
    spans: list[tuple[int, int]] = []
    n = len(command)
    idx = 0
    for _ in range(limit):
        for _ in range(n - idx):
            if command[idx] not in " \t\r":
                break
            idx += 1
        if idx >= n:
            break
        start = idx
        if command[idx] in ";&|<>()\n":
            for _ in range(n - idx):
                if command[idx] not in ";&|<>()\n":
                    break
                idx += 1
        else:
            idx = _advance_word_span(command, idx)
        spans.append((start, idx))
    return spans


def _split_tokens(command: str) -> list[str] | None:
    """Split a shell command into raw tokens without executing substitutions or expansions."""
    if len(command.encode("utf-8", "surrogatepass")) > MAX_COMMAND:
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        raw_tokens = list(lexer)
    except ValueError:
        return None
    tokens: list[str] = []
    idx = 0
    raw_slice = raw_tokens[: MAX_TOKENS + 2]
    spans = _raw_token_spans(command, len(raw_slice))
    for _ in range(len(raw_slice)):
        if idx >= len(raw_slice):
            break
        p_idx = idx
        token = raw_slice[p_idx]
        idx += 1
        if all(c in ";&|<>()\n" for c in token):
            prev = spans[p_idx - 1] if p_idx > 0 else (0, 0)
            cur = spans[p_idx] if p_idx < len(spans) else (0, 0)
            attach_left = (
                p_idx > 0
                and prev[1] == cur[0]
                and prev[1] > prev[0]
                and command[prev[0] : prev[1]].isdigit()
                and bool(tokens)
                and tokens[-1] == raw_slice[p_idx - 1]
            )
            idx = _append_punctuation(token, tokens, raw_slice, idx, attach_left=attach_left)
            continue
        tokens.append(token)
    if len(tokens) > MAX_TOKENS:
        return None
    return tokens


def _tokens(command: str) -> list[str] | None:
    """Split a shell command and resolve descriptor dups; None when unparsable or refused."""
    tokens = _split_tokens(command)
    return None if tokens is None else _resolve_herestring_dups(tokens)


def _strip_redirections(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Separate command words from redirection operators, targets, and heredoc tags."""
    words: list[str] = []
    fd0_tags: list[str] = []
    other_tags: list[str] = []
    idx = 0
    tok_len = len(tokens)
    for _ in range(tok_len):
        if idx >= tok_len:
            break
        tok = tokens[idx]
        idx += 1
        if tok.startswith(("__RCG_HD_", "__RCG_HS_0_")):
            fd0_tags.append(tok)
        elif tok.startswith("__RCG_HS_"):
            other_tags.append(tok)
        elif _is_redirect_word_op(tok):
            if idx < tok_len and tokens[idx] not in SEPARATORS:
                idx += 1
        elif not _is_self_redirect_tok(tok):
            words.append(tok)
    attached = [fd0_tags[-1], *fd0_tags[:-1], *other_tags] if fd0_tags else other_tags
    return words, attached


def _close_arith_span(line: bytes, start: int) -> int | None:
    """Return the end byte index after one arithmetic expansion or None when unclosed."""
    depth = 2
    pair = -1
    pos = start + 3
    for _ in range(len(line) - pos + 8):
        if pos >= len(line):
            return None
        byte = line[pos]
        pos += 1
        if byte == ord("("):
            depth += 1
        elif byte == ord(")"):
            depth -= 1
            if depth == 1:
                pair = pos
            elif depth == 0:
                return pos if pair == pos - 1 else None
    return None


def _line_arith_spans(line: bytes) -> list[tuple[int, int]]:
    """Return byte spans of one-line arithmetic expansions outside single quotes."""
    spans: list[tuple[int, int]] = []
    in_single = False
    in_double = False
    pos = 0
    for _ in range(len(line) + 16):
        if pos >= len(line):
            break
        byte = line[pos : pos + 1]
        if not in_double and byte == b"'":
            in_single = not in_single
            pos += 1
            continue
        if not in_single and byte == b'"':
            in_double = not in_double
            pos += 1
            continue
        if in_single:
            pos += 1
            continue
        if byte == b"\\":
            pos += 2
            continue
        if pos + 3 <= len(line) and line[pos : pos + 3] == b"$((":
            end = _close_arith_span(line, pos)
            if end is not None:
                spans.append((pos, end))
                pos = end
                continue
        pos += 1
    return spans


def _shift_allowed(line: bytes, offset: int) -> bool:
    """Accept << at offset only when it is part of <<< or a one-line arithmetic shift."""
    if offset + 2 < len(line) and line[offset : offset + 3] == b"<<<":
        return True
    if line[offset : offset + 2] != b"<<":
        return False
    return any(begin <= offset < end for begin, end in _line_arith_spans(line))


def script_blocks_fd_herestring_allowlist(raw: bytes) -> bool:
    """Return whether script-wide preconditions forbid a descriptor here-string allow-list."""
    if b"\r" in raw or b"\\\n" in raw or b"`" in raw:
        return True
    offset = 0
    for _ in range(4096):
        pos = raw.find(b"<<", offset)
        if pos < 0:
            break
        line_start = raw.rfind(b"\n", 0, pos) + 1
        line_end = raw.find(b"\n", pos)
        if line_end < 0:
            line_end = len(raw)
        line = raw[line_start:line_end]
        local = pos - line_start
        if not _shift_allowed(line, local):
            return True
        offset = pos + 2
        if offset > len(raw):
            break
    return raw.find(b"<<", offset) >= 0


def _step_dq_heredoc_delim(
    raw: bytes, idx: int, line_end: int, buf: bytearray
) -> tuple[int, int] | None:
    """Advance one byte inside a double-quoted heredoc delimiter or return None."""
    b = raw[idx]
    if b == ord('"'):
        return idx + 1, 0
    if b in b"$`\r":
        return None
    if b == ord("\\"):
        if idx + 1 >= line_end:
            return None
        if raw[idx + 1] in b'\\"':
            buf.append(raw[idx + 1])
        else:
            buf.extend(raw[idx : idx + 2])
        return idx + 2, ord('"')
    buf.append(b)
    return idx + 1, ord('"')


def _step_unquoted_heredoc_delim(
    raw: bytes, idx: int, line_end: int, buf: bytearray
) -> tuple[int, int] | None:
    """Advance one byte outside quotes in a heredoc delimiter, or return None on rejection."""
    b = raw[idx]
    if b in b"$`\r":
        return None
    if b == ord("\\"):
        if idx + 1 >= line_end:
            return None
        buf.append(raw[idx + 1])
        return idx + 2, 0
    if b in (ord("'"), ord('"')):
        return idx + 1, b
    buf.append(b)
    return idx + 1, 0


def _parse_heredoc_delim_bytes(raw: bytes, pos: int, line_end: int) -> tuple[bytes, int] | None:
    """Parse one static heredoc delimiter on [pos, line_end) or return None if unmodelled."""
    pos = _skip_spaces_tabs(raw, pos)
    if pos >= line_end or raw[pos] == ord("#"):
        return None
    buf = bytearray()
    idx = pos
    quote = 0
    for _ in range(line_end - pos + 1):
        if idx >= line_end or (quote == 0 and raw[idx] in b" \t;&|<>()"):
            break
        if quote == 0:
            step = _step_unquoted_heredoc_delim(raw, idx, line_end, buf)
        elif quote == ord("'"):
            if raw[idx] != ord("'"):
                buf.append(raw[idx])
            step = (idx + 1, 0 if raw[idx] == ord("'") else ord("'"))
        else:
            step = _step_dq_heredoc_delim(raw, idx, line_end, buf)
        if step is None:
            return None
        idx, quote = step
    return (bytes(buf), idx) if (quote == 0 and buf) else None


def _line_heredoc_openers(
    raw: bytes, masked: bytes, line_start: int, line_end: int
) -> list[tuple[bytes, bool]] | None:
    """Collect (delimiter, tab_strip) pairs on one line, or None when unmodelled."""
    if b"<<" not in masked[line_start:line_end]:
        return []
    if line_end > line_start and masked[line_end - 1] in (ord("\r"), ord("\\")):
        return None
    arith = _line_arith_spans(raw[line_start:line_end])
    openers: list[tuple[bytes, bool]] = []
    pos = line_start
    for _ in range(line_end - line_start + 1):
        if pos >= line_end:
            break
        if masked[pos : pos + 2] != b"<<":
            pos += 1
            continue
        if masked[pos : pos + 3] == b"<<<":
            if pos + 3 < line_end and masked[pos + 3] == ord("<"):
                return None
            pos += 3
            continue
        local = pos - line_start
        if any(begin <= local < end for begin, end in arith):
            pos += 2
            continue
        tab_strip = pos + 2 < line_end and raw[pos + 2] == ord("-")
        parsed = _parse_heredoc_delim_bytes(raw, pos + (3 if tab_strip else 2), line_end)
        if parsed is None:
            return None
        openers.append((parsed[0], tab_strip))
        pos = parsed[1]
    return openers


def _consume_heredoc_body(
    raw: bytes, cursor: int, delim: bytes, tab_strip: bool
) -> tuple[int, int, int] | None:
    """Return (span_start, span_end, next_line_start) for one heredoc body, or None."""
    n = len(raw)
    pos = cursor
    for _ in range(n - cursor + 2):
        if pos >= n:
            return None
        nl = raw.find(b"\n", pos)
        b_end = n if nl < 0 else nl
        if b_end > pos and raw[b_end - 1] == ord("\r"):
            return None
        line = raw[pos:b_end].lstrip(b"\t") if tab_strip else raw[pos:b_end]
        if line == delim:
            return cursor, b_end, (n + 1 if nl < 0 else nl + 1)
        if nl < 0:
            return None
        pos = nl + 1
    return None


def _mask_line_range(
    raw: bytes,
    buf: bytearray,
    span: tuple[int, int],
    state: tuple[int | None, bool],
) -> tuple[int | None, bool]:
    """Mask quoted and comment bytes within span and return updated quote state."""
    idx, end = span
    quote, ansi = state
    for _ in range(end - idx + 1):
        if idx >= end:
            break
        if quote is None:
            idx, quote, ansi = _advance_unquoted_mask(raw, buf, idx)
        else:
            idx, quote, ansi = _advance_quoted_mask(raw, buf, idx, quote, ansi)
    return quote, ansi


def _consume_line_heredocs(
    raw: bytes, buf: bytearray, cursor: int, openers: list[tuple[bytes, bool]]
) -> int | None:
    """Mask each heredoc payload opened on one line and return next line offset or None."""
    for delim, tab_strip in openers:
        taken = _consume_heredoc_body(raw, cursor, delim, tab_strip)
        if taken is None:
            return None
        buf[taken[0] : taken[1]] = b"\x01" * (taken[1] - taken[0])
        cursor = taken[2]
    return cursor


def _mask_descriptor_scan_bytes(raw: bytes) -> bytes:
    """Mask quoted, comment, and closed here-document payload spans to SOH."""
    if b"<<" not in raw:
        return _mask_quoted_bytes(raw)
    n = len(raw)
    buf = bytearray(raw)
    state: tuple[int | None, bool] = (None, False)
    line_start = 0
    for _ in range(n + 2):
        if line_start >= n:
            return bytes(buf)
        nl = raw.find(b"\n", line_start)
        line_end = n if nl < 0 else nl
        state = _mask_line_range(raw, buf, (line_start, line_end), state)
        openers = (
            [] if state[0] is not None else _line_heredoc_openers(raw, buf, line_start, line_end)
        )
        if openers is None or (openers and nl < 0):
            return _mask_quoted_bytes(raw)
        if not openers:
            line_start = n if nl < 0 else nl + 1
            continue
        next_start = _consume_line_heredocs(raw, buf, nl + 1, openers)
        if next_start is None:
            return _mask_quoted_bytes(raw)
        line_start = next_start
    return _mask_quoted_bytes(raw)


def strip_descriptor_tail_marks(raw: bytes) -> bytes:
    """Build twin bytes with each unquoted descriptor prefix before <<< removed."""
    masked = _mask_descriptor_scan_bytes(raw)
    parts: list[bytes] = []
    cursor = 0
    for match in _TAIL_MARK.finditer(masked):
        start, end = match.span(1)
        parts.append(raw[cursor:start])
        cursor = end
    parts.append(raw[cursor:])
    return b"".join(parts)


def descriptor_tail_marks_present(raw: bytes) -> bool:
    """Return whether raw bytes contain an unquoted descriptor prefix before <<<."""
    return _TAIL_MARK.search(_mask_descriptor_scan_bytes(raw)) is not None


def _herestring_word_end_bytes(seg: bytes, masked: bytes, pos: int) -> tuple[int, int] | None:
    """Return start and end byte offsets of the here-string word starting at or after pos."""
    n = len(seg)
    start = pos
    for _ in range(n - pos):
        if seg[start] not in (32, 9):
            break
        start += 1
    if start >= n:
        return None
    end = start
    for _ in range(n - start):
        if end >= n or masked[end] in b" \t\r\n;&|<>()":
            break
        end += 1
    return (start, end) if end > start else None


def _byte_words(seg: bytes, stripped: bytearray) -> list[str]:
    """Return the raw words of one stage with redirections blanked, decoded for the shared rules."""
    return [
        seg[found.start() : found.end()].decode("latin-1")
        for found in re.finditer(rb"[^ \t\r\n]+", bytes(stripped))
    ]


def _dup_replacement(resolved: Any, seg: bytes, start: int, stage: _StageState) -> bytes | None:
    """Return the <<< word replacing a resolved fd 0 dup, or None when unresolved or refused."""
    if isinstance(resolved, _Marker):
        stage.refusal = stage.refusal or resolved.reason
        return None
    if resolved is None:
        return None
    word = resolved.word if isinstance(resolved, _Bound) else resolved
    lead = b"<<< " if start == 0 or seg[start - 1 : start] in b" \t" else b" <<< "
    return lead + word


def _step_segment_redirect(
    seg: bytes, masked_seg: bytes, match: re.Match[bytes], stage: _StageState
) -> tuple[int, bytes | None]:
    """Apply one matched byte-surface redirect in source order; return end and replacement."""
    start, end = match.span()
    if match.group("hd") is not None:
        return end, None
    if match.group("hs") is not None:
        word_span = _herestring_word_end_bytes(seg, masked_seg, end)
        if word_span is None:
            return end, None
        stage.stripped[start : word_span[1]] = b" " * (word_span[1] - start)
        fd = _descriptor_fd(match.group("hs_fd"))
        if fd is not None:
            word = seg[word_span[0] : word_span[1]]
            stage.fds[fd] = _bound_word(word, _word_class(word))
        return word_span[1], None
    if match.group("dup") is not None:
        stage.stripped[start:end] = b" " * (end - start)
        resolved = _apply_dup_or_close(
            stage.fds, match.group("dup_fd"), match.group("dup_op"), match.group("dup_rhs")
        )
        return end, _dup_replacement(resolved, seg, start, stage)
    word_span = _herestring_word_end_bytes(seg, masked_seg, end)
    stop = word_span[1] if word_span is not None else end
    stage.stripped[start:stop] = b" " * (stop - start)
    if match.group("amp") is not None:
        _apply_file_redirect(stage.fds, None, match.group("amp"))
    else:
        _apply_file_redirect(stage.fds, match.group("file_fd"), match.group("file_op"))
    return stop, None


def _run_byte_stage(payload: tuple[bytes, bytes], flow: _FdFlow) -> _StageState:
    """Update segment descriptors in source order and replace resolved fd 0 dups with <<< word."""
    seg, masked_seg = payload
    stage = _StageState(flow.fds)
    stage.stripped = bytearray(masked_seg)
    parts: list[bytes] = []
    cursor = 0
    scan_pos = 0
    for match in _SEG_REDIR_BYTES.finditer(masked_seg):
        if match.start() < scan_pos:
            continue
        scan_pos, replacement = _step_segment_redirect(seg, masked_seg, match, stage)
        if replacement is not None:
            parts.append(seg[cursor : match.start()])
            parts.append(replacement)
            cursor = scan_pos
    parts.append(seg[cursor:])
    stage.out = [b"".join(parts)]
    stage.words = _byte_words(seg, stage.stripped)
    return stage


def _byte_sep_kind(masked: bytes, match: re.Match[bytes]) -> str | None:
    """Classify one separator match, or None when it spells part of a redirection operator."""
    tok = match.group()
    start = match.start()
    prev = masked[start - 1 : start] if start else b""
    if tok == b"&":
        nxt = masked[match.end() : match.end() + 1]
        return None if prev in (b"<", b">") or nxt == b">" else "&"
    if tok == b"|" and prev == b">":
        return None
    if tok in (b"(", b")"):
        return tok.decode("ascii")
    return "|" if tok in (b"|", b"|&") else ";"


def _byte_events(raw: bytes, masked: bytes) -> list[_Event]:
    """Split raw bytes into stages ended by an unquoted separator, group edge or backtick."""
    events: list[_Event] = []
    start = 0
    ticks = 0
    for match in _BYTE_SEP.finditer(masked):
        kind = _byte_sep_kind(masked, match)
        if kind is None:
            continue
        if match.group() == b"`":
            ticks += 1
            kind = "(" if ticks % 2 else ")"
        seg = raw[start : match.start()]
        payload = (seg, masked[start : match.start()])
        events.append(_Event(payload, raw[match.start() : match.end()], kind, [seg]))
        start = match.end()
    events.append(_Event((raw[start:], masked[start:]), b"", ";", [raw[start:]]))
    return events


def rewrite_descriptor_dups_checked(raw: bytes) -> tuple[bytes, str | None]:
    """Rewrite fd 0 dups into here-string words and return the first named refusal, if any."""
    masked = _mask_descriptor_scan_bytes(raw)
    if _DUP_STDIN_BYTES.search(masked) is None:
        return raw, None
    events = _byte_events(raw, masked)
    flow = _FdFlow(b"lastpipe" in raw or b"shopt" in raw)
    results = _drive_stages(events, _run_byte_stage, flow)
    out = [b"".join(res) + event.sep for event, res in zip(events, results, strict=True)]
    return b"".join(out), flow.refusal


def rewrite_descriptor_dups(raw: bytes) -> bytes:
    """Rewrite 0<&N, <&N, and moves onto fd 0 when the source fd carries a here-string."""
    return rewrite_descriptor_dups_checked(raw)[0]


def descriptor_dup_refusal(raw: bytes) -> str | None:
    """Return the named reason a descriptor dup cannot be resolved in raw bytes, if any."""
    return rewrite_descriptor_dups_checked(raw)[1]


def _parse_herestring_word(line: bytes, pos: int) -> int | None:
    """Return the byte offset after one here-string word starting at pos."""
    end: int | None = None
    if pos < len(line) and line[pos] == ord(b"'"):
        stop = line.find(b"'", pos + 1)
        end = stop + 1 if stop >= 0 else None
    elif pos < len(line) and line[pos] == ord(b'"'):
        stop = line.find(b'"', pos + 1)
        if stop >= 0:
            inner = line[pos + 1 : stop]
            if b"$(" not in inner and b"`" not in inner and _DQ_TAIL_INNER.fullmatch(inner):
                end = stop + 1
    else:
        match = _TAIL_WORD.match(line, pos)
        end = match.end() if match else None
    return end


def _skip_blanks(line: bytes, pos: int, blanks: bytes) -> int:
    """Return the index after any of the blank bytes at pos without copying the line."""
    start = pos if pos >= 0 else max(len(line) + pos, 0)
    for idx in range(start, len(line)):
        if line[idx] not in blanks:
            return pos + (idx - start)
    return pos + (len(line) - start) if start < len(line) else pos


def _skip_spaces_tabs(line: bytes, pos: int) -> int:
    """Return the index after horizontal whitespace at pos."""
    return _skip_blanks(line, pos, b" \t")


def _skip_spaces(line: bytes, pos: int) -> int:
    """Return the index after space characters at pos."""
    return _skip_blanks(line, pos, b" ")


def _redirect_target_slice(line: bytes, pos: int) -> tuple[int, bytes] | None:
    """Return the index after one redirect target word and the target bytes."""
    pos = _skip_spaces_tabs(line, pos)
    word_end = _parse_herestring_word(line, pos)
    if word_end is not None:
        return word_end, line[pos:word_end]
    match = _TAIL_WORD.match(line, pos)
    if match:
        return match.end(), line[pos : match.end()]
    return None


def _append_redirect_target(line: bytes, pos: int, targets: list[bytes]) -> int | None:
    """Parse a redirect with a target word and append the target bytes."""
    taken = _redirect_target_slice(line, pos)
    if taken is None:
        return None
    targets.append(taken[1])
    return taken[0]


def _parse_digit_redirect(line: bytes, pos: int, targets: list[bytes]) -> int | None:
    """Parse a one-digit fd redirect or duplicator starting at pos."""
    if pos + 1 < len(line) and line[pos + 1 : pos + 3] == b">&":
        if pos + 3 >= len(line) or not (ord(b"0") <= line[pos + 3] <= ord(b"9")):
            return None
        return pos + 4
    if pos + 2 < len(line) and line[pos + 1 : pos + 3] == b">>":
        return _append_redirect_target(line, pos + 3, targets)
    if pos + 1 < len(line) and line[pos + 1 : pos + 2] in (b">", b"<"):
        return _append_redirect_target(line, pos + 2, targets)
    return None


def _parse_tail_redirect(line: bytes, pos: int, targets: list[bytes]) -> int | None:
    """Parse one redirection starting at pos or return None on rejection."""
    pos = _skip_spaces_tabs(line, pos)
    if pos >= len(line):
        return len(line)
    next_pos: int | None = None
    if line[pos : pos + 2] == b">&":
        next_pos = (
            pos + 3 if pos + 2 < len(line) and ord(b"0") <= line[pos + 2] <= ord(b"9") else None
        )
    elif ord(b"0") <= line[pos] <= ord(b"9"):
        next_pos = _parse_digit_redirect(line, pos, targets)
    elif line[pos : pos + 2] == b">>":
        next_pos = _append_redirect_target(line, pos + 2, targets)
    elif line[pos : pos + 1] in (b">", b"<"):
        next_pos = _append_redirect_target(line, pos + 1, targets)
    return next_pos


def _tail_line_suffix_valid(line: bytes, digit: int) -> tuple[bool, list[bytes]]:
    """Validate the tail suffix from a descriptor digit through end of line."""
    if line[digit + 1 : digit + 4] != b"<<<":
        return False, []
    pos = _skip_spaces(line, digit + 4)
    word_end = _parse_herestring_word(line, pos)
    if word_end is None:
        return False, []
    pos = word_end
    targets: list[bytes] = []
    for _ in range(8):
        nxt = _parse_tail_redirect(line, pos, targets)
        if nxt is None:
            return False, []
        pos = nxt
        if pos >= len(line):
            break
    pos = _skip_spaces(line, pos)
    return pos >= len(line), targets


def descriptor_tail_mark_count(raw: bytes) -> int:
    """Count unquoted descriptor prefixes immediately followed by <<< in raw script bytes."""
    masked = _mask_descriptor_scan_bytes(raw)
    return sum(1 for _ in _TAIL_MARK.finditer(masked))


def find_descriptor_herestring_tail(raw: bytes) -> tuple[int, int, int, list[bytes]] | None:
    """Locate exactly one allowed descriptor here-string tail line in raw script bytes."""
    if script_blocks_fd_herestring_allowlist(raw):
        return None
    masked = _mask_descriptor_scan_bytes(raw)
    marks: list[tuple[bytes, int, int, int]] = []
    for match in _TAIL_MARK.finditer(masked):
        pos = match.start(1)
        line_start = raw.rfind(b"\n", 0, pos) + 1
        line_end = raw.find(b"\n", pos)
        if line_end < 0:
            line_end = len(raw)
        marks.append((raw[line_start:line_end], pos - line_start, line_start, line_end))
        if len(marks) > 1:
            break
    if len(marks) != 1:
        return None
    line, digit, line_start, line_end = marks[0]
    ok, targets = _tail_line_suffix_valid(line, digit)
    if not ok:
        return None
    return line_start + digit, line_start, line_end, targets


_ERROR_COLLECT_CEILING = 4096


def collect_error_nodes(root: object) -> list[tuple[int, int]] | None:
    """Collect ERROR spans or None when the walk stops before the stack empties."""
    stack = [root]
    spans: list[tuple[int, int]] = []
    bound = getattr(root, "descendant_count", 0) + _ERROR_COLLECT_CEILING
    for _ in range(bound):
        if not stack:
            return spans
        node = stack.pop()
        if node.type == "ERROR":
            spans.append((node.start_byte, node.end_byte))
        stack.extend(node.children)
    return None


_BLOCKED_ANCESTORS = frozenset(
    {
        "function_definition",
        "if_statement",
        "elif_clause",
        "else_clause",
        "for_statement",
        "while_statement",
        "until_statement",
        "case_statement",
        "case_item",
        "compound_statement",
        "subshell",
    }
)


def tail_line_is_toplevel(root: object, digit_byte: int) -> bool:
    """Return whether a tail digit sits on a top-level simple command line."""
    node = root.descendant_for_byte_range(digit_byte, digit_byte + 1)
    cur = node
    for _ in range(32):
        if cur is None or cur.type == "program":
            return cur is not None
        if cur.type in _BLOCKED_ANCESTORS:
            return False
        cur = cur.parent
    return False


def errors_within_tail_span(
    errors: list[tuple[int, int]], digit_byte: int, line_end: int, raw_len: int
) -> bool:
    """Return whether every ERROR span lies inside the tail digit through line end."""
    limit = line_end + 1 if line_end < raw_len else line_end
    return all(start >= digit_byte and end <= limit for start, end in errors)
