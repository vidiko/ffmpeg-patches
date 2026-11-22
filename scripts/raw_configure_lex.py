# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Shell tokenizer, substitution and heredoc scanners of the raw configure guard."""

from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

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

HERESTRING_WORD_STARTS = frozenset(" \t\n;&|()")


@dataclass
class _LexState:
    """Track active quote, word-boundary, continuation and arithmetic state across lines."""

    quote: str | None = None
    word_start: bool = True
    continued: bool = False
    arith_depth: int = 0
    heredocs: list[tuple[str, bool]] = field(default_factory=list)


def _append_redirect_fd(punc: str, tokens: list[str], raw_tokens: list[str], idx: int) -> int:
    """Attach a redirection operator and any immediate target descriptor."""
    if tokens and tokens[-1].isdigit():
        tokens[-1] += punc
    else:
        tokens.append(punc)
    if idx < len(raw_tokens) and (raw_tokens[idx].isdigit() or raw_tokens[idx] == "-"):
        tokens[-1] += raw_tokens[idx]
        return idx + 1
    return idx


def _append_punctuation(token: str, tokens: list[str], raw_tokens: list[str], idx: int) -> int:
    """Expand one punctuation run and merge shell redirect operators."""
    pos = 0
    for _ in range(len(token)):
        if pos >= len(token):
            break
        if token[pos : pos + 3] == "&>>":
            tokens.append("&>>")
            pos += 3
        elif token[pos : pos + 2] in (">&", "<&"):
            idx = _append_redirect_fd(token[pos : pos + 2], tokens, raw_tokens, idx)
            pos += 2
        elif token[pos : pos + 2] == "&>":
            tokens.append("&>")
            pos += 2
        elif token[pos : pos + 2] == ">|":
            tokens.append(">")
            tokens.append("|")
            pos += 2
        elif token[pos : pos + 2] in ("&&", "||", ">>", "<<"):
            tokens.append(token[pos : pos + 2])
            pos += 2
        elif token[pos : pos + 2] == "|&":
            tokens.append("|")
            pos += 2
        else:
            tokens.append(token[pos])
            pos += 1
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


def _skip_blanks(text: str, pos: int, limit: int) -> int:
    """Advance past space and horizontal tab characters up to limit."""
    for _ in range(limit - pos):
        if pos >= limit or text[pos] not in " \t":
            break
        pos += 1
    return pos


def _parse_heredoc_at(line: str, pos: int, line_len: int) -> tuple[int, str, bool, bool] | None:
    """Parse heredoc marker details starting after << operator."""
    tab_strip = pos < line_len and line[pos] == "-"
    pos = _skip_blanks(line, pos + (1 if tab_strip else 0), line_len)
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


def _consume_heredoc_body(
    lines: list[str], idx: int, delim: str, tab_strip: bool
) -> tuple[int, bool]:
    """Advance past one heredoc body to its delimiter line and report closure."""
    num_lines = len(lines)
    for _ in range(num_lines - idx + 1):
        if idx >= num_lines:
            break
        check = lines[idx].lstrip("\t") if tab_strip else lines[idx]
        idx += 1
        if check.rstrip("\r\n") == delim:
            return idx, True
    return idx, False


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
        end_idx, closed = _consume_heredoc_body(lines, idx, delim, tab_strip)
        if not closed:
            return None
        heredocs[tag] = "".join(lines[idx : end_idx - 1])
        idx = end_idx
    return "".join(out_lines), heredocs, expanding_tags


def _herestring_fd_end(line: str, pos: int, line_len: int) -> int | None:
    """Return the end offset of an ASCII digit run followed immediately by <<<."""
    end = pos
    for _ in range(line_len - pos):
        if end >= line_len or not ("0" <= line[end] <= "9"):
            break
        end += 1
    return end if end > pos and line[end : end + 3] == "<<<" else None


def _step_quoted(line: str, pos: int, quote: str) -> tuple[int, str | None]:
    """Advance past one character or backslash escape inside an active quote."""
    ch = line[pos]
    if quote != "'" and ch == "\\":
        return min(pos + 2, len(line)), quote
    if quote == "$'":
        return pos + 1, (None if ch == "'" else quote)
    return pos + 1, _update_quote(ch, quote)


def _step_escape_or_quote(line: str, pos: int, state: _LexState) -> int | None:
    """Handle backslash escapes, comments and quote starts in unquoted shell text."""
    ch = line[pos]
    if ch == "\\":
        crlf = line[pos + 1 : pos + 3] == "\r\n"
        if crlf or line[pos + 1 : pos + 2] == "\n":
            state.continued = True
            return pos + (3 if crlf else 2)
        state.word_start = False
        return min(pos + 2, len(line))
    if ch == "#" and state.word_start:
        state.word_start = line.endswith("\n")
        return len(line)
    if line[pos : pos + 2] == "$'" or ch in ("'", '"'):
        ansi = line[pos : pos + 2] == "$'"
        state.quote = "$'" if ansi else _update_quote(ch, state.quote)
        state.word_start = False
        return pos + (2 if ansi else 1)
    return None


def _step_arith(line: str, pos: int, state: _LexState) -> int | None:
    """Track $(( and (( arithmetic parenthesis depth at one unquoted position."""
    if state.arith_depth == 0:
        if line[pos : pos + 3] == "$((":
            state.arith_depth = 2
            state.word_start = True
            return pos + 3
        if line[pos : pos + 2] == "((":
            state.arith_depth = 2
            state.word_start = True
            return pos + 2
        return None
    if line[pos] in "()":
        state.arith_depth += 1 if line[pos] == "(" else -1
        state.word_start = True
        return pos + 1
    return None


def _step_heredoc_op(line: str, pos: int, state: _LexState) -> int | None:
    """Queue a heredoc delimiter at << outside arithmetic and return the next offset."""
    if line[pos : pos + 2] != "<<" or line[pos : pos + 3] == "<<=":
        return None
    state.word_start = False
    if state.arith_depth > 0:
        return pos + 2
    parsed = _parse_heredoc_at(line, pos + 2, len(line))
    if parsed is None:
        return pos + 2
    state.heredocs.append((parsed[1], parsed[2]))
    return parsed[0]


def _step_herestring_or_char(line: str, pos: int, chars: list[str], state: _LexState) -> int:
    """Blank word-initial fd digits before <<< or advance one unquoted token."""
    line_len = len(line)
    ch = line[pos]
    if state.word_start and "0" <= ch <= "9":
        fd_end = _herestring_fd_end(line, pos, line_len)
        if fd_end is not None:
            chars[pos:fd_end] = [" "] * (fd_end - pos)
            state.word_start = False
            return _skip_blanks(line, fd_end + 3, line_len)
    if line[pos : pos + 3] == "<<<":
        state.word_start = False
        return _skip_blanks(line, pos + 3, line_len)
    hd_next = _step_heredoc_op(line, pos, state)
    if hd_next is not None:
        return hd_next
    state.word_start = ch in HERESTRING_WORD_STARTS
    return pos + 1


def _blank_line(line: str, state: _LexState) -> str:
    """Blank word-initial fd digits before <<< across one line and update lex state."""
    chars = list(line)
    state.continued = False
    pos = 0
    line_len = len(line)
    for _ in range(line_len):
        if pos >= line_len:
            break
        if state.quote is not None:
            pos, state.quote = _step_quoted(line, pos, state.quote)
            continue
        nxt = _step_escape_or_quote(line, pos, state)
        if nxt is None:
            nxt = _step_arith(line, pos, state)
        if nxt is not None:
            pos = nxt
            continue
        pos = _step_herestring_or_char(line, pos, chars, state)
    return "".join(chars)


def blank_herestring_fds(raw: bytes) -> bytes:
    """Return equal-length shell bytes with word-initial fd digits before <<< made spaces."""
    if b"<<<" not in raw:
        return bytes(raw)
    lines = raw.decode("utf-8", "surrogateescape").splitlines(keepends=True)
    out_lines: list[str] = []
    state = _LexState()
    idx = 0
    num_lines = len(lines)
    for _ in range(num_lines):
        if idx >= num_lines:
            break
        line = lines[idx]
        out_lines.append(_blank_line(line, state))
        idx += 1
        if state.quote is None and not state.continued and line.endswith("\n"):
            for _ in range(len(state.heredocs)):
                if not state.heredocs:
                    break
                delim, tab_strip = state.heredocs.pop(0)
                end_idx, _ = _consume_heredoc_body(lines, idx, delim, tab_strip)
                out_lines.extend(lines[idx:end_idx])
                idx = end_idx
    return "".join(out_lines).encode("utf-8", "surrogateescape")


def _scan_herestrings(command: str) -> tuple[str, dict[str, str], list[str]]:
    """Extract here-strings outside quotes and replace with placeholders."""
    herestrings: dict[str, str] = {}
    hs_to_scan: list[str] = []
    quote = None
    pos = 0
    cmd_len = len(command)
    pieces: list[str] = []
    for _ in range(cmd_len):
        if pos >= cmd_len:
            break
        ch = command[pos]
        if quote is None:
            if ch in ("'", '"'):
                quote = ch
            elif command[pos : pos + 3] == "<<<":
                pos = _skip_blanks(command, pos + 3, cmd_len)
                val, pos, q_delim = _read_delim(command, pos, cmd_len)
                tag = f"__RCG_HS_{len(herestrings)}__"
                herestrings[tag] = val
                if q_delim != "'":
                    hs_to_scan.append(val)
                pieces.append(tag)
                continue
        elif ch == quote:
            quote = None
        pieces.append(ch)
        pos += 1
    return "".join(pieces), herestrings, hs_to_scan


def _tokens(command: str) -> list[str] | None:
    """Split a shell command without executing substitutions or expansions."""
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
    for _ in range(len(raw_slice)):
        if idx >= len(raw_slice):
            break
        token = raw_slice[idx]
        idx += 1
        if all(c in ";&|<>()\n" for c in token):
            idx = _append_punctuation(token, tokens, raw_slice, idx)
            continue
        tokens.append(token)
    return tokens if len(tokens) <= MAX_TOKENS else None


def _strip_redirections(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Separate command words from redirection operators, targets, and heredoc tags."""
    words: list[str] = []
    attached: list[str] = []
    idx = 0
    tok_len = len(tokens)
    for _ in range(tok_len):
        if idx >= tok_len:
            break
        tok = tokens[idx]
        idx += 1
        if tok.startswith("__RCG_HD_") or tok.startswith("__RCG_HS_"):
            attached.append(tok)
            continue
        if tok in REDIRECT_TARGET_OPS or re.fullmatch(r"^\d*(?:>>|>|<|&>|&>>|>\|)$", tok):
            if idx < tok_len and tokens[idx] not in SEPARATORS:
                idx += 1
            continue
        if SELF_REDIRECT.fullmatch(tok) or tok in (">&", "<&"):
            continue
        words.append(tok)
    return words, attached
