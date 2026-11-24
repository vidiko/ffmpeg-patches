# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Shell tokenizer, substitution and heredoc scanners of the raw configure guard."""

from __future__ import annotations

import itertools
import re
import shlex
import sys
from pathlib import Path
from typing import Any

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
_TAIL_MARK = re.compile(_DESCRIPTOR_PREFIX + rb"<<<")
_DUP_STDIN = re.compile(rf"(?:{_DESCRIPTOR_PREFIX_STR})?<&([0-9]+)$")
_DUP_STDIN_BYTES = re.compile(rb"(?:" + _DESCRIPTOR_PREFIX + rb")?<&\s*([0-9]+)(?![0-9A-Za-z_])")
_HS_FD_TAG = re.compile(r"^__RCG_HS_FD([0-9]+)_([0-9]+)__$")
_HS_ZERO_TAG = re.compile(r"^__RCG_HS_0_([0-9]+)__$")
_DUP_OR_CLOSE_TOK = re.compile(rf"^(?:{_DESCRIPTOR_PREFIX_STR})?(<&|>&)([0-9]+|-)$")
_FILE_REDIR_TOK = re.compile(r"^([0-9]*)(>>|<>|>\||<|>|&>|&>>)$")
_SPLIT_FILE_OPS = frozenset(("<", ">", ">>", "<>", ">|"))
_EXEC_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SEG_REDIR_BYTES = re.compile(
    rb"(?:"
    rb"(?P<hd>(?:" + _DESCRIPTOR_PREFIX + rb")?<<-?(?!<))"
    rb"|(?P<hs>(?P<hs_fd>" + _DESCRIPTOR_PREFIX + rb")?<<<)"
    rb"|(?P<dup>(?P<dup_fd>"
    + _DESCRIPTOR_PREFIX
    + rb")?(?P<dup_op><&|>&)\s*(?P<dup_rhs>[0-9]+|-)(?![0-9A-Za-z_]))"
    rb"|(?P<amp>&>>|&>|>&)"
    rb"|(?P<file>(?P<file_fd>" + _DESCRIPTOR_PREFIX + rb")?(?P<file_op>>>|<>|>\||<|>)(?![<&>(]))"
    rb")"
)


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
    return int(right)


def _apply_dup_or_close(
    fds: dict[int, Any], left: str | bytes | None, op: str | bytes, rhs: str | bytes
) -> Any | None:
    """Apply one N<&M, N>&M, N<&-, or N>&- operation to fds; return resolved stdin value."""
    is_in = op in ("<&", b"<&")
    target = (0 if is_in else 1) if not left else _descriptor_fd(left)
    if target is None:
        return None
    rhs_text = rhs.decode("ascii") if isinstance(rhs, bytes) else rhs
    if rhs_text == "-":
        fds.pop(target, None)
        return None
    val = fds.get(int(rhs_text))
    if val is None:
        fds.pop(target, None)
        return None
    fds[target] = val
    return val if is_in and _dup_stdin_fd(left, rhs_text) is not None else None


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
        elif token[pos : pos + 2] in ("&&", "||", ">>", "<<", "<>", ">|"):
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
        tag = f"__RCG_HS_FD{fd}_{idx}__"
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
    """Return whether tok is a descriptor-duplication or close redirection token."""
    return tok in (">&", "<&") or SELF_REDIRECT.fullmatch(tok) is not None


def _dup_stdin_source(tok: str) -> int | None:
    """Return source fd when tok ends with a numeric descriptor dup onto fd 0."""
    match = _DUP_STDIN.search(tok)
    return _dup_stdin_fd(match.group(1), match.group(2)) if match is not None else None


def _step_stage_token(
    stage: list[str],
    idx: int,
    local_fds: dict[int, str],
    out: list[str],
    words: list[str],
) -> int:
    """Process one command-stage token or redirection in source order and return next index."""
    tok = stage[idx]
    if tok.startswith(("__RCG_HD_", "__RCG_HS_")):
        if (fd_match := _HS_FD_TAG.fullmatch(tok)) is not None:
            local_fds[int(fd_match.group(1))] = f"__RCG_HS_0_{fd_match.group(2)}__"
        elif _HS_ZERO_TAG.fullmatch(tok) is not None:
            local_fds[0] = tok
        elif tok.startswith("__RCG_HD_"):
            local_fds.pop(0, None)
        out.append(tok)
        return idx + 1
    if (
        tok.isdigit()
        and idx + 2 < len(stage)
        and stage[idx + 1] in _SPLIT_FILE_OPS
        and stage[idx + 2] not in SEPARATORS
    ):
        _apply_file_redirect(local_fds, tok, stage[idx + 1])
        out.extend(stage[idx : idx + 3])
        return idx + 3
    if (
        (fmatch := _FILE_REDIR_TOK.fullmatch(tok)) is not None
        and idx + 1 < len(stage)
        and stage[idx + 1] not in SEPARATORS
    ):
        _apply_file_redirect(local_fds, fmatch.group(1), fmatch.group(2))
        out.extend(stage[idx : idx + 2])
        return idx + 2
    if (dmatch := _DUP_OR_CLOSE_TOK.fullmatch(tok)) is not None:
        resolved = _apply_dup_or_close(local_fds, dmatch.group(1), dmatch.group(2), dmatch.group(3))
        out.append(resolved if resolved is not None else tok)
        return idx + 1
    if words or _EXEC_ASSIGN.match(tok) is None:
        words.append(tok)
    out.append(tok)
    return idx + 1


def _resolve_stage_dups(
    stage: list[str], exec_fds: dict[int, str]
) -> tuple[list[str], dict[int, str]]:
    """Update descriptor bindings in source order and resolve fd 0 dups within one stage."""
    local_fds = dict(exec_fds)
    out: list[str] = []
    words: list[str] = []
    idx = 0
    for _ in range(len(stage)):
        if idx >= len(stage):
            break
        idx = _step_stage_token(stage, idx, local_fds, out, words)
    next_exec = local_fds if words == ["exec"] else exec_fds
    return out, next_exec


def _resolve_herestring_dups(tokens: list[str]) -> list[str]:
    """Resolve descriptor here-string dups onto fd 0 across simple commands."""
    result: list[str] = []
    stage: list[str] = []
    exec_fds: dict[int, str] = {}
    for tok in tokens:
        if tok in SEPARATORS:
            if stage:
                resolved, exec_fds = _resolve_stage_dups(stage, exec_fds)
                result.extend(resolved)
                stage = []
            result.append(tok)
        else:
            stage.append(tok)
    if stage:
        resolved, _ = _resolve_stage_dups(stage, exec_fds)
        result.extend(resolved)
    return result


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
    if len(tokens) > MAX_TOKENS:
        return None
    return _resolve_herestring_dups(tokens)


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
    depth = 1
    pos = start + 3
    for _ in range(len(line) - pos + 8):
        if pos >= len(line):
            return None
        if line[pos : pos + 2] == b"((":
            depth += 1
            pos += 2
        elif line[pos : pos + 2] == b"))":
            depth -= 1
            pos += 2
        else:
            pos += 1
        if depth == 0:
            return pos
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


def strip_descriptor_tail_marks(raw: bytes) -> bytes:
    """Build twin bytes with each unquoted descriptor prefix before <<< removed."""
    masked = _mask_quoted_bytes(raw)
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
    return _TAIL_MARK.search(_mask_quoted_bytes(raw)) is not None


def _herestring_word_end_bytes(seg: bytes, masked: bytes, pos: int) -> tuple[int, int] | None:
    """Return start and end byte offsets of the here-string word starting at or after pos."""
    n = len(seg)
    start = pos + (len(seg[pos:]) - len(seg[pos:].lstrip(b" \t")))
    if start >= n:
        return None
    end = start
    for _ in range(n - start):
        if end >= n or masked[end] in b" \t\r\n;&|<>()":
            break
        end += 1
    return (start, end) if end > start else None


def _step_segment_redirect(
    seg: bytes,
    masked_seg: bytes,
    match: re.Match[bytes],
    local_fds: dict[int, bytes],
    stripped: bytearray,
) -> tuple[int, bytes | None]:
    """Apply one matched byte-surface redirect in source order; return end and replacement."""
    start, end = match.span()
    if match.group("hd") is not None:
        return end, None
    if match.group("hs") is not None:
        word_span = _herestring_word_end_bytes(seg, masked_seg, end)
        if word_span is None:
            return end, None
        stripped[start : word_span[1]] = b" " * (word_span[1] - start)
        fd = _descriptor_fd(match.group("hs_fd"))
        if fd is not None:
            local_fds[fd] = seg[word_span[0] : word_span[1]]
        return word_span[1], None
    if match.group("dup") is not None:
        stripped[start:end] = b" " * (end - start)
        resolved = _apply_dup_or_close(
            local_fds, match.group("dup_fd"), match.group("dup_op"), match.group("dup_rhs")
        )
        if resolved is None:
            return end, None
        lead = b"<<< " if start == 0 or seg[start - 1 : start] in b" \t" else b" <<< "
        return end, lead + resolved
    word_span = _herestring_word_end_bytes(seg, masked_seg, end)
    stop = word_span[1] if word_span is not None else end
    stripped[start:stop] = b" " * (stop - start)
    if match.group("amp") is not None:
        _apply_file_redirect(local_fds, None, match.group("amp"))
    else:
        _apply_file_redirect(local_fds, match.group("file_fd"), match.group("file_op"))
    return stop, None


def _rewrite_segment_dups(
    seg: bytes, masked_seg: bytes, exec_fds: dict[int, bytes]
) -> tuple[bytes, dict[int, bytes]]:
    """Update segment descriptors in source order and replace resolved fd 0 dups with <<< word."""
    local_fds = dict(exec_fds)
    stripped = bytearray(masked_seg)
    parts: list[bytes] = []
    cursor = 0
    scan_pos = 0
    for match in _SEG_REDIR_BYTES.finditer(masked_seg):
        if match.start() < scan_pos:
            continue
        scan_pos, replacement = _step_segment_redirect(seg, masked_seg, match, local_fds, stripped)
        if replacement is not None:
            parts.append(seg[cursor : match.start()])
            parts.append(replacement)
            cursor = scan_pos
    parts.append(seg[cursor:])
    next_exec = local_fds if bytes(stripped).strip() == b"exec" else exec_fds
    return b"".join(parts), next_exec


def _is_separator_byte(masked: bytes, idx: int) -> bool:
    """Return whether idx in masked bytes is an unquoted command separator."""
    b = masked[idx]
    if b in (ord(";"), ord("\n")):
        return True
    if b == ord("|"):
        return not (idx > 0 and masked[idx - 1] == ord(">"))
    if b == ord("&"):
        prev_redir = idx > 0 and masked[idx - 1] in b"><"
        next_redir = idx + 1 < len(masked) and masked[idx + 1] == ord(">")
        return not (prev_redir or next_redir)
    return False


def rewrite_descriptor_dups(raw: bytes) -> bytes:
    """Rewrite 0<&N and <&N to plain here-strings when fd N carries a here-string word."""
    masked = _mask_quoted_bytes(raw)
    if _DUP_STDIN_BYTES.search(masked) is None:
        return raw
    out: list[bytes] = []
    exec_fds: dict[int, bytes] = {}
    seg_start = 0
    for idx in range(len(raw)):
        if _is_separator_byte(masked, idx):
            if idx > seg_start:
                rewritten, exec_fds = _rewrite_segment_dups(
                    raw[seg_start:idx], masked[seg_start:idx], exec_fds
                )
                out.append(rewritten)
            out.append(raw[idx : idx + 1])
            seg_start = idx + 1
    if seg_start < len(raw):
        rewritten, _ = _rewrite_segment_dups(raw[seg_start:], masked[seg_start:], exec_fds)
        out.append(rewritten)
    return b"".join(out)


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


def _skip_spaces_tabs(line: bytes, pos: int) -> int:
    """Return the index after horizontal whitespace at pos."""
    tail = line[pos:]
    return pos + (len(tail) - len(tail.lstrip(b" \t")))


def _skip_spaces(line: bytes, pos: int) -> int:
    """Return the index after space characters at pos."""
    tail = line[pos:]
    return pos + (len(tail) - len(tail.lstrip(b" ")))


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
    masked = _mask_quoted_bytes(raw)
    return sum(1 for _ in _TAIL_MARK.finditer(masked))


def find_descriptor_herestring_tail(raw: bytes) -> tuple[int, int, int, list[bytes]] | None:
    """Locate exactly one allowed descriptor here-string tail line in raw script bytes."""
    if script_blocks_fd_herestring_allowlist(raw):
        return None
    masked = _mask_quoted_bytes(raw)
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
