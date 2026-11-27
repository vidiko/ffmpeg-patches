#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Compare CPU sample normalization in vf_*.c with linked Vulkan shader loaders."""

from __future__ import annotations

import re
import sys
from bisect import bisect_right
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.sweep_vulkan_features import (  # noqa: E402
    SHADER_PATH,
    diff_names,
    linked_shaders,
    owners_for_shaders,
)
from scripts.variant_sweep import (  # noqa: E402
    MAX_REPORT_BYTES,
    REPORT_TABLES,
    check_deadline,
    check_limit,
    git,
    mask_literals,
    read_sources,
)

TABLE = REPORT_TABLES["port-parity"]
MAX_PAIRS = 64
FILTER_PAIR = re.compile(r"libavfilter/vf_(\w+)\.c\Z")
VULKAN_PAIR = re.compile(r"libavfilter/vf_(\w+)_vulkan\.c\Z")
SAMPLE_READ = re.compile(
    r"(?:src\s*\[[^\]]+\]|AV_RN16[A-Z]?\s*\(|AV_RL16\s*\(|AV_RB16\s*\()",
    re.ASCII,
)
MASK = re.compile(r"&\s*0x[0-9A-Fa-f]+[uUlL]?", re.ASCII)
SHIFT = re.compile(r">>\s*(?:\([^)]+\)|\w+)", re.ASCII)
CLIP = re.compile(r"\b(?:av_clip|CLIP)\w*\s*\(", re.ASCII)
CLAMP = re.compile(r"\bclamp\s*\(", re.ASCII)
SHADER_LOAD = re.compile(r"\b(?:imageLoad|texelFetch)\s*\(", re.ASCII)
_LOOP_HEADER = re.compile(r"^\s*(?:for|while)\s*\(", re.ASCII)
_FOR_LOOP = re.compile(r"^\s*for\b", re.ASCII)
_OPERAND_OPS = 64
_SUBSCRIPT_DEPTH = 32
_WHITESPACE = " \t\n\r"
_MAX_LOADS = 64
_MAX_STATEMENTS = 4096
_MAX_COUNTED_EVENTS = 256
_USE_WINDOW = 32
_SUFFIX_STEPS = 8
_HELPER_DEFINITIONS = 8
_CONTROL_WORDS = frozenset({"if", "for", "while", "switch", "return", "else"})
_LOAD_SUFFIX = re.compile(r"\s*(?:\.[A-Za-z_]\w*|\[)", re.ASCII)
_GLSL_DECLARATION = re.compile(
    r"\s*(?:(?:const|lowp|mediump|highp|precise)\s+)*"
    r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?=[=;]|$)",
    re.ASCII,
)
_GLSL_VECTOR = re.compile(r"[biud]?vec([2-4])", re.ASCII)
_LOAD_ASSIGN = re.compile(r"\A\s*(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)\s*=\s*\Z", re.ASCII)
_VALUE_ASSIGNMENT = re.compile(r"\s*(?:<<=|>>=|[+*/%&|^\-]=|=(?!=))", re.ASCII)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*", re.ASCII)
_UNWRAP_STEPS = 8
_TARGET_PARENS = 8
_GLSL_CONSTRUCTORS = frozenset(
    {
        "bool",
        "int",
        "uint",
        "float",
        "double",
        "bvec2",
        "bvec3",
        "bvec4",
        "ivec2",
        "ivec3",
        "ivec4",
        "uvec2",
        "uvec3",
        "uvec4",
        "vec2",
        "vec3",
        "vec4",
        "dvec2",
        "dvec3",
        "dvec4",
    }
)


def pair_name(path: str) -> str | None:
    """Return the filter stem for a CPU or Vulkan C path."""
    if match := VULKAN_PAIR.fullmatch(path):
        return match[1]
    if match := FILTER_PAIR.fullmatch(path):
        return match[1]
    return None


def pair_paths_at_head(directory: str, head: str, stems: list[str], deadline: float) -> set[str]:
    """Return CPU and Vulkan filter paths that exist at head for up to MAX_PAIRS stems."""
    paths: list[str] = []
    for stem in stems[:MAX_PAIRS]:
        paths.append(f"libavfilter/vf_{stem}.c")
        paths.append(f"libavfilter/vf_{stem}_vulkan.c")
    if not paths:
        return set()
    text = git(
        directory,
        "ls-tree",
        "-r",
        "--name-only",
        head,
        "--",
        *paths,
        deadline=deadline,
    )
    return {line for line in text.splitlines() if line}


def collect_pairs(
    directory: str, head: str, names: set[str], deadline: float
) -> dict[str, tuple[str, str, bool]]:
    """Map filter stems to CPU/Vulkan pairs and whether the diff touched them."""
    shaders = {path for path in names if SHADER_PATH.fullmatch(path)}
    stems: dict[str, bool] = {}
    for path in names:
        if stem := pair_name(path):
            stems[stem] = True
    for path in owners_for_shaders(directory, head, shaders, deadline):
        if stem := pair_name(path):
            stems[stem] = True
    check_limit("filter pair count", len(stems), MAX_PAIRS)
    stems_sorted = sorted(stems)
    existing = pair_paths_at_head(directory, head, stems_sorted, deadline)
    pairs: dict[str, tuple[str, str, bool]] = {}
    for stem in stems_sorted:
        cpu = f"libavfilter/vf_{stem}.c"
        vk = f"libavfilter/vf_{stem}_vulkan.c"
        if cpu in existing and vk in existing:
            pairs[stem] = (cpu, vk, stems[stem])
    return pairs


def statement_spans(masked: str, *, shader: bool = False) -> list[tuple[int, int]]:
    """Split at top-level statement delimiters; keep GLSL initializer lists intact."""
    spans: list[tuple[int, int]] = []
    start = 0
    paren_depth = initializer_depth = 0
    index = 0
    limit = len(masked)
    while index < limit:
        ch = masked[index]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif (
            shader
            and paren_depth == 0
            and ch == "{"
            and (initializer_depth or masked[start:index].rstrip().endswith("="))
        ):
            initializer_depth += 1
        elif initializer_depth and paren_depth == 0 and ch == "}":
            initializer_depth -= 1
        elif paren_depth == initializer_depth == 0 and ch in ";{}":
            end = index + 1
            spans.append((start, end))
            start = end
        index += 1
    if start < limit:
        piece = masked[start:limit]
        if piece.strip():
            spans.append((start, limit))
    return spans


def matching_close_paren(text: str, open_index: int) -> int | None:
    """Return the index of ')' that balances '(' at open_index."""
    depth = 0
    limit = len(text)
    for index in range(open_index, limit):
        ch = text[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


_MACRO_READ = re.compile(r"\b(?:AV_RN16[A-Z]?|AV_RL16|AV_RB16)\s*\(", re.ASCII)


def _sample_subscript_end(statement: str, opening: int, read_end: int) -> int:
    """Return the outer subscript end, falling back to the initial match."""
    depth = 1
    for index in range(opening + 1, len(statement)):
        ch = statement[index]
        if ch == "[":
            depth += 1
            if depth > _SUBSCRIPT_DEPTH:
                break
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return index + 1
    return read_end


def sample_read_end(statement: str, read_start: int, read_end: int) -> int:
    """Extend a sample read through its balanced subscript or macro arguments."""
    if read_end > read_start and statement[read_end - 1] == "]":
        opening = statement.find("[", read_start, read_end)
        if opening >= 0:
            return _sample_subscript_end(statement, opening, read_end)
    if read_end <= read_start or statement[read_end - 1] != "(":
        return read_end
    prefix = statement[read_start:read_end]
    if _MACRO_READ.match(prefix) is None:
        return read_end
    close_index = matching_close_paren(statement, read_end - 1)
    if close_index is None:
        return read_end
    return close_index + 1


def enclosing_clip_focus(statement: str, read_start: int, read_end: int) -> str | None:
    """Return clip or clamp call text when the sample read is one of its arguments."""
    for pattern in (CLIP, CLAMP):
        for match in pattern.finditer(statement):
            open_index = match.end() - 1
            close_index = matching_close_paren(statement, open_index)
            if close_index is None:
                continue
            if open_index < read_start and read_end <= close_index:
                return statement[match.start() : close_index + 1]
    return None


def loop_header_bounds(statement: str) -> tuple[int, int] | None:
    """Return the inclusive header bounds for a leading for/while statement."""
    trimmed = statement.lstrip()
    lead = len(statement) - len(trimmed)
    match = _LOOP_HEADER.match(trimmed)
    if match is None:
        return None
    open_index = lead + match.end() - 1
    close_index = matching_close_paren(statement, open_index)
    if close_index is None:
        return None
    return open_index + 1, close_index


def _skip_space(text: str, position: int, limit: int) -> int:
    """Advance past ASCII whitespace."""
    for index in range(position, limit):
        if text[index] not in _WHITESPACE:
            return index
    return limit


def _extend_shift_tail(text: str, position: int, limit: int) -> int:
    """Advance past the rhs of one '>>' shift attached to a sample operand."""
    for _ in range(16):
        if position >= limit:
            break
        ch = text[position]
        if ch.isdigit() or ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_":
            position += 1
            continue
        if ch == "(":
            close = matching_close_paren(text, position)
            if close is not None:
                position = close + 1
            break
        break
    return position


def _extend_mask_tail(text: str, position: int, limit: int) -> int:
    """Advance past the rhs of one '&' mask attached to a sample operand."""
    for _ in range(32):
        if position >= limit or text[position] not in "0123456789xXaAbBcCdDeEfFuUlL":
            break
        position += 1
    return position


def _operand_scan_end(
    statement: str,
    read_end: int,
    depth: int,
    *,
    shift_rhs_spans: list[tuple[int, int]] | None = None,
    result_parens: int = 0,
) -> int:
    """Return the attached operator tail's end, optionally recording shift counts."""
    limit = len(statement)
    position = read_end
    saw_shift = False
    for _ in range(_OPERAND_OPS):
        position = _skip_space(statement, position, limit)
        op = position
        # A mask after a group around the shifted value is not part of its count.
        while saw_shift and result_parens and op < limit and statement[op] == ")":
            result_parens -= 1
            depth -= 1
            op = _skip_space(statement, op + 1, limit)
        if op >= limit or (statement[op] == "," and depth == 0):
            break
        if statement.startswith(">>", op):
            after = _skip_space(statement, op + 2, limit)
            position = _extend_shift_tail(statement, after, limit)
            if shift_rhs_spans is not None:
                shift_rhs_spans.append((after, position))
            saw_shift = True
            continue
        if statement[op] == "&" and op + 1 < limit and statement[op + 1] != "&":
            position = _extend_mask_tail(statement, _skip_space(statement, op + 1, limit), limit)
            continue
        break
    return position


def _attached_result_parens(statement: str, read_start: int) -> int:
    """Count grouping opens immediately before the operand that the tail can cross."""
    count = 0
    start = read_start
    for _ in range(_TARGET_PARENS):
        opening = _non_space_index(statement, start - 1, 0)
        if opening is None or statement[opening] != "(":
            return count
        previous = _non_space_index(statement, opening - 1, 0)
        # Do not cross a call boundary or a group used as another shift's count.
        if (
            previous is not None
            and statement[previous] not in "=(,;?:{|^"
            and re.search(r"\breturn$", statement[: previous + 1]) is None
        ):
            return count
        count += 1
        start = opening
    return count


def attached_operator_text(statement: str, read_start: int, read_end: int) -> str:
    """Return attached operator text with shift-count normalization excluded."""
    depth = statement[:read_start].count("(") - statement[:read_start].count(")")
    shift_rhs_spans: list[tuple[int, int]] = []
    end = _operand_scan_end(
        statement,
        read_end,
        depth,
        shift_rhs_spans=shift_rhs_spans,
        result_parens=_attached_result_parens(statement, read_start),
    )
    pieces: list[str] = []
    start = read_end
    for rhs_start, rhs_end in shift_rhs_spans:
        pieces.append(statement[start:rhs_start])
        # Keep offsets stable for callers that clip the focus to a header boundary.
        count = statement[rhs_start:rhs_end].replace("&", " ")
        for pattern in (CLIP, CLAMP):
            count = pattern.sub(lambda match: " " * (len(match[0]) - 1) + "(", count)
        pieces.append(count)
        start = rhs_end
    pieces.append(statement[start:end])
    return "".join(pieces)


def header_inner_call_depth(statement: str, read_start: int, bounds: tuple[int, int]) -> int:
    """Return parenthesis depth at read_start from the loop header opening parenthesis."""
    depth = 0
    for index in range(max(0, bounds[0] - 1), read_start):
        ch = statement[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth


def _whole_word_at(text: str, index: int, name: str) -> bool:
    """Return whether name appears as a whole identifier at index."""
    if not text.startswith(name, index):
        return False
    after = index + len(name)
    if index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_"):
        return False
    return not (after < len(text) and (text[after].isalnum() or text[after] == "_"))


def for_init_clause_end(statement: str, bounds: tuple[int, int]) -> int:
    """Return the index of the first ';' that ends the for-init clause in bounds."""
    depth = 0
    for index in range(bounds[0], bounds[1]):
        ch = statement[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ";" and depth == 0:
            return index
    return bounds[1]


def _non_space_index(statement: str, index: int, floor: int) -> int | None:
    """Return the highest index at or above floor that is not whitespace."""
    for idx in range(index, floor - 1, -1):
        if statement[idx] not in _WHITESPACE:
            return idx
    return None


def _identifier_span_backward(statement: str, end: int, floor: int) -> tuple[int, int] | None:
    """Return the inclusive identifier span ending at end when it starts at or above floor."""
    if end < floor or not (statement[end].isalnum() or statement[end] == "_"):
        return None
    start = end
    for idx in range(end - 1, floor - 1, -1):
        ch = statement[idx]
        if ch.isalnum() or ch == "_":
            start = idx
        else:
            break
    name = statement[start : end + 1]
    if not name or not (name[0].isalpha() or name[0] == "_"):
        return None
    return start, end


def _for_init_lhs_prefix_ok(statement: str, name_start: int, init_start: int) -> bool:
    """Return whether text before name_start allows a declared for-init loop variable."""
    precede = _non_space_index(statement, name_start - 1, init_start - 1)
    if precede is None or precede < init_start:
        return True
    ch = statement[precede]
    return ch == "," or ch.isalnum() or ch == "_"


def _declared_name_at_equals(statement: str, eq_index: int, init_start: int) -> str | None:
    """Return a simple lhs name at '=' only when declarator shape permits for-init binding."""
    pos = _non_space_index(statement, eq_index - 1, init_start)
    if pos is None or pos < init_start:
        return None
    span = _identifier_span_backward(statement, pos, init_start)
    if span is None:
        return None
    name_start, name_end = span
    if not _for_init_lhs_prefix_ok(statement, name_start, init_start):
        return None
    return statement[name_start : name_end + 1]


def for_init_bound_name(
    statement: str, read_start: int, read_end: int, bounds: tuple[int, int]
) -> tuple[str, int] | None:
    """Return bound for-init name and its clause end when the read is the whole initializer."""
    if _FOR_LOOP.match(statement.lstrip()) is None:
        return None
    init_end = for_init_clause_end(statement, bounds)
    if read_start >= init_end:
        return None
    depth = statement[:read_start].count("(") - statement[:read_start].count(")")
    rhs_end = _operand_scan_end(statement, read_end, depth)
    paren_depth = 0
    init_start = bounds[0]
    for index in range(init_start, init_end):
        ch = statement[index]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif ch == "=" and paren_depth == 0:
            name = _declared_name_at_equals(statement, index, init_start)
            if name is None:
                continue
            rhs_start = _skip_space(statement, index + 1, init_end)
            if rhs_start != read_start or rhs_end > init_end:
                continue
            tail_at = _skip_space(statement, rhs_end, init_end)
            if tail_at == init_end or statement[tail_at] == ",":
                return (name, init_end)
    return None


def _follows_member_operator(statement: str, name_start: int, floor: int) -> bool:
    """Return whether non-space text before name_start ends with '->' or '.'."""
    precede = _non_space_index(statement, name_start - 1, floor)
    if precede is None:
        return False
    if statement[precede] == ".":
        return True
    return precede > 0 and statement[precede - 1 : precede + 1] == "->"


def _top_level_separators(text: str, start: int, end: int, delimiters: str) -> Iterator[int]:
    """Yield ungrouped delimiter positions up to the current expression's close."""
    depth = 0
    for index in range(start, end):
        ch = text[index]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                if ch in delimiters:
                    yield index
                return
            depth -= 1
        elif depth == 0 and ch in delimiters:
            yield index


def _unwrap_target_parens(
    statement: str, start: int, end: int, floor: int, limit: int
) -> tuple[int, int]:
    """Extend a target span through balanced parentheses holding it alone."""
    for _ in range(_TARGET_PARENS):
        left = _non_space_index(statement, start - 1, floor)
        right = _skip_space(statement, end, limit)
        if left is None or right >= limit or statement[left] != "(" or statement[right] != ")":
            break
        start, end = left, right + 1
    return start, end


def _header_assignment_rhs(
    statement: str, hit: int, name_len: int, floor: int, limit: int
) -> int | None:
    """Return the RHS start of a header assignment with the name as its whole LHS."""
    lhs_start, lhs_end = _unwrap_target_parens(statement, hit, hit + name_len, floor, limit)
    previous = _non_space_index(statement, lhs_start - 1, floor)
    if previous is not None and statement[previous] not in "(,;?:":
        return None
    match = _VALUE_ASSIGNMENT.match(statement, lhs_end, limit)
    return match.end() if match is not None else None


def _compound_assignment_focus(statement: str, rhs: int, end: int) -> str:
    """Return attached-operator text when the assignment ending at rhs is compound."""
    if statement.endswith(">>=", 0, rhs):
        # The whole RHS is the count; only the shift applies to the old value.
        return ">> 0"
    if statement.endswith("<<=", 0, rhs):
        return ""
    if rhs >= 2 and statement[rhs - 2] in "+-*/%&|^":
        prefix = statement[rhs - 2 : rhs - 1]
    else:
        return ""
    synthetic = f"{prefix} {statement[rhs:end]}"
    return synthetic[: _operand_scan_end(synthetic, 0, 0)]


def bound_variable_operator_focus(statement: str, name: str, init_end: int, header_end: int) -> str:
    """Return attached mask or shift text from later non-member uses of one loop variable."""
    pieces: list[str] = []
    index = init_end
    name_len = len(name)
    for _ in range(_OPERAND_OPS):
        if index >= header_end:
            break
        hit = statement.find(name, index, header_end)
        if hit < 0:
            break
        if not _whole_word_at(statement, hit, name):
            index = hit + 1
            continue
        if _follows_member_operator(statement, hit, init_end):
            index = hit + 1
            continue
        pieces.append(attached_operator_text(statement, hit, hit + name_len))
        rhs = _header_assignment_rhs(statement, hit, name_len, init_end, header_end)
        if rhs is not None:
            end = next(_top_level_separators(statement, rhs, header_end, ",;)]}"), header_end)
            pieces.append(_compound_assignment_focus(statement, rhs, end))
            header_end = end
        index = hit + name_len
    return "".join(pieces)


def normalization_focus(statement: str, read_start: int, read_end: int) -> str:
    """Return the statement slice searched for normalization on one sample read."""
    clip_text = enclosing_clip_focus(statement, read_start, read_end)
    if clip_text is not None:
        return clip_text
    tail = attached_operator_text(statement, read_start, read_end)
    bounds = loop_header_bounds(statement)
    if bounds is not None and bounds[0] <= read_start <= bounds[1]:
        header_end = bounds[1] + 1
        tail_end = min(read_end + len(tail), header_end)
        tail_slice = tail[: tail_end - read_end]
        if header_inner_call_depth(statement, read_start, bounds) > 1:
            return tail_slice
        if normalization_kind(tail_slice) is not None:
            return tail_slice
        bound = for_init_bound_name(statement, read_start, read_end, bounds)
        if bound is not None:
            name, init_end = bound
            return bound_variable_operator_focus(statement, name, init_end, bounds[1])
        return tail_slice
    return tail


def normalization_kind(text: str) -> str | None:
    """Classify one sample expression slice as mask, shift, clip, or clamp."""
    if CLIP.search(text):
        return "clip"
    if CLAMP.search(text):
        return "clamp"
    if MASK.search(text):
        return "mask"
    if SHIFT.search(text):
        return "shift"
    return None


def _sample_read_matches(statement: str) -> Iterator[re.Match[str]]:
    """Yield every sample-read match in statement, including nested subscript reads."""
    cursor = 0
    for _ in range(_OPERAND_OPS + 1):
        match = SAMPLE_READ.search(statement, cursor)
        if match is None:
            return
        yield match
        opening = statement.find("[", match.start(), match.end())
        cursor = opening + 1 if opening >= 0 else match.end()


def statement_sites(masked: str, start: int, end: int) -> list[tuple[int, str]]:
    """Classify every sample read of one statement span with its own operators and line."""
    statement = masked[start:end]
    sites: list[tuple[int, str]] = []
    for count, read_match in enumerate(_sample_read_matches(statement)):
        read_start = read_match.start()
        if count >= _OPERAND_OPS:
            break
        read_end = sample_read_end(statement, read_start, read_match.end())
        kind = normalization_kind(normalization_focus(statement, read_start, read_end))
        if kind is not None:
            sites.append((masked.count("\n", 0, start + read_start) + 1, kind))
    return sites


def cpu_sites(source: str) -> list[tuple[int, str]]:
    """List sample-load normalization sites in one CPU filter source."""
    sites: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    masked = mask_literals(source)
    for start, end in statement_spans(masked):
        for site in statement_sites(masked, start, end):
            if site not in seen:
                seen.add(site)
                sites.append(site)
    return sites


def _suffix_end(statement: str, start: int) -> int:
    """Return the end of one member or balanced index suffix, if present."""
    match = _LOAD_SUFFIX.match(statement, start)
    if match is None:
        return start
    if statement[match.end() - 1] == "[":
        return _sample_subscript_end(statement, match.end() - 1, start)
    return match.end()


def _load_end(statement: str, call_end: int) -> int:
    """Extend a shader load call through swizzle, member and index suffixes."""
    position = call_end
    for _ in range(_SUFFIX_STEPS):
        end = _suffix_end(statement, position)
        if end == position:
            break
        position = end
    return position


def shader_loads(statement: str) -> list[tuple[int, int]]:
    """Return up to _MAX_LOADS shader load expression spans in one statement."""
    loads: list[tuple[int, int]] = []
    for match in SHADER_LOAD.finditer(statement):
        if len(loads) >= _MAX_LOADS:
            break
        close_index = matching_close_paren(statement, match.end() - 1)
        if close_index is not None:
            loads.append((match.start(), _load_end(statement, close_index + 1)))
    return loads


def _wrapper_start(statement: str, open_index: int) -> int | None:
    """Return where the grouping or type constructor of '(' starts, or None for a call."""
    before = _non_space_index(statement, open_index - 1, 0)
    if before is None or not (statement[before].isalnum() or statement[before] == "_"):
        return open_index
    span = _identifier_span_backward(statement, before, 0)
    if span is None or statement[span[0] : span[1] + 1] not in _GLSL_CONSTRUCTORS:
        return None
    return span[0]


def _unwrap_step(statement: str, start: int, end: int) -> tuple[int, int] | None:
    """Grow an expression span by one wrapping pair of parentheses holding it alone."""
    before = _non_space_index(statement, start - 1, 0)
    after = _skip_space(statement, end, len(statement))
    if before is None or after >= len(statement):
        return None
    if statement[before] != "(" or statement[after] != ")":
        return None
    if matching_close_paren(statement, before) != after:
        return None
    wrapper = _wrapper_start(statement, before)
    return None if wrapper is None else (wrapper, _load_end(statement, after + 1))


def unwrap_expression(statement: str, start: int, end: int) -> tuple[int, int]:
    """Extend a load or use span outward through grouping parentheses and type constructors."""
    for _ in range(_UNWRAP_STEPS):
        grown = _unwrap_step(statement, start, end)
        if grown is None:
            break
        start, end = grown
    return (start, end)


def _call_name_before(statement: str, open_index: int) -> str | None:
    """Return the identifier directly before '(' at open_index."""
    end = _non_space_index(statement, open_index - 1, 0)
    span = None if end is None else _identifier_span_backward(statement, end, 0)
    if span is None:
        return None
    return statement[span[0] : span[1] + 1]


def _call_argument_slot(
    statement: str, open_index: int, load_start: int, load_end: int
) -> tuple[int, int] | None:
    """Return (position, arity) when (load_start, load_end) is one whole call argument."""
    close_index = matching_close_paren(statement, open_index)
    if close_index is None or load_end > close_index:
        return None
    ends = [*_top_level_separators(statement, open_index + 1, close_index, ","), close_index]
    arity = len(ends)
    arg_start = open_index + 1
    for position, arg_end in enumerate(ends):
        first = _skip_space(statement, arg_start, arg_end)
        last = _non_space_index(statement, arg_end - 1, first)
        trimmed = (first, first if last is None else last + 1)
        if trimmed == (load_start, load_end):
            return position, arity
        arg_start = arg_end + 1
    return None


def _enclosing_call(statement: str, load_start: int, load_end: int) -> tuple[str, int, int] | None:
    """Return enclosing call (name, position, arity) when the load is a whole argument."""
    depth = 0
    for index in range(load_start - 1, -1, -1):
        ch = statement[index]
        if ch == ")":
            depth += 1
        elif ch == "(" and depth > 0:
            depth -= 1
        elif ch == "(":
            name = _call_name_before(statement, index)
            if name is None or name in _CONTROL_WORDS:
                return None
            slot = _call_argument_slot(statement, index, load_start, load_end)
            return None if slot is None else (name, slot[0], slot[1])
    return None


def _brace_body(masked: str, open_index: int) -> str | None:
    """Return the text from the '{' at open_index through its balancing '}'."""
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[open_index : index + 1]
    return None


def _parameter_count(parameters: str) -> int:
    """Return the declared parameter count of a GLSL function parameter list."""
    stripped = parameters.strip()
    if not stripped or stripped == "void":
        return 0
    return sum(1 for _ in _top_level_separators(parameters, 0, len(parameters), ",")) + 1


def _helper_parameter(parameters: str, position: int) -> str | None:
    """Return the last identifier of the parameter at the requested position."""
    start = 0
    ends = [*_top_level_separators(parameters, 0, len(parameters), ","), len(parameters)]
    for index, end in enumerate(ends):
        if index == position:
            names = _IDENTIFIER.findall(parameters, start, end)
            return names[-1] if names else None
        start = end + 1
    return None


def _helper_applies(
    masked: str, name: str, position: int, arity: int, pattern: re.Pattern[str]
) -> bool:
    """Credit no name with more definitions than the limit; require matching overloads to agree."""
    definition = re.compile(
        rf"\b[A-Za-z_]\w*\s+{re.escape(name)}\s*\(([^;{{}}]*)\)\s*\{{", re.ASCII
    )
    matched = False
    for count, match in enumerate(definition.finditer(masked)):
        if count >= _HELPER_DEFINITIONS:
            return False
        if _parameter_count(match[1]) != arity:
            continue
        parameter = _helper_parameter(match[1], position)
        body = _brace_body(masked, match.end() - 1)
        if (
            body is not None
            and parameter is not None
            and any(
                _statement_use_matches(body[start:end], parameter, pattern)
                for start, end in statement_spans(body)[:_MAX_STATEMENTS]
            )
        ):
            matched = True
        else:
            return False
    return matched


def _assigned_name(statement: str, load_start: int, load_end: int) -> str | None:
    """Return the simple name that receives the whole load expression."""
    if statement[load_end:].strip(_WHITESPACE + ";"):
        return None
    match = _LOAD_ASSIGN.match(statement[:load_start])
    return None if match is None else match[1]


def _selector_indices(selector: str) -> list[int]:
    """Return static selector indices, or an empty list for an unknown selector."""
    if selector.startswith("."):
        swizzle = selector[1:]
        for alphabet in ("xyzw", "rgba", "stpq"):
            if all(char in alphabet for char in swizzle):
                return [alphabet.index(char) for char in swizzle]
        return []
    literal = selector[1:-1].strip().removesuffix("u").removesuffix("U")
    if re.fullmatch(r"(?:0[xX]0*[0-3]|0*[0-3])", literal, re.ASCII):
        return [int(literal[-1])]
    return []


def _vector_access(statement: str, start: int, end: int, width: int) -> tuple[int, int, int]:
    """Return a grouped access span and the set of lanes it may select."""
    lanes = list(range(width))
    known = True
    for _ in range(_SUFFIX_STEPS + 1):
        left, right = _unwrap_target_parens(statement, start, end, 0, len(statement))
        # A pair belonging to a call is not grouping around its argument.
        if left < start and _wrapper_start(statement, left) == left:
            start, end = left, right
        suffix_end = _suffix_end(statement, end)
        if suffix_end == end:
            break
        indices = _selector_indices(statement[end:suffix_end].strip())
        known = known and bool(indices) and max(indices) < len(lanes)
        if known:
            lanes = [lanes[i] for i in indices]
        end = suffix_end
    return start, end, sum(1 << lane for lane in set(lanes))


def _statement_use_matches(
    statement: str, name: str, pattern: re.Pattern[str], width: int = 0, live: int = 0
) -> bool:
    """Return whether a non-member use of name in the statement carries the pattern."""
    index = 0
    for _ in range(_OPERAND_OPS):
        hit = statement.find(name, index)
        if hit < 0:
            return False
        index = hit + 1
        if not _whole_word_at(statement, hit, name) or _follows_member_operator(statement, hit, 0):
            continue
        base_end = hit + len(name)
        use_start = hit
        if width:
            use_start, use_end, lanes = _vector_access(statement, hit, base_end, width)
            if lanes & live != lanes or _follows_member_operator(statement, use_start, 0):
                continue
        else:
            use_end = _load_end(statement, base_end)
        use_start, use_end = unwrap_expression(statement, use_start, use_end)
        if pattern.search(normalization_focus(statement, use_start, use_end)):
            return True
    return False


def _statement_assignment(statement: str, name: str, width: int) -> tuple[int, int] | None:
    """Return the RHS start and affected lanes for a recognized assignment."""
    limit = len(statement)
    start = _skip_space(statement, 0, limit)
    openings = []
    for _ in range(_TARGET_PARENS):
        if start >= limit or statement[start] != "(":
            break
        openings.append(start)
        start = _skip_space(statement, start + 1, limit)
    if not _whole_word_at(statement, start, name):
        return None

    base_end = start + len(name)
    if width:
        target_start, target_end, lanes = _vector_access(statement, start, base_end, width)
    else:
        target_start, target_end = _unwrap_target_parens(statement, start, base_end, 0, limit)
        lanes = 1
    match = _VALUE_ASSIGNMENT.match(statement, target_end)
    if match is None:
        return None

    if openings and openings[0] < target_start:
        # The leading assignment may be followed by a comma expression.
        close = matching_close_paren(statement, openings[0])
        if close is None:
            return None
        tail = _skip_space(statement, close + 1, limit)
        if tail < limit and statement[tail] not in ",;":
            return None
    return match.end(), lanes


def _statement_expressions(statement: str) -> Iterator[str]:
    """Yield comma operands in evaluation order, including grouped comma expressions."""
    pending = [(statement, 0)]
    while pending:
        expression, depth = pending.pop()
        expression = expression.strip().removesuffix(";").rstrip()
        if depth >= _TARGET_PARENS:
            yield expression
            continue
        if (
            expression.startswith("(")
            and matching_close_paren(expression, 0) == len(expression) - 1
        ):
            pending.append((expression[1:-1], depth + 1))
            continue
        commas = list(_top_level_separators(expression, 0, len(expression), ","))
        if not commas:
            yield expression
            continue
        starts = [0, *(comma + 1 for comma in commas)]
        ends = [*commas, len(expression)]
        pending.extend(
            (expression[start:end], depth + 1)
            for start, end in reversed(list(zip(starts, ends, strict=True)))
        )


def _expression_use(
    expression: str, name: str, pattern: re.Pattern[str], width: int, live: int
) -> tuple[bool, int]:
    """Check reads before applying the expression's write to the lane state."""
    assignment = _statement_assignment(expression, name, width)
    if assignment is None:
        return _statement_use_matches(expression, name, pattern, width, live), live
    rhs, lanes = assignment
    limit = len(expression)
    end = next(_top_level_separators(expression, rhs, limit, ",;)]}"), limit)
    if lanes & live == lanes and pattern.search(_compound_assignment_focus(expression, rhs, end)):
        return True, live
    matched = _statement_use_matches(expression[rhs:end], name, pattern, width, live)
    return matched, live & ~lanes


def _statement_sequence_use(
    statement: str, name: str, pattern: re.Pattern[str], width: int, live: int
) -> tuple[bool, int]:
    """Check comma operands in order, stopping on a match or when no lanes remain."""
    for expression in _statement_expressions(statement):
        matched, live = _expression_use(expression, name, pattern, width, live)
        if matched or not live:
            return matched, live
    return False, live


_ShaderEvent = tuple[str, int, int]


def _shader_control(masked: str, start: int, boundary: int) -> tuple[str, int, int] | None:
    """Locate a leading control header within the current statement span."""
    word = _IDENTIFIER.match(masked, start, boundary)
    if word is None or word[0] not in {"if", "for", "while", "switch"}:
        return None
    opening = _skip_space(masked, word.end(), boundary)
    if opening == boundary or masked[opening] != "(":
        return None
    close = matching_close_paren(masked, opening)
    if close is None or close >= boundary:
        return None
    return word[0], opening + 1, close


def _shader_schedule_body(
    events: list[_ShaderEvent], pending: list[_ShaderEvent], depth: int
) -> None:
    """Give one controlled statement its own scope, even without braces."""
    events.append(("enter", 0, 0))
    pending.extend((("exit", 0, 0), ("statement", depth + 1, 0)))


def _shader_schedule_control(
    scan: tuple[str, bool],
    control: tuple[str, int, int],
    depth: int,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> bool:
    """Emit the header and schedule the body followed by its continuations."""
    kind, first, close = control
    if kind in {"for", "while"}:
        return _shader_schedule_loop(scan, control, depth, events, pending)
    pending.append(("join", 0, 0))
    if kind == "if":
        pending.append(("else", depth, 0))
    events.extend((("expr", first, close), (kind, first, close)))
    _shader_schedule_body(events, pending, depth)
    return True


def _shader_schedule_loop(
    scan: tuple[str, bool],
    control: tuple[str, int, int],
    depth: int,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> bool:
    """Place the initializer outside the back edge and scope each condition evaluation."""
    masked, proof_safe = scan
    kind, first, close = control
    test_end = close
    update = ("update", close, close)
    if kind == "for":
        clauses = list(_top_level_separators(masked, first, close, ";"))
        if len(clauses) != 2:
            return False
        init_end, test_end = clauses
        events.extend((("enter", 0, 0), ("expr", first, init_end)))
        pending.append(("exit", 0, 0))
        first = init_end + 1
        update = ("update", test_end + 1, close)
    events.extend((("loop", 0, 0), ("enter", 0, 0), ("expr", first, test_end)))
    test = "test"
    if proof_safe:
        condition = masked[first:test_end].strip()
        if condition in {"", "true"}:
            test = "always"
        elif condition == "false":
            test = "never"
    events.append((test, 0, 0))
    pending.extend((("join", 0, 0), ("repeat", 0, 0), ("exit", 0, 0), update))
    _shader_schedule_body(events, pending, depth)
    return True


def _shader_schedule_statement(
    scan: tuple[str, bool],
    span: tuple[int, int],
    depth: int,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> int:
    """Consume a statement prefix and schedule any nested statements."""
    masked, _ = scan
    start, boundary = span
    if masked[start] == "{":
        events.append(("enter", start, start + 1))
        pending.append(("block", depth + 1, 0))
        return start + 1
    if _whole_word_at(masked, start, "do"):
        events.append(("do", 0, 0))
        pending.extend((("join", 0, 0), ("do_tail", 0, 0)))
        _shader_schedule_body(events, pending, depth)
        return start + 2
    label = _shader_label(masked, start, boundary)
    if label is not None:
        events.append(label)
        pending.append(("label_body", depth, 0))
        return label[2]
    control = _shader_control(masked, start, boundary)
    if control is not None and _shader_schedule_control(scan, control, depth, events, pending):
        return control[2] + 1
    if masked[boundary - 1] == "{":
        # A function or interface header is not a local declaration.
        events.append(("header", start, boundary - 1))
        pending.append(("statement", depth + 1, 0))
        return boundary - 1
    if masked[boundary - 1] != "}":
        events.append(("expr", start, boundary))
    return boundary


def _shader_label(masked: str, start: int, boundary: int) -> _ShaderEvent | None:
    word = _IDENTIFIER.match(masked, start, boundary)
    if word is None or word[0] not in {"case", "default"}:
        return None
    ternaries = 0
    for position in _top_level_separators(masked, word.end(), boundary, "?:"):
        if masked[position] == "?":
            ternaries += 1
        elif ternaries:
            ternaries -= 1
        else:
            return word[0], start, position + 1
    return None


def _shader_do_tail(
    scan: tuple[str, bool], cursor: int, boundary: int, events: list[_ShaderEvent]
) -> int:
    masked, proof_safe = scan
    control = _shader_control(masked, cursor, boundary)
    if control is None or control[0] != "while":
        return cursor
    _, first, close = control
    semicolon = _skip_space(masked, close + 1, boundary)
    if semicolon == boundary or masked[semicolon] != ";":
        return cursor
    events.append(("do_test", first, close))
    condition = masked[first:close].strip() if proof_safe else ""
    kind = {"true": "do_repeat", "false": "do_exit"}.get(condition, "do_branch")
    events.append((kind, 0, 0))
    return semicolon + 1


def _shader_pp_events(
    masked: str, groups: list[tuple[list[int], int, bool]]
) -> list[_ShaderEvent] | None:
    """Scan conditional boundaries as zero-effect statements, not GLSL tokens."""
    markers: dict[int, _ShaderEvent] = {}
    for arms, end, empty in groups:
        for i, start in enumerate(arms):
            markers[start] = ("pp_open" if i == 0 else "pp_next", start, start + 1)
        markers[end] = ("pp_end", end, end + 1 + int(empty))
    if not markers:
        return None
    if len(markers) > _MAX_STATEMENTS:
        return None
    view = list(masked)
    for start in markers:
        view[start] = ";"
    scan = "".join(view)
    spans = statement_spans(scan, shader=True)
    if len(spans) > _MAX_STATEMENTS:
        return None
    events, complete = _shader_scan_events((scan, False), [end for _, end in spans], markers)
    if not complete or sum(kind.startswith("pp_") for kind, _, _ in events) != len(markers):
        return None
    return _shader_pp_balanced(events)


def _shader_pp_group_step(
    kind: str, context: tuple[int, int], groups: list[tuple[int, int]]
) -> bool:
    """Track a directive group and verify each arm boundary's context."""
    if kind == "pp_open":
        groups.append(context)
    elif not groups or groups[-1] != context:
        return False
    elif kind == "pp_end":
        groups.pop()
    return True


def _shader_pp_balanced(events: list[_ShaderEvent]) -> list[_ShaderEvent] | None:
    """Reject arms crossing lexical scopes or splitting a GLSL control construct."""
    scopes: list[int] = []
    controls: list[int] = []
    groups: list[tuple[int, int]] = []
    for index, (kind, _, _) in enumerate(events):
        if kind == "enter":
            scopes.append(index)
        elif kind == "exit":
            if not scopes:
                return None
            scopes.pop()
        elif kind in {"if", "switch", "loop", "do"}:
            controls.append(index)
        elif kind == "join":
            if not controls:
                return None
            controls.pop()
        elif kind.startswith("pp_"):
            context = (scopes[-1] if scopes else -1, controls[-1] if controls else -1)
            if not _shader_pp_group_step(kind, context, groups):
                return None
    return events if not groups and not scopes and not controls else None


def _shader_events(masked: str, *, proof_safe: bool = False) -> list[_ShaderEvent]:
    """Split shader statements into expression, lexical-scope and control events."""
    spans = statement_spans(masked, shader=True)
    if not spans:
        return []
    complete = len(spans) <= _MAX_STATEMENTS
    spans = spans[:_MAX_STATEMENTS]
    events, closed = _shader_scan_events((masked, proof_safe), [end for _, end in spans])
    return _counted_events(masked, events) if complete and closed and proof_safe else events


def _shader_scan_marker(
    marker: _ShaderEvent,
    continuation: _ShaderEvent,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> bool:
    """Emit a directive marker unless it splits a required statement or tail."""
    kind = continuation[0]
    if kind in {"statement", "do_tail"}:
        return False
    events.append(marker)
    # A label need not have a statement before a directive or '}'.
    if kind == "label_body":
        return bool(pending) and pending[-1][0] in {"root", "block"}
    pending.append(continuation)
    return True


def _shader_scan_control_tail(
    scan: tuple[str, bool],
    ends: list[int],
    tail: _ShaderEvent,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> int:
    """Resume an else probe or consume the trailing test of a do loop."""
    kind, first, cursor = tail
    if kind == "else":
        return _shader_schedule_else(scan[0], (cursor, ends[-1]), first, events, pending)
    return _shader_scan_do_tail(scan, cursor, ends, events)


def _shader_scan_next_statement(
    scan: tuple[str, bool],
    ends: list[int],
    step: tuple[_ShaderEvent, int],
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> int:
    """Schedule a bounded statement, retaining its enclosing continuation if needed."""
    continuation, cursor = step
    kind, first, _ = continuation
    if kind not in {"statement", "label_body"}:
        pending.append(continuation)
    boundary = ends[bisect_right(ends, cursor)]
    return _shader_schedule_statement(scan, (cursor, boundary), first, events, pending)


def _shader_scan_events(
    scan: tuple[str, bool], ends: list[int], markers: dict[int, _ShaderEvent] | None = None
) -> tuple[list[_ShaderEvent], bool]:
    """Consume bounded statements and report whether the event scan finished."""
    masked, _ = scan
    limit = ends[-1]
    complete = True
    events: list[_ShaderEvent] = []
    # Private continuations share the tuple shape but are never emitted.
    pending: list[_ShaderEvent] = [("root", 0, 0)]
    cursor = 0
    while pending:
        if len(events) >= 8 * _MAX_STATEMENTS:
            events.append(("stop", 0, 0))
            complete = False
            break
        continuation = pending.pop()
        kind, first, _ = continuation
        if kind not in {"root", "block", "statement", "label_body", "else", "do_tail"}:
            events.append(continuation)
            continue
        cursor = _skip_space(masked, cursor, limit)
        if kind != "else" and markers is not None and cursor in markers:
            if not _shader_scan_marker(markers[cursor], continuation, events, pending):
                return events, False
            cursor += 1
            continue
        if kind in {"else", "do_tail"}:
            cursor = _shader_scan_control_tail(scan, ends, (kind, first, cursor), events, pending)
            continue
        if kind == "block" and (cursor == limit or masked[cursor] == "}"):
            end = min(cursor + 1, limit)
            events.append(("exit", cursor, end))
            complete = complete and cursor < end
            cursor = end
            continue
        if cursor == limit:
            continue
        if first >= _SUBSCRIPT_DEPTH:
            events.append(("stop", 0, 0))
            complete = False
            break
        cursor = _shader_scan_next_statement(scan, ends, (continuation, cursor), events, pending)
    return events, complete


def _shader_scan_do_tail(
    scan: tuple[str, bool], cursor: int, ends: list[int], events: list[_ShaderEvent]
) -> int:
    """Consume a do-loop tail only when it starts inside the scan window."""
    if cursor >= ends[-1]:
        return cursor
    return _shader_do_tail(scan, cursor, ends[bisect_right(ends, cursor)], events)


def _shader_schedule_else(
    masked: str,
    bounds: tuple[int, int],
    depth: int,
    events: list[_ShaderEvent],
    pending: list[_ShaderEvent],
) -> int:
    """Consume an optional else arm and give it its own lexical scope."""
    cursor, limit = bounds
    if cursor >= limit or not _whole_word_at(masked, cursor, "else"):
        return cursor
    events.append(("alternate", 0, 0))
    _shader_schedule_body(events, pending, depth)
    return cursor + len("else")


_COUNTED_DECIMAL = r"(?:0|[1-9][0-9]{0,9})"
_COUNTED_INIT = re.compile(rf"int\s+([A-Za-z_]\w*)\s*=\s*({_COUNTED_DECIMAL})", re.ASCII)
_COUNTED_TEST = re.compile(rf"([A-Za-z_]\w*)\s*<\s*({_COUNTED_DECIMAL})", re.ASCII)
_COUNTED_NAME = r"[A-Za-z_]\w*"
_COUNTED_FLOAT = r"(?:[0-9]+\.[0-9]*|\.[0-9]+)"
_COUNTED_TYPE = r"(?:int|float|[iu]?vec[234])"
_COUNTED_ATOM = rf"(?:{_COUNTED_NAME}|{_COUNTED_DECIMAL}|{_COUNTED_FLOAT})"
_COUNTED_VALUE = re.compile(
    rf"(?:{_COUNTED_ATOM}|{_COUNTED_TYPE}\s*\(\s*{_COUNTED_ATOM}\s*\)"
    rf"|clamp\s*\(\s*{_COUNTED_NAME}\s*,\s*{_COUNTED_FLOAT}\s*,\s*{_COUNTED_FLOAT}\s*\)"
    rf"|imageLoad\s*\(\s*{_COUNTED_NAME}\s*,\s*ivec2\s*\(\s*{_COUNTED_DECIMAL}\s*\)\s*\))",
    re.ASCII,
)
_COUNTED_ASSIGN = re.compile(
    rf"(?:(?:{_COUNTED_TYPE})\s+)?{_COUNTED_NAME}\s*=\s*(.+)", re.ASCII | re.DOTALL
)
_COUNTED_CALL = re.compile(r"\b(clamp|imageLoad)\s*\(", re.ASCII)
_COUNTED_GLOBAL_TOKEN = re.compile(r"[{}]|\b(clamp|imageLoad)\s*(?=\()", re.ASCII)


def _counted_ambiguous_calls(masked: str) -> set[str]:
    """Treat file-scope call-shaped names as possible function declarations."""
    names: set[str] = set()
    depth = 0
    for token in _COUNTED_GLOBAL_TOKEN.finditer(masked):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
        elif depth == 0:
            # GLSL declares functions at file scope. Do not parse the return type
            # or try to distinguish prototypes from global initializer calls.
            names.add(token[1])
    return names


def _counted_assignment(text: str, counter: str) -> bool:
    """Accept only simple writes with RHS forms that cannot write through an argument."""
    if counter in _IDENTIFIER.findall(text):
        return False
    match = _COUNTED_ASSIGN.fullmatch(text)
    return match is not None and _COUNTED_VALUE.fullmatch(match[1]) is not None


def _counted_initializer(masked: str, events: list[_ShaderEvent], opening: int) -> str:
    """Read a header declaration or a physically adjacent standalone declaration."""
    _, start, end = events[opening - 1]
    init = masked[start:end].strip()
    if init or opening < 3:
        return init
    kind, start, previous_end = events[opening - 3]
    if kind != "expr" or not re.fullmatch(r"\s*for\s*\(\s*", masked[previous_end:end]):
        return ""
    return masked[start:previous_end].strip().removesuffix(";").rstrip()


def _counted_distance(init: str, test: str) -> tuple[str, int] | None:
    """Prove the arithmetic for the exact signed-int declaration and comparison."""
    declaration = _COUNTED_INIT.fullmatch(init)
    comparison = _COUNTED_TEST.fullmatch(test)
    if declaration is None or comparison is None or declaration[1] != comparison[1]:
        return None
    initial, bound = int(declaration[2]), int(comparison[2])
    count = max(0, bound - initial)
    if max(initial, bound) > 2**31 - 1 or count > 2:
        return None
    return declaration[1], count


def _counted_body(events: list[_ShaderEvent], opening: int) -> int | None:
    """Find the physical body close only for a complete straight-line braced loop."""
    prefix = [kind for kind, _, _ in events[opening - 2 : opening + 6]]
    if prefix != ["enter", "expr", "loop", "enter", "expr", "test", "enter", "enter"]:
        return None
    if events[opening + 5][1] == events[opening + 5][2]:
        return None
    close = opening + 6
    while close < len(events) and events[close][0] == "expr":
        close += 1
    suffix = [kind for kind, _, _ in events[close : close + 7]]
    if suffix != ["exit", "exit", "update", "exit", "repeat", "join", "exit"]:
        return None
    return close if events[close][1] < events[close][2] else None


def _counted_steps(body: list[str], update: str, counter: str) -> bool:
    """Require one unconditional standalone increment and whitelist all other writes."""
    if any(not statement.endswith(";") for statement in body):
        return False
    statements = [statement[:-1].rstrip() for statement in body]
    name = re.escape(counter)
    increment = re.compile(rf"(?:\+\+\s*{name}|{name}\s*\+\+)")
    if increment.fullmatch(update):
        return all(_counted_assignment(text, counter) for text in statements)
    if not statements or not increment.fullmatch(statements[-1]):
        return False
    if update and not _counted_assignment(update, counter):
        return False
    return all(_counted_assignment(text, counter) for text in statements[:-1])


def _counted_proof(
    masked: str,
    events: list[_ShaderEvent],
    opening: int,
    close: int,
    ambiguous_calls: set[str],
) -> int | None:
    """Return the exact small count only for whitelisted, unambiguous steps."""
    _, start, end = events[opening + 2]
    init = _counted_initializer(masked, events, opening)
    proof = _counted_distance(init, masked[start:end].strip())
    if proof is None:
        return None
    counter, count = proof
    body = [masked[start:end].strip() for _, start, end in events[opening + 6 : close]]
    _, start, end = events[close + 2]
    update = masked[start:end].strip()
    if ambiguous_calls and any(
        call[1] in ambiguous_calls
        for text in (*body, update)
        for call in _COUNTED_CALL.finditer(text)
    ):
        return None
    return count if _counted_steps(body, update, counter) else None


_GLSL_NEWLINE = re.compile(r"\r\n|[\r\n]")
_GLSL_LITERALS = re.compile(
    r"(?m:^[ \t]*\#[^\n]*)|//[^\n]*|/\*.*?\*/"
    r"""|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' """.rstrip(),
    re.S,
)


def _glsl_lexical_view(source: str) -> str:
    """Make every physical line end in LF in the lexer view, without shifting offsets."""
    return source.replace("\r\n", " \n").replace("\r", "\n")


def _glsl_blank(text: str) -> str:
    return re.sub(r"[^\r\n]", " ", text)


_GLSL_SPLICE = re.compile(r"\\(?:\r\n|[\r\n])")


def _shader_directive_view(source: str) -> tuple[str, list[int], list[int]]:
    """Splice physical lines before lexing; record how to restore source offsets."""
    pieces: list[str] = []
    positions: list[int] = []
    removed = [0]
    cursor = 0
    for splice in _GLSL_SPLICE.finditer(source):
        pieces.append(source[cursor : splice.start()])
        positions.append(splice.start() - removed[-1])
        removed.append(removed[-1] + len(splice[0]))
        cursor = splice.end()
    pieces.append(source[cursor:])
    return _glsl_lexical_view("".join(pieces)), positions, removed


def _shader_physical_span(
    start: int, end: int, positions: list[int], removed: list[int]
) -> tuple[int, int]:
    """Map a nonempty lexer match through its first and last surviving characters."""
    return (
        start + removed[bisect_right(positions, start)],
        end + removed[bisect_right(positions, end - 1)],
    )


def _shader_arm_activity(
    parent: bool | None, available: bool, possible: bool, truth: bool | None
) -> bool | None:
    """Classify a preprocessor arm as dead, live, or uncertain."""
    if parent is False or not possible or truth is False:
        return False
    if parent is True and available and truth is True:
        return True
    return None


def _shader_mask_arm(
    directive: tuple[str, str],
    active: bool | None,
    start: int,
    stack: list[tuple[bool | None, bool, bool, list[int]]],
) -> bool | None:
    """Record a conditional arm and return its activity, or leave activity unchanged."""
    name, argument = directive
    if name in {"if", "ifdef", "ifndef"}:
        parent, available, possible, arms = active, True, True, []
    elif name in {"elif", "else"} and stack:
        parent, available, possible, arms = stack.pop()
    else:
        return active
    truth = True if name == "else" else None
    if name in {"if", "elif"}:
        truth = {"0": False, "1": True}.get(argument)
    active = _shader_arm_activity(parent, available, possible, truth)
    if active is not False:
        arms.append(start)
    stack.append((parent, available and truth is False, possible and truth is not True, arms))
    return active


def _shader_mask(
    source: str, groups: list[tuple[list[int], int, bool]] | None = None
) -> tuple[str, list[int], list[int]]:
    """Blank dead arms and record uncertain spans and feasible arm boundaries."""
    # Each frame records parent activity, whether no earlier arm could or
    # must have matched, and the physical starts of feasible arms.
    stack: list[tuple[bool | None, bool, bool, list[int]]] = []
    active: bool | None = True
    pieces: list[str] = []
    uncertain_starts: list[int] = []
    uncertain_ends: list[int] = []
    cursor = 0
    view, positions, removed = _shader_directive_view(source)
    for match in _GLSL_LITERALS.finditer(view):
        start, end = _shader_physical_span(match.start(), match.end(), positions, removed)
        text = source[cursor:start]
        pieces.append(_glsl_blank(text) if active is False else text)
        if active is None and cursor < start:
            uncertain_starts.append(cursor)
            uncertain_ends.append(start)
        pieces.append(_glsl_blank(source[start:end]))
        cursor = end
        directive = re.match(r"[ \t]*#[ \t]*(\w+)\b(.*)", match[0], re.S)
        if directive is None:
            continue
        name, argument = directive[1], directive[2].strip()
        if name == "endif" and stack:
            active, _, empty, arms = stack.pop()
            if groups is not None and len(arms) + int(empty) > 1:
                groups.append((arms, start, empty))
            continue
        active = _shader_mask_arm((name, argument), active, start, stack)
    if stack and groups is not None:
        groups.clear()
    text = source[cursor:]
    pieces.append(_glsl_blank(text) if active is False else text)
    if active is None and text:
        uncertain_starts.append(cursor)
        uncertain_ends.append(len(source))
    return "".join(pieces), uncertain_starts, uncertain_ends


_COUNTED_VERSION = re.compile(
    r"[ \t]*#[ \t]*version[ \t]+450(?:[ \t]+(?:core|compatibility))?[ \t]*\r?"
)


def _shader_proof_safe(source: str) -> bool:
    """Reject raw source whose preprocessing could change loop proof tokens."""
    # GLSL splices lines before tokenization, including inside comments.
    # Check raw source before masking and leave all offsets untouched.
    if "\\\n" in source or "\\\r" in source:
        return False
    # Support desktop GLSL 450, optionally with core or compatibility, on a
    # single line without inline comments. Whitespace and comments may precede it.
    leading = True
    cursor = 0
    for match in _GLSL_LITERALS.finditer(_glsl_lexical_view(source)):
        if source[cursor : match.start()].strip():
            leading = False
        text = match[0]
        if text.lstrip(" \t").startswith("#"):
            if not leading or _COUNTED_VERSION.fullmatch(text) is None:
                return False
            leading = False
        elif not text.startswith(("//", "/*")):
            leading = False
        cursor = match.end()
    return True


def _counted_events(masked: str, events: list[_ShaderEvent]) -> list[_ShaderEvent]:
    """Expand proven loops within the event budget, retaining spans for load matching."""
    ambiguous_calls = _counted_ambiguous_calls(masked)
    expanded: list[_ShaderEvent] = []
    cursor = growth = 0
    for opening, (kind, _, _) in enumerate(events):
        if opening < cursor or kind != "loop":
            continue
        close = _counted_body(events, opening)
        if close is None:
            continue
        count = _counted_proof(masked, events, opening, close, ambiguous_calls)
        if count is None:
            continue
        # Charge every copied event beyond the first iteration, without credit
        # for removed events. The final scoped test is also charged.
        cost = max(0, count - 1) * (close + 4 - opening - 2) + 3
        if growth + cost > _MAX_COUNTED_EVENTS:
            continue
        growth += cost
        test = events[opening + 1 : opening + 3]
        # The copied update executes as an expression, not as a loop-frame edge.
        _, start, end = events[close + 2]
        iteration = (
            test
            + events[opening + 4 : close + 2]
            + [("expr", start, end)]
            + events[close + 3 : close + 4]
        )
        expanded.extend(events[cursor:opening])
        expanded.extend(iteration * count)
        expanded.extend((*test, ("exit", 0, 0)))
        cursor = close + 6
    expanded.extend(events[cursor:])
    return expanded


_SWITCH_INTEGER = re.compile(rf"({_COUNTED_DECIMAL})([uU]?)", re.ASCII)


def _switch_integer(text: str) -> tuple[int, bool] | None:
    """Prove a nonnegative decimal int or uint literal, optionally grouped."""
    text = text.strip()
    for _ in range(_TARGET_PARENS):
        if not (text.startswith("(") and text.endswith(")")):
            break
        text = text[1:-1].strip()
    match = _SWITCH_INTEGER.fullmatch(text)
    if match is None:
        return None
    value, unsigned = int(match[1]), bool(match[2])
    return (value, unsigned) if value < 2 ** (32 if unsigned else 31) else None


class _ShaderFrame:
    """Collect edges whose destination is not known until a control construct ends."""

    def __init__(self, kind: str, opening: int) -> None:
        self.kind = kind
        self.opening = opening
        self.branch = opening
        self.exit_only = False
        self.alternate: int | None = None
        self.breaks: list[int] = []
        self.continues: list[int] = []
        self.labels: list[int] = []
        self.default: int | None = None
        self.selector: tuple[int, bool] | None = None
        self.matching_case: int | None = None

    def switch_targets(self, end: int) -> tuple[int, ...]:
        """Choose an entry only when the selector and all labels were proven."""
        fallback = end if self.default is None else self.default
        if self.selector is not None:
            return (fallback if self.matching_case is None else self.matching_case,)
        return tuple(self.labels) + ((end,) if self.default is None else ())

    def finish(self, edges: list[tuple[int, ...]], end: int) -> None:
        """Connect the optional arm and all breaks to their destinations."""
        alternate = self.alternate
        if self.exit_only:
            edges[self.branch] = (end,)
        else:
            edges[self.branch] = (self.branch + 1, end if alternate is None else alternate + 1)
        if alternate is not None:
            edges[alternate] = (end,)
        for origin in self.breaks:
            edges[origin] = (end,)


def _shader_jump(
    word: str, index: int, frames: list[_ShaderFrame], edges: list[tuple[int, ...]]
) -> None:
    """Terminate an abrupt path and, if applicable, record its structured target."""
    if word not in {"return", "discard", "break", "continue"}:
        return
    edges[index] = ()
    if word == "break":
        for frame in reversed(frames):
            if frame.kind in {"loop", "do", "switch"}:
                frame.breaks.append(index)
                return
    if word == "continue":
        for frame in reversed(frames):
            if frame.kind in {"loop", "do"}:
                frame.continues.append(index)
                return


def _shader_finish_frame(frame: _ShaderFrame, edges: list[tuple[int, ...]], index: int) -> None:
    """Resolve a join, with only break edges exiting an always-true loop."""
    if frame.kind == "switch":
        edges[frame.opening] = frame.switch_targets(index)
    elif frame.kind == "loop" and frame.branch != frame.opening or frame.kind == "if":
        frame.finish(edges, index)
        return
    for origin in frame.breaks:
        edges[origin] = (index,)


def _shader_record_case(frame: _ShaderFrame, index: int, expression: str) -> None:
    """Track a unique constant case match, or invalidate selector pruning."""
    selector = frame.selector
    if selector is None:
        return
    value = _switch_integer(expression)
    if value is None or value[1] != selector[1]:
        frame.selector = None
    elif value == selector:
        if frame.matching_case is None:
            frame.matching_case = index
        else:
            frame.selector = None


def _shader_record_label(
    label: _ShaderEvent,
    index: int,
    frames: list[_ShaderFrame],
    masked: str,
    uncertain: tuple[list[int], list[int]] | None,
) -> None:
    """Attach a label to its switch and keep a bypass for an optional default."""
    kind, start, end = label
    optional = False
    if uncertain is not None:
        starts, ends = uncertain
        span = bisect_right(starts, end - 1) - 1
        optional = span >= 0 and ends[span] > start
    for frame in reversed(frames):
        if frame.kind != "switch":
            continue
        frame.labels.append(index)
        if optional:
            frame.selector = None
        elif kind == "default":
            if frame.default is not None or masked[start + len(kind) : end - 1].strip():
                frame.selector = None
            else:
                frame.default = index
        else:
            _shader_record_case(frame, index, masked[start + len(kind) : end - 1])
        return


def _shader_control_edge(
    kind: str,
    index: int,
    frames: list[_ShaderFrame],
    edges: list[tuple[int, ...]],
) -> None:
    """Resolve branches, loop back edges and pending abrupt transfers."""
    if kind in {"if", "switch", "loop", "do"}:
        frames.append(_ShaderFrame(kind, index))
    elif kind in {"do_test", "update"}:
        for origin in frames[-1].continues:
            edges[origin] = (index,)
    elif kind in {"do_repeat", "do_branch"}:
        back = frames[-1].opening + 1
        edges[index] = (back,) if kind == "do_repeat" else (back, index + 1)
    elif kind in {"test", "never"}:
        frames[-1].branch = index
        frames[-1].exit_only = kind == "never"
    # An "always" event keeps its fallthrough and leaves branch at opening.
    elif kind == "alternate":
        frames[-1].alternate = index
    elif kind == "repeat":
        edges[index] = (frames[-1].opening + 1,)
    elif kind == "join":
        _shader_finish_frame(frames.pop(), edges, index)


def _shader_pp_edge(
    event: _ShaderEvent, index: int, groups: list[list[int]], edges: list[tuple[int, ...]]
) -> None:
    """Choose one arm at entry; skip siblings at the end of each arm."""
    kind, start, end = event
    if kind == "pp_open":
        groups.append([index])
    elif kind == "pp_next":
        groups[-1].append(index)
    elif kind == "pp_end":
        opening, *siblings = groups.pop()
        entries = (opening + 1, *(sibling + 1 for sibling in siblings))
        edges[opening] = entries + ((index,) if end - start == 2 else ())
        for sibling in siblings:
            edges[sibling] = (index,)


class _ShaderFlow:
    """Store shader events, successor edges and lexical depths before each event."""

    @classmethod
    def from_source(cls, source: str) -> _ShaderFlow:
        proof_safe = _shader_proof_safe(source)
        groups: list[tuple[list[int], int, bool]] = []
        masked, starts, ends = _shader_mask(source, groups)
        events = _shader_pp_events(masked, groups)
        return cls(masked, proof_safe=proof_safe, uncertain=(starts, ends), pp_events=events)

    def __init__(
        self,
        masked: str,
        *,
        proof_safe: bool = False,
        uncertain: tuple[list[int], list[int]] | None = None,
        pp_events: list[_ShaderEvent] | None = None,
    ) -> None:
        self.masked = masked
        self.events = (
            pp_events if pp_events is not None else _shader_events(masked, proof_safe=proof_safe)
        )
        groups: list[list[int]] = []
        self.edges: list[tuple[int, ...]] = [(i + 1,) for i in range(len(self.events))]
        self.depths: list[int] = []
        frames: list[_ShaderFrame] = []
        depth = 0
        for index, (kind, start, end) in enumerate(self.events):
            self.depths.append(depth)
            depth += int(kind == "enter") - int(kind == "exit")
            if kind.startswith("pp_"):
                _shader_pp_edge((kind, start, end), index, groups, self.edges)
                continue
            _shader_control_edge(kind, index, frames, self.edges)
            if kind == "switch" and proof_safe:
                frames[-1].selector = _switch_integer(masked[start:end])
            elif kind in {"case", "default"}:
                _shader_record_label((kind, start, end), index, frames, masked, uncertain)
            if kind == "expr":
                word = _IDENTIFIER.match(masked, start, end)
                if word is not None:
                    _shader_jump(word[0], index, frames, self.edges)
            if kind in {"stop", "header"}:
                self.edges[index] = ()
        if uncertain is not None and pp_events is None:
            self._restore_uncertain_fallthrough(*uncertain)

    def _restore_uncertain_fallthrough(self, starts: list[int], ends: list[int]) -> None:
        """Keep fallthrough possible when preprocessing might remove a jump."""
        for index, (kind, start, end) in enumerate(self.events):
            if kind != "expr":
                continue
            span = bisect_right(starts, start) - 1
            if span < 0 or start >= ends[span]:
                continue
            word = _IDENTIFIER.match(self.masked, start, end)
            if (
                word is not None
                and word[0] in {"return", "discard", "break", "continue"}
                and index + 1 not in self.edges[index]
            ):
                self.edges[index] += (index + 1,)

    def reachable(self) -> set[int]:
        """Follow control edges from the source entry and independent header/body entries."""
        pending = [0]
        for index, (kind, _, _) in enumerate(self.events):
            if kind == "header":
                pending.extend((index, index + 1))
        seen: set[int] = set()
        while pending:
            index = pending.pop()
            if index >= len(self.events) or index in seen:
                continue
            seen.add(index)
            pending.extend(self.edges[index])
        return seen


def _shader_declaration(statement: str) -> re.Match[str] | None:
    """Recognize a simple declaration of a supported GLSL value type."""
    declaration = _GLSL_DECLARATION.match(statement)
    if declaration is not None and declaration[1] in _GLSL_CONSTRUCTORS:
        return declaration
    return None


def _visible_binding(
    masked: str, events: list[_ShaderEvent], index: int, name: str
) -> tuple[int, int]:
    """Return the binding width and the number of enclosing exits it survives."""
    closed = distance = 0
    for previous in range(index, -1, -1):
        kind, start, end = events[previous]
        if kind == "exit":
            closed += 1
        elif kind == "enter":
            if closed:
                closed -= 1
            else:
                distance += 1
        elif kind == "expr" and not closed:
            declaration = _shader_declaration(masked[start:end])
            if declaration is not None and declaration[2] == name:
                vector = _GLSL_VECTOR.fullmatch(declaration[1])
                return (int(vector[1]) if vector is not None else 0), distance
    # An unresolved name must not be followed into another top-level block.
    return 0, max(0, distance - 1)


_LaneState = tuple[int, int, int]


class _ShaderUse:
    """Transfer one load's provenance without merging lanes from different paths."""

    def __init__(self, name: str, pattern: re.Pattern[str], width: int, floor: int) -> None:
        self.name = name
        self.pattern = pattern
        self.width = width
        self.floor = floor

    def expression(self, text: str, depth: int, live: int) -> tuple[bool, int, int]:
        """Read the initializer in the old scope before installing a shadow."""
        shadow = -1
        declaration = _shader_declaration(text)
        if declaration is not None and declaration[2] == self.name:
            shadow = depth
            initializer = text[declaration.end() :].lstrip()
            text = initializer[1:] if initializer.startswith("=") else ""
        matched, live = _statement_sequence_use(text, self.name, self.pattern, self.width, live)
        return matched, live, shadow

    def successor(
        self, flow: _ShaderFlow, target: int, live: int, shadow: int
    ) -> _LaneState | None:
        """Unwind any scopes skipped by the edge before visiting its destination."""
        if target >= len(flow.events) or flow.depths[target] < self.floor:
            return None
        return target, live, shadow if shadow <= flow.depths[target] else -1


def _shader_enqueue_successors(
    flow: _ShaderFlow, use: _ShaderUse, state: _LaneState, queue: list[_LaneState]
) -> None:
    """Queue successors that remain within the load's scope."""
    index, live, shadow = state
    for target in flow.edges[index]:
        successor = use.successor(flow, target, live, shadow)
        if successor is not None:
            queue.append(successor)


def _shader_use_paths(masked: str, flow: _ShaderFlow, origin: int, use: _ShaderUse) -> bool:
    """Visit finite lane states in expression-distance order, up to the use window."""
    live = (1 << (use.width or 1)) - 1
    pending = [(target, live, -1) for target in flow.edges[origin]]
    seen: set[_LaneState] = set()
    for distance in range(_USE_WINDOW + 1):
        later: list[_LaneState] = []
        while pending:
            state = pending.pop()
            index, live, shadow = state
            if state in seen or index >= len(flow.events) or flow.depths[index] < use.floor:
                continue
            kind, start, end = flow.events[index]
            step = kind in {"expr", "update", "do_test"} and start < end
            if step and distance == _USE_WINDOW:
                continue
            seen.add(state)
            if step and shadow < 0:
                matched, live, shadow = use.expression(masked[start:end], flow.depths[index], live)
                if matched:
                    return True
            if live:
                queue = later if step else pending
                _shader_enqueue_successors(flow, use, (index, live, shadow), queue)
        if not later:
            break
        pending = later
    return False


def _use_normalized(
    masked: str, flow: _ShaderFlow, index: int, name: str, pattern: re.Pattern[str]
) -> bool:
    """Track the load's binding and surviving lanes on reachable control-flow edges."""
    width, lifetime = _visible_binding(masked, flow.events, index, name)
    use = _ShaderUse(name, pattern, width, flow.depths[index] - lifetime)
    return _shader_use_paths(masked, flow, index, use)


def _load_normalized(
    masked: str,
    flow: _ShaderFlow,
    load: tuple[int, int, int],
    pattern: re.Pattern[str],
    helpers: dict[tuple[str, int, int], bool],
) -> bool:
    """Return whether the pattern acts on a (event index, start, end) load result."""
    index, load_start, load_end = load
    kind, start, end = flow.events[index]
    statement = masked[start:end]
    load_start, load_end = unwrap_expression(statement, load_start, load_end)
    if pattern.search(normalization_focus(statement, load_start, load_end)):
        return True
    caller = _enclosing_call(statement, load_start, load_end)
    if caller is not None:
        if caller not in helpers:
            helpers[caller] = _helper_applies(masked, *caller, pattern)
        if helpers[caller]:
            return True
    name = _assigned_name(statement, load_start, load_end)
    if kind not in {"expr", "update", "do_test"} or name is None:
        return False
    return _use_normalized(masked, flow, index, name, pattern)


def shader_site(shader_path: str, source: str, kind: str) -> str | None:
    """Return the first shader file:line whose load result gets the same normalization kind."""
    checks = {
        "mask": MASK,
        "shift": SHIFT,
        "clip": CLIP,
        "clamp": CLAMP,
    }
    pattern = checks.get(kind)
    if pattern is None:
        return None
    flow = _ShaderFlow.from_source(source)
    masked = flow.masked
    reachable = flow.reachable()
    helpers: dict[tuple[str, int, int], bool] = {}
    first_offset: int | None = None
    for index, (event, start, end) in enumerate(flow.events):
        if index not in reachable or event not in {"expr", "header", "update", "do_test"}:
            continue
        if first_offset is not None and start >= first_offset:
            continue
        for load_start, load_end in shader_loads(masked[start:end]):
            if _load_normalized(masked, flow, (index, load_start, load_end), pattern, helpers):
                first_offset = start + load_start
                break
    if first_offset is None:
        return None
    line = 1 + sum(1 for _ in _GLSL_NEWLINE.finditer(source, 0, first_offset))
    return f"{shader_path}:{line}"


def first_shader_match(
    directory: str,
    head: str,
    shaders: list[str],
    kind: str,
    deadline: float,
) -> str | None:
    """Search sorted linked shaders and return the first matching normalization site."""
    for shader_path in sorted(shaders):
        source = git(
            directory,
            "show",
            f"{head}:{shader_path}",
            deadline=deadline,
            maximum=2 * 1024 * 1024,
            limit_name="shader source size",
        )
        site = shader_site(shader_path, source, kind)
        if site is not None:
            return site
    return None


def sweep(directory: str, base: str, head: str, deadline: float) -> str:
    """Render port-parity rows for CPU/Vulkan filter pairs touched by the diff."""
    names = diff_names(directory, base, head, deadline)
    pairs = collect_pairs(directory, head, names, deadline)
    touched_pairs = {stem: paths for stem, paths in pairs.items() if paths[2]}
    if not touched_pairs:
        return "\n".join(
            [
                "class: port-parity",
                f"head: {head}",
                "",
                TABLE,
                "| --- | --- | --- | --- |",
                "no hits",
                "",
            ]
        )
    lines = ["class: port-parity", f"head: {head}", "", TABLE, "| --- | --- | --- | --- |"]
    count = 0
    size = len(("\n".join(lines) + "\n").encode())
    for _stem, (cpu_path, vk_path, _touched) in touched_pairs.items():
        check_deadline(deadline)
        sources: dict[str, str] = {}
        read_sources(directory, head, {cpu_path, vk_path}, sources, deadline)
        if cpu_path not in sources or vk_path not in sources:
            continue
        shaders = linked_shaders(sources[vk_path])
        shader_key = tuple(sorted(shaders))
        match_cache: dict[tuple[tuple[str, ...], str], str | None] = {}
        for line_number, kind in cpu_sites(sources[cpu_path]):
            cache_key = (shader_key, kind)
            if cache_key not in match_cache:
                match_cache[cache_key] = first_shader_match(
                    directory, head, shaders, kind, deadline
                )
            site = match_cache[cache_key]
            shader_col = site if site is not None else "none"
            row = f"| {cpu_path}:{line_number} | {kind} | {shader_col} | TODO |"
            size += len((row + "\n").encode())
            check_limit("report size", size, MAX_REPORT_BYTES)
            lines.append(row)
            count += 1
    if not count:
        lines.append("no hits")
    check_deadline(deadline)
    report = "\n".join(lines) + "\n"
    check_limit("report size", len(report.encode()), MAX_REPORT_BYTES)
    return report
