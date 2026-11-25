#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Compare CPU sample normalization in vf_*.c with linked Vulkan shader loaders."""

from __future__ import annotations

import re
import sys
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
_WHITESPACE = " \t\n\r"
_MAX_LOADS = 64
_MAX_STATEMENTS = 4096
_USE_WINDOW = 32
_SUFFIX_STEPS = 8
_HELPER_DEFINITIONS = 8
_CONTROL_WORDS = frozenset({"if", "for", "while", "switch", "return", "else"})
_LOAD_SUFFIX = re.compile(r"\s*(?:\.[A-Za-z_]\w*|\[[^\]\[]*\])", re.ASCII)
_LOAD_ASSIGN = re.compile(r"\A\s*(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)\s*=\s*\Z", re.ASCII)
_UNWRAP_STEPS = 8
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


def statement_spans(masked: str) -> list[tuple[int, int]]:
    """Return statement spans ending at ;, { or } at parenthesis depth 0, without a blank tail."""
    spans: list[tuple[int, int]] = []
    start = 0
    paren_depth = 0
    index = 0
    limit = len(masked)
    while index < limit:
        ch = masked[index]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif paren_depth == 0 and ch in ";{}":
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


def sample_read_end(statement: str, read_start: int, read_end: int) -> int:
    """Extend one macro sample read through its balanced argument list."""
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


def _operand_scan_end(statement: str, read_end: int, depth: int) -> int:
    """Return the end offset after attached mask or shift operators following read_end."""
    limit = len(statement)
    position = read_end
    for _ in range(_OPERAND_OPS):
        position = _skip_space(statement, position, limit)
        if position >= limit or (statement[position] == "," and depth == 0):
            break
        if statement.startswith(">>", position):
            after = _skip_space(statement, position + 2, limit)
            position = _extend_shift_tail(statement, after, limit)
            continue
        if statement[position] == "&" and position + 1 < limit and statement[position + 1] != "&":
            position = _extend_mask_tail(
                statement, _skip_space(statement, position + 1, limit), limit
            )
            continue
        break
    return position


def attached_operator_text(statement: str, read_start: int, read_end: int) -> str:
    """Return operators attached after one sample read without its argument or macro text."""
    depth = statement[:read_start].count("(") - statement[:read_start].count(")")
    end = _operand_scan_end(statement, read_end, depth)
    return statement[read_end:end]


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
        tail_slice = statement[read_end:tail_end]
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


def statement_sites(masked: str, start: int, end: int) -> list[tuple[int, str]]:
    """Classify every sample read of one statement span with its own operators and line."""
    statement = masked[start:end]
    sites: list[tuple[int, str]] = []
    covered = 0
    for count, read_match in enumerate(SAMPLE_READ.finditer(statement)):
        read_start = read_match.start()
        if count >= _OPERAND_OPS:
            break
        if read_start < covered:
            continue
        read_end = sample_read_end(statement, read_start, read_match.end())
        covered = read_end
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


def _load_end(statement: str, call_end: int) -> int:
    """Extend a shader load call through swizzle, member and index suffixes."""
    position = call_end
    for _ in range(_SUFFIX_STEPS):
        match = _LOAD_SUFFIX.match(statement, position)
        if match is None:
            break
        position = match.end()
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


def _enclosing_call_name(statement: str, load_start: int) -> str | None:
    """Return the function name whose argument list holds load_start, or None."""
    depth = 0
    for index in range(load_start - 1, -1, -1):
        ch = statement[index]
        if ch == ")":
            depth += 1
        elif ch == "(" and depth > 0:
            depth -= 1
        elif ch == "(":
            name = _call_name_before(statement, index)
            if name is not None:
                return None if name in _CONTROL_WORDS else name
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


def _helper_applies(masked: str, name: str, pattern: re.Pattern[str]) -> bool:
    """Return whether a function with a body named name matches the pattern."""
    definition = re.compile(rf"\b[A-Za-z_]\w*\s+{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", re.ASCII)
    for count, match in enumerate(definition.finditer(masked)):
        if count >= _HELPER_DEFINITIONS:
            break
        body = _brace_body(masked, match.end() - 1)
        if body is not None and pattern.search(body):
            return True
    return False


def _assigned_name(statement: str, load_start: int, load_end: int) -> str | None:
    """Return the simple name that receives the whole load expression."""
    if statement[load_end:].strip(_WHITESPACE + ";"):
        return None
    match = _LOAD_ASSIGN.match(statement[:load_start])
    return None if match is None else match[1]


def _statement_use_matches(statement: str, name: str, pattern: re.Pattern[str]) -> bool:
    """Return whether a non-member use of name in the statement carries the pattern."""
    index = 0
    for _ in range(_OPERAND_OPS):
        hit = statement.find(name, index)
        if hit < 0:
            return False
        index = hit + 1
        if not _whole_word_at(statement, hit, name) or _follows_member_operator(statement, hit, 0):
            continue
        use_end = _load_end(statement, hit + len(name))
        use_start, use_end = unwrap_expression(statement, hit, use_end)
        if pattern.search(normalization_focus(statement, use_start, use_end)):
            return True
    return False


def _use_normalized(
    masked: str,
    spans: list[tuple[int, int]],
    index: int,
    name: str,
    pattern: re.Pattern[str],
) -> bool:
    """Return whether a later use of name in the same block carries the pattern."""
    depth = 0
    for follow in range(index + 1, min(len(spans), index + 1 + _USE_WINDOW)):
        statement = masked[spans[follow][0] : spans[follow][1]]
        if _statement_use_matches(statement, name, pattern):
            return True
        if statement.endswith("{"):
            depth += 1
        elif statement.endswith("}"):
            if depth == 0:
                return False
            depth -= 1
    return False


def _load_normalized(
    masked: str,
    spans: list[tuple[int, int]],
    load: tuple[int, int, int],
    pattern: re.Pattern[str],
    helpers: dict[str, bool],
) -> bool:
    """Return whether the pattern acts on a (statement index, start, end) load result."""
    index, load_start, load_end = load
    statement = masked[spans[index][0] : spans[index][1]]
    load_start, load_end = unwrap_expression(statement, load_start, load_end)
    if pattern.search(normalization_focus(statement, load_start, load_end)):
        return True
    caller = _enclosing_call_name(statement, load_start)
    if caller is not None:
        if caller not in helpers:
            helpers[caller] = _helper_applies(masked, caller, pattern)
        if helpers[caller]:
            return True
    name = _assigned_name(statement, load_start, load_end)
    return name is not None and _use_normalized(masked, spans, index, name, pattern)


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
    masked = mask_literals(source)
    spans = statement_spans(masked)
    helpers: dict[str, bool] = {}
    for index, (start, end) in enumerate(spans[:_MAX_STATEMENTS]):
        for load_start, load_end in shader_loads(masked[start:end]):
            if _load_normalized(masked, spans, (index, load_start, load_end), pattern, helpers):
                line_number = masked.count("\n", 0, start + load_start) + 1
                return f"{shader_path}:{line_number}"
    return None


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
