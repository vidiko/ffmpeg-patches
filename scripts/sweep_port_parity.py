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
_OPERAND_OPS = 64


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
    while position < limit and text[position] in " \t\n\r":
        position += 1
    return position


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


def sample_operand_text(statement: str, read_start: int, read_end: int) -> str:
    """Extend one sample read through attached mask, shift, clip, or clamp operators."""
    limit = len(statement)
    depth = statement[:read_start].count("(") - statement[:read_start].count(")")
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
    return statement[read_start:position]


def normalization_focus(statement: str, read_start: int, read_end: int) -> str:
    """Return the statement slice searched for normalization on one sample read."""
    bounds = loop_header_bounds(statement)
    if bounds is not None and read_start <= bounds[1]:
        return statement[bounds[0] : bounds[1]]
    return sample_operand_text(statement, read_start, read_end)


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


def cpu_sites(source: str) -> list[tuple[int, str]]:
    """List sample-load normalization sites in one CPU filter source."""
    sites: list[tuple[int, str]] = []
    masked = mask_literals(source)
    for start, end in statement_spans(masked):
        statement = masked[start:end]
        read_match = SAMPLE_READ.search(statement)
        if read_match is None:
            continue
        focus = normalization_focus(statement, read_match.start(), read_match.end())
        kind = normalization_kind(focus)
        if kind is None:
            continue
        offset = start + read_match.start()
        line_number = masked.count("\n", 0, offset) + 1
        sites.append((line_number, kind))
    return sites


def shader_site(shader_path: str, source: str, kind: str) -> str | None:
    """Return the first shader file:line that applies the same normalization kind."""
    checks = {
        "mask": MASK,
        "shift": SHIFT,
        "clip": CLIP,
        "clamp": CLAMP,
    }
    pattern = checks.get(kind)
    if pattern is None:
        return None
    body = mask_literals(source).splitlines()
    for line_number in range(1, len(body) + 1):
        if not SHADER_LOAD.search(body[line_number - 1]):
            continue
        window = "\n".join(body[max(0, line_number - 4) : min(len(body), line_number + 6)])
        if pattern.search(window):
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
