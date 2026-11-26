#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Compare Vulkan feature gates in libavfilter/vf_*_vulkan.c against linked SPIR-V needs."""

from __future__ import annotations

import re
import subprocess  # nosec B404 - fixed tool argv from allow-list, bounded timeout.
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.variant_sweep import (  # noqa: E402
    MAX_REPORT_BYTES,
    REPORT_TABLES,
    SweepPrerequisiteError,
    check_deadline,
    check_limit,
    git,
    mask_literals,
    read_sources,
)

TABLE = REPORT_TABLES["vulkan-features"]
GLSLANG = Path("/usr/bin/glslangValidator")
SPIRV_DIS = Path("/usr/bin/spirv-dis")
SPIRV_VAL = Path("/usr/bin/spirv-val")
VK_XML = Path("/usr/share/vulkan/registry/vk.xml")
GLSLANG_ARGS = ("-V", "--target-env", "spirv1.6", "--glsl-version", "460", "-S", "comp")
MAX_VULKAN_FILES = 64
MAX_SHADERS = 64
MAX_TOOL_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTIC = 160
SHADER_SYMBOL = re.compile(r"\bff_(\w+)_comp_spv_data\b", re.ASCII)
FEATURE_READ = re.compile(r"(?:\.\s*|->\s*)([A-Za-z]\w*)", re.ASCII)
FEATURE_STRUCT_DECL = re.compile(
    r"\b(VkPhysicalDevice\w+)\s*(\*+\s*|\s+)(\w+)\s*(?=[,;=)])",
    re.ASCII,
)
VULKAN_C = re.compile(r"libavfilter/vf_.+_vulkan\.c\Z")
SHADER_PATH = re.compile(r"libavfilter/vulkan/.+\.comp\.glsl\Z")


class VulkanMapState:
    """Hold lazily loaded vk.xml maps for one process."""

    loaded = False
    allowlist: frozenset[str] = frozenset()
    capability_map: dict[str, CapabilityEnables] = {}
    feature_allowlist: frozenset[str] = frozenset()
    feature_struct_names: frozenset[str] = frozenset()
    derivable: frozenset[str] = frozenset()


MAP_STATE = VulkanMapState()


class VulkanFeatureSweepError(SweepPrerequisiteError):
    """Raised when Vulkan sweep prerequisites or shader compilation fail."""


class ShaderValidationError(VulkanFeatureSweepError):
    """Raised when spirv-val rejects a shader in both layout modes."""


class FeatureSite(NamedTuple):
    """Hold one feature gate read site in a Vulkan filter C file."""

    line: int
    feature: str


class FeatureScopeContext(NamedTuple):
    """Hold scoped declaration maps for resolving one feature read receiver."""

    bounds: list[tuple[int, int]]
    region_decls: list[list[tuple[int, str, str | None, int]]]
    file_decls: list[tuple[int, str, str | None, int]]
    member_types: dict[str, dict[str, tuple[str, bool]]]
    typedef_aliases: dict[str, str]


class ShaderNeeds(NamedTuple):
    """Hold derived shader feature requirements for one linked shader."""

    path: str
    features: set[str]
    evidence: dict[str, str]
    unvalidated: str = ""


class CapabilityEnables(NamedTuple):
    """Hold feature and non-feature enables for one SPIR-V capability."""

    features: frozenset[str]
    non_feature: bool


def feature_allowlist_from_xml(root: ET.Element) -> frozenset[str]:
    """Collect VkBool32 members from VkPhysicalDeviceFeatures and Features2 extensions."""
    allow: set[str] = {"scalarBlockLayout"}
    for struct in root.iter("type"):
        if struct.get("category") != "struct":
            continue
        name = struct.get("name", "")
        extends = struct.get("structextends", "")
        if name != "VkPhysicalDeviceFeatures" and "VkPhysicalDeviceFeatures2" not in extends:
            continue
        for member in struct.findall("member"):
            kind = member.find("type")
            label = member.find("name")
            if kind is not None and kind.text == "VkBool32" and label is not None and label.text:
                allow.add(label.text)
    return frozenset(allow)


def feature_struct_names_from_xml(root: ET.Element) -> frozenset[str]:
    """Collect Vk feature struct names that may hold VkPhysicalDeviceFeatures gates."""
    names: set[str] = {"VkPhysicalDeviceFeatures"}
    for struct in root.iter("type"):
        if struct.get("category") != "struct":
            continue
        name = struct.get("name", "")
        extends = struct.get("structextends", "")
        if name == "VkPhysicalDeviceFeatures":
            continue
        if "VkPhysicalDeviceFeatures2" in extends:
            names.add(name)
    return frozenset(names)


def derivable_features(cap_map: dict[str, CapabilityEnables]) -> frozenset[str]:
    """Return feature names derivable from SPIR-V capabilities, indexing, or scalar layout."""
    features: set[str] = {
        "scalarBlockLayout",
        "shaderStorageImageArrayDynamicIndexing",
        "shaderStorageImageArrayNonUniformIndexing",
    }
    for mapped in cap_map.values():
        features |= mapped.features
    return frozenset(features)


def load_maps(
    xml_path: Path,
) -> tuple[frozenset[str], dict[str, CapabilityEnables], frozenset[str], frozenset[str]]:
    """Build SPIR-V capability map and Vk feature allow-lists from vk.xml."""
    root = ET.parse(xml_path).getroot()
    allow: set[str] = set()
    cap_map: dict[str, CapabilityEnables] = {}
    for cap in root.iter("spirvcapability"):
        name = cap.get("name")
        if not name:
            continue
        features: set[str] = set()
        non_feature = False
        for enable in cap.findall("enable"):
            feature = enable.get("feature")
            if feature:
                features.add(feature)
                allow.add(feature)
            elif enable.get("version") or enable.get("extension") or enable.get("property"):
                non_feature = True
        if features or non_feature:
            cap_map[name] = CapabilityEnables(frozenset(features), non_feature)
    feature_allow = feature_allowlist_from_xml(root)
    struct_names = feature_struct_names_from_xml(root)
    return frozenset(allow), cap_map, feature_allow, struct_names


def ensure_maps() -> None:
    """Load vk.xml maps once on the first non-empty sweep scope."""
    if MAP_STATE.loaded:
        return
    if not VK_XML.is_file():
        raise VulkanFeatureSweepError(f"missing vk.xml: {VK_XML}")
    allowlist, capability_map, feature_allowlist, struct_names = load_maps(VK_XML)
    MAP_STATE.allowlist = allowlist
    MAP_STATE.capability_map = capability_map
    MAP_STATE.feature_allowlist = feature_allowlist
    MAP_STATE.feature_struct_names = struct_names
    MAP_STATE.derivable = derivable_features(capability_map)
    MAP_STATE.loaded = True


def require_tool(tool: str) -> None:
    """Refuse an absent allow-listed tool before launching it."""
    if not Path(tool).is_file():
        raise VulkanFeatureSweepError(f"missing tool: {tool}")


def run_tool(argv: list[str], deadline: float, maximum: int, label: str) -> str:
    """Run one allow-listed external tool with a bounded deadline and output size."""
    timeout = min(120, check_deadline(deadline))
    require_tool(argv[0])
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(  # nosec B603 - argv built from fixed tool paths only.
            argv,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            check=False,
        )
        check_deadline(deadline)
        if result.returncode:
            stderr.seek(0)
            detail = stderr.read(4096).decode("utf-8", errors="replace")
            raise VulkanFeatureSweepError(f"{label} failed: {detail.strip()}")
        stdout.seek(0, 2)
        size = stdout.tell()
        check_limit(label, size, maximum)
        stdout.seek(0)
        return stdout.read(maximum + 1).decode("utf-8", errors="replace")


def linked_shaders(c_source: str) -> list[str]:
    """Return head-commit shader paths referenced by ff_*_comp_spv_data symbols."""
    paths: list[str] = []
    seen: set[str] = set()
    for match in SHADER_SYMBOL.finditer(mask_literals(c_source)):
        path = f"libavfilter/vulkan/{match[1]}.comp.glsl"
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def diff_names(directory: str, base: str, head: str, deadline: float) -> set[str]:
    """Return in-tree libavfilter paths changed between base and head."""
    text = git(
        directory,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--name-only",
        "--diff-filter=d",
        base,
        head,
        "--",
        "libavfilter/",
        deadline=deadline,
    )
    return {line for line in text.splitlines() if line}


def shader_stem(path: str) -> str | None:
    """Return the ff_<stem>_comp_spv_data stem for one shader path."""
    name = Path(path).name
    if name.endswith(".comp.glsl"):
        return name[: -len(".comp.glsl")]
    return None


def owners_for_shaders(directory: str, head: str, shaders: set[str], deadline: float) -> set[str]:
    """Locate Vulkan C files that link changed shaders at head."""
    owners: set[str] = set()
    linked_by_path: dict[str, list[str]] = {}
    for shader in sorted(shaders):
        stem = shader_stem(shader)
        if stem is None:
            continue
        listing = git(
            directory,
            "grep",
            "-l",
            f"ff_{stem}_comp_spv_data",
            head,
            "--",
            "libavfilter/*_vulkan.c",
            deadline=deadline,
            missing_ok=True,
        )
        shader_path = f"libavfilter/vulkan/{stem}.comp.glsl"
        prefix = f"{head}:"
        for line in listing.splitlines():
            path = line[len(prefix) :] if line.startswith(prefix) else line
            if not VULKAN_C.fullmatch(path):
                continue
            if path not in linked_by_path:
                source = git(
                    directory,
                    "show",
                    f"{head}:{path}",
                    deadline=deadline,
                    maximum=MAX_TOOL_BYTES,
                    limit_name="source size",
                )
                linked_by_path[path] = linked_shaders(source)
            if shader_path in linked_by_path[path]:
                owners.add(path)
    return owners


def collect_targets(
    directory: str, head: str, names: set[str], deadline: float
) -> dict[str, list[str]]:
    """Map each in-scope Vulkan C file to linked shader paths at head."""
    vulkan = {path for path in names if VULKAN_C.fullmatch(path)}
    shaders = {path for path in names if SHADER_PATH.fullmatch(path)}
    vulkan |= owners_for_shaders(directory, head, shaders, deadline)
    check_limit("vulkan file count", len(vulkan), MAX_VULKAN_FILES)
    if not vulkan:
        return {}
    sources: dict[str, str] = {}
    read_sources(directory, head, vulkan, sources, deadline)
    targets = {path: linked_shaders(source) for path, source in sources.items()}
    check_limit("shader count", sum(len(items) for items in targets.values()), MAX_SHADERS)
    return targets


_IDENT_TAIL = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_PAREN_RECEIVER = re.compile(
    r"((?:\(\s*)+)([A-Za-z_]\w*)((?:\s*\))+)(?=\s*(?:\.|->))",
    re.ASCII,
)
PLAIN_ASSIGN_WINDOW = 256
WRAPPER_PRED_KEYWORDS = frozenset({"return", "else", "do", "case"})


def _non_ws_before(text: str, open_index: int, floor: int) -> int:
    """Return the index of the last non-whitespace character before open_index."""
    index = open_index - 1
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if index < floor:
            return -1
        if text[index] not in " \t\n\r":
            return index
        index -= 1
    return -1


def _identifier_ending_at(text: str, end_index: int, floor: int) -> str | None:
    """Return the identifier ending at end_index, or None when not an identifier tail."""
    if end_index < floor or text[end_index] not in _IDENT_TAIL:
        return None
    start = end_index
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if start < floor or text[start] not in _IDENT_TAIL:
            break
        start -= 1
    start += 1
    if start > end_index:
        return None
    return text[start : end_index + 1]


def _member_pred_ok(text: str, index: int) -> bool:
    """Return True when '(' at index is not opened by a call, subscript, or index expression."""
    if index <= 0:
        return True
    floor = max(0, index - PLAIN_ASSIGN_WINDOW)
    back = _non_ws_before(text, index, floor)
    if back < floor:
        return True
    previous = text[back]
    if previous in "])":
        return False
    if previous in _IDENT_TAIL:
        ident = _identifier_ending_at(text, back, floor)
        return ident is not None and ident in WRAPPER_PRED_KEYWORDS
    return True


def _skip_ws_back(text: str, index: int, floor: int) -> int:
    """Return the last index at or above floor that is not whitespace."""
    while index >= floor and text[index] in " \t\n\r":
        index -= 1
    return index


def _scan_ident_start(text: str, index: int, floor: int) -> int:
    """Return the index where the identifier ending at index begins."""
    while index >= floor and text[index] in _IDENT_TAIL:
        index -= 1
    return index + 1


def _scan_balanced_open(text: str, index: int, floor: int, open_ch: str, close_ch: str) -> int:
    """Return the index of open_ch balancing close_ch at index."""
    depth = 1
    index -= 1
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if index < floor:
            return floor
        ch = text[index]
        if ch == close_ch:
            depth += 1
        elif ch == open_ch:
            depth -= 1
            if depth == 0:
                return index
        index -= 1
    return floor


def _scan_primary_start(text: str, index: int, floor: int) -> int:
    """Return the start index of the primary expression ending at index."""
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if index < floor:
            return floor
        ch = text[index]
        if ch in _IDENT_TAIL:
            return _scan_ident_start(text, index, floor)
        if ch == ")":
            index = _scan_balanced_open(text, index, floor, "(", ")")
            continue
        if ch == "]":
            index = _scan_balanced_open(text, index, floor, "[", "]")
            continue
        if ch in "(*":
            return index
        return index
    return floor


def _extend_access_chain(text: str, token_start: int, floor: int) -> int:
    """Walk left across '->' and '.' to the first token of a member chain."""
    cursor = token_start
    for _ in range(32):
        back = _skip_ws_back(text, cursor - 1, floor)
        if back >= floor + 1 and text[back] == ">" and text[back - 1] == "-":
            back = _skip_ws_back(text, back - 2, floor)
            if back < floor:
                break
            cursor = _scan_primary_start(text, back, floor)
            token_start = cursor
            continue
        if back >= floor and text[back] == ".":
            back = _skip_ws_back(text, back - 1, floor)
            if back < floor:
                break
            cursor = _scan_primary_start(text, back, floor)
            token_start = cursor
            continue
        break
    return token_start


def access_expr_first_token_start(text: str, member_access_start: int) -> int:
    """Return the index of the first token left of '.' or '->' (identifier, '(' or '*')."""
    floor = max(0, member_access_start - PLAIN_ASSIGN_WINDOW)
    end = _skip_ws_back(text, member_access_start - 1, floor)
    if end < floor:
        return floor
    return _extend_access_chain(text, _scan_primary_start(text, end, floor), floor)


def matching_open_paren(text: str, close_index: int, lower_bound: int) -> int | None:
    """Return the index of '(' matching close_index when scanning back to lower_bound."""
    if close_index >= len(text) or text[close_index] != ")":
        return None
    depth = 1
    for index in range(close_index - 1, lower_bound - 1, -1):
        ch = text[index]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return index
    return None


def wrapper_paren_closes_write(
    text: str, close_index: int, member_end: int, member_access_start: int
) -> bool:
    """Return True when close_index ends a wrapper '(' enclosing the member access."""
    if member_end > close_index:
        return False
    open_index = matching_open_paren(text, close_index, 0)
    if open_index is None or open_index >= member_access_start:
        return False
    if not _member_pred_ok(text, open_index):
        return False
    expr_start = access_expr_first_token_start(text, member_access_start)
    after = open_index + 1
    limit = min(len(text), open_index + PLAIN_ASSIGN_WINDOW)
    while after < limit and text[after] in " \t\n\r":
        after += 1
    return after <= expr_start


def plain_assignment_after(text: str, member_end: int, member_access_start: int) -> bool:
    """Return True when text after member_end is optional ')' wrappers then plain '='."""
    position = member_end
    limit = min(len(text), member_end + PLAIN_ASSIGN_WINDOW)
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if position >= limit:
            return False
        while position < limit and text[position] in " \t\n\r":
            position += 1
        if position >= limit:
            return False
        ch = text[position]
        if ch == ")":
            if not wrapper_paren_closes_write(text, position, member_end, member_access_start):
                return False
            position += 1
            continue
        if ch != "=":
            return False
        return position + 1 >= len(text) or text[position + 1] != "="
    return False


MAX_MASK_BYTES = 1_048_576
STRUCT_TAG_DECL = re.compile(
    r"\bstruct\s+(\w+)\s*(\*+\s*|\s+)(\w+)\s*(?=[,;=)])",
    re.ASCII,
)
GENERIC_DECL = re.compile(
    r"\b(?!VkPhysicalDevice|struct|if|for|while|return|sizeof|switch)"
    r"([A-Za-z_]\w*)\s+(\*+\s*)?(\w+)\s*(?=[,;=)])",
    re.ASCII,
)
MEMBER_FIELD_DECL = re.compile(
    r"\b(?!if|for|while|return|sizeof|switch|struct|union)"
    r"([A-Za-z_]\w*)\s+(\*+\s*)?(\w+)\s*;",
    re.ASCII,
)
TYPEDEF_STRUCT_BODY = re.compile(r"\btypedef\s+struct\s+(\w+)\s*\{", re.ASCII)
TYPEDEF_ANON_STRUCT = re.compile(r"\btypedef\s+struct\s*\{", re.ASCII)
TYPEDEF_STRUCT_ALIAS = re.compile(
    r"\btypedef\s+(?:struct|union)\s+(\w+)\s+(\w+)\s*;",
    re.ASCII,
)
TYPEDEF_SIMPLE_ALIAS = re.compile(
    r"\btypedef\s+(?!(?:struct|union|enum)\b)(?:const\s+)?(\w+)\s+(\w+)\s*;",
    re.ASCII,
)


def c_top_level_region_bounds(masked: str) -> list[tuple[int, int]]:
    """Return half-open spans between brace-depth-0 terminators."""
    limit = min(len(masked), MAX_MASK_BYTES)
    bounds: list[tuple[int, int]] = []
    start = 0
    brace = 0
    for index in range(limit):
        ch = masked[index]
        if ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
            if brace == 0:
                bounds.append((start, index + 1))
                start = index + 1
        elif ch == ";" and brace == 0:
            bounds.append((start, index + 1))
            start = index + 1
    if start < limit:
        bounds.append((start, limit))
    if not bounds:
        bounds.append((0, limit))
    return bounds


def c_brace_paren_depth(masked: str, position: int) -> tuple[int, int]:
    """Return brace and parenthesis nesting depths just before position."""
    brace = 0
    paren = 0
    limit = min(position, len(masked), MAX_MASK_BYTES)
    for index in range(limit):
        ch = masked[index]
        if ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
    return brace, paren


def c_depths_before_positions(masked: str, positions: list[int]) -> dict[int, tuple[int, int]]:
    """Return brace and parenthesis depths just before each sorted position."""
    limit = min(len(masked), MAX_MASK_BYTES)
    next_pos = sorted(set(positions))
    depths: dict[int, tuple[int, int]] = {}
    if not next_pos:
        return depths
    brace = 0
    paren = 0
    pi = 0
    for index in range(limit + 1):
        for _ in range(32):
            if pi >= len(next_pos) or next_pos[pi] != index:
                break
            depths[next_pos[pi]] = (brace, paren)
            pi += 1
        if index >= limit:
            break
        ch = masked[index]
        if ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
    return depths


def c_brace_open_to_close(masked: str) -> dict[int, int]:
    """Map each opening brace index to its matching closing brace index."""
    limit = min(len(masked), MAX_MASK_BYTES)
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index in range(limit):
        ch = masked[index]
        if ch == "{":
            stack.append(index)
        elif ch == "}" and stack:
            pairs[stack.pop()] = index
    return pairs


def _scoped_decl_visibility_end(
    brace: int,
    region_end: int,
    text_end: int,
    brace_stack: list[int],
    pairs: dict[int, int],
) -> int:
    """Return the source offset where a scoped declaration stops being visible."""
    if brace == 0:
        return region_end
    if not brace_stack:
        return text_end
    close = pairs.get(brace_stack[-1])
    if close is None:
        return text_end
    return close


def _advance_brace_stack_to(
    masked: str, brace_stack: list[int], scan: int, position: int, limit: int
) -> int:
    """Update brace_stack for masked indices in [scan, position) and return position."""
    for index in range(scan, min(position, limit)):
        ch = masked[index]
        if ch == "{":
            brace_stack.append(index)
        elif ch == "}" and brace_stack:
            brace_stack.pop()
    return position


class _ScopedDeclSink(NamedTuple):
    """Hold mutable declaration maps while collecting scoped C bindings."""

    masked: str
    bounds: list[tuple[int, int]]
    pairs: dict[int, int]
    region_decls: list[list[tuple[int, str, str | None, int]]]
    file_decls: list[tuple[int, str, str | None, int]]
    brace_stack: list[int]


def _record_scoped_var_decl(
    sink: _ScopedDeclSink,
    position: int,
    name: str,
    kind: str | None,
    brace_paren: tuple[int, int],
) -> None:
    """Append one scoped declaration with its visibility end to the region maps."""
    brace, paren = brace_paren
    region = _region_index_for(sink.bounds, position)
    vis_end = _scoped_decl_visibility_end(
        brace, sink.bounds[region][1], len(sink.masked), sink.brace_stack, sink.pairs
    )
    sink.region_decls[region].append((position, name, kind, vis_end))
    if brace == 0 and paren == 0:
        sink.file_decls.append((position, name, kind, len(sink.masked)))


def _region_index_for(bounds: list[tuple[int, int]], position: int) -> int:
    """Return the region index containing position."""
    for index, (start, end) in enumerate(bounds):
        if start <= position < end:
            return index
    return max(0, len(bounds) - 1)


def _vk_decl_kind(struct: str, allowed: frozenset[str]) -> str | None:
    """Return an eligible Vk feature struct tag or None when the type is ineligible."""
    return struct if struct in allowed else None


def c_collect_scoped_var_decls(
    masked: str,
) -> tuple[
    list[tuple[int, int]],
    list[list[tuple[int, str, str | None, int]]],
    list[tuple[int, str, str | None, int]],
]:
    """Collect per-region and file-scope identifier declarations for feature reads."""
    allowed = MAP_STATE.feature_struct_names
    bounds = c_top_level_region_bounds(masked)
    region_decls: list[list[tuple[int, str, str | None, int]]] = [[] for _ in bounds]
    file_decls: list[tuple[int, str, str | None, int]] = []
    pairs = c_brace_open_to_close(masked)
    brace_stack: list[int] = []
    scan = 0
    limit = min(len(masked), MAX_MASK_BYTES)
    events: list[tuple[int, str, str | None]] = []
    for match in FEATURE_STRUCT_DECL.finditer(masked):
        events.append((match.start(3), match.group(3), _vk_decl_kind(match.group(1), allowed)))
    struct_vars = {match.start(3) for match in STRUCT_TAG_DECL.finditer(masked)}
    for match in STRUCT_TAG_DECL.finditer(masked):
        events.append((match.start(3), match.group(3), match.group(1)))
    for match in GENERIC_DECL.finditer(masked):
        if match.group(1) == "void":
            continue
        if match.start(3) in struct_vars:
            continue
        events.append((match.start(3), match.group(3), match.group(1)))
    for match in re.finditer(r"\}\s*(\w+)\s*;", masked):
        events.append((match.start(1), match.group(1), match.group(1)))
    events.sort(key=lambda item: item[0])
    depth_map = c_depths_before_positions(masked, [item[0] for item in events])
    sink = _ScopedDeclSink(masked, bounds, pairs, region_decls, file_decls, brace_stack)
    for position, name, kind in events:
        scan = _advance_brace_stack_to(masked, brace_stack, scan, position, limit)
        brace, paren = depth_map.get(position, (0, 0))
        _record_scoped_var_decl(sink, position, name, kind, (brace, paren))
    return bounds, region_decls, file_decls


def _struct_body_span(masked: str, open_brace: int) -> tuple[int, int] | None:
    """Return the half-open body span for a struct whose opening brace is at open_brace."""
    if open_brace >= len(masked) or masked[open_brace] != "{":
        return None
    depth = 1
    limit = min(len(masked), open_brace + MAX_MASK_BYTES)
    for index in range(open_brace + 1, limit):
        ch = masked[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_brace + 1, index
    return None


def _member_decl_types(body: str) -> dict[str, tuple[str, bool]]:
    """Collect member field names and type names from one struct body."""
    tag_members: dict[str, tuple[str, bool]] = {}
    for inner in FEATURE_STRUCT_DECL.finditer(body):
        is_ptr = "*" in inner.group(2)
        tag_members[inner.group(3)] = (inner.group(1), is_ptr)
    for inner in MEMBER_FIELD_DECL.finditer(body):
        field = inner.group(3)
        if field in tag_members:
            continue
        ptr = inner.group(2)
        is_ptr = ptr is not None and "*" in ptr
        tag_members[field] = (inner.group(1), is_ptr)
    return tag_members


def _typedef_alias_after_body(masked: str, body_end: int) -> str | None:
    """Return the typedef name after a struct body closes at body_end."""
    limit = min(len(masked), body_end + 64)
    tail = masked[body_end:limit]
    match = re.match(r"\}\s*(\w+)\s*;", tail)
    if match is None:
        return None
    return match.group(1)


def c_simple_typedef_aliases(masked: str) -> dict[str, str]:
    """Map typedef names to the single identifier they rename in masked source."""
    return {
        match.group(2): match.group(1)
        for match in TYPEDEF_SIMPLE_ALIAS.finditer(masked)
        if match.group(1) != match.group(2)
    }


def c_typedef_alias_map(masked: str) -> dict[str, str]:
    """Map typedef names to struct or union tags declared in masked source."""
    aliases: dict[str, str] = {}
    for match in TYPEDEF_STRUCT_ALIAS.finditer(masked):
        aliases[match.group(2)] = match.group(1)
    for match in TYPEDEF_STRUCT_BODY.finditer(masked):
        tag = match.group(1)
        span = _struct_body_span(masked, match.end() - 1)
        if span is None:
            continue
        alias = _typedef_alias_after_body(masked, span[1])
        if alias is not None and alias != tag:
            aliases[alias] = tag
        aliases[tag] = tag
    for match in TYPEDEF_ANON_STRUCT.finditer(masked):
        span = _struct_body_span(masked, match.end() - 1)
        if span is None:
            continue
        alias = _typedef_alias_after_body(masked, span[1])
        if alias is not None:
            aliases[alias] = alias
    for match in re.finditer(r"\b(?:struct|union)\s+(\w+)\s*\{", masked):
        aliases.setdefault(match.group(1), match.group(1))
    return {**c_simple_typedef_aliases(masked), **aliases}


def c_struct_member_types(masked: str) -> dict[str, dict[str, tuple[str, bool]]]:
    """Map struct tags and typedef names to member field type names."""
    members: dict[str, dict[str, tuple[str, bool]]] = {}

    def record(tag: str, span: tuple[int, int]) -> None:
        """Store member types for one struct body under tag and optional typedef alias."""
        body = masked[span[0] : span[1]]
        tag_members = _member_decl_types(body)
        members[tag] = tag_members
        alias = _typedef_alias_after_body(masked, span[1])
        if alias is not None:
            members[alias] = tag_members

    for match in re.finditer(r"\b(?:struct|union)\s+(\w+)\s*\{", masked):
        span = _struct_body_span(masked, match.end() - 1)
        if span is not None:
            record(match.group(1), span)
    for match in TYPEDEF_STRUCT_BODY.finditer(masked):
        span = _struct_body_span(masked, match.end() - 1)
        if span is not None:
            record(match.group(1), span)
    for match in TYPEDEF_ANON_STRUCT.finditer(masked):
        span = _struct_body_span(masked, match.end() - 1)
        if span is None:
            continue
        alias = _typedef_alias_after_body(masked, span[1])
        if alias is None:
            continue
        body = masked[span[0] : span[1]]
        members[alias] = _member_decl_types(body)
    return members


def _last_decl_before(
    declarations: list[tuple[int, str, str | None, int]], position: int, name: str
) -> tuple[int, str, str | None, int] | None:
    """Return the last same-name declaration still visible strictly before position."""
    found: tuple[int, str, str | None, int] | None = None
    for item in declarations:
        if item[0] >= position:
            break
        if item[1] != name:
            continue
        if item[3] <= position:
            continue
        found = item
    return found


def resolve_var_kind(
    position: int,
    name: str,
    bounds: list[tuple[int, int]],
    region_decls: list[list[tuple[int, str, str | None, int]]],
    file_decls: list[tuple[int, str, str | None, int]],
) -> tuple[bool, str | None]:
    """Return whether name is unknown at position and its resolved struct tag if known."""
    region = _region_index_for(bounds, position)
    local = _last_decl_before(region_decls[region], position, name)
    if local is not None:
        return False, local[2]
    file_hit = _last_decl_before(file_decls, position, name)
    if file_hit is not None:
        return False, file_hit[2]
    return True, None


def feature_read_receiver_root(masked: str, member_access_start: int) -> str | None:
    """Return the root identifier for the receiver of one feature member access."""
    token_start = access_expr_first_token_start(masked, member_access_start)
    limit = len(masked)
    if token_start < limit and masked[token_start] == "(":
        match = _PAREN_RECEIVER.match(masked, token_start, member_access_start + 2)
        if match is not None and match[1].count("(") == match[3].count(")"):
            return match[2]
        return None
    for index in range(token_start, limit):
        if masked[index] not in _IDENT_TAIL:
            end = index
            break
    else:
        end = limit
    if end == token_start:
        return None
    return masked[token_start:end]


def _align_chain_cursor(masked: str, start: int) -> int:
    """Advance start through whitespace to '.' or the '-' of an arrow."""
    limit = len(masked)
    index = start
    for _ in range(PLAIN_ASSIGN_WINDOW):
        if index >= limit:
            return start
        ch = masked[index]
        if ch in " \t\n\r":
            index += 1
            continue
        if ch in {".", "-"}:
            return index
        break
    return start


def _access_op_at(masked: str, cursor: int) -> str | None:
    """Return '.' or '>' for the member access operator at cursor."""
    limit = len(masked)
    index = cursor
    for _ in range(8):
        if index >= limit:
            return None
        if masked[index] in " \t\n\r":
            index += 1
            continue
        if masked[index] == ".":
            return "."
        if masked[index] == "-" and index + 1 < limit and masked[index + 1] == ">":
            return ">"
        break
    return None


def feature_receiver_member_chain(masked: str, member_access_start: int) -> list[str]:
    """Return member names between the access root and the feature."""
    root_start = access_expr_first_token_start(masked, member_access_start)
    names: list[str] = []
    floor = max(0, member_access_start - PLAIN_ASSIGN_WINDOW)
    anchor = _align_chain_cursor(masked, member_access_start)
    cursor = _skip_ws_back(masked, anchor - 1, floor)
    for _ in range(32):
        if cursor < floor or masked[cursor] not in _IDENT_TAIL:
            break
        end = cursor
        start = _scan_ident_start(masked, end, floor)
        if start <= root_start:
            break
        names.insert(0, masked[start : end + 1])
        prev = _skip_ws_back(masked, start - 1, floor)
        if prev >= floor and masked[prev] == ".":
            cursor = _skip_ws_back(masked, prev - 1, floor)
            continue
        if prev > floor + 1 and masked[prev] == ">" and masked[prev - 1] == "-":
            cursor = _skip_ws_back(masked, prev - 2, floor)
            continue
        break
    return names


def _eligible_from_kind(unknown: bool, kind: str | None) -> bool:
    """Return whether unknown or eligible Vk feature struct kind satisfies a read."""
    if unknown:
        return True
    return kind is not None and kind in MAP_STATE.feature_struct_names


def _resolve_type_alias(type_name: str, aliases: dict[str, str]) -> str:
    """Follow typedef aliases to a struct tag or typedef name."""
    current = type_name
    for _ in range(32):
        nxt = aliases.get(current, current)
        if nxt == current:
            return current
        current = nxt
    return current


def _other_vk_physical_type(type_name: str) -> bool:
    """Return True for ineligible VkPhysicalDevice struct type names."""
    return (
        type_name.startswith("VkPhysicalDevice") and type_name not in MAP_STATE.feature_struct_names
    )


def _final_receiver_type_eligible(final_type: str, scope: FeatureScopeContext) -> bool:
    """Return whether the chain end type may hold a Vk feature gate read."""
    resolved = _resolve_type_alias(final_type, scope.typedef_aliases)
    if resolved in MAP_STATE.feature_struct_names:
        return True
    if _other_vk_physical_type(resolved):
        return False
    return resolved not in scope.member_types


def _walk_member_type(parent: str, member: str, scope: FeatureScopeContext) -> str | None:
    """Return the next type name for one chain step, or None when unresolved."""
    resolved = _resolve_type_alias(parent, scope.typedef_aliases)
    table = scope.member_types.get(resolved)
    if table is None or member not in table:
        return None
    type_name, _ = table[member]
    return type_name


def _chained_receiver_eligible(
    scope: FeatureScopeContext,
    position: int,
    root: str,
    members: list[str],
) -> bool:
    """Return whether a member chain resolves to an eligible Vk feature struct."""
    unknown, kind = resolve_var_kind(
        position, root, scope.bounds, scope.region_decls, scope.file_decls
    )
    if unknown:
        return True
    if kind is None:
        return False
    current = _resolve_type_alias(kind, scope.typedef_aliases)
    for member in members:
        step = _walk_member_type(current, member, scope)
        if step is None:
            return True
        current = step
    return _final_receiver_type_eligible(current, scope)


def feature_read_from_eligible_struct(
    masked: str, match: re.Match[str], scope: FeatureScopeContext
) -> bool:
    """Return True when a feature member read uses an eligible Vk feature struct."""
    position = match.start()
    root = feature_read_receiver_root(masked, position)
    members = feature_receiver_member_chain(masked, position)
    if not members:
        if root is None:
            return True
        unknown, kind = resolve_var_kind(
            position, root, scope.bounds, scope.region_decls, scope.file_decls
        )
        if kind is not None:
            kind = _resolve_type_alias(kind, scope.typedef_aliases)
        return _eligible_from_kind(unknown, kind)
    if root is None:
        return True
    return _chained_receiver_eligible(scope, position, root, members)


def c_feature_reads(source: str) -> list[FeatureSite]:
    """Collect VkPhysicalDeviceFeatures gate reads from masked C source."""
    masked = mask_literals(source)
    bounds, region_decls, file_decls = c_collect_scoped_var_decls(masked)
    member_types = c_struct_member_types(masked)
    typedef_aliases = c_typedef_alias_map(masked)
    scope = FeatureScopeContext(bounds, region_decls, file_decls, member_types, typedef_aliases)
    sites: list[FeatureSite] = []
    for match in FEATURE_READ.finditer(masked):
        feature = match[1]
        if feature not in MAP_STATE.feature_allowlist:
            continue
        if not feature_read_from_eligible_struct(masked, match, scope):
            continue
        if plain_assignment_after(masked, match.end(), match.start()):
            continue
        line_number = masked.count("\n", 0, match.start()) + 1
        sites.append(FeatureSite(line_number, feature))
    return sites


def compile_shader(shader_text: str, work: Path, deadline: float) -> Path:
    """Compile one GLSL shader to SPIR-V in a temporary directory."""
    glsl = work / "shader.comp.glsl"
    spv = work / "shader.spv"
    glsl.write_text(shader_text, encoding="utf-8")
    argv = [str(GLSLANG), *GLSLANG_ARGS, "-o", str(spv), str(glsl)]
    run_tool(argv, deadline, MAX_TOOL_BYTES, "glslangValidator")
    if not spv.is_file():
        raise VulkanFeatureSweepError("glslangValidator produced no SPIR-V output")
    return spv


def spirv_capabilities(disasm: str) -> set[str]:
    """Parse OpCapability names from spirv-dis output."""
    return {match[1] for match in re.finditer(r"OpCapability (\w+)", disasm)}


def validation_diagnostic(result: subprocess.CompletedProcess[bytes]) -> str:
    """Return the first stderr line of a failed spirv-val run, bounded and table-safe."""
    text = result.stderr.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text[:4096].splitlines() if line.strip()]
    line = lines[0] if lines else f"exit status {result.returncode}"
    return line.replace("|", "/")[:MAX_DIAGNOSTIC]


def spirv_needs_scalar(spv: Path, deadline: float) -> bool:
    """Return whether spirv-val requires scalar-block-layout for this module."""
    require_tool(str(SPIRV_VAL))
    base = [str(SPIRV_VAL), "--target-env", "vulkan1.3", str(spv)]
    scalar = [*base, "--scalar-block-layout"]
    for argv in (base, scalar):
        timeout = min(120, check_deadline(deadline))
        result = subprocess.run(  # nosec B603 - fixed spirv-val argv, bounded sweep deadline.
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        check_deadline(deadline)
        if argv is base:
            default_rc = result.returncode
        else:
            if default_rc != 0 and result.returncode != 0:
                raise ShaderValidationError(validation_diagnostic(result))
            return default_rc != 0 and result.returncode == 0
    return False


def spirv_type_operands(disasm: str) -> dict[str, list[str]]:
    """Map SPIR-V result ids to opcode and operand tokens from disassembly text."""
    types: dict[str, list[str]] = {}
    for match in re.finditer(r"(%\w+) = (Op\w+)(.*)", disasm):
        tail = match[3].split()
        types[match[1]] = [match[2], *tail]
    return types


def spirv_array_element(type_id: str, types: dict[str, list[str]]) -> str | None:
    """Return the element type id for one SPIR-V array or runtime-array type."""
    entry = types.get(type_id)
    if entry is None:
        return None
    if entry[0] in ("OpTypeArray", "OpTypeRuntimeArray") and len(entry) > 1:
        return entry[1]
    return None


def spirv_storage_image_type(image_id: str, types: dict[str, list[str]]) -> bool:
    """Return whether one SPIR-V image type is a non-buffer storage image."""
    entry = types.get(image_id)
    if entry is None or entry[0] != "OpTypeImage" or len(entry) < 8:
        return False
    if entry[2] == "Buffer":
        return False
    return entry[6] == "2"


def storage_image_array_vars(disasm: str) -> set[str]:
    """Return UniformConstant variables that point at storage-image arrays."""
    types = spirv_type_operands(disasm)
    vars_found: set[str] = set()
    for match in re.finditer(r"(%\w+) = OpVariable (%\w+) UniformConstant", disasm):
        ptr = types.get(match[2])
        if ptr is None or ptr[0] != "OpTypePointer" or len(ptr) < 3:
            continue
        if ptr[1] != "UniformConstant":
            continue
        element = spirv_array_element(ptr[2], types)
        if element is not None and spirv_storage_image_type(element, types):
            vars_found.add(match[1])
    return vars_found


def spirv_pointer_loads(disasm: str) -> dict[str, set[str]]:
    """Map SPIR-V pointer operand ids to every OpLoad result id."""
    loads: dict[str, set[str]] = {}
    for match in re.finditer(r"(%\w+) = OpLoad \S+ (%\w+)", disasm):
        loads.setdefault(match[2], set()).add(match[1])
    return loads


def spirv_object_copies(disasm: str) -> dict[str, set[str]]:
    """Map SPIR-V OpCopyObject source ids to every copy result id."""
    copies: dict[str, set[str]] = {}
    for match in re.finditer(r"(%\w+) = OpCopyObject \S+ (%\w+)", disasm):
        copies.setdefault(match[2], set()).add(match[1])
    return copies


def storage_index_nonuniform(
    chain_id: str,
    index: str,
    base: str,
    maps: tuple[set[str], dict[str, set[str]], dict[str, set[str]]],
) -> bool:
    """Return whether one storage-image access is non-uniform via index, base, or image operand."""
    nonuniform_ids, loads, copies = maps
    if index in nonuniform_ids or base in nonuniform_ids:
        return True
    if chain_id in nonuniform_ids:
        return True
    load_ids = loads.get(chain_id)
    if not load_ids:
        return False
    for load_id in load_ids:
        if load_id in nonuniform_ids:
            return True
        copy_ids = copies.get(load_id)
        if not copy_ids:
            continue
        for copy_id in copy_ids:
            if copy_id in nonuniform_ids:
                return True
    return False


def dynamic_storage_index(disasm: str) -> tuple[bool, bool]:
    """Detect dynamic and non-uniform storage-image array indexing in SPIR-V text."""
    assignments = {match[1]: match[2] for match in re.finditer(r"(%\w+) = (Op\w+)", disasm)}
    constants = {name for name, op in assignments.items() if op == "OpConstant"}
    for match in re.finditer(r"(%\w+) = OpCopyObject \S+ (%\w+)", disasm):
        if match[2].startswith("%int_") or match[2] in constants:
            constants.add(match[1])
    nonuniform_ids = {match[1] for match in re.finditer(r"OpDecorate (%\w+) NonUniform", disasm)}
    array_vars = storage_image_array_vars(disasm)
    loads = spirv_pointer_loads(disasm)
    copies = spirv_object_copies(disasm)
    index_maps: tuple[set[str], dict[str, set[str]], dict[str, set[str]]] = (
        nonuniform_ids,
        loads,
        copies,
    )
    dynamic = False
    nonuniform = False
    for line in disasm.splitlines():
        chain = re.search(r"(%\w+) = OpAccessChain \S+ (%\w+)(?: (%\w+))?", line)
        if chain is None:
            continue
        chain_id = chain[1]
        base = chain[2]
        index = chain[3]
        if index is None or base not in array_vars:
            continue
        if storage_index_nonuniform(chain_id, index, base, index_maps):
            nonuniform = True
            continue
        if index not in constants and not index.startswith("%int_"):
            dynamic = True
    return dynamic, nonuniform


def capability_need_key(enables: CapabilityEnables) -> str | None:
    """Return one shader need key for a SPIR-V capability enable set, or None."""
    if not enables.features:
        return None
    if len(enables.features) == 1 and not enables.non_feature:
        return next(iter(enables.features))
    suffix = ",non-feature" if enables.non_feature else ""
    return "any-of:" + ",".join(sorted(enables.features)) + suffix


def shader_requirements(
    directory: str, head: str, shader_path: str, work: Path, deadline: float
) -> ShaderNeeds:
    """Derive required Vk features for one linked shader at head."""
    source = git(
        directory,
        "show",
        f"{head}:{shader_path}",
        deadline=deadline,
        maximum=MAX_TOOL_BYTES,
        limit_name="shader source size",
    )
    spv = compile_shader(source, work, deadline)
    disasm = run_tool([str(SPIRV_DIS), str(spv)], deadline, MAX_TOOL_BYTES, "spirv-dis")
    features: set[str] = set()
    evidence: dict[str, str] = {}
    for capability in spirv_capabilities(disasm):
        enables = MAP_STATE.capability_map.get(capability)
        if enables is None:
            continue
        need_key = capability_need_key(enables)
        if need_key is None:
            continue
        features.add(need_key)
        evidence.setdefault(need_key, f"capability:{capability}")
    dynamic, nonuniform = dynamic_storage_index(disasm)
    if dynamic:
        features.add("shaderStorageImageArrayDynamicIndexing")
        evidence.setdefault(
            "shaderStorageImageArrayDynamicIndexing",
            f"{shader_path}:dynamic storage-image index",
        )
    if nonuniform:
        features.add("shaderStorageImageArrayNonUniformIndexing")
        evidence.setdefault(
            "shaderStorageImageArrayNonUniformIndexing",
            f"{shader_path}:NonUniform storage-image index",
        )
    unvalidated = ""
    try:
        if spirv_needs_scalar(spv, deadline):
            features.add("scalarBlockLayout")
            evidence.setdefault("scalarBlockLayout", f"{shader_path}:spirv-val scalar layout")
    except ShaderValidationError as error:
        unvalidated = str(error)
    return ShaderNeeds(shader_path, features, evidence, unvalidated)


def anyof_members(group_key: str) -> frozenset[str]:
    """Parse sorted feature names from one any-of capability group key."""
    body = group_key.removeprefix("any-of:")
    if body.endswith(",non-feature"):
        body = body[: -len(",non-feature")]
    return frozenset(part for part in body.split(",") if part)


def anyof_group_satisfied(feature: str, used: set[str], checked_names: set[str]) -> bool:
    """Return whether one checked feature satisfies a linked any-of capability group."""
    for group_key in used:
        if not group_key.startswith("any-of:"):
            continue
        members = anyof_members(group_key)
        if feature in members and members & checked_names:
            return True
    return False


def gate_row_anchor(
    text: str,
    anchor_by_feature: dict[str, str],
    feature: str,
    c_path: str,
) -> str:
    """Choose the file prefix for one shader-side mismatch row."""
    if "/" in text:
        return text.split(":", 1)[0]
    if feature in anchor_by_feature:
        return anchor_by_feature[feature]
    return c_path


def unanalyzed_rows(needs: list[ShaderNeeds]) -> list[tuple[str, str, str, str]]:
    """Emit one unanalyzed row per shader whose validation failed in both layouts."""
    text = "spirv-val rejected both layouts: "
    return [
        (f"{entry.path}:1", "scalarBlockLayout", text + entry.unvalidated, "unanalyzed")
        for entry in sorted(needs, key=lambda item: item.path)
        if entry.unvalidated
    ]


def compare_gates(
    c_path: str,
    checked: list[FeatureSite],
    needs: list[ShaderNeeds],
) -> list[tuple[str, str, str, str]]:
    """Emit mismatch rows for one Vulkan filter file."""
    used: set[str] = set()
    evidence_by_feature: dict[str, str] = {}
    anchor_by_feature: dict[str, str] = {}
    for entry in needs:
        used |= entry.features
        for feature in entry.features:
            anchor_by_feature.setdefault(feature, entry.path)
        for feature, text in entry.evidence.items():
            evidence_by_feature.setdefault(feature, text)
    rows: list[tuple[str, str, str, str]] = []
    checked_names = {site.feature for site in checked}
    fully_analyzed = not any(entry.unvalidated for entry in needs)
    for site in checked:
        if site.feature not in MAP_STATE.derivable:
            rows.append((f"{c_path}:{site.line}", site.feature, "n/a", "unmapped"))
        elif (
            fully_analyzed
            and site.feature not in used
            and not anyof_group_satisfied(site.feature, used, checked_names)
        ):
            rows.append((f"{c_path}:{site.line}", site.feature, "none", "required-unused"))
    for feature in sorted(used - checked_names):
        if feature.startswith("any-of:") and anyof_members(feature) & checked_names:
            continue
        direction = "ambiguous" if feature.startswith("any-of:") else "used-unchecked"
        text = evidence_by_feature.get(feature, "shader")
        anchor = gate_row_anchor(text, anchor_by_feature, feature, c_path)
        rows.append((f"{anchor}:1", feature, text, direction))
    rows.extend(unanalyzed_rows(needs))
    return rows


def sweep(directory: str, base: str, head: str, deadline: float) -> str:
    """Render vulkan-features rows for touched Vulkan filters and linked shaders."""
    names = diff_names(directory, base, head, deadline)
    vulkan = {path for path in names if VULKAN_C.fullmatch(path)}
    shaders = {path for path in names if SHADER_PATH.fullmatch(path)}
    if not vulkan and not shaders:
        return "\n".join(
            [
                "class: vulkan-features",
                f"head: {head}",
                "",
                TABLE,
                "| --- | --- | --- | --- | --- |",
                "no hits",
                "",
            ]
        )
    ensure_maps()
    targets = collect_targets(directory, head, names, deadline)
    lines = [
        "class: vulkan-features",
        f"head: {head}",
        "",
        TABLE,
        "| --- | --- | --- | --- | --- |",
    ]
    count = 0
    size = len(("\n".join(lines) + "\n").encode())
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        for c_path in sorted(targets):
            check_deadline(deadline)
            c_source = git(
                directory,
                "show",
                f"{head}:{c_path}",
                deadline=deadline,
                maximum=MAX_TOOL_BYTES,
                limit_name="source size",
            )
            checked = c_feature_reads(c_source)
            needs = [
                shader_requirements(directory, head, shader, work, deadline)
                for shader in targets[c_path]
            ]
            for file_line, feature, evidence, direction in compare_gates(c_path, checked, needs):
                row = f"| {file_line} | {feature} | {evidence} | {direction} | TODO |"
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
