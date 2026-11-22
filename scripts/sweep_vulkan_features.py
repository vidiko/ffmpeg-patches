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
SHADER_SYMBOL = re.compile(r"ff_(\w+)_comp_spv_data", re.ASCII)
FEATURE_READ = re.compile(r"(?:\.\s*|\s*->\s*)([A-Za-z]\w*)", re.ASCII)
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


class FeatureSite(NamedTuple):
    """Hold one feature gate read site in a Vulkan filter C file."""

    line: int
    feature: str


class ShaderNeeds(NamedTuple):
    """Hold derived shader feature requirements for one linked shader."""

    path: str
    features: set[str]
    evidence: dict[str, str]


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


def run_tool(argv: list[str], deadline: float, maximum: int, label: str) -> str:
    """Run one allow-listed external tool with a bounded deadline and output size."""
    timeout = min(120, check_deadline(deadline))
    if not Path(argv[0]).is_file():
        raise VulkanFeatureSweepError(f"missing tool: {argv[0]}")
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
PLAIN_ASSIGN_WINDOW = 256


def _member_pred_ok(text: str, index: int) -> bool:
    """Return True when '(' at index is not directly after an identifier, ']' or ')'."""
    if index <= 0:
        return True
    previous = text[index - 1]
    return previous not in _IDENT_TAIL and previous not in "])"


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


def c_feature_var_types(masked: str) -> dict[str, str | None]:
    """Map identifiers to eligible Vk feature struct types, or None when ineligible."""
    types: dict[str, str | None] = {}
    allowed = MAP_STATE.feature_struct_names
    for match in FEATURE_STRUCT_DECL.finditer(masked):
        struct = match[1]
        types[match[3]] = struct if struct in allowed else None
    for match in re.finditer(
        r"\b(?!VkPhysicalDevice|struct|if|for|while|return|sizeof|switch)"
        r"([A-Za-z_]\w*)\s+(\*+\s*|\s+)(\w+)\s*(?=[,;=)])",
        masked,
    ):
        struct = match[1]
        if struct == "void":
            continue
        var = match[3]
        if var not in types:
            types[var] = None
    for match in re.finditer(r"\}\s*(\w+)\s*;", masked):
        var = match[1]
        if var not in types:
            types[var] = None
    return types


def feature_read_receiver_root(masked: str, member_access_start: int) -> str | None:
    """Return the root identifier for the receiver of one feature member access."""
    token_start = access_expr_first_token_start(masked, member_access_start)
    limit = len(masked)
    end = token_start
    for index in range(token_start, limit):
        if masked[index] not in _IDENT_TAIL:
            end = index
            break
    else:
        end = limit
    if end == token_start:
        return None
    return masked[token_start:end]


def feature_read_from_eligible_struct(
    masked: str, match: re.Match[str], var_types: dict[str, str | None]
) -> bool:
    """Return True when a feature member read uses an eligible Vk feature struct."""
    root = feature_read_receiver_root(masked, match.start())
    if root is None:
        return True
    if root not in var_types:
        return True
    struct = var_types[root]
    return struct is not None and struct in MAP_STATE.feature_struct_names


def c_feature_reads(source: str) -> list[FeatureSite]:
    """Collect VkPhysicalDeviceFeatures gate reads from masked C source."""
    masked = mask_literals(source)
    var_types = c_feature_var_types(masked)
    sites: list[FeatureSite] = []
    for match in FEATURE_READ.finditer(masked):
        feature = match[1]
        if feature not in MAP_STATE.feature_allowlist:
            continue
        if not feature_read_from_eligible_struct(masked, match, var_types):
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


def spirv_needs_scalar(spv: Path, deadline: float) -> bool:
    """Return whether spirv-val requires scalar-block-layout for this module."""
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


def dynamic_storage_index(disasm: str) -> tuple[bool, bool]:
    """Detect dynamic and non-uniform storage-image array indexing in SPIR-V text."""
    assignments = {match[1]: match[2] for match in re.finditer(r"(%\w+) = (Op\w+)", disasm)}
    constants = {name for name, op in assignments.items() if op == "OpConstant"}
    for match in re.finditer(r"(%\w+) = OpCopyObject \S+ (%\w+)", disasm):
        if match[2].startswith("%int_") or match[2] in constants:
            constants.add(match[1])
    nonuniform_ids = {match[1] for match in re.finditer(r"OpDecorate (%\w+) NonUniform", disasm)}
    array_vars = storage_image_array_vars(disasm)
    dynamic = False
    nonuniform = False
    for line in disasm.splitlines():
        chain = re.search(r"(%\w+) = OpAccessChain \S+ (%\w+)(?: (%\w+))?", line)
        if chain is None:
            continue
        base = chain[2]
        index = chain[3]
        if index is None or base not in array_vars:
            continue
        indexed_nonuniform = index in nonuniform_ids or base in nonuniform_ids
        if indexed_nonuniform:
            nonuniform = True
        elif index not in constants and not index.startswith("%int_"):
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
    if spirv_needs_scalar(spv, deadline):
        features.add("scalarBlockLayout")
        evidence.setdefault("scalarBlockLayout", f"{shader_path}:spirv-val scalar layout")
    return ShaderNeeds(shader_path, features, evidence)


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
    for site in checked:
        if site.feature not in MAP_STATE.derivable:
            rows.append((f"{c_path}:{site.line}", site.feature, "n/a", "unmapped"))
        elif site.feature not in used and not anyof_group_satisfied(
            site.feature, used, checked_names
        ):
            rows.append((f"{c_path}:{site.line}", site.feature, "none", "required-unused"))
    for feature in sorted(used - checked_names):
        if feature.startswith("any-of:") and anyof_members(feature) & checked_names:
            continue
        direction = "ambiguous" if feature.startswith("any-of:") else "used-unchecked"
        text = evidence_by_feature.get(feature, "shader")
        anchor = gate_row_anchor(text, anchor_by_feature, feature, c_path)
        rows.append((f"{anchor}:1", feature, text, direction))
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
