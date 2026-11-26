# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Exercise Vulkan feature and port-parity sweeps against synthetic Git fixtures."""

from __future__ import annotations

import importlib.util
import subprocess  # nosec B404 - fixed interpreter argv in temporary repositories.
import tempfile
import time
import unittest
import unittest.mock
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

from scripts import sweep_port_parity, sweep_vulkan_features, variant_sweep
from tests import test_variant_sweep as fixtures
from tests.helpers import isolated_git_environment
from tests.helpers import run_git as fixture_git

run_git = fixture_git
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "variant_sweep.py"
GLSLANG = Path("/usr/bin/glslangValidator")
SPIRV_DIS = Path("/usr/bin/spirv-dis")
SPIRV_VAL = Path("/usr/bin/spirv-val")
SYSTEM_VK_XML = Path("/usr/share/vulkan/registry/vk.xml")
_VULKAN_TOOLS_PRESENT = all(tool.is_file() for tool in (GLSLANG, SPIRV_DIS, SPIRV_VAL))
_SYSTEM_VKXML_PRESENT = SYSTEM_VK_XML.is_file()
SKIP_VULKAN = not _VULKAN_TOOLS_PRESENT or not _SYSTEM_VKXML_PRESENT


def vulkan_skip_reason() -> str:
    """Return the skip reason when the Vulkan toolchain or system vk.xml is absent."""
    reasons: list[str] = []
    if not _VULKAN_TOOLS_PRESENT:
        reasons.append("Vulkan toolchain binaries missing under /usr/bin")
    if not _SYSTEM_VKXML_PRESENT:
        reasons.append(f"system vk.xml missing: {SYSTEM_VK_XML}")
    return "; ".join(reasons)


SKIP_REASON = vulkan_skip_reason()

SIMPLE_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform readonly uimage2D img;
void main() { imageLoad(img, ivec2(0)); }
"""

MATCHED_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
#extension GL_EXT_scalar_block_layout : require
#extension GL_EXT_nonuniform_qualifier : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform readonly uimage2D imgs[];
layout(set = 0, binding = 1, scalar) buffer B {
    layout(offset = 0) uint a;
    layout(offset = 8) uvec3 b;
} blk;
void main() {
    imageLoad(imgs[nonuniformEXT(0)], ivec2(0));
    blk.b = uvec3(1u);
}
"""

DYNAMIC_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(constant_id = 0) const uint planes = 3;
layout(set = 0, binding = 0) uniform readonly uimage2D imgs[planes];
layout(push_constant) uniform PC { uint idx; } pc;
void main() { imageLoad(imgs[pc.idx], ivec2(0)); }
"""

SAMPLED_DYNAMIC_SHADER = """\
#version 460
#extension GL_EXT_nonuniform_qualifier : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform texture2D texs[4];
layout(set = 0, binding = 1) uniform sampler texsSmp;
layout(push_constant) uniform PC { uint idx; } pc;
void main() {
    texture(sampler2D(texs[nonuniformEXT(pc.idx)], texsSmp), vec2(0.0));
}
"""

R7_SAMPLED_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%uint_4 = OpConstant %uint 4",
        "%7 = OpTypeImage %float 2D 0 0 0 1 Unknown",
        "%_arr_7_uint_4 = OpTypeArray %7 %uint_4",
        "%_ptr_UniformConstant__arr_7_uint_4 = OpTypePointer UniformConstant %_arr_7_uint_4",
        "%texs = OpVariable %_ptr_UniformConstant__arr_7_uint_4 UniformConstant",
        "%_ptr_UniformConstant_7 = OpTypePointer UniformConstant %7",
        "%idx = OpLoad %uint %pc_idx",
        "%19 = OpAccessChain %_ptr_UniformConstant_7 %texs %idx",
    )
)

R7_STORAGE_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%uint_4 = OpConstant %uint 4",
        "%7 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%_arr_7_uint_4 = OpTypeArray %7 %uint_4",
        "%_ptr_UniformConstant__arr_7_uint_4 = OpTypePointer UniformConstant %_arr_7_uint_4",
        "%imgs = OpVariable %_ptr_UniformConstant__arr_7_uint_4 UniformConstant",
        "%_ptr_UniformConstant_7 = OpTypePointer UniformConstant %7",
        "%idx = OpLoad %uint %pc_idx",
        "%21 = OpAccessChain %_ptr_UniformConstant_7 %imgs %idx",
    )
)

R7_BUFFER_DISASM = "\n".join(
    (
        "%uint = OpTypeInt 32 0",
        "%uint_4 = OpConstant %uint 4",
        "%7 = OpTypeImage %uint Buffer 0 0 0 2 Rgba8",
        "%_arr_7_uint_4 = OpTypeArray %7 %uint_4",
        "%_ptr_UniformConstant__arr_7_uint_4 = OpTypePointer UniformConstant %_arr_7_uint_4",
        "%bufs = OpVariable %_ptr_UniformConstant__arr_7_uint_4 UniformConstant",
        "%_ptr_UniformConstant_7 = OpTypePointer UniformConstant %7",
        "%idx = OpLoad %uint %pc_idx",
        "%21 = OpAccessChain %_ptr_UniformConstant_7 %bufs %idx",
    )
)

LITERAL_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(constant_id = 0) const uint planes = 3;
layout(set = 0, binding = 0) uniform readonly uimage2D imgs[planes];
void main() { imageLoad(imgs[0], ivec2(0)); }
"""

RUNTIME_BUFFER_SHADER = """\
#version 460
#extension GL_EXT_scalar_block_layout : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0, scalar) buffer B { int t[]; } blk;
void main() { blk.t[0] = 1; }
"""

MASK_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform readonly uimage2D img;
uint load(uint raw) { return raw >> 4u; }
void main() { imageLoad(img, ivec2(0)); }
"""

MASKED_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform readonly uimage2D img;
uint load(uint raw) { return (raw & 0xFFF0u) >> 4u; }
void main() { load(imageLoad(img, ivec2(0)).x); }
"""

SECOND_MASKED_SHADER = """\
#version 460
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 1) in;
layout(set = 0, binding = 0) uniform readonly uimage2D img;
uint norm(uint raw) { return (raw & 0xFF00u) >> 8u; }
void main() { norm(imageLoad(img, ivec2(0)).x); }
"""


def cpu_line_source(line: str) -> str:
    """Return a CPU source whose only statement text sits on line 3."""
    return f"void f(void)\n{{\n    {line}\n}}\n"


def shader_line_source(*lines: str) -> str:
    """Return a shader source whose body statements start on line 3."""
    return "void main()\n{\n" + "".join(f"    {line}\n" for line in lines) + "}\n"


R6_T3_VKXML = """\
<registry>
  <spirvcapabilities>
    <spirvcapability name="TriAtomics">
      <enable feature="shaderBufferInt64Atomics"/>
      <enable feature="shaderSharedInt64Atomics"/>
      <enable feature="shaderImageInt64Atomics"/>
    </spirvcapability>
    <spirvcapability name="MixedStorage">
      <enable feature="shaderStorageImageReadWithoutFormat"/>
      <enable version="VK_VERSION_1_3"/>
    </spirvcapability>
    <spirvcapability name="SingleRead">
      <enable feature="shaderStorageImageWriteWithoutFormat"/>
    </spirvcapability>
    <spirvcapability name="DupDraw">
      <enable feature="drawIndirectFirstInstance" struct="VkPhysicalDeviceFeatures"/>
      <enable feature="drawIndirectFirstInstance" struct="VkPhysicalDeviceVulkan11Features"/>
    </spirvcapability>
    <spirvcapability name="VersionOnly">
      <enable version="VK_VERSION_1_2"/>
    </spirvcapability>
  </spirvcapabilities>
</registry>
"""


def r6_t3_capability_map(scratch: Path) -> dict[str, sweep_vulkan_features.CapabilityEnables]:
    """Load the r6 T3 vk.xml fixture into a capability map."""
    xml_path = scratch / "vk.xml"
    xml_path.write_text(R6_T3_VKXML, encoding="utf-8")
    _, cap_map, _, _ = sweep_vulkan_features.load_maps(xml_path)
    return cap_map


def install_r6_t3_derivable(cap_map: dict[str, sweep_vulkan_features.CapabilityEnables]) -> None:
    """Point MAP_STATE.derivable at features from the r6 T3 fixture map."""
    state = sweep_vulkan_features.MAP_STATE
    state.derivable = sweep_vulkan_features.derivable_features(cap_map)


def reset_vulkan_maps() -> None:
    """Clear lazy vk.xml map caches so patched registry paths apply."""
    state = sweep_vulkan_features.MAP_STATE
    state.loaded = False
    state.allowlist = frozenset()
    state.capability_map = {}
    state.feature_allowlist = frozenset()
    state.feature_struct_names = frozenset()
    state.derivable = frozenset()


def install_g3_registry(scratch: Path) -> Path:
    """Write a minimal vk.xml with one Vk feature member for parser-only tests."""
    xml = scratch / "vk-g3.xml"
    xml.write_text(
        "\n".join(
            (
                "<registry>",
                '  <types><type category="struct" name="VkPhysicalDeviceFeatures">',
                "    <member><type>VkBool32</type><name>shaderInt64</name></member>",
                "  </type></types>",
                "  <spirvcapabilities>",
                '    <spirvcapability name="Int64">',
                '      <enable feature="shaderInt64"/>',
                "    </spirvcapability>",
                "  </spirvcapabilities>",
                "</registry>",
            )
        ),
        encoding="utf-8",
    )
    return xml


def ensure_maps_fixture() -> None:
    """Load MAP_STATE from the minimal G3 vk.xml fixture."""
    reset_vulkan_maps()
    with tempfile.TemporaryDirectory() as scratch:
        xml = install_g3_registry(Path(scratch))
        allow, cap_map, feature_allow, struct_names = sweep_vulkan_features.load_maps(xml)
    state = sweep_vulkan_features.MAP_STATE
    state.loaded = True
    state.allowlist = allow
    state.capability_map = cap_map
    state.feature_allowlist = feature_allow
    state.feature_struct_names = struct_names
    state.derivable = sweep_vulkan_features.derivable_features(cap_map)


def bind_g3_maps_fixture(test: unittest.TestCase) -> None:
    """Reset MAP_STATE after the test and preload maps from the G3 vk.xml fixture."""
    test.addCleanup(reset_vulkan_maps)
    ensure_maps_fixture()


R7_NONUNIFORM_ONLY_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%uint_4 = OpConstant %uint 4",
        "%7 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%_arr_7_uint_4 = OpTypeArray %7 %uint_4",
        "%_ptr_UniformConstant__arr_7_uint_4 = OpTypePointer UniformConstant %_arr_7_uint_4",
        "%imgs = OpVariable %_ptr_UniformConstant__arr_7_uint_4 UniformConstant",
        "%_ptr_UniformConstant_7 = OpTypePointer UniformConstant %7",
        "%idx = OpLoad %uint %pc_idx",
        "OpDecorate %idx NonUniform",
        "%21 = OpAccessChain %_ptr_UniformConstant_7 %imgs %idx",
    )
)

R7_NONUNIFORM_RESOURCE_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%28 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%uint_4 = OpConstant %uint 4",
        "%_arr_28_uint_4 = OpTypeArray %28 %uint_4",
        "%_ptr_UniformConstant__arr_28_uint_4 = OpTypePointer UniformConstant %_arr_28_uint_4",
        "%src = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%_ptr_UniformConstant_28 = OpTypePointer UniformConstant %28",
        "%37 = OpTypeImage %float 2D 0 0 0 2 Unknown",
        "%dst = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%int = OpTypeInt 32 1",
        "%int_0 = OpConstant %int 0",
        "OpDecorate %38 NonUniform",
        "%35 = OpAccessChain %_ptr_UniformConstant_28 %src %33",
        "%36 = OpLoad %28 %35",
        "%38 = OpCopyObject %37 %36",
        "%43 = OpAccessChain %_ptr_UniformConstant_28 %dst %int_0",
    )
)

R7_NONUNIFORM_MIXED_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%28 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%uint_4 = OpConstant %uint 4",
        "%_arr_28_uint_4 = OpTypeArray %28 %uint_4",
        "%_ptr_UniformConstant__arr_28_uint_4 = OpTypePointer UniformConstant %_arr_28_uint_4",
        "%src = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%_ptr_UniformConstant_28 = OpTypePointer UniformConstant %28",
        "%37 = OpTypeImage %float 2D 0 0 0 2 Unknown",
        "%dst = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "OpDecorate %38 NonUniform",
        "%35 = OpAccessChain %_ptr_UniformConstant_28 %src %33",
        "%36 = OpLoad %28 %35",
        "%38 = OpCopyObject %37 %36",
        "%49 = OpAccessChain %_ptr_UniformConstant_28 %dst %48",
    )
)

CR16_NONUNIFORM_INDEX_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%28 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%uint_4 = OpConstant %uint 4",
        "%_arr_28_uint_4 = OpTypeArray %28 %uint_4",
        "%_ptr_UniformConstant__arr_28_uint_4 = OpTypePointer UniformConstant %_arr_28_uint_4",
        "%src = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%dst = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%_ptr_UniformConstant_28 = OpTypePointer UniformConstant %28",
        "OpDecorate %34 NonUniform",
        "OpDecorate %36 NonUniform",
        "OpDecorate %37 NonUniform",
        "%34 = OpCopyObject %uint %33",
        "%36 = OpAccessChain %_ptr_UniformConstant_28 %src %34",
        "%37 = OpLoad %28 %36",
        "%47 = OpLoad %uint %46",
        "%48 = OpAccessChain %_ptr_UniformConstant_28 %dst %47",
    )
)

CR16B_DOUBLE_LOAD_NONUNIFORM_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%28 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%uint_4 = OpConstant %uint 4",
        "%_arr_28_uint_4 = OpTypeArray %28 %uint_4",
        "%_ptr_UniformConstant__arr_28_uint_4 = OpTypePointer UniformConstant %_arr_28_uint_4",
        "%src = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%_ptr_UniformConstant_28 = OpTypePointer UniformConstant %28",
        "%37 = OpTypeImage %float 2D 0 0 0 2 Unknown",
        "%dst = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%int = OpTypeInt 32 1",
        "%int_0 = OpConstant %int 0",
        "OpDecorate %38 NonUniform",
        "%35 = OpAccessChain %_ptr_UniformConstant_28 %src %33",
        "%36 = OpLoad %28 %35",
        "%38 = OpCopyObject %37 %36",
        "%44 = OpLoad %28 %35",
        "%43 = OpAccessChain %_ptr_UniformConstant_28 %dst %int_0",
    )
)

CR16B_DOUBLE_COPY_NONUNIFORM_DISASM = "\n".join(
    (
        "%float = OpTypeFloat 32",
        "%uint = OpTypeInt 32 0",
        "%28 = OpTypeImage %float 2D 0 0 0 2 Rgba8",
        "%uint_4 = OpConstant %uint 4",
        "%_arr_28_uint_4 = OpTypeArray %28 %uint_4",
        "%_ptr_UniformConstant__arr_28_uint_4 = OpTypePointer UniformConstant %_arr_28_uint_4",
        "%src = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%_ptr_UniformConstant_28 = OpTypePointer UniformConstant %28",
        "%37 = OpTypeImage %float 2D 0 0 0 2 Unknown",
        "%dst = OpVariable %_ptr_UniformConstant__arr_28_uint_4 UniformConstant",
        "%int = OpTypeInt 32 1",
        "%int_0 = OpConstant %int 0",
        "OpDecorate %38 NonUniform",
        "%35 = OpAccessChain %_ptr_UniformConstant_28 %src %33",
        "%36 = OpLoad %28 %35",
        "%38 = OpCopyObject %37 %36",
        "%40 = OpCopyObject %37 %36",
        "%43 = OpAccessChain %_ptr_UniformConstant_28 %dst %int_0",
    )
)

NU_RES2_SHADER = """\
#version 460
#extension GL_EXT_nonuniform_qualifier : require
#extension GL_EXT_shader_image_load_formatted : require
layout(local_size_x = 8, local_size_y = 8) in;
layout(set = 0, binding = 0, rgba8) uniform readonly image2D src[4];
layout(set = 0, binding = 1, rgba8) uniform writeonly image2D dst[4];
void main() {
    uint i = gl_GlobalInvocationID.z;
    ivec2 pos = ivec2(gl_GlobalInvocationID.xy);
    vec4 v = imageLoad(nonuniformEXT(src[i]), pos);
    imageStore(dst[0], pos, v);
}
"""


def load_mutant_module(rel_path: str, old: str, new: str, tmp: Path) -> ModuleType:
    """Load a sweep module copy with exactly one matching mutation anchor."""
    root = Path(__file__).resolve().parents[1]
    source = (root / rel_path).read_text(encoding="utf-8")
    anchor_count = source.count(old)
    if anchor_count != 1:
        raise RuntimeError(f"{rel_path}: expected one mutation anchor, found {anchor_count}")
    mutant_path = tmp / "mutant.py"
    mutant_path.write_text(source.replace(old, new, 1), encoding="utf-8")
    name = f"mutant_{mutant_path.stem}_{id(mutant_path)}"
    spec = importlib.util.spec_from_file_location(name, mutant_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load mutant from {rel_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def section(report: str, name: str) -> str:
    """Return one named class section without neighboring class rows."""
    return report.split(f"class: {name}\n", 1)[1].split("class: ", 1)[0]


class VulkanSweepTest(unittest.TestCase):
    """Cover Vulkan feature gates and port-parity rows with synthetic fixtures."""

    def setUp(self) -> None:
        """Create an empty Git tree with libavfilter layout."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        run_git(self.repo, "init", "-q")
        (self.repo / "libavfilter" / "vulkan").mkdir(parents=True)
        (self.repo / "libavfilter" / "fix.c").write_text(
            "int fix(void) { return 0; }\n", encoding="utf-8"
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "base")
        self.base = run_git(self.repo, "rev-parse", "HEAD")
        self.output = self.repo / "sweep.md"
        self.deadline = time.monotonic() + 120

    def commit_filter(
        self,
        *,
        c_vulkan: str,
        shader_name: str,
        shader: str,
        cpu: str | None = None,
        cpu_name: str = "vf_test.c",
    ) -> str:
        """Commit one Vulkan filter, shader, and optional CPU pair."""
        (self.repo / "libavfilter" / "vf_test_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / shader_name).write_text(shader, encoding="utf-8")
        if cpu is not None:
            (self.repo / "libavfilter" / cpu_name).write_text(cpu, encoding="utf-8")
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        return run_git(self.repo, "rev-parse", "HEAD")

    def vk_report(self, head: str) -> str:
        """Run the vulkan-features sweep against one head revision."""
        return sweep_vulkan_features.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

    def parity_report(self, head: str) -> str:
        """Run the port-parity sweep against one head revision."""
        return sweep_port_parity.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_required_unused_features(self) -> None:
        """Case (a) lists required-unused rows when gates exceed shader needs."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceVulkan12Features *v12) {\n"
            "    if (!v12->runtimeDescriptorArray) return -1;\n"
            "    if (!v12->scalarBlockLayout) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )
        report = self.vk_report(head)
        self.assertIn("| runtimeDescriptorArray |", report)
        self.assertIn("| scalarBlockLayout |", report)
        self.assertEqual(report.count("| required-unused |"), 2)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_matched_gates_no_hits(self) -> None:
        """Case (b) emits no hits when C gates match linked shader needs."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceFeatures *feats, VkPhysicalDeviceVulkan12Features *v12) {\n"
            "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
            "    if (!v12->runtimeDescriptorArray) return -1;\n"
            "    if (!v12->scalarBlockLayout) return -1;\n"
            "    if (!v12->shaderStorageImageArrayNonUniformIndexing) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=MATCHED_SHADER,
        )
        self.assertIn("no hits", self.vk_report(head))

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_dynamic_index_used_unchecked(self) -> None:
        """Case (c) reports used-unchecked when dynamic indexing is unchecked."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceFeatures *feats) {\n"
            "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=DYNAMIC_SHADER,
        )
        report = self.vk_report(head)
        self.assertIn("| shaderStorageImageArrayDynamicIndexing |", report)
        self.assertIn("| used-unchecked |", report)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_literal_index_boundary(self) -> None:
        """Case (d) emits no hits for constant storage-image array indices."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceFeatures *feats) {\n"
            "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=LITERAL_SHADER,
        )
        self.assertIn("no hits", self.vk_report(head))

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_runtime_buffer_not_runtime_descriptor(self) -> None:
        """Case (e) treats runtime buffer members as not requiring runtimeDescriptorArray."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(void *v12) {\n"
            "    if (!((typeof(v12))v12)->runtimeDescriptorArray) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=RUNTIME_BUFFER_SHADER,
        )
        report = self.vk_report(head)
        self.assertIn("| runtimeDescriptorArray |", report)
        self.assertIn("| required-unused |", report)

    def test_empty_scope_skips_tools(self) -> None:
        """Case (f) returns no hits without calling external tools when scope is empty."""
        (self.repo / "libavfilter" / "fix.c").write_text(
            "int fix(void) { return 1; }\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/fix.c")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        with unittest.mock.patch("scripts.sweep_vulkan_features.run_tool") as run_tool:
            report = self.vk_report(head)
            run_tool.assert_not_called()
        self.assertIn("no hits", report)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_missing_glslang_raises(self) -> None:
        """Case (g) raises when scope is non-empty but glslangValidator is unavailable."""
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
            ),
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )
        with (
            unittest.mock.patch.object(
                sweep_vulkan_features,
                "GLSLANG",
                Path("/nonexistent/glslangValidator"),
            ),
            self.assertRaises(sweep_vulkan_features.VulkanFeatureSweepError),
        ):
            self.vk_report(head)

    def test_port_parity_missing_shader_mask(self) -> None:
        """Port-parity reports none when the CPU masks but the shader does not."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFFF0u; (void)v; }\n"
        c_vulkan = (
            "extern const unsigned char ff_test_comp_spv_data[];\nint f(void) { return 0; }\n"
        )
        head = self.commit_filter(
            c_vulkan=c_vulkan,
            shader_name="test.comp.glsl",
            shader=MASK_SHADER,
            cpu=cpu,
        )
        report = self.parity_report(head)
        self.assertIn("| mask | none |", report)

    def test_port_parity_shader_mask_site(self) -> None:
        """Port-parity names the shader line when the same mask is present."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFFF0u; (void)v; }\n"
        c_vulkan = "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
        head = self.commit_filter(
            c_vulkan=c_vulkan,
            shader_name="test.comp.glsl",
            shader=MASKED_SHADER,
            cpu=cpu,
        )
        report = self.parity_report(head)
        self.assertRegex(report, r"libavfilter/vulkan/test\.comp\.glsl:\d+")

    def test_cr21b_shader_mask_on_unrelated_value_reports_none(self) -> None:
        """Port-parity reports none when the only shader mask acts on an unrelated value."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFFF0u; (void)v; }\n"
        c_vulkan = "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
        shader = MASK_SHADER.replace(
            "void main() { imageLoad(img, ivec2(0)); }\n",
            "void main()\n{\n    uvec4 px = imageLoad(img, ivec2(0));\n"
            "    uint flags = u.bits & 0xFFu;\n}\n",
        ).replace("raw >> 4u", "raw")
        head = self.commit_filter(
            c_vulkan=c_vulkan,
            shader_name="test.comp.glsl",
            shader=shader,
            cpu=cpu,
        )
        self.assertIn("| mask | none |", self.parity_report(head))

    def test_port_parity_no_pair_in_diff(self) -> None:
        """Port-parity emits no hits when the diff does not touch a CPU/Vulkan pair."""
        (self.repo / "libavfilter" / "other.c").write_text(
            "int other(void){return 1;}\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/other.c")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        self.assertIn("no hits", self.parity_report(head))

    def test_t1_import_without_registry_empty_scope(self) -> None:
        """t1: modules import with missing vk.xml; empty scope prints no hits."""
        missing = Path("/nonexistent/vk.xml")
        reset_vulkan_maps()
        self.addCleanup(reset_vulkan_maps)
        with unittest.mock.patch.object(sweep_vulkan_features, "VK_XML", missing):
            (self.repo / "libavfilter" / "fix.c").write_text(
                "int fix(void){return 2;}\n", encoding="utf-8"
            )
            run_git(self.repo, "add", "libavfilter/fix.c")
            run_git(self.repo, "commit", "-qm", "head")
            head = run_git(self.repo, "rev-parse", "HEAD")
            deadline = time.monotonic() + 120
            self.assertIn(
                "no hits",
                sweep_vulkan_features.sweep(str(self.repo), self.base, head, deadline),
            )
            self.assertIn(
                "no hits",
                sweep_port_parity.sweep(str(self.repo), self.base, head, deadline),
            )

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_t1_missing_registry_nonempty_scope(self) -> None:
        """t1: a non-empty scope with missing vk.xml raises the named registry error."""
        missing = Path("/nonexistent/vk-registry-missing/vk.xml")
        reset_vulkan_maps()
        self.addCleanup(reset_vulkan_maps)
        with unittest.mock.patch.object(sweep_vulkan_features, "VK_XML", missing):
            head = self.commit_filter(
                c_vulkan=(
                    "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
                ),
                shader_name="test.comp.glsl",
                shader=SIMPLE_SHADER,
            )
            with self.assertRaisesRegex(
                sweep_vulkan_features.VulkanFeatureSweepError,
                f"missing vk.xml: {missing}",
            ):
                sweep_vulkan_features.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

    def test_t2_linked_worktree_leaves_git_clean(self) -> None:
        """t2: sweeps use TMPDIR scratch and leave a separate-git-dir worktree clean."""
        root = Path(self.directory.name)
        git_parent = root / "actual.git"
        work = root / "wt"
        work.mkdir()
        subprocess.run(  # nosec B603 B607 - fixed git init argv in an isolated fixture.
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "user.name=Dev",
                "-c",
                "user.email=dev@invalid",
                "init",
                "--separate-git-dir",
                str(git_parent),
                str(work),
            ],
            check=True,
            capture_output=True,
            timeout=60,
            env=isolated_git_environment(),
        )
        (work / "libavfilter" / "vulkan").mkdir(parents=True)
        (work / "libavfilter" / "fix.c").write_text("int fix(void){return 0;}\n", encoding="utf-8")
        run_git(work, "add", ".")
        run_git(work, "commit", "-qm", "base")
        base = run_git(work, "rev-parse", "HEAD")
        (work / "libavfilter" / "fix.c").write_text("int fix(void){return 1;}\n", encoding="utf-8")
        run_git(work, "add", "libavfilter/fix.c")
        run_git(work, "commit", "-qm", "head")
        head = run_git(work, "rev-parse", "HEAD")
        status_before = run_git(work, "status", "--short")
        self.assertEqual(status_before, "")
        sweep_vulkan_features.sweep(str(work), base, head, time.monotonic() + 120)
        sweep_port_parity.sweep(str(work), base, head, time.monotonic() + 120)
        self.assertEqual(run_git(work, "status", "--short"), "")
        self.assertTrue((work / ".git").is_file())

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_t3_non_feature_members_no_row(self) -> None:
        """t3: sampler, shader, and storage_buf reads produce no vulkan-features row."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "typedef struct { void *sampler; void *shader; void *storage_buf; } S;\n"
            "int gate(VkPhysicalDeviceFeatures *feats, S *s) {\n"
            "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
            "    if (!s->sampler || !s->shader || !s->storage_buf) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source, shader_name="test.comp.glsl", shader=SIMPLE_SHADER
        )
        self.assertIn("no hits", self.vk_report(head))

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_t3_unmapped_feature_struct_member(self) -> None:
        """t3: an un-derivable VkPhysicalDeviceFeatures member yields one unmapped row."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceFeatures *feats) {\n"
            "    if (!feats->robustBufferAccess) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source, shader_name="test.comp.glsl", shader=SIMPLE_SHADER
        )
        report = self.vk_report(head)
        self.assertIn("| robustBufferAccess |", report)
        self.assertIn("| unmapped |", report)
        self.assertEqual(report.count("| unmapped |"), 1)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_t4_shader_without_owner_no_hits(self) -> None:
        """t4: a changed shader with no owning Vulkan C file yields no hits in both sweeps."""
        (self.repo / "libavfilter" / "vulkan" / "orphan.comp.glsl").write_text(
            SIMPLE_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        self.assertIn("no hits", self.vk_report(head))
        self.assertIn("no hits", self.parity_report(head))

    def test_t5_pair_limit_before_slice(self) -> None:
        """t5: two touched filter pairs exceed MAX_PAIRS=1 and raise the named limit error."""
        for stem in ("one", "two"):
            (self.repo / "libavfilter" / f"vf_{stem}.c").write_text(
                f"void f_{stem}(void){{}}\n", encoding="utf-8"
            )
            (self.repo / "libavfilter" / f"vf_{stem}_vulkan.c").write_text(
                "int vk(void){return 0;}\n", encoding="utf-8"
            )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        with (
            unittest.mock.patch.object(sweep_port_parity, "MAX_PAIRS", 1),
            self.assertRaisesRegex(RuntimeError, "filter pair count"),
        ):
            sweep_port_parity.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

    def test_r6_t1_partial_pair_skips_missing_twin(self) -> None:
        """T1: a touched filter with only one CPU or Vulkan twin yields no hits and no error."""
        (self.repo / "libavfilter" / "vf_vkonly_vulkan.c").write_text(
            "int vk(void){return 0;}\n", encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vf_cpuonly.c").write_text(
            "void cpu(void){}\n", encoding="utf-8"
        )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        self.assertIn("no hits", self.parity_report(head))

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_r6_t2_dot_and_spaced_arrow_feature_reads(self) -> None:
        """T2: dot and spaced-arrow allowlisted reads match; unlisted dot reads do not."""
        reset_vulkan_maps()
        self.addCleanup(reset_vulkan_maps)
        sweep_vulkan_features.ensure_maps()
        source = (
            "int gate(VkPhysicalDeviceVulkan12Features *v12, VkPhysicalDeviceFeatures *feats) {\n"
            "    if (!v12.runtimeDescriptorArray) return -1;\n"
            "    if (!v12 -> scalarBlockLayout) return -1;\n"
            "    if (!feats.notAnAllowlistedMember) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        names = {site.feature for site in sites}
        self.assertIn("runtimeDescriptorArray", names)
        self.assertIn("scalarBlockLayout", names)
        self.assertNotIn("notAnAllowlistedMember", names)
        self.assertEqual(len(names), 2)

    def test_r6_t3_capability_need_keys_from_fixture(self) -> None:
        """T3: map-derived capability keys match single, any-of, non-feature, and absent rules."""
        with tempfile.TemporaryDirectory() as scratch:
            cap_map = r6_t3_capability_map(Path(scratch))
        helper = sweep_vulkan_features.capability_need_key
        tri = helper(cap_map["TriAtomics"])
        self.assertEqual(
            tri,
            "any-of:shaderBufferInt64Atomics,shaderImageInt64Atomics,shaderSharedInt64Atomics",
        )
        mixed = helper(cap_map["MixedStorage"])
        self.assertEqual(mixed, "any-of:shaderStorageImageReadWithoutFormat,non-feature")
        single = helper(cap_map["SingleRead"])
        self.assertEqual(single, "shaderStorageImageWriteWithoutFormat")
        dup = helper(cap_map["DupDraw"])
        self.assertEqual(dup, "drawIndirectFirstInstance")
        self.assertIsNone(helper(cap_map["VersionOnly"]))

    def test_r6_t3_anyof_group_compare_gates(self) -> None:
        """T3: compare_gates treats map-derived any-of groups as ambiguous or satisfied."""
        with tempfile.TemporaryDirectory() as scratch:
            cap_map = r6_t3_capability_map(Path(scratch))
        self.addCleanup(reset_vulkan_maps)
        install_r6_t3_derivable(cap_map)
        group = sweep_vulkan_features.capability_need_key(cap_map["TriAtomics"])
        self.assertIsNotNone(group)
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/test.comp.glsl",
                {group},
                {group: "capability:TriAtomics"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", [], needs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], group)
        self.assertEqual(rows[0][3], "ambiguous")
        checked = [sweep_vulkan_features.FeatureSite(2, "shaderBufferInt64Atomics")]
        self.assertEqual(
            sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", checked, needs),
            [],
        )

    def test_r6_t3_non_feature_compare_gates(self) -> None:
        """T3: feature-plus-version capabilities surface ,non-feature any-of keys in rows."""
        with tempfile.TemporaryDirectory() as scratch:
            cap_map = r6_t3_capability_map(Path(scratch))
        self.addCleanup(reset_vulkan_maps)
        install_r6_t3_derivable(cap_map)
        mixed = sweep_vulkan_features.capability_need_key(cap_map["MixedStorage"])
        self.assertIsNotNone(mixed)
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/s.comp.glsl",
                {mixed},
                {mixed: "capability:MixedStorage"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", [], needs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], mixed)
        self.assertTrue(mixed.endswith(",non-feature"))

    def test_r6_t8_shader_requirements_uses_capability_need_key(self) -> None:
        """T8: shader_requirements maps SPIR-V capabilities through capability_need_key wiring."""
        cap_map = r6_t3_capability_map(self.repo)
        self.addCleanup(reset_vulkan_maps)
        reset_vulkan_maps()
        sweep_vulkan_features.MAP_STATE.capability_map = cap_map
        work = self.repo / "spv-work"
        work.mkdir()
        spv = work / "shader.spv"
        spv.write_bytes(b"\x00")
        caps = (
            "TriAtomics",
            "MixedStorage",
            "SingleRead",
            "DupDraw",
            "VersionOnly",
            "UnknownNotInFixture",
        )
        disasm = "\n".join(f"OpCapability {name}" for name in caps)
        helper = sweep_vulkan_features.capability_need_key
        cap_names = ("TriAtomics", "MixedStorage", "SingleRead", "DupDraw")
        expected = {helper(cap_map[name]) for name in cap_names}
        deadline = time.monotonic() + 120
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "git", return_value="//"),
            unittest.mock.patch.object(sweep_vulkan_features, "compile_shader", return_value=spv),
            unittest.mock.patch.object(sweep_vulkan_features, "run_tool", return_value=disasm),
            unittest.mock.patch.object(
                sweep_vulkan_features, "spirv_needs_scalar", return_value=False
            ),
        ):
            needs = sweep_vulkan_features.shader_requirements(
                str(self.repo),
                self.base,
                "libavfilter/vulkan/t.comp.glsl",
                work,
                deadline,
            )
        self.assertEqual(needs.features, expected)
        for cap in cap_names:
            key = helper(cap_map[cap])
            self.assertIsNotNone(key)
            self.assertEqual(needs.evidence[key], f"capability:{cap}")

    def test_r6_t4_shader_diff_finds_existing_owner(self) -> None:
        """T4: a shader-only diff locates the owning vf_<stem>_vulkan.c at head for sweeps."""
        c_vulkan = "extern const unsigned char ff_v360_comp_spv_data[];\nint f(void){return 0;}\n"
        (self.repo / "libavfilter" / "vf_v360_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / "v360.comp.glsl").write_text(
            SIMPLE_SHADER, encoding="utf-8"
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "base2")
        base = run_git(self.repo, "rev-parse", "HEAD")
        (self.repo / "libavfilter" / "vulkan" / "v360.comp.glsl").write_text(
            SIMPLE_SHADER + "\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/vulkan/v360.comp.glsl")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        deadline = time.monotonic() + 120
        owners = sweep_vulkan_features.owners_for_shaders(
            str(self.repo),
            head,
            {"libavfilter/vulkan/v360.comp.glsl"},
            deadline,
        )
        self.assertIn("libavfilter/vf_v360_vulkan.c", owners)
        names = sweep_vulkan_features.diff_names(str(self.repo), base, head, deadline)
        targets = sweep_vulkan_features.collect_targets(str(self.repo), head, names, deadline)
        self.assertIn("libavfilter/vf_v360_vulkan.c", targets)

    def test_r6_t5_deleted_vulkan_c_omitted_from_diff(self) -> None:
        """T5: deleted Vulkan C paths stay out of diff_names and vulkan-features sweep rows."""
        (self.repo / "libavfilter" / "vf_drop_vulkan.c").write_text(
            "int drop(void){return 0;}\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/vf_drop_vulkan.c")
        run_git(self.repo, "commit", "-qm", "mid")
        drop_base = run_git(self.repo, "rev-parse", "HEAD")
        run_git(self.repo, "rm", "libavfilter/vf_drop_vulkan.c")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        deadline = time.monotonic() + 120
        names = sweep_vulkan_features.diff_names(str(self.repo), drop_base, head, deadline)
        self.assertNotIn("libavfilter/vf_drop_vulkan.c", names)
        report = sweep_vulkan_features.sweep(str(self.repo), drop_base, head, deadline)
        self.assertNotIn("vf_drop_vulkan.c", report)
        self.assertIn("no hits", report)

    def test_r6_t6_vulkan_limit_after_shader_owner_union(self) -> None:
        """T6: owner union can exceed MAX_VULKAN_FILES and block before read_sources."""
        for stem, symbol in (("one", "one"), ("two", "two")):
            sym = f"ff_{symbol}_comp_spv_data"
            body = f"extern const unsigned char {sym}[];\nint f(void){{return 0;}}\n"
            (self.repo / "libavfilter" / f"vf_{stem}_vulkan.c").write_text(body, encoding="utf-8")
            (self.repo / "libavfilter" / "vulkan" / f"{symbol}.comp.glsl").write_text(
                SIMPLE_SHADER, encoding="utf-8"
            )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "mid")
        (self.repo / "libavfilter" / "vulkan" / "one.comp.glsl").write_text(
            SIMPLE_SHADER + "\n", encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "two.comp.glsl").write_text(
            SIMPLE_SHADER + "\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/vulkan")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        bind_g3_maps_fixture(self)
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "MAX_VULKAN_FILES", 1),
            unittest.mock.patch(
                "scripts.sweep_vulkan_features.read_sources",
                side_effect=AssertionError("read_sources called"),
            ),
            self.assertRaisesRegex(RuntimeError, "vulkan file count"),
        ):
            self.vk_report(head)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_r6_t7_spirv_scalar_recomputes_timeout(self) -> None:
        """T7: spirv_needs_scalar passes a fresh timeout on each spirv-val invocation."""
        with tempfile.TemporaryDirectory() as scratch:
            spv = Path(scratch) / "test.spv"
            spv.write_bytes(b"\x03\x02\x23\x07" + b"\x00" * 16)
            recorded: list[float] = []
            deadline_calls = 0

            def fake_deadline(_deadline: float) -> float:
                nonlocal deadline_calls
                deadline_calls += 1
                if deadline_calls == 1:
                    return 90.0
                if deadline_calls == 3:
                    return 30.0
                return 30.0

            def fake_run(*_args, **kwargs):
                recorded.append(kwargs["timeout"])
                result = unittest.mock.Mock()
                result.returncode = 0 if len(recorded) == 1 else 1
                return result

            with (
                unittest.mock.patch(
                    "scripts.sweep_vulkan_features.check_deadline", side_effect=fake_deadline
                ),
                unittest.mock.patch(
                    "scripts.sweep_vulkan_features.subprocess.run", side_effect=fake_run
                ),
            ):
                sweep_vulkan_features.spirv_needs_scalar(spv, time.monotonic() + 120)
            self.assertEqual(recorded, [90.0, 30.0])

    def test_r7_g1_cpu_sites_wrapped_mask_statement(self) -> None:
        """G1: cpu_sites finds mask normalization when the mask continues on the next line."""
        source = "unsigned v = src[x]\n    & 0xFFF0u;\n"
        sites = sweep_port_parity.cpu_sites(source)
        self.assertEqual(sites, [(1, "mask")])

    def test_r7_g1_port_parity_wrapped_mask_row(self) -> None:
        """G1: port-parity reports mask when the CPU mask wraps across two lines."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0]\n    & 0xFFF0u; (void)v; }\n"
        c_vulkan = (
            "extern const unsigned char ff_test_comp_spv_data[];\nint f(void) { return 0; }\n"
        )
        head = self.commit_filter(
            c_vulkan=c_vulkan,
            shader_name="test.comp.glsl",
            shader=MASK_SHADER,
            cpu=cpu,
        )
        self.assertIn("| mask | none |", self.parity_report(head))

    def test_r7_g1_cpu_sites_semicolon_statement_boundary(self) -> None:
        """G1: two statements on one line only classify sample reads inside the first statement."""
        source = "uint16_t v = src[0]; int t = other >> 4;\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_r7b_g1_cpu_sites_function_body_five_cases(self) -> None:
        """G1 r7b: cpu_sites classifies each statement inside braced bodies separately."""
        cases = (
            (
                (
                    "static void f(const uint16_t *src)\n{\n"
                    "    int a = src[0];\n"
                    "    int m = x & 0xFFF0u;\n"
                    "}\n"
                ),
                [],
            ),
            (
                (
                    "static void f(const uint16_t *src)\n{\n"
                    "    int a = src[0] & 0xFFF0u;\n"
                    "    int b = src[1] >> 4;\n"
                    "}\n"
                ),
                [(3, "mask"), (4, "shift")],
            ),
            (
                (
                    "static void f(const uint16_t *src)\n{\n"
                    "    int a = src[0]\n"
                    "        & 0xFFF0u;\n"
                    "}\n"
                ),
                [(3, "mask")],
            ),
            (
                (
                    "static void f(const uint16_t *src, uint16_t *dst, int n)\n"
                    "{\n"
                    "    for (int i = 0; i < n; i++)\n"
                    "        dst[i] = src[i] & 0xFFF0u;\n"
                    "}\n"
                ),
                [(4, "mask")],
            ),
            (
                (
                    "static void f(const uint16_t *src)\n{\n"
                    "    if (x) {\n"
                    "        a = src[0] & 0xFFF0u;\n"
                    "    }\n"
                    "    b = src[1];\n"
                    "}\n"
                ),
                [(4, "mask")],
            ),
        )
        for source, expected in cases:
            with self.subTest(source=source.splitlines()[0]):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_r7b_g1_statement_spans_split_function_body(self) -> None:
        """G1 r7b: statement_spans does not merge separate statements inside a function body."""
        source = (
            "static void f(const uint16_t *src)\n"
            "{\n"
            "    int a = src[0];\n"
            "    int m = x & 0xFFF0u;\n"
            "}\n"
        )
        masked = variant_sweep.mask_literals(source)
        spans = sweep_port_parity.statement_spans(masked)
        self.assertGreaterEqual(len(spans), 3)
        for start, end in spans:
            piece = source[start:end]
            self.assertFalse("src[0]" in piece and "0xFFF0u" in piece)

    def test_r7c_g1_statement_spans_for_header_semicolons(self) -> None:
        """G1 r7c: semicolons inside a for header parentheses do not split statement_spans."""
        source = "for (i = 0; i < n; i++)\n    x = src[i] & 0xFFF0u;\n"
        masked = variant_sweep.mask_literals(source)
        end = source.rindex(";") + 1
        self.assertEqual(sweep_port_parity.statement_spans(masked), [(0, end)])

    def test_r7c_g1_statement_spans_trailing_whitespace(self) -> None:
        """G1 r7c: trailing whitespace after the last statement terminator yields no extra span."""
        source = "a = 1;\n\n"
        masked = variant_sweep.mask_literals(source)
        self.assertEqual(sweep_port_parity.statement_spans(masked), [(0, 6)])

    def test_r7c_g1_cpu_sites_for_condition_mask(self) -> None:
        """G1 r7c: cpu_sites keeps sample read and mask in one for-statement span."""
        source = (
            "static void f(const uint16_t *src)\n"
            "{\n"
            "    for (int v = src[0]; (v & 0xFFF0u) != 0; v++)\n"
            "        n++;\n"
            "}\n"
        )
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "mask")])

    def test_r7_g2_linked_shaders_ignores_masked_symbols(self) -> None:
        """G2: linked_shaders ignores shader symbols inside comments and string literals."""
        c_source = (
            "/* extern const unsigned char ff_old_comp_spv_data[]; */\n"
            "// ff_old_comp_spv_data\n"
            'const char *s = "ff_old_comp_spv_data";\n'
        )
        self.assertEqual(sweep_vulkan_features.linked_shaders(c_source), [])

    def test_r7_g2_linked_shaders_keeps_active_declarations(self) -> None:
        """G2: linked_shaders still returns active ff_*_comp_spv_data shader links."""
        c_source = (
            "/* ff_old_comp_spv_data */\nextern const unsigned char ff_new_comp_spv_data[];\n"
        )
        self.assertEqual(
            sweep_vulkan_features.linked_shaders(c_source),
            ["libavfilter/vulkan/new.comp.glsl"],
        )

    def test_cr10_4658985440_g3_fixture_registry(self) -> None:
        """CR10-5440: G3 parser tests load vk.xml maps from the minimal fixture registry."""
        missing = Path("/nonexistent/vk-cr10-5440/vk.xml")
        self.addCleanup(reset_vulkan_maps)
        with unittest.mock.patch.object(sweep_vulkan_features, "VK_XML", missing):
            ensure_maps_fixture()
            sites = sweep_vulkan_features.c_feature_reads("if (feats->shaderInt64 == VK_TRUE) {}\n")
            self.assertEqual([site.feature for site in sites], ["shaderInt64"])

    def test_r7_g3_feature_reads_skip_plain_writes(self) -> None:
        """G3: c_feature_reads ignores plain assignments but keeps genuine feature reads."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        write_only = "feats->shaderInt64 = VK_TRUE;\n"
        self.assertEqual(sweep_vulkan_features.c_feature_reads(write_only), [])
        wrapped = "feats->shaderInt64\n    = VK_TRUE;\n"
        self.assertEqual(sweep_vulkan_features.c_feature_reads(wrapped), [])
        checks = (
            "if (feats->shaderInt64 == VK_TRUE) {}\n",
            "ok = feats->shaderInt64;\n",
            "feats->shaderInt64 |= other;\n",
            "a.shaderInt64 = b.shaderInt64;\n",
        )
        for source in checks:
            sites = sweep_vulkan_features.c_feature_reads(source)
            self.assertEqual(len(sites), 1, source)
            self.assertEqual(sites[0].feature, "shaderInt64")

    def test_r7_g3_compare_gates_write_only_feature(self) -> None:
        """G3: compare_gates reports used-unchecked when C only writes an unchecked feature."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = "feats->shaderInt64 = VK_TRUE;\n"
        checked = sweep_vulkan_features.c_feature_reads(source)
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/b.comp.glsl",
                {"shaderInt64"},
                {"shaderInt64": "capability:Int64"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", checked, needs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "shaderInt64")
        self.assertEqual(rows[0][3], "used-unchecked")

    def test_r7_g3_feature_reads_skip_paren_wrapped_writes(self) -> None:
        """G3: c_feature_reads skips parenthesized plain '=' assignment targets."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        write_sources = (
            "(feats->shaderInt64) = VK_TRUE;\n",
            "((feats->shaderInt64)) = VK_TRUE;\n",
            "( feats->shaderInt64 )\n    = VK_TRUE;\n",
            "(s->feats.shaderInt64) = VK_TRUE;\n",
            "(*feats).shaderInt64 = VK_TRUE;\n",
        )
        for source in write_sources:
            self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [], source)

    def test_r7_g3_feature_reads_keep_paren_non_writes(self) -> None:
        """G3: parenthesized forms that are not plain writes remain feature reads."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        read_sources = (
            "if ((feats->shaderInt64) == VK_TRUE) {}\n",
            "ok = (feats->shaderInt64);\n",
            "(feats->shaderInt64) |= other;\n",
            "GET(feats->shaderInt64) = 1;\n",
            "if (feats->shaderInt64)\n    ok = 1;\n",
            "x = (a) + (feats->shaderInt64);\n",
        )
        for source in read_sources:
            sites = sweep_vulkan_features.c_feature_reads(source)
            self.assertEqual(len(sites), 1, source)
            self.assertEqual(sites[0].feature, "shaderInt64")

    def test_r7_g3_compare_gates_paren_wrapped_write_only_feature(self) -> None:
        """G3: compare_gates treats parenthesized plain writes as used-unchecked."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = "(feats->shaderInt64) = VK_TRUE;\n"
        checked = sweep_vulkan_features.c_feature_reads(source)
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/b.comp.glsl",
                {"shaderInt64"},
                {"shaderInt64": "capability:Int64"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", checked, needs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "shaderInt64")
        self.assertEqual(rows[0][3], "used-unchecked")

    def test_r12_g3_feature_reads_macro_whitespace_before_open_paren(self) -> None:
        """G3: macro call with whitespace before '(' keeps the parenthesized feature read."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        read_sources = (
            "SLOT (feats->shaderInt64) = 1;\n",
            "SLOT\t(feats->shaderInt64) = 1;\n",
            "SLOT\n(feats->shaderInt64) = 1;\n",
            "SLOT  (feats->shaderInt64) = 1;\n",
        )
        for source in read_sources:
            with self.subTest(source=source):
                sites = sweep_vulkan_features.c_feature_reads(source)
                self.assertEqual(len(sites), 1)
                self.assertEqual(sites[0].feature, "shaderInt64")

    def test_r12_g3_feature_reads_keyword_paren_wrapped_plain_writes(self) -> None:
        """G3: keyword-prefixed parenthesized plain '=' targets are not feature reads."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        write_sources = (
            "return (feats->shaderInt64) = 1;\n",
            "else (feats->shaderInt64) = 1;\n",
            " (feats->shaderInt64) = VK_TRUE;\n",
        )
        for source in write_sources:
            with self.subTest(source=source):
                self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_r12_g3_compare_gates_macro_whitespace_before_open_paren(self) -> None:
        """G3: macro whitespace before '(' is a read, not compare_gates used-unchecked."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = "#define SLOT(i) slots[(i)]\nSLOT (feats->shaderInt64) = 1;\n"
        checked = sweep_vulkan_features.c_feature_reads(source)
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/b.comp.glsl",
                {"shaderInt64"},
                {"shaderInt64": "capability:Int64"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", checked, needs)
        self.assertEqual(rows, [])

    def test_r7_g4_dynamic_storage_index_disasm_cases(self) -> None:
        """G4: dynamic_storage_index counts storage-image arrays only, not sampled or buffers."""
        sampled = sweep_vulkan_features.dynamic_storage_index(R7_SAMPLED_DISASM)
        storage = sweep_vulkan_features.dynamic_storage_index(R7_STORAGE_DISASM)
        buffer = sweep_vulkan_features.dynamic_storage_index(R7_BUFFER_DISASM)
        self.assertEqual(sampled, (False, False))
        self.assertEqual(storage, (True, False))
        self.assertEqual(buffer, (False, False))

    def test_cr11_h1_skip_space_leading_whitespace_and_empty_tail(self) -> None:
        """CR11 H1: _skip_space skips leading whitespace and stops at end-of-text."""
        text = "  \t\n\rident"
        limit = len(text)
        self.assertEqual(sweep_port_parity._skip_space(text, 0, limit), 5)
        self.assertEqual(sweep_port_parity._skip_space("  \t\n\r", 0, 5), 5)

    def test_cr11_h1_feature_read_receiver_root_identifier_to_tail(self) -> None:
        """CR11 H1: feature_read_receiver_root scans identifier tails or returns None."""
        masked = "receiver.feats"
        dot = masked.index(".")
        self.assertEqual(sweep_vulkan_features.feature_read_receiver_root(masked, dot), "receiver")
        self.assertIsNone(sweep_vulkan_features.feature_read_receiver_root("   ", 3))

    def test_cr10_4658985427_shift_not_mask_from_separate_arg(self) -> None:
        """CR10-5427: mask on a later call argument does not override shift on the sample."""
        source = "unsigned v = use(src[0] >> 4, flags & 0xff);\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(1, "shift")])

    def test_cr16_loop_header_while_shift_operand_focus(self) -> None:
        """CR16: while-header sample reads classify shift without a later header mask."""
        source = "void f(void)\n{\n    while (use(src[0] >> 4, flags & 0xff)) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr16_loop_header_for_shift_operand_focus(self) -> None:
        """CR16: for-header sample reads classify shift without a later header mask."""
        source = "void f(void)\n{\n    for (int i = use(src[0] >> 4, flags & 0xff); i; i--) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr16_loop_header_no_mask_without_shift(self) -> None:
        """CR16: a header sample without shift ignores mask on a separate call argument."""
        source = "void f(void)\n{\n    while (use(src[0], flags & 0xff)) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr16_enclosing_av_clip_counts_for_read(self) -> None:
        """CR16: a sample read inside av_clip classifies as clip normalization."""
        source = "void f(void)\n{\n    *out = av_clip(src[0], 0, 255);\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "clip")])

    def test_cr16_read_outside_enclosing_clip_ignored(self) -> None:
        """CR16: a sample read after av_clip does not inherit clip from that call."""
        source = "void f(void)\n{\n    *out = av_clip(x, 0, 255) + src[0];\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr16_macro_r_n16_shift_after_close_paren(self) -> None:
        """CR16: AV_RN16 shift after the macro argument list classifies as shift."""
        source = "void f(uint16_t *src, uint16_t *out)\n{\n    *out = AV_RN16(src) >> 4;\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr16_macro_r_n16_mask_after_close_paren(self) -> None:
        """CR16: AV_RN16 mask after the macro argument list classifies as mask."""
        source = "void f(uint16_t *src, uint16_t *out)\n{\n    *out = AV_RN16(src) & 0x3ff;\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "mask")])

    def test_cr16_macro_mask_inside_args_not_outside(self) -> None:
        """CR16: mask operators inside AV_RN16 arguments do not classify the read."""
        source = (
            "void f(uint16_t *src, int n, uint16_t *out)\n"
            "{\n"
            "    *out = AV_RN16(src + (n & 0xff));\n"
            "}\n"
        )
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr16_plain_shift_line_kept(self) -> None:
        """CR16: plain src shift on its line still classifies as shift."""
        source = "void f(void)\n{\n    *out = src[0] >> 4;\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr18_while_mask_on_other_operand_ignored(self) -> None:
        """CR18 H1: while-header mask on another operand does not classify the sample read."""
        source = "void f(void)\n{\n    while (src[0] && (flags & 0xff)) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr18_while_shift_on_other_operand_ignored(self) -> None:
        """CR18 H2: while-header shift on another operand does not classify the sample read."""
        source = "void f(void)\n{\n    while (src[0] && (n >> 2)) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr18_for_condition_mask_on_other_operand_ignored(self) -> None:
        """CR18 H3: for-condition mask on another operand does not classify the sample read."""
        source = "void f(void)\n{\n    for (i = 0; src[i] && (flags & 0xff); i++) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr18_for_init_mask_on_unbound_name_ignored(self) -> None:
        """CR18: for-init bound read ignores mask on a different loop variable."""
        source = "void f(void)\n{\n    for (int v = src[0]; (w & 0xFFF0u) != 0; v++) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr18_for_init_shift_on_bound_name(self) -> None:
        """CR18: for-init bound read classifies shift on the bound loop variable."""
        source = "void f(void)\n{\n    for (int v = src[0]; (v >> 2) != 0; v++) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr18_for_init_non_whole_word_name_ignored(self) -> None:
        """CR18: for-init bound read ignores mask on a substring-matching identifier."""
        source = "void f(void)\n{\n    for (int v = src[0]; (vv & 0xFFF0u) != 0; v++) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr18_loop_header_focus_regressions(self) -> None:
        """CR18 H4: attached and bound-variable header reads still classify correctly."""
        cases = [
            (
                "while_mask_on_sample",
                "void f(void)\n{\n    while ((src[0] & 0xff) != 0) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "while_mask_suffix",
                "void f(void)\n{\n    while (src[0] & 0x3ff) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "while_cast_mask",
                "void f(void)\n{\n    while ((int)src[0] & 0x3ff) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "for_init_mask_on_rhs",
                "void f(void)\n{\n    for (v = src[0] & 0x3ff; v; v--) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "while_plain_read",
                "void f(void)\n{\n    while (src[0]) {}\n}\n",
                [],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr19_for_init_member_assign_not_bound(self) -> None:
        """CR19 F1: for-init on p->x does not bind mask on unrelated identifier x."""
        source = "void f(void)\n{\n    for (p->x = src[0]; (x & 0xff) != 0; ) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr19_for_init_dot_member_assign_not_bound(self) -> None:
        """CR19 F2: for-init on s.x does not bind mask on unrelated identifier x."""
        source = "void f(void)\n{\n    for (s.x = src[0]; (x & 0xff) != 0; ) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr19_for_init_deref_assign_not_bound(self) -> None:
        """CR19 F3: for-init on *q does not bind mask on unrelated identifier q."""
        source = "void f(void)\n{\n    for (*q = src[0]; (q & 0xff) != 0; ) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr19_for_init_declarator_binding_regressions(self) -> None:
        """CR19 F4: declared for-init names still bind and classify header operand reads."""
        cases = [
            (
                "mask_int_v",
                "void f(void)\n{\n    for (int v = src[0]; (v & 0xFFF0u) != 0; v++) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "mask_multi_init",
                "void f(void)\n{\n    for (int i = 0, v = src[0]; (v & 0xff) != 0; i++) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "shift_multi_decl",
                "void f(void)\n{\n    for (int v = src[0], w = 0; (v >> 2) != 0; v++) {}\n}\n",
                [(3, "shift")],
            ),
            (
                "mask_uint8",
                "void f(void)\n{\n    for (uint8_t v = src[0]; (v & 0x0f) != 0; v++) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "shift_const_int",
                "void f(void)\n{\n    for (const int v = src[0]; (v >> 1) != 0; ) {}\n}\n",
                [(3, "shift")],
            ),
            (
                "mask_cond_only",
                "void f(void)\n{\n    for (int v = src[0]; v; v = v & 0x0f) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "mask_plain_assign",
                "void f(void)\n{\n    for (v = src[0]; v & 0x3ff; v--) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "no_bind_rhs_arithmetic",
                "void f(void)\n{\n    for (int v = src[0] + 1; (v & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr20_for_init_member_mask_ignored(self) -> None:
        """CR20 F1-F2: for-init bound read ignores masks on arrow and dot struct members."""
        cases = [
            (
                "arrow_member",
                "void f(void)\n{\n    for (int v = src[0]; (p->v & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
            (
                "dot_member",
                "void f(void)\n{\n    for (int v = src[0]; (s.v & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr20_for_init_spaced_member_mask_ignored(self) -> None:
        """CR20 F3-F4: for-init bound read ignores masks on spaced arrow and dot members."""
        cases = [
            (
                "spaced_arrow_member",
                "void f(void)\n{\n    for (int v = src[0]; (p -> v & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
            (
                "spaced_dot_member",
                "void f(void)\n{\n    for (int v = src[0]; (s . v & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr20_for_init_member_shift_ignored(self) -> None:
        """CR20 F5: for-init bound read ignores shift on an arrow struct member."""
        source = "void f(void)\n{\n    for (int v = src[0]; (p->v >> 2) != 0; v++) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr20_for_init_increment_member_mask_ignored(self) -> None:
        """CR20 F6: for-init bound read ignores member mask in the increment clause."""
        source = "void f(void)\n{\n    for (int v = src[0]; v; p->v = p->v & 0x0f) {}\n}\n"
        self.assertEqual(sweep_port_parity.cpu_sites(source), [])

    def test_cr20_for_init_member_skipped_keeps_later_bound_use(self) -> None:
        """CR20 F7: skipping a member mask preserves a later shift on the loop variable."""
        source = (
            "void f(void)\n{\n    for (int v = src[0]; (p->v & 0xff) != 0 && (v >> 1); v++) {}\n}\n"
        )
        self.assertEqual(sweep_port_parity.cpu_sites(source), [(3, "shift")])

    def test_cr20_for_init_bound_use_regressions(self) -> None:
        """CR20 F8: non-member bound uses and non-matching member bases keep expected sites."""
        cases = [
            (
                "cond_mask",
                "void f(void)\n{\n    for (int v = src[0]; (v & 0xff) != 0; v++) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "incr_mask",
                "void f(void)\n{\n    for (int v = src[0]; v; v = v & 0x0f) {}\n}\n",
                [(3, "mask")],
            ),
            (
                "other_member_then_bound_mask",
                (
                    "void f(void)\n"
                    "{\n"
                    "    for (int v = src[0]; (p->w & 0xff) != 0 && (v & 0xff); v++) {}\n"
                    "}\n"
                ),
                [(3, "mask")],
            ),
            (
                "index_by_bound",
                "void f(void)\n{\n    for (int v = src[0]; (a[v] & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
            (
                "bound_arrow_base",
                "void f(void)\n{\n    for (int v = src[0]; (v->x & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
            (
                "bound_dot_base",
                "void f(void)\n{\n    for (int v = src[0]; (v.x & 0xff) != 0; v++) {}\n}\n",
                [],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr21b_for_init_member_split_across_lines_ignored(self) -> None:
        """CR21B F1: a line break after a member operator still marks a member access."""
        cases = [
            (
                "arrow_newline",
                cpu_line_source("for (int v = src[0]; (p->\nv & 0xff) != 0; v++) {}"),
                [],
            ),
            (
                "arrow_crlf",
                cpu_line_source("for (int v = src[0]; (p->\r\nv & 0xff) != 0; v++) {}"),
                [],
            ),
            (
                "dot_newline",
                cpu_line_source("for (int v = src[0]; (s.\n    v & 0xff) != 0; v++) {}"),
                [],
            ),
            (
                "real_split_use",
                cpu_line_source("for (int v = src[0];\n    (v & 0xff) != 0; v++) {}"),
                [(3, "mask")],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr21b_for_init_declarator_line_breaks_bind(self) -> None:
        """CR21B F2: line breaks inside the for-init declarator keep the binding."""
        cases = [
            (
                "after_type",
                cpu_line_source("for (int\n    v = src[0]; (v & 0xff) != 0; v++) {}"),
                [(4, "mask")],
            ),
            (
                "before_equals",
                cpu_line_source("for (int v\n    = src[0]; (v & 0xff) != 0; v++) {}"),
                [(4, "mask")],
            ),
            (
                "after_type_crlf",
                cpu_line_source("for (int\r\n    v = src[0]; (v & 0xff) != 0; v++) {}"),
                [(4, "mask")],
            ),
            (
                "after_comma",
                cpu_line_source("for (int a = 0,\n    v = src[0]; (v & 0xff) != 0; v++) {}"),
                [(4, "mask")],
            ),
            (
                "one_line",
                cpu_line_source("for (int v = src[0]; (v & 0xff) != 0; v++) {}"),
                [(3, "mask")],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr21b_every_sample_read_in_statement_classified(self) -> None:
        """CR21B F3: each sample read of one statement is classified with its own operators."""
        cases = [
            (
                "second_read_mask",
                cpu_line_source("dst[0] = src[0] + (src[1] & 0xff);"),
                [(3, "mask")],
            ),
            (
                "second_read_shift",
                cpu_line_source("dst[0] = src[0] + (src[1] >> 4);"),
                [(3, "shift")],
            ),
            (
                "macro_then_shift",
                cpu_line_source("dst[0] = AV_RN16(p) + (src[1] >> 4);"),
                [(3, "shift")],
            ),
            (
                "mask_and_shift",
                cpu_line_source("dst[0] = (src[0] & 0xff) + (src[1] >> 4);"),
                [(3, "mask"), (3, "shift")],
            ),
            (
                "same_kind_once",
                cpu_line_source("dst[0] = (src[0] & 0xff) + (src[1] & 0x0f);"),
                [(3, "mask")],
            ),
            (
                "read_line_of_each_read",
                "void f(void)\n{\n    dst[0] = src[0] +\n        (src[1] >> 4);\n}\n",
                [(4, "shift")],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr21b_shader_site_follows_load_result(self) -> None:
        """CR21B F4: shader normalization counts only when it acts on the load result."""
        far_helper = (
            "uint load(uint raw) { return raw & 0xFFF0u; }\n"
            + "\n" * 6
            + "void main() { load(imageLoad(img, ivec2(0)).x); }\n"
        )
        cases = [
            (
                "mask_on_other_value",
                shader_line_source("vec4 px = imageLoad(img, pos);", "uint flags = u.bits & 0xff;"),
                "mask",
                None,
            ),
            (
                "mask_on_other_operand",
                shader_line_source("uint a = imageLoad(img, pos).r + (pc.flags & 0xff);"),
                "mask",
                None,
            ),
            ("far_helper", far_helper, "mask", "s.comp.glsl:8"),
            (
                "direct_mask",
                shader_line_source("uint px = imageLoad(img, pos).r & 0xff;"),
                "mask",
                "s.comp.glsl:3",
            ),
            (
                "variable_mask",
                shader_line_source("uvec4 px = imageLoad(img, pos);", "uint m = px.r & 0xffu;"),
                "mask",
                "s.comp.glsl:3",
            ),
            (
                "mask_on_other_name",
                shader_line_source("uvec4 px = imageLoad(img, pos);", "uint m = q.r & 0xffu;"),
                "mask",
                None,
            ),
        ]
        for label, source, kind, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, kind), expected
                )

    def test_cr21b_shader_site_follows_load_result_scopes(self) -> None:
        """CR21B F4: shader normalization through helpers and variable scopes follows the load."""
        cases = [
            ("masked_helper", MASKED_SHADER, "mask", "s.comp.glsl:6"),
            (
                "mask_on_dot_member_of_name",
                shader_line_source("uvec4 px = imageLoad(img, pos);", "uint m = s.px & 0xffu;"),
                "mask",
                None,
            ),
            (
                "mask_on_arrow_member_of_name",
                shader_line_source("uvec4 px = imageLoad(img, pos);", "uint m = s->px & 0xffu;"),
                "mask",
                None,
            ),
            (
                "mask_after_block_closed",
                shader_line_source(
                    "uvec4 px = imageLoad(img, pos);", "}", "uint m = px.r & 0xffu;"
                ),
                "mask",
                None,
            ),
            ("second_masked_helper", SECOND_MASKED_SHADER, "mask", "s.comp.glsl:6"),
            ("shift_only_shader_has_no_mask", MASK_SHADER, "mask", None),
        ]
        for label, source, kind, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, kind), expected
                )

    def test_cr21c_shader_site_follows_wrapped_load(self) -> None:
        """CR21C F5: a load or a use of its variable counts through parentheses and constructors."""
        cases = [
            (
                "constructor_around_load_swizzle",
                shader_line_source("uint px = uint(imageLoad(img, pos).r) & 0xffu;"),
                "mask",
            ),
            (
                "constructor_around_load_variable",
                shader_line_source(
                    "uvec4 px = uvec4(imageLoad(img, pos));", "uint m = px.r & 0xffu;"
                ),
                "mask",
            ),
            (
                "grouping_around_load_swizzle",
                shader_line_source("uint px = (imageLoad(img, pos).r) & 0xffu;"),
                "mask",
            ),
            (
                "signed_constructor_texel_fetch",
                shader_line_source("int v = int(texelFetch(tex, pos, 0).x) & 0xff;"),
                "mask",
            ),
            (
                "constructor_around_variable_use",
                shader_line_source(
                    "uvec4 px = imageLoad(img, pos);", "uint m = uint(px.r) & 0xffu;"
                ),
                "mask",
            ),
            (
                "constructor_shift",
                shader_line_source("uint v = uint(imageLoad(img, pos).r) >> 4u;"),
                "shift",
            ),
            (
                "unwrapped_direct_mask",
                shader_line_source("uint px = imageLoad(img, pos).r & 0xff;"),
                "mask",
            ),
            (
                "unwrapped_variable_mask",
                shader_line_source("uvec4 px = imageLoad(img, pos);", "uint m = px.r & 0xffu;"),
                "mask",
            ),
        ]
        for label, source, kind in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, kind), "s.comp.glsl:3"
                )

    def test_cr21c_shader_site_wrapped_other_value_reports_none(self) -> None:
        """CR21C F5: a call, another value or a larger constructor is not the load result."""
        cases = [
            (
                "call_not_constructor",
                shader_line_source("uint px = pack(imageLoad(img, pos).r) & 0xffu;"),
                "mask",
            ),
            (
                "constructor_masks_other_value",
                shader_line_source("uint a = imageLoad(img, pos).r + uint(pc.flags & 0xff);"),
                "mask",
            ),
            (
                "constructor_holds_more_than_load",
                shader_line_source(
                    "uvec2 px = uvec2(imageLoad(img, pos).r, q);", "uint m = px.x & 0xffu;"
                ),
                "mask",
            ),
            (
                "shift_on_other_constructed_value",
                shader_line_source(
                    "vec4 c = imageLoad(img, pos);", "uint v = uint(pc.flags) >> 4u;"
                ),
                "shift",
            ),
        ]
        for label, source, kind in cases:
            with self.subTest(label=label):
                self.assertIsNone(sweep_port_parity.shader_site("s.comp.glsl", source, kind))

    def test_cr22_balanced_sample_subscripts(self) -> None:
        """Sample operators follow the outer subscript and keep the read's line."""
        cases = [
            ("nested_shift", "x = src[indices[i]] >> 4;", [(1, "shift")]),
            ("nested_mask", "x = src[a[b[i]]] & 0xff;", [(1, "mask")]),
            ("multiline", "x = src[indices[\n    i]] >> 4;", [(1, "shift")]),
            ("flat", "x = src[i] >> 4;", [(1, "shift")]),
            ("addition", "x = src[indices[i]] + 4;", []),
            ("unbalanced", "x = src[indices[i] >> 4;", [(1, "shift")]),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source + "\n"), expected)

    def test_cr22_loop_header_binding_ends_at_assignment(self) -> None:
        """A loop-header assignment ends the sample binding after its right-hand side."""
        cases = [
            ("plain", "(v = flags, v & 0xffu); ", []),
            ("compound", "(v |= flags, v & 0xffu); ", []),
            ("shift_assign", "(v >>= 1, v & 0xffu); ", [(1, "shift")]),
            ("mask_before_write", "(v & 0xffu, v = flags); ", [(1, "mask")]),
            ("equal", "(v == 3, v & 0xffu); ", [(1, "mask")]),
            ("not_equal", "(v != 3, v & 0xffu); ", [(1, "mask")]),
            ("less_equal", "(v <= 3, v & 0xffu); ", [(1, "mask")]),
            ("greater_equal", "(v >= 3, v & 0xffu); ", [(1, "mask")]),
            ("mask_only", "v & 0xffu; ", [(1, "mask")]),
            ("rhs", "v; v = v >> 1", [(1, "shift")]),
            ("shift_before_write", "(v >> 4, v = flags); ", [(1, "shift")]),
        ]
        for label, tail, expected in cases:
            with self.subTest(label=label):
                source = f"for (unsigned v = src[0]; {tail}) {{}}\n"
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr22_helper_parameter_at_load_position(self) -> None:
        """A helper attributes normalization to the load's own parameter."""
        px_first = "uint px, uint flags"
        flags_first = "uint flags, uint px"
        load_first = "uint r = combine(imageLoad(img, pos).r, flags);"
        load_second = "uint r = combine(flags, imageLoad(img, pos).r);"
        cases = [
            ("other_parameter", px_first, "flags", (load_first,), None),
            ("wrong_position", flags_first, "px", (load_first,), None),
            ("first", px_first, "px", (load_first,), "s.comp.glsl:7"),
            ("second", flags_first, "px", (load_second,), "s.comp.glsl:7"),
            ("qualified", "in uint px, in uint flags", "px", (load_first,), "s.comp.glsl:7"),
            (
                "cache_by_position",
                px_first,
                "flags",
                (load_first, "uint b = combine(flags, imageLoad(img, pos).g);"),
                "s.comp.glsl:8",
            ),
            ("too_few_parameters", "uint px", "px", (load_second,), None),
            ("member", px_first, "flags.px", (load_first,), None),
            (
                "nested_comma",
                flags_first,
                "px",
                ("uint r = combine(pair(flags, mask), imageLoad(img, pos).r);",),
                "s.comp.glsl:7",
            ),
        ]
        for label, parameters, operand, calls, expected in cases:
            with self.subTest(label=label):
                helper = f"uint combine({parameters})\n{{\n    return {operand} & 0xffu;\n}}\n"
                source = helper + shader_line_source(*calls)
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, "mask"), expected
                )

    def test_cr22_shader_binding_ends_at_overwrite(self) -> None:
        """Only an overwrite at the load's block depth ends the forward scan."""
        output = "uint o = px & 0xffu;"
        site = "s.comp.glsl:3"
        cases = [
            ("plain", ("px = flags;", output), None),
            ("compound", ("px |= flags;", output), None),
            ("rhs", ("px = px & 0xffu;",), site),
            ("mask_only", (output,), site),
            ("mask_before_write", (output, "px = flags;"), site),
            ("comparison", ("bool z = px == flags;", output), site),
            ("nested_assignment", ("if (c) {", "px = flags;", "}", output), site),
            ("other_rhs", ("px = flags & 0xffu;",), None),
            ("compound_mask", ("px &= 0xffu;",), site),
        ]
        for label, tail, expected in cases:
            with self.subTest(label=label):
                source = shader_line_source("uint px = imageLoad(img, pos).r;", *tail)
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, "mask"), expected
                )

    def test_cr22_shader_symbol_identifier_boundaries(self) -> None:
        """Shader symbols link only as whole identifiers in first-seen order."""
        path = "libavfilter/vulkan/test.comp.glsl"
        cases = [
            ("suffix", "x = ff_test_comp_spv_data_backup;", []),
            ("prefix_letter", "x = xff_test_comp_spv_data;", []),
            ("prefix_underscore", "x = _ff_test_comp_spv_data;", []),
            ("exact", "x = ff_test_comp_spv_data;", [path]),
            (
                "ordered_unique",
                (
                    "extern const unsigned char ff_test_comp_spv_data[];\n"
                    "p = &ff_test_comp_spv_data;\nq = ff_b_comp_spv_data;\n"
                ),
                [path, "libavfilter/vulkan/b.comp.glsl"],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_vulkan_features.linked_shaders(source), expected)

    def test_cr22_generic_declaration_separator(self) -> None:
        """Generic declarations accept one space without backtracking over the separator."""
        bind_g3_maps_fixture(self)
        pattern = sweep_vulkan_features.GENERIC_DECL
        gate = [("GateFeatures", "p")]
        cases = [
            ("single_space", "GateFeatures p;", gate),
            ("tab", "GateFeatures\tp;", gate),
            ("initialized", "int a = 1;", [("int", "a")]),
            ("two_spaces", "GateFeatures  p;", gate),
            ("pointer", "GateFeatures *p;", gate),
            ("spaced_pointer", "GateFeatures * p;", gate),
            ("double_pointer", "GateFeatures  **p,", gate),
            ("no_space", "GateFeatures*p;", []),
            ("no_space_before_star", "GateFeatures* p;", []),
            ("pointer_shape", "x * y;", [("x", "y")]),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    [(match[1], match[3]) for match in pattern.finditer(source)], expected
                )
        for gap in (" ", "  "):
            with self.subTest(typedef_gap=gap):
                source = (
                    "struct Other { int shaderInt64; };\ntypedef struct Other OtherT;\n"
                    f"int f(void) {{\n    OtherT{gap}p;\n"
                    "    if (p.shaderInt64) return 1;\n    return 0;\n}\n"
                )
                self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])
        with self.subTest(separator_length=50_000):
            source = "a" + " " * 50_000 + "!"
            start = time.monotonic()
            self.assertEqual(list(pattern.finditer(source)), [])
            self.assertLess(time.monotonic() - start, 2.0)

    def test_cr22_parenthesized_feature_receiver(self) -> None:
        """Redundant parentheses preserve the feature receiver's root type."""
        bind_g3_maps_fixture(self)
        feature = ["shaderInt64"]
        cases = [
            ("bare", "struct Other *p", "p->", []),
            ("one_pair", "struct Other *p", "(p)->", []),
            ("nested", "struct Other *p", "((p))->", []),
            ("spaced", "struct Other *p", "( p )->", []),
            ("unresolved", "struct Other *p", "(q)->", feature),
            ("feature_struct", "VkPhysicalDeviceFeatures *feats", "(feats)->", feature),
            ("dereference", "struct Other *p", "(*p).", feature),
            ("member_chain", "struct Outer *p", "((p))->other.", []),
        ]
        for label, parameter, receiver, expected in cases:
            with self.subTest(label=label):
                source = (
                    "struct Other { int shaderInt64; };\n"
                    "struct Outer { struct Other other; };\n"
                    f"int f({parameter}) {{\n    if ({receiver}shaderInt64) return 1;\n"
                    "    return 0;\n}\n"
                )
                self.assertEqual(
                    [site.feature for site in sweep_vulkan_features.c_feature_reads(source)],
                    expected,
                )

    def test_cr22_unanalyzed_shader_suppresses_required_unused(self) -> None:
        """An absence row requires every linked shader to have been analyzed."""
        bind_g3_maps_fixture(self)
        owner = "libavfilter/vf_t_vulkan.c"
        shader = "libavfilter/vulkan/a.comp.glsl"
        checked = [sweep_vulkan_features.FeatureSite(3, "shaderInt64")]
        cases = [
            (
                "unanalyzed",
                "error: bad",
                [
                    (
                        f"{shader}:1",
                        "scalarBlockLayout",
                        "spirv-val rejected both layouts: error: bad",
                        "unanalyzed",
                    )
                ],
            ),
            ("analyzed", "", [(f"{owner}:3", "shaderInt64", "none", "required-unused")]),
        ]
        for label, diagnostic, expected in cases:
            with self.subTest(label=label):
                needs = [sweep_vulkan_features.ShaderNeeds(shader, set(), {}, diagnostic)]
                self.assertEqual(
                    sweep_vulkan_features.compare_gates(owner, checked, needs), expected
                )

    def test_cr23_inner_subscript_read_classified(self) -> None:
        """Classify sample reads nested inside balanced subscripts on their own lines."""
        cases = [
            ("inner_mask", "dst[0] = src[src[i] & 0xffu];\n", [(1, "mask")]),
            ("inner_after_bracket", "dst[0] = src[a[0] + (src[i] & 0xffu)];\n", [(1, "mask")]),
            ("outer_shift", "dst[0] = src[indices[i]] >> 4;\n", [(1, "shift")]),
            ("no_operator", "dst[0] = src[src[i]];\n", []),
            ("later_line", "dst[0] = src[\n    src[i] & 0xffu];\n", [(2, "mask")]),
            (
                "outer_and_later_inner",
                "dst[0] = src[\n    src[i] & 0xffu] >> 4;\n",
                [(1, "shift"), (2, "mask")],
            ),
        ]
        for label, source, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr23_parenthesized_loop_assignment(self) -> None:
        """End a loop-header binding when a parenthesized target names the loop variable."""
        cases = [
            ("paren_plain", "(v) = flags, v & 0xffu; ", []),
            ("nested_compound", "((v)) |= flags, v & 0xffu; ", []),
            ("grouped_comma", "((v) = flags, v & 0xffu); ", []),
            ("arrow_member", "(p->v) = flags, v & 0xffu; ", [(1, "mask")]),
            ("dot_member", "(s.v) = flags, v & 0xffu; ", [(1, "mask")]),
            ("deref", "(*v) = flags, v & 0xffu; ", [(1, "mask")]),
            ("outer_deref", "*(v) = flags, v & 0xffu; ", [(1, "mask")]),
            ("bare_rhs", "v; v = v >> 1", [(1, "shift")]),
            ("paren_rhs", "v; (v) = v >> 1", [(1, "shift")]),
        ]
        for label, tail, expected in cases:
            with self.subTest(label=label):
                source = f"for (unsigned v = src[0]; {tail}) {{}}\n"
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected)

    def test_cr23_load_as_index_not_credited(self) -> None:
        """Credit an enclosing helper call only when the unwrapped load is its argument."""
        one_param = "uint norm(uint p)\n{\n    return p & 0xffu;\n}\n"
        two_param = "uint norm(uint a, uint p)\n{\n    return p & 0xffu;\n}\n"
        site = "s.comp.glsl:7"
        cases = [
            ("subscript_index", one_param, "uint r = norm(table[imageLoad(img, pos).r]);", None),
            (
                "wrapped_index",
                one_param,
                "uint r = norm(table[(imageLoad(img, pos).r)]);",
                None,
            ),
            ("direct_arg", one_param, "uint r = norm(imageLoad(img, pos).r);", site),
            ("constructor_arg", one_param, "uint r = norm(uint(imageLoad(img, pos).r));", site),
            ("grouped_arg", one_param, "uint r = norm((imageLoad(img, pos).r));", site),
            (
                "second_after_subscript",
                two_param,
                "uint r = norm(a[0], imageLoad(img, pos).r);",
                site,
            ),
        ]
        for label, helper, call, expected in cases:
            with self.subTest(label=label):
                source = helper + shader_line_source(call)
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, "mask"), expected
                )

    def test_cr23_helper_overloads_disagree(self) -> None:
        """Require every candidate helper overload of matching arity to carry the pattern."""
        masked_uint = "uint norm(uint p) { return p & 0xffu; }\n"
        masked_int = "int norm(int p) { return p & 0xff; }\n"
        unmasked_uint = "uint norm(uint p) { return p; }\n"
        unmasked_two = "uint norm(uint p, uint q) { return p + q; }\n"
        masked_two = "uint norm(uint p, uint q) { return p & 0xffu; }\n"
        one_arg_call = ("uint r = norm(imageLoad(img, pos).r);",)
        cases = [
            ("disagree", unmasked_uint + masked_int, one_arg_call, None),
            ("disagree_masked_first", masked_int + unmasked_uint, one_arg_call, None),
            ("both_mask", masked_uint + masked_int, one_arg_call, "s.comp.glsl:5"),
            ("different_arity", masked_uint + unmasked_two, one_arg_call, "s.comp.glsl:5"),
            (
                "cache_by_arity",
                unmasked_uint + masked_two,
                (
                    "uint a = norm(imageLoad(img, pos).r);",
                    "uint b = norm(imageLoad(img, pos).g, flags);",
                ),
                "s.comp.glsl:6",
            ),
            ("single_mask", masked_uint, one_arg_call, "s.comp.glsl:4"),
        ]
        for label, helpers_src, calls, expected in cases:
            with self.subTest(label=label):
                source = helpers_src + shader_line_source(*calls)
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, "mask"), expected
                )

    def test_cr23_compound_assignment_classified(self) -> None:
        """Classify compound assignments on bound values before ending their bindings."""
        site = "s.comp.glsl:3"
        shader_cases = [
            ("shader_compound_mask", ("px &= 0xffu;",), "mask", site),
            ("shader_compound_shift", ("px >>= 4;",), "shift", site),
            ("shader_compound_or_stops", ("px |= flags;", "uint o = px & 0xffu;"), "mask", None),
            ("shader_plain_other_rhs", ("px = flags & 0xffu;",), "mask", None),
            ("shader_plain_self_rhs", ("px = px & 0xffu;",), "mask", site),
        ]
        for label, tail, kind, expected in shader_cases:
            with self.subTest(label=label):
                source = shader_line_source("uint px = imageLoad(img, pos).r;", *tail)
                self.assertEqual(
                    sweep_port_parity.shader_site("s.comp.glsl", source, kind), expected
                )
        header_cases = [
            ("header_compound_mask", "(v &= 0xffu); ", [(1, "mask")]),
            ("header_compound_or_stops", "(v |= flags, v & 0xffu); ", []),
        ]
        for label, tail_src, expected_sites in header_cases:
            with self.subTest(label=label):
                source = f"for (unsigned v = src[0]; {tail_src}) {{}}\n"
                self.assertEqual(sweep_port_parity.cpu_sites(source), expected_sites)

    def test_cr23_call_parentheses_not_receiver(self) -> None:
        """Keep unknown-type fallback for call argument parentheses but resolve keyword wrappers."""
        bind_g3_maps_fixture(self)
        feature = ["shaderInt64"]
        other_param = "struct Other *p"
        vk_param = "VkPhysicalDeviceFeatures *p"
        cases = [
            ("call_ident", other_param, "if (get_features(p)->shaderInt64) return 1;", feature),
            ("call_subscript", other_param, "if (fns[0](p)->shaderInt64) return 1;", feature),
            ("call_paren", other_param, "if (get_fn()(p)->shaderInt64) return 1;", feature),
            ("standalone_one", other_param, "if ((p)->shaderInt64) return 1;", []),
            ("standalone_nested", other_param, "if (((p))->shaderInt64) return 1;", []),
            ("statement_start", other_param, "(p)->shaderInt64;", []),
            ("kw_return", other_param, "return (p)->shaderInt64;", []),
            ("kw_return_nested", other_param, "return ((p))->shaderInt64;", []),
            ("kw_else", other_param, "if (0) return 0; else (p)->shaderInt64;", []),
            ("kw_do", other_param, "do (p)->shaderInt64; while (0);", []),
            ("kw_case", other_param, "switch (0) { case (p)->shaderInt64: break; }", []),
            ("eligible_return", vk_param, "return (p)->shaderInt64;", feature),
        ]
        for label, parameter, body, expected in cases:
            with self.subTest(label=label):
                source = (
                    "struct Other { int shaderInt64; };\n"
                    f"int f({parameter}) {{\n    {body}\n    return 0;\n}}\n"
                )
                self.assertEqual(
                    [site.feature for site in sweep_vulkan_features.c_feature_reads(source)],
                    expected,
                )

    def test_cr10_4658985429_linked_shaders_dedupes_repeated_symbols(self) -> None:
        """CR10-5429: repeated extern and use symbols link one shader path in first-seen order."""
        c_source = (
            "extern const unsigned char ff_dup_comp_spv_data[];\n"
            "const unsigned char *p = ff_dup_comp_spv_data;\n"
        )
        self.assertEqual(
            sweep_vulkan_features.linked_shaders(c_source),
            ["libavfilter/vulkan/dup.comp.glsl"],
        )

    def test_cr10_4658985429_sixty_five_distinct_shaders_exceed_limit(self) -> None:
        """CR10-5429: 65 distinct linked shaders still fail the shader count cap."""
        symbols = "".join(
            f"extern const unsigned char ff_n{i}_comp_spv_data[];\n" for i in range(65)
        )
        (self.repo / "libavfilter" / "vf_big_vulkan.c").write_text(symbols, encoding="utf-8")
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        deadline = time.monotonic() + 120
        names = sweep_vulkan_features.diff_names(str(self.repo), self.base, head, deadline)
        with self.assertRaisesRegex(RuntimeError, "shader count"):
            sweep_vulkan_features.collect_targets(str(self.repo), head, names, deadline)

    def test_cr10_4658985432_owner_requires_active_shader_link(self) -> None:
        """CR10-5432: owners_for_shaders ignores C files that only mention a shader in comments."""
        (self.repo / "libavfilter" / "vf_ghost_vulkan.c").write_text(
            "/* ff_ghost_comp_spv_data */\nint f(void){return 0;}\n",
            encoding="utf-8",
        )
        (self.repo / "libavfilter" / "vulkan" / "ghost.comp.glsl").write_text(
            SIMPLE_SHADER + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        deadline = time.monotonic() + 120
        owners = sweep_vulkan_features.owners_for_shaders(
            str(self.repo),
            head,
            {"libavfilter/vulkan/ghost.comp.glsl"},
            deadline,
        )
        self.assertNotIn("libavfilter/vf_ghost_vulkan.c", owners)

    def test_cr11_h3_owners_for_shaders_one_git_show_per_owner_path(self) -> None:
        """CR11 H3: two changed shaders on one owner C file trigger one git show per path."""
        c_vulkan = (
            "extern const unsigned char ff_one_comp_spv_data[];\n"
            "extern const unsigned char ff_two_comp_spv_data[];\n"
            "int f(void){return 0;}\n"
        )
        (self.repo / "libavfilter" / "vf_dual_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / "one.comp.glsl").write_text(
            SIMPLE_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "two.comp.glsl").write_text(
            SIMPLE_SHADER, encoding="utf-8"
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "mid")
        (self.repo / "libavfilter" / "vulkan" / "one.comp.glsl").write_text(
            SIMPLE_SHADER + "\n", encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "two.comp.glsl").write_text(
            SIMPLE_SHADER + "\n", encoding="utf-8"
        )
        run_git(self.repo, "add", "libavfilter/vulkan")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        deadline = time.monotonic() + 120
        shows: list[str] = []
        real_git = sweep_vulkan_features.git

        def counting_git(directory: str, *args: object, **kwargs: object) -> str:
            if args and args[0] == "show":
                shows.append(str(args[1]))
            return real_git(directory, *args, **kwargs)

        with unittest.mock.patch.object(
            sweep_vulkan_features, "git", wraps=real_git
        ) as tracked_git:
            tracked_git.side_effect = counting_git
            owners = sweep_vulkan_features.owners_for_shaders(
                str(self.repo),
                head,
                {
                    "libavfilter/vulkan/one.comp.glsl",
                    "libavfilter/vulkan/two.comp.glsl",
                },
                deadline,
            )
        self.assertEqual(owners, {"libavfilter/vf_dual_vulkan.c"})
        owner_shows = [path for path in shows if path.endswith(":libavfilter/vf_dual_vulkan.c")]
        self.assertEqual(len(owner_shows), 1)

    def test_cr10_4658985437_nonuniform_index_without_dynamic(self) -> None:
        """CR10-5437: NonUniform storage-image indexing does not imply dynamic uniform indexing."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(R7_NONUNIFORM_ONLY_DISASM),
            (False, True),
        )

    def test_cr16_nonuniform_resource_copy_operand(self) -> None:
        """CR16: NonUniform on OpCopyObject image operand yields non-uniform without dynamic."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(R7_NONUNIFORM_RESOURCE_DISASM),
            (False, True),
        )

    def test_cr16b_nonuniform_double_pointer_load(self) -> None:
        """CR16b: first decorated load copy wins when the same pointer is loaded again."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(CR16B_DOUBLE_LOAD_NONUNIFORM_DISASM),
            (False, True),
        )

    def test_cr16b_nonuniform_double_load_copy(self) -> None:
        """CR16b: decorated copy wins when the same load is copied again without decorate."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(CR16B_DOUBLE_COPY_NONUNIFORM_DISASM),
            (False, True),
        )

    def test_cr16_nonuniform_mixed_dynamic_and_copy(self) -> None:
        """CR16: decorated image operand with dynamic dst index yields both flags."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(R7_NONUNIFORM_MIXED_DISASM),
            (True, True),
        )

    def test_cr16_nonuniform_index_form_dynamic_and_nonuniform(self) -> None:
        """CR16: index-form NonUniform src access with dynamic dst keeps both requirements."""
        self.assertEqual(
            sweep_vulkan_features.dynamic_storage_index(CR16_NONUNIFORM_INDEX_DISASM),
            (True, True),
        )

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_cr16_nu_res2_glslang_copy_object_nonuniform(self) -> None:
        """CR16: resource-form NonUniform decorates OpCopyObject and yields non-uniform only."""
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            deadline = time.monotonic() + 120
            spv = sweep_vulkan_features.compile_shader(NU_RES2_SHADER, work, deadline)
            disasm = sweep_vulkan_features.run_tool(
                [
                    str(sweep_vulkan_features.SPIRV_DIS),
                    str(spv),
                ],
                deadline,
                sweep_vulkan_features.MAX_TOOL_BYTES,
                "spirv-dis",
            )
        copy_id = ""
        for line in disasm.splitlines():
            if "OpCopyObject" in line and "=" in line:
                copy_id = line.split("=", 1)[0].strip()
                break
        self.assertRegex(copy_id, r"%\w+")
        self.assertIn(f"OpDecorate {copy_id} NonUniform", disasm)
        self.assertEqual(sweep_vulkan_features.dynamic_storage_index(disasm), (False, True))

    def test_cr13_f2_scoped_params_both_orders(self) -> None:
        """Scoped params keep the VkPhysicalDeviceFeatures gate read in either declaration order."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        first = (
            "int gate(VkPhysicalDeviceFeatures *p) {\n"
            "    if (p->shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
            "void other(VkPhysicalDeviceProperties *p) { (void)p; }\n"
        )
        second = (
            "void other(VkPhysicalDeviceProperties *p) { (void)p; }\n"
            "int gate(VkPhysicalDeviceFeatures *p) {\n"
            "    if (p->shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        for source, line in ((first, 2), (second, 3)):
            with self.subTest(line=line):
                sites = sweep_vulkan_features.c_feature_reads(source)
                self.assertEqual(len(sites), 1)
                self.assertEqual(sites[0].feature, "shaderInt64")
                self.assertEqual(sites[0].line, line)

    def test_cr13_f2_single_eligible_and_file_scope(self) -> None:
        """One eligible declaration and file-scope variables still yield their feature sites."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        single = "VkPhysicalDeviceFeatures *feats;\nif (feats->shaderInt64) {}\n"
        sites = sweep_vulkan_features.c_feature_reads(single)
        self.assertEqual(len(sites), 1)
        file_scope = (
            "VkPhysicalDeviceFeatures feats;\n"
            "void gate(VkPhysicalDeviceFeatures *p) { (void)p; }\n"
            "void later(void) {\n"
            "    if (feats.shaderInt64) {}\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(file_scope)
        self.assertEqual(len(sites), 1)
        self.assertIn("feats.shaderInt64", file_scope.splitlines()[sites[0].line - 1])

    def test_cr13_f2_unrelated_param_stays_excluded(self) -> None:
        """A feature read through a known unrelated Vk struct parameter remains excluded."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "int bad(VkPhysicalDeviceProperties *p) {\n"
            "    if (p->shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr13_f3_wrapper_member_chain(self) -> None:
        """A wrapped VkPhysicalDeviceFeatures member yields the chained feature read site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "struct Wrapper { VkPhysicalDeviceFeatures features; };\n"
            "int gate(struct Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr13_f3_wrong_member_type_excluded(self) -> None:
        """A chained read through VkPhysicalDeviceProperties does not satisfy the gate."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "struct Wrapper { VkPhysicalDeviceProperties features; };\n"
            "int gate(struct Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr13_f3_unknown_member_chain_accepted(self) -> None:
        """A member chain with no declaration keeps the unknown-type accept fallback."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "struct Wrapper { Mystery features; };\n"
            "int gate(struct Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)

    def test_cr14_f3_typedef_wrapper_name_member_chain(self) -> None:
        """A typedef-named wrapper accepting ctx->features.shaderInt64 yields one feature site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Wrapper { VkPhysicalDeviceFeatures features; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr14_f3_unresolvable_header_chain_accepted(self) -> None:
        """A chain through a header-only typedef member keeps the unknown fallback and one site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct GateCtx { FFVulkanContext vkctx; } GateCtx;\n"
            "int gate(GateCtx *s) {\n"
            "    if (s->vkctx.feats.features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr15c_f3_unresolved_member_step_accepted(self) -> None:
        """A missing member step on a file-defined struct keeps unknown-type accept and one site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Wrapper { int x; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->missing.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr14_f3_pointer_member_arrow_feature_read(self) -> None:
        """A pointer-typed features member read through arrow yields one shaderInt64 site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "struct Wrapper { VkPhysicalDeviceFeatures *features; };\n"
            "int gate(struct Wrapper *ctx) {\n"
            "    if (ctx->features->shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr14_f3_typedef_unrelated_member_excluded(self) -> None:
        """A typedef wrapper with VkPhysicalDeviceProperties features yields no feature site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Wrapper { VkPhysicalDeviceProperties features; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr14_f3_direct_typedef_wrapper_excluded(self) -> None:
        """A direct feature read on a typedef wrapper pointer stays excluded."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Wrapper { VkPhysicalDeviceFeatures features; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr14_f3_pointer_inner_dot_after_arrow_chain(self) -> None:
        """A chain through a pointer inner member and dot on features yields one site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Inner { VkPhysicalDeviceFeatures features; } Inner;\n"
            "typedef struct Wrapper { Inner *inner; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->inner->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr14_f3_anonymous_typedef_feature_chain(self) -> None:
        """An anonymous typedef struct read through its typedef name yields one feature site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct { VkPhysicalDeviceFeatures features; } Shell;\n"
            "int gate(Shell *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr14_f3_scoped_wrapper_chain_single_site(self) -> None:
        """Scoped typedef params keep the eligible wrapper chain site only in the first function."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Wrapper { VkPhysicalDeviceFeatures features; } Wrapper;\n"
            "typedef struct Other { VkPhysicalDeviceProperties features; } Other;\n"
            "int good(Wrapper *ctx) {\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
            "void bad(Other *ctx) {\n"
            "    if (ctx->features.shaderInt64) {}\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        self.assertEqual(sites[0].line, 4)

    def test_cr15_forward_typedef_alias_member_chain(self) -> None:
        """Forward typedef tag alias keeps the features member site when props is ineligible."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct HolderTag Holder;\n"
            "struct HolderTag {\n"
            "    VkPhysicalDeviceProperties props;\n"
            "    VkPhysicalDeviceFeatures features;\n"
            "};\n"
            "int gate(Holder *ctx) {\n"
            "    if (ctx->props.shaderInt64) {}\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        self.assertIn("ctx->features.shaderInt64", source.splitlines()[sites[0].line - 1])

    def test_cr15_forward_union_typedef_alias_member_chain(self) -> None:
        """Forward union tag alias keeps the features member site when props is ineligible."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef union HolderTag Holder;\n"
            "union HolderTag {\n"
            "    VkPhysicalDeviceProperties props;\n"
            "    VkPhysicalDeviceFeatures features;\n"
            "};\n"
            "int gate(Holder *ctx) {\n"
            "    if (ctx->props.shaderInt64) {}\n"
            "    if (ctx->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        self.assertIn("ctx->features.shaderInt64", source.splitlines()[sites[0].line - 1])

    def test_cr15_cross_function_shadow_resolves_file_scope(self) -> None:
        """Cross-function local shadow leaves file-scope feats visible in a later function."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "static VkPhysicalDeviceFeatures feats;\n"
            "void a(void) {\n"
            "    VkPhysicalDeviceProperties feats;\n"
            "    (void)feats;\n"
            "}\n"
            "void b(void) {\n"
            "    if (feats.shaderInt64) {}\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        self.assertIn("feats.shaderInt64", source.splitlines()[sites[0].line - 1])

    def test_cr15_nested_block_shadow_resolves_file_scope(self) -> None:
        """Nested-block local feats shadow does not hide file-scope feats in a later function."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "static VkPhysicalDeviceFeatures feats;\n"
            "void a(void) {\n"
            "    { { VkPhysicalDeviceProperties feats; } }\n"
            "}\n"
            "void b(void) {\n"
            "    if (feats.shaderInt64) {}\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        self.assertIn("feats.shaderInt64", source.splitlines()[sites[0].line - 1])

    def test_cr17_f1_inner_block_shadow_expires_before_outer_read(self) -> None:
        """CR17 F1: a read after an inner block resolves the outer parameter declaration."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "void gate(VkPhysicalDeviceFeatures *p) {\n"
            "    {\n"
            "        VkPhysicalDeviceProperties *p = 0;\n"
            "        (void)p;\n"
            "    }\n"
            "    if (p->shaderInt64) {}\n"
            "}\n"
        )
        pairs = [(s.feature, s.line) for s in sweep_vulkan_features.c_feature_reads(source)]
        self.assertEqual(pairs, [("shaderInt64", 6)])

    def test_cr17_f2_inner_local_shadow_expires_before_outer_read(self) -> None:
        """CR17 F2: a read after an inner block resolves the outer local declaration."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "void gate(void) {\n"
            "    VkPhysicalDeviceFeatures feats;\n"
            "    { VkPhysicalDeviceProperties feats; (void)feats; }\n"
            "    if (feats.shaderInt64) {}\n"
            "}\n"
        )
        pairs = [(s.feature, s.line) for s in sweep_vulkan_features.c_feature_reads(source)]
        self.assertEqual(pairs, [("shaderInt64", 4)])

    def test_cr17_f3_reverse_inner_features_shadow_expires(self) -> None:
        """CR17 F3: inner Features param shadow does not hide outer Properties after the block."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "void gate(VkPhysicalDeviceProperties *p) {\n"
            "    {\n"
            "        VkPhysicalDeviceFeatures *p = 0;\n"
            "        (void)p;\n"
            "    }\n"
            "    if (p->shaderInt64) {}\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr17_f4_nested_two_level_shadow_expiry(self) -> None:
        """CR17 F4: nested block shadows expire; the function-local decl wins after outer blocks."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        nested = (
            "void gate(void) {\n"
            "    VkPhysicalDeviceFeatures feats;\n"
            "    {\n"
            "        VkPhysicalDeviceProperties feats;\n"
            "        {\n"
            "            VkPhysicalDeviceFeatures feats;\n"
            "            (void)feats;\n"
            "        }\n"
            "        if (feats.shaderInt64) {}\n"
            "    }\n"
            "    if (feats.shaderInt64) {}\n"
            "}\n"
        )
        pairs = [(s.feature, s.line) for s in sweep_vulkan_features.c_feature_reads(nested)]
        with self.subTest(which="inner_block_read"):
            self.assertNotIn(("shaderInt64", 9), pairs)
            self.assertEqual([p for p in pairs if p[1] == 9], [])
        with self.subTest(which="after_outer_block"):
            self.assertEqual([p for p in pairs if p[1] == 11], [("shaderInt64", 11)])

    def test_cr17_f3_regression_sibling_and_no_inner_block(self) -> None:
        """CR17 F3: inner-block, sibling-block, and no-inner-block cases keep expected reads."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        cases = (
            (
                "read_inside_inner",
                (
                    "void gate(void) {\n"
                    "    VkPhysicalDeviceFeatures feats;\n"
                    "    { VkPhysicalDeviceProperties feats; if (feats.shaderInt64) {} }\n"
                    "}\n"
                ),
                [],
            ),
            (
                "sibling_blocks",
                (
                    "void gate(void) {\n"
                    "    { VkPhysicalDeviceFeatures feats; }\n"
                    "    { VkPhysicalDeviceProperties feats; if (feats.shaderInt64) {} }\n"
                    "}\n"
                ),
                [],
            ),
            (
                "param_no_inner",
                ("void gate(VkPhysicalDeviceFeatures *p) {\n    if (p->shaderInt64) {}\n}\n"),
                [("shaderInt64", 2)],
            ),
            (
                "local_no_inner",
                (
                    "void gate(void) {\n"
                    "    VkPhysicalDeviceFeatures feats;\n"
                    "    if (feats.shaderInt64) {}\n"
                    "}\n"
                ),
                [("shaderInt64", 3)],
            ),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                pairs = [(s.feature, s.line) for s in sweep_vulkan_features.c_feature_reads(source)]
                self.assertEqual(pairs, expected)

    def test_cr15b_inner_arrow_ineligible_properties_excluded(self) -> None:
        """An inner-arrow chain ending at VkPhysicalDeviceProperties yields no feature site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Inner { VkPhysicalDeviceProperties features; } Inner;\n"
            "typedef struct Wrapper { Inner *inner; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->inner->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr15b_mixed_dot_inner_arrow_ineligible_excluded(self) -> None:
        """A dot-then-inner-arrow chain ending at VkPhysicalDeviceProperties yields no site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Inner { VkPhysicalDeviceProperties features; } Inner;\n"
            "typedef struct Holder { Inner *inner; } Holder;\n"
            "typedef struct Wrapper { Holder holder; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->holder.inner->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        self.assertEqual(sweep_vulkan_features.c_feature_reads(source), [])

    def test_cr15b_mixed_dot_inner_arrow_eligible_single_site(self) -> None:
        """A dot-then-inner-arrow chain through VkPhysicalDeviceFeatures yields one site."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "typedef struct Inner { VkPhysicalDeviceFeatures features; } Inner;\n"
            "typedef struct Holder { Inner *inner; } Holder;\n"
            "typedef struct Wrapper { Holder holder; } Wrapper;\n"
            "int gate(Wrapper *ctx) {\n"
            "    if (ctx->holder.inner->features.shaderInt64) return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")

    def test_cr10_b_minor_ineligible_struct_feature_read(self) -> None:
        """CR10 minor: allowlisted members read from unrelated structs do not satisfy gates."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        source = (
            "struct Other { VkBool32 shaderInt64; } other;\n"
            "VkPhysicalDeviceFeatures *feats;\n"
            "if (feats->shaderInt64 && other.shaderInt64) {}\n"
        )
        sites = sweep_vulkan_features.c_feature_reads(source)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].feature, "shaderInt64")
        needs = [
            sweep_vulkan_features.ShaderNeeds(
                "libavfilter/vulkan/b.comp.glsl",
                {"shaderInt64"},
                {"shaderInt64": "capability:Int64"},
            )
        ]
        rows = sweep_vulkan_features.compare_gates("libavfilter/vf_test_vulkan.c", sites, needs)
        self.assertEqual(rows, [])

    def test_cr10_b_nitpick_first_shader_match_cached_per_kind(self) -> None:
        """CR10 nitpick: repeated CPU mask sites reuse one first_shader_match lookup per kind."""
        calls: list[tuple[object, ...]] = []
        real = sweep_port_parity.first_shader_match

        def recorder(*args, **kwargs):
            calls.append(args)
            return real(*args, **kwargs)

        cpu = (
            "void f(const uint16_t *src, uint16_t *dst) {\n"
            "    dst[0] = src[0] & 0xFF00u;\n"
            "    dst[1] = src[1] & 0xFF00u;\n"
            "}\n"
        )
        c_vulkan = (
            "extern const unsigned char ff_test_comp_spv_data[];\nint f(void) { return 0; }\n"
        )
        head = self.commit_filter(
            c_vulkan=c_vulkan,
            shader_name="test.comp.glsl",
            shader=MASKED_SHADER,
            cpu=cpu,
        )
        match_patch = unittest.mock.patch.object(
            sweep_port_parity, "first_shader_match", side_effect=recorder
        )
        with match_patch:
            self.parity_report(head)
        self.assertEqual(len(calls), 1)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_r7_g4_sampled_array_no_storage_dynamic_row(self) -> None:
        """G4: dynamically indexed sampled-image arrays do not require storage-image indexing."""
        c_source = (
            "extern const unsigned char ff_test_comp_spv_data[];\n"
            "int gate(VkPhysicalDeviceFeatures *feats) {\n"
            "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        head = self.commit_filter(
            c_vulkan=c_source,
            shader_name="test.comp.glsl",
            shader=SAMPLED_DYNAMIC_SHADER,
        )
        report = self.vk_report(head)
        self.assertNotIn("shaderStorageImageArrayDynamicIndexing", report)

    def test_r7_g5_gate_row_anchor_shader_order(self) -> None:
        """G5: slash-free evidence anchors used-unchecked rows on the first linked shader need."""
        path_a = "libavfilter/vulkan/a.comp.glsl"
        path_b = "libavfilter/vulkan/b.comp.glsl"
        empty = sweep_vulkan_features.ShaderNeeds(path_a, set(), {})
        int64_b = sweep_vulkan_features.ShaderNeeds(
            path_b,
            {"shaderInt64"},
            {"shaderInt64": "capability:Int64"},
        )
        c_path = "libavfilter/vf_test_vulkan.c"
        rows = sweep_vulkan_features.compare_gates(c_path, [], [empty, int64_b])
        self.assertEqual(rows[0][0], f"{path_b}:1")
        rows_b = sweep_vulkan_features.compare_gates(c_path, [], [int64_b])
        self.assertEqual(rows_b[0][0], f"{path_b}:1")
        int64_a = sweep_vulkan_features.ShaderNeeds(
            path_a,
            {"shaderInt64"},
            {"shaderInt64": "capability:Int64"},
        )
        int64_b2 = sweep_vulkan_features.ShaderNeeds(
            path_b,
            {"shaderInt64"},
            {"shaderInt64": "capability:Int64"},
        )
        rows_both = sweep_vulkan_features.compare_gates(c_path, [], [int64_a, int64_b2])
        self.assertEqual(rows_both[0][0], f"{path_a}:1")

    def test_t6_second_linked_shader_mask_site(self) -> None:
        """t6: port-parity names the second linked shader when only it applies the mask."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFF00u; (void)v; }\n"
        c_vulkan = (
            "extern const unsigned char ff_a_comp_spv_data[];\n"
            "extern const unsigned char ff_b_comp_spv_data[];\n"
            "int f(void) { return 0; }\n"
        )
        (self.repo / "libavfilter" / "vf_test_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vf_test.c").write_text(cpu, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / "a.comp.glsl").write_text(
            MASK_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "b.comp.glsl").write_text(
            SECOND_MASKED_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        report = self.parity_report(head)
        self.assertRegex(report, r"libavfilter/vulkan/b\.comp\.glsl:\d+")


class VulkanFullReportTest(unittest.TestCase):
    """Validate full reports that include the new sweep sections."""

    setUp = fixtures.VariantSweepTest.setUp
    commit_head = fixtures.VariantSweepTest.commit_head
    sweep = fixtures.VariantSweepTest.sweep

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_full_report_sections_and_validation(self) -> None:
        """A full sweep renders both new sections and refuses unresolved TODO rows."""
        head = self.commit_head("int f(void) { return 0; }\n")
        result = self.sweep(head, "all")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.output.read_text(encoding="utf-8")
        self.assertIn("class: vulkan-features", report)
        self.assertIn("class: port-parity", report)
        with self.assertRaisesRegex(RuntimeError, "review-classes:|TODO"):
            variant_sweep.validate_full_report(self.output, head)
        cleaned = report.replace("| TODO |", "| no-variant: fixture |")
        self.output.write_text(cleaned, encoding="utf-8")
        self.assertTrue(variant_sweep.validate_full_report(self.output, head))


class MutantLoaderTest(unittest.TestCase):
    """Exercise the source anchor contract independently of the Vulkan tools."""

    def test_cr22_mutant_anchor_exact_once(self) -> None:
        """Reject missing and repeated anchors and load a unique mutation."""
        rel_path = "scripts/sweep_vulkan_features.py"
        source = (Path(__file__).resolve().parents[1] / rel_path).read_text(encoding="utf-8")
        missing = "MUTANT_LOADER_MISSING_ANCHOR"
        repeated = "\n    return "
        unique = "MAX_DIAGNOSTIC = 160"
        self.assertEqual(source.count(missing), 0)
        repeated_count = source.count(repeated)
        self.assertGreaterEqual(repeated_count, 2)
        self.assertEqual(source.count(unique), 1)
        cases = (
            ("missing", missing, missing, 0),
            ("repeated", repeated, repeated, repeated_count),
            ("unique", unique, "MAX_DIAGNOSTIC = 161", 1),
        )
        for label, old, new, count in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as scratch:
                if count == 1:
                    module = load_mutant_module(rel_path, old, new, Path(scratch))
                    self.assertEqual(module.MAX_DIAGNOSTIC, 161)
                else:
                    with self.assertRaises(RuntimeError) as error:
                        load_mutant_module(rel_path, old, new, Path(scratch))
                    self.assertEqual(
                        str(error.exception),
                        f"{rel_path}: expected one mutation anchor, found {count}",
                    )


class VulkanMutantHarness(unittest.TestCase):
    """Shared synthetic repository setup for planted mutant checks."""

    setUp = VulkanSweepTest.setUp
    commit_filter = VulkanSweepTest.commit_filter
    vk_report = VulkanSweepTest.vk_report
    parity_report = VulkanSweepTest.parity_report

    def assert_mutant_kills(
        self,
        rel_path: str,
        old: str,
        new: str,
        real_check: Callable[[], None],
        mutant_check: Callable[[ModuleType], None],
    ) -> None:
        """Assert the real module passes a check and the mutant copy fails it."""
        real_check()
        with tempfile.TemporaryDirectory() as scratch:
            mutant = load_mutant_module(rel_path, old, new, Path(scratch))
            mutant_check(mutant)


class PortParityMutantTest(VulkanMutantHarness):
    """Run port-parity mutants without requiring the Vulkan toolchain."""

    def test_mutant_m4_shader_mask(self) -> None:
        """m4: disabling shader mask matching passes on real and fails on mutant."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFFF0u; (void)v; }\n"
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
            ),
            shader_name="test.comp.glsl",
            shader=MASKED_SHADER,
            cpu=cpu,
        )

        def real() -> None:
            self.assertRegex(self.parity_report(head), r"libavfilter/vulkan/test\.comp\.glsl:\d+")

        def mutant(module: ModuleType) -> None:
            report = module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)
            self.assertRegex(report, r"\| mask \| none \|")

        self.assert_mutant_kills(
            "scripts/sweep_port_parity.py",
            "if _load_normalized(",
            "if False and _load_normalized(",
            real,
            mutant,
        )

    def test_mutant_m5_pair_limit_slice(self) -> None:
        """m5: slicing before the pair limit passes on real and fails on mutant."""
        for stem in ("one", "two"):
            (self.repo / "libavfilter" / f"vf_{stem}.c").write_text(
                f"void f_{stem}(void){{}}\n", encoding="utf-8"
            )
            (self.repo / "libavfilter" / f"vf_{stem}_vulkan.c").write_text(
                "int vk(void){return 0;}\n", encoding="utf-8"
            )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")

        def real() -> None:
            with (
                unittest.mock.patch.object(sweep_port_parity, "MAX_PAIRS", 1),
                self.assertRaisesRegex(RuntimeError, "filter pair count"),
            ):
                sweep_port_parity.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

        def mutant(module: ModuleType) -> None:
            module.MAX_PAIRS = 1
            module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)

        slice_mutant_old = (
            '    check_limit("filter pair count", len(stems), MAX_PAIRS)\n'
            "    stems_sorted = sorted(stems)\n"
            "    existing = pair_paths_at_head(directory, head, stems_sorted, deadline)"
        )
        slice_mutant_new = (
            "    stems_sorted = sorted(stems)[:MAX_PAIRS]\n"
            "    existing = pair_paths_at_head(directory, head, stems_sorted, deadline)"
        )
        self.assert_mutant_kills(
            "scripts/sweep_port_parity.py",
            slice_mutant_old,
            slice_mutant_new,
            real,
            mutant,
        )

    def test_mutant_m6_first_shader_only(self) -> None:
        """m6: reading only the first linked shader passes on real and fails on mutant."""
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFF00u; (void)v; }\n"
        c_vulkan = (
            "extern const unsigned char ff_a_comp_spv_data[];\n"
            "extern const unsigned char ff_b_comp_spv_data[];\n"
            "int f(void) { return 0; }\n"
        )
        (self.repo / "libavfilter" / "vf_test_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vf_test.c").write_text(cpu, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / "a.comp.glsl").write_text(
            MASK_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "b.comp.glsl").write_text(
            SECOND_MASKED_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")

        def real() -> None:
            self.assertRegex(self.parity_report(head), r"libavfilter/vulkan/b\.comp\.glsl:\d+")

        def mutant(module: ModuleType) -> None:
            report = module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)
            self.assertRegex(report, r"\| mask \| none \|")

        self.assert_mutant_kills(
            "scripts/sweep_port_parity.py",
            "    for shader_path in sorted(shaders):",
            "    for shader_path in sorted(shaders)[:1]:",
            real,
            mutant,
        )


class VulkanMutantTest(VulkanMutantHarness):
    """Run planted mutants on temporary module copies without editing scripts/."""

    @classmethod
    def setUpClass(cls) -> None:
        """Skip the suite when the Vulkan toolchain is unavailable."""
        if SKIP_VULKAN:
            raise unittest.SkipTest(SKIP_REASON)

    def test_mutant_m1_required_unused(self) -> None:
        """m1: disabling required-unused detection passes on real and fails on mutant."""
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\n"
                "int gate(VkPhysicalDeviceVulkan12Features *v12) {\n"
                "    if (!v12->runtimeDescriptorArray) return -1;\n"
                "    if (!v12->scalarBlockLayout) return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )

        def real() -> None:
            self.assertIn("| required-unused |", self.vk_report(head))

        def mutant(module: ModuleType) -> None:
            report = module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)
            self.assertNotIn("| required-unused |", report)

        required_branch = (
            "elif (\n"
            "            fully_analyzed\n"
            "            and site.feature not in used\n"
            "            and not anyof_group_satisfied(site.feature, used, checked_names)"
        )
        self.assert_mutant_kills(
            "scripts/sweep_vulkan_features.py",
            required_branch,
            required_branch.replace("fully_analyzed", "False and fully_analyzed", 1),
            real,
            mutant,
        )

    def test_mutant_m2_dynamic_index(self) -> None:
        """m2: disabling dynamic index detection passes on real and fails on mutant."""
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\n"
                "int gate(VkPhysicalDeviceFeatures *feats) {\n"
                "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
            shader_name="test.comp.glsl",
            shader=DYNAMIC_SHADER,
        )

        def real() -> None:
            self.assertIn("| used-unchecked |", self.vk_report(head))

        def mutant(module: ModuleType) -> None:
            report = module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)
            self.assertNotIn("| used-unchecked |", report)

        self.assert_mutant_kills(
            "scripts/sweep_vulkan_features.py",
            'if index not in constants and not index.startswith("%int_"):',
            'if False and index not in constants and not index.startswith("%int_"):',
            real,
            mutant,
        )

    def test_mutant_m3_spirv_scalar(self) -> None:
        """m3: disabling scalar layout detection passes on real and fails on mutant."""
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\n"
                "int gate(VkPhysicalDeviceFeatures *feats,\n"
                "        VkPhysicalDeviceVulkan12Features *v12) {\n"
                "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
                "    if (!v12->runtimeDescriptorArray) return -1;\n"
                "    if (!v12->scalarBlockLayout) return -1;\n"
                "    if (!v12->shaderStorageImageArrayNonUniformIndexing) return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
            shader_name="test.comp.glsl",
            shader=MATCHED_SHADER,
        )

        def real() -> None:
            self.assertIn("no hits", self.vk_report(head))

        def mutant(module: ModuleType) -> None:
            report = module.sweep(str(self.repo), self.base, head, time.monotonic() + 120)
            self.assertNotIn("no hits", report)

        self.assert_mutant_kills(
            "scripts/sweep_vulkan_features.py",
            "return default_rc != 0 and result.returncode == 0",
            "return False",
            real,
            mutant,
        )

    def exec_source_copy(self, missing: Path, tail: str) -> None:
        """Execute a fresh copy of the sweep module with VK_XML replaced and tail appended."""
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts/sweep_vulkan_features.py").read_text(encoding="utf-8")
        old = 'VK_XML = Path("/usr/share/vulkan/registry/vk.xml")'
        self.assertIn(old, source)
        source = source.replace(old, f'VK_XML = Path("{missing}")')
        if tail:
            source = source.rstrip() + "\n" + tail
        with tempfile.TemporaryDirectory() as scratch:
            copy_path = Path(scratch) / "sweep_vulkan_features_copy.py"
            copy_path.write_text(source, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("sweep_vulkan_features_copy", copy_path)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

    def test_mutant_m7_import_maps(self) -> None:
        """m7: import-time map load passes on real and fails on mutant."""
        missing = Path("/nonexistent/vk-registry-mutant/vk.xml")

        def real() -> None:
            reset_vulkan_maps()
            with unittest.mock.patch.object(sweep_vulkan_features, "VK_XML", missing):
                head = self.commit_filter(
                    c_vulkan=(
                        "extern const unsigned char ff_test_comp_spv_data[];\n"
                        "int f(void){return 0;}\n"
                    ),
                    shader_name="test.comp.glsl",
                    shader=SIMPLE_SHADER,
                )
                with self.assertRaisesRegex(
                    sweep_vulkan_features.VulkanFeatureSweepError,
                    f"missing vk.xml: {missing}",
                ):
                    sweep_vulkan_features.sweep(
                        str(self.repo), self.base, head, time.monotonic() + 120
                    )
            reset_vulkan_maps()
            self.exec_source_copy(missing, "")

        def mutant(_module: ModuleType) -> None:
            tail = (
                "ALLOWLIST, CAPABILITY_MAP, FEATURE_ALLOWLIST = load_maps(VK_XML)\n"
                "DERIVABLE = derivable_features(CAPABILITY_MAP)\n_MAPS_LOADED = True\n"
            )
            with self.assertRaises(
                (FileNotFoundError, sweep_vulkan_features.VulkanFeatureSweepError)
            ):
                self.exec_source_copy(missing, tail)

        self.assert_mutant_kills(
            "scripts/sweep_vulkan_features.py",
            "MAP_STATE = VulkanMapState()",
            "MAP_STATE = VulkanMapState()",
            real,
            mutant,
        )


class PortParityWithoutToolsTest(VulkanMutantHarness):
    """Prove port-parity survives missing Vulkan binaries while feature sweeps do not."""

    def test_port_parity_second_shader_with_hidden_tools(self) -> None:
        """Port-parity names the second linked shader when tool paths are patched away."""
        missing = Path(self.directory.name) / "no-vulkan-tool"
        cpu = "void f(const uint16_t *src) { uint16_t v = src[0] & 0xFF00u; (void)v; }\n"
        c_vulkan = (
            "extern const unsigned char ff_a_comp_spv_data[];\n"
            "extern const unsigned char ff_b_comp_spv_data[];\n"
            "int f(void) { return 0; }\n"
        )
        (self.repo / "libavfilter" / "vf_test_vulkan.c").write_text(c_vulkan, encoding="utf-8")
        (self.repo / "libavfilter" / "vf_test.c").write_text(cpu, encoding="utf-8")
        (self.repo / "libavfilter" / "vulkan" / "a.comp.glsl").write_text(
            MASK_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "vulkan" / "b.comp.glsl").write_text(
            SECOND_MASKED_SHADER, encoding="utf-8"
        )
        (self.repo / "libavfilter" / "fix.c").write_text(
            (self.repo / "libavfilter" / "fix.c").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        run_git(self.repo, "add", ".")
        run_git(self.repo, "commit", "-qm", "head")
        head = run_git(self.repo, "rev-parse", "HEAD")
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "GLSLANG", missing),
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_DIS", missing),
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_VAL", missing),
        ):
            report = self.parity_report(head)
        self.assertRegex(report, r"libavfilter/vulkan/b\.comp\.glsl:\d+")

    def test_vk_report_raises_with_hidden_tools(self) -> None:
        """Vulkan-feature sweep raises when tool paths are patched away."""
        missing = Path(self.directory.name) / "no-vulkan-tool"
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\nint f(void){return 0;}\n"
            ),
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )
        bind_g3_maps_fixture(self)
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "GLSLANG", missing),
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_DIS", missing),
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_VAL", missing),
            self.assertRaises(sweep_vulkan_features.VulkanFeatureSweepError) as caught,
        ):
            self.vk_report(head)
        message = str(caught.exception)
        self.assertIn("missing tool:", message)
        self.assertIn(str(missing), message)


class VulkanUnvalidatedShaderTest(unittest.TestCase):
    """Cover arrow scan start, typedef aliases, and unvalidated shader reporting."""

    setUp = VulkanSweepTest.setUp
    commit_filter = VulkanSweepTest.commit_filter
    vk_report = VulkanSweepTest.vk_report

    def write_tool(self) -> Path:
        """Create an empty file that stands in for an installed spirv-val."""
        tool = Path(self.directory.name) / "spirv-val"
        tool.write_bytes(b"")
        return tool

    def run_scalar(self, *results: tuple[int, bytes]) -> bool:
        """Run spirv_needs_scalar with scripted spirv-val results and return its verdict."""
        spv = Path(self.directory.name) / "m.spv"
        spv.write_bytes(b"")
        done = [subprocess.CompletedProcess(["x"], rc, b"", err) for rc, err in results]
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_VAL", self.write_tool()),
            unittest.mock.patch.object(sweep_vulkan_features.subprocess, "run", side_effect=done),
        ):
            return sweep_vulkan_features.spirv_needs_scalar(spv, time.monotonic() + 120)

    def alias_sites(self, source: str) -> list[sweep_vulkan_features.FeatureSite]:
        """Return feature read sites for one source under the minimal vk.xml fixture."""
        self.addCleanup(reset_vulkan_maps)
        ensure_maps_fixture()
        return sweep_vulkan_features.c_feature_reads(source)

    def test_arrow_match_starts_at_arrow(self) -> None:
        """FEATURE_READ starts a spaced arrow match at the arrow, not at the blanks."""
        text = "p   ->shaderInt64"
        match = sweep_vulkan_features.FEATURE_READ.search(text)
        self.assertIsNotNone(match)
        self.assertEqual(match.start(), text.index("-"))

    def test_spaced_and_split_arrow_reads(self) -> None:
        """A spaced arrow reports its line and a split arrow reports the arrow line."""
        spaced = "int g(VkPhysicalDeviceFeatures *p) {\n    return p -> shaderInt64;\n}\n"
        split = (
            "int g(VkPhysicalDeviceFeatures *feats) {\n"
            "    return feats\n"
            "        ->shaderInt64;\n"
            "}\n"
        )
        feature = sweep_vulkan_features.FeatureSite
        self.assertEqual(self.alias_sites(spaced), [feature(2, "shaderInt64")])
        self.assertEqual(self.alias_sites(split), [feature(3, "shaderInt64")])

    def test_long_masked_comment_without_member_access(self) -> None:
        """A very long block comment without member access yields no read sites."""
        source = "/*" + "a" * 20000 + "*/\nint x;\n"
        self.assertEqual(self.alias_sites(source), [])

    def test_typedef_alias_direct_read(self) -> None:
        """A direct read through a typedef alias of the feature struct is reported."""
        source = (
            "typedef VkPhysicalDeviceFeatures GateFeatures;\n"
            "\n"
            "int gate(const GateFeatures *p) {\n"
            "    return p->shaderInt64 ? 0 : -1;\n"
            "}\n"
        )
        feature = sweep_vulkan_features.FeatureSite
        self.assertEqual(self.alias_sites(source), [feature(4, "shaderInt64")])

    def test_typedef_alias_two_steps(self) -> None:
        """An alias of an alias of the feature struct still resolves to one site."""
        source = (
            "typedef VkPhysicalDeviceFeatures StepA;\n"
            "typedef StepA StepB;\n"
            "int gate(const StepB *p) {\n"
            "    return p->shaderInt64 ? 0 : -1;\n"
            "}\n"
        )
        self.assertEqual(len(self.alias_sites(source)), 1)

    def test_typedef_alias_of_other_types_rejected(self) -> None:
        """Aliases of other Vk structs and of unrelated types stay rejected."""
        props = (
            "typedef VkPhysicalDeviceProperties GateProps;\n"
            "int gate(const GateProps *p) {\n"
            "    return p->shaderInt64 ? 0 : -1;\n"
            "}\n"
        )
        flags = (
            "typedef int Flags;\n"
            "int gate(const Flags *p) {\n"
            "    return p->shaderInt64 ? 0 : -1;\n"
            "}\n"
        )
        self.assertEqual(self.alias_sites(props), [])
        self.assertEqual(self.alias_sites(flags), [])

    def test_absent_spirv_val_is_prerequisite(self) -> None:
        """An absent spirv-val raises the missing-tool prerequisite error."""
        missing = Path(self.directory.name) / "no-spirv-val"
        spv = Path(self.directory.name) / "m.spv"
        spv.write_bytes(b"")
        with (
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_VAL", missing),
            self.assertRaisesRegex(
                sweep_vulkan_features.VulkanFeatureSweepError, "missing tool:"
            ) as caught,
        ):
            sweep_vulkan_features.spirv_needs_scalar(spv, time.monotonic() + 120)
        self.assertIsInstance(caught.exception, variant_sweep.SweepPrerequisiteError)

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_absent_spirv_val_keeps_port_parity_section(self) -> None:
        """A full sweep records the missing spirv-val and still runs port-parity."""
        self.addCleanup(reset_vulkan_maps)
        reset_vulkan_maps()
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\n"
                "int gate(VkPhysicalDeviceFeatures *feats) {\n"
                "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )
        missing = Path(self.directory.name) / "no-spirv-val"
        loader = variant_sweep.sibling_module

        def share_module(name: str) -> ModuleType:
            if name == "sweep_vulkan_features":
                return sweep_vulkan_features
            return loader(name)

        with (
            unittest.mock.patch.object(sweep_vulkan_features, "SPIRV_VAL", missing),
            unittest.mock.patch.object(variant_sweep, "sibling_module", share_module),
        ):
            report = variant_sweep.sweep_all(str(self.repo), self.base, head)
        self.assertIn("prerequisite: missing tool:", section(report, "vulkan-features"))
        self.assertIn("class: port-parity", report)

    def test_both_layouts_rejected_raises_with_diagnostic(self) -> None:
        """Rejection in both layout modes raises with the scalar-run stderr line."""
        with self.assertRaises(sweep_vulkan_features.ShaderValidationError) as caught:
            self.run_scalar((1, b"default failure\n"), (1, b"\n  error: line 69: bad type\nmore\n"))
        self.assertIn("error: line 69: bad type", str(caught.exception))
        self.assertNotIn("default failure", str(caught.exception))
        self.assertNotIn("more", str(caught.exception))

    def test_diagnostic_is_bounded_and_table_safe(self) -> None:
        """A long stderr line with a pipe yields at most 160 characters and no pipe."""
        pipe_index = 80
        line = ("x" * pipe_index + "|" + "y" * 300).encode()
        with self.assertRaises(sweep_vulkan_features.ShaderValidationError) as caught:
            self.run_scalar((1, b"a\n"), (1, line + b"\n"))
        self.assertLessEqual(len(str(caught.exception)), 160)
        self.assertNotIn("|", str(caught.exception))
        self.assertEqual(str(caught.exception)[pipe_index], "/")

    def test_scalar_verdicts_unchanged(self) -> None:
        """Default-fail then scalar-pass needs scalar; both passing does not."""
        self.assertTrue(self.run_scalar((1, b"e\n"), (0, b"")))
        self.assertFalse(self.run_scalar((0, b""), (0, b"")))

    def test_compare_gates_unanalyzed_rows(self) -> None:
        """Each shader with a diagnostic adds one unanalyzed row after the other rows."""
        needs = sweep_vulkan_features.ShaderNeeds
        row = sweep_vulkan_features.compare_gates(
            "libavfilter/vf_test_vulkan.c",
            [],
            [needs("libavfilter/vulkan/a.comp.glsl", set(), {}, "diag")],
        )
        self.assertEqual(
            row,
            [
                (
                    "libavfilter/vulkan/a.comp.glsl:1",
                    "scalarBlockLayout",
                    "spirv-val rejected both layouts: diag",
                    "unanalyzed",
                )
            ],
        )
        rows = sweep_vulkan_features.compare_gates(
            "libavfilter/vf_test_vulkan.c",
            [],
            [
                needs("libavfilter/vulkan/b.comp.glsl", set(), {}, "second"),
                needs("libavfilter/vulkan/a.comp.glsl", set(), {}, "first"),
                needs("libavfilter/vulkan/c.comp.glsl", {"shaderInt64"}, {}, ""),
            ],
        )
        self.assertEqual(
            [(r[0], r[3]) for r in rows],
            [
                ("libavfilter/vulkan/c.comp.glsl:1", "used-unchecked"),
                ("libavfilter/vulkan/a.comp.glsl:1", "unanalyzed"),
                ("libavfilter/vulkan/b.comp.glsl:1", "unanalyzed"),
            ],
        )

    @unittest.skipIf(SKIP_VULKAN, SKIP_REASON)
    def test_sweep_reports_unanalyzed_when_spirv_val_rejects(self) -> None:
        """A sweep whose spirv-val rejects both modes reports one unanalyzed row."""
        self.addCleanup(reset_vulkan_maps)
        reset_vulkan_maps()
        head = self.commit_filter(
            c_vulkan=(
                "extern const unsigned char ff_test_comp_spv_data[];\n"
                "int gate(VkPhysicalDeviceFeatures *feats) {\n"
                "    if (!feats->shaderStorageImageReadWithoutFormat) return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
            shader_name="test.comp.glsl",
            shader=SIMPLE_SHADER,
        )
        real_run = subprocess.run

        def wrapper(argv, *args, **kwargs):
            if argv[0] == str(SPIRV_VAL):
                return subprocess.CompletedProcess(argv, 1, b"", b"error: planted rejection\n")
            return real_run(argv, *args, **kwargs)

        with unittest.mock.patch.object(sweep_vulkan_features.subprocess, "run", wrapper):
            report = self.vk_report(head)
        rows = [line for line in report.splitlines() if "| unanalyzed |" in line]
        self.assertEqual(len(rows), 1, report)
        self.assertIn("libavfilter/vulkan/test.comp.glsl:1", rows[0])
        self.assertIn("planted rejection", rows[0])
        self.assertNotIn("prerequisite:", report)


if __name__ == "__main__":
    unittest.main()
