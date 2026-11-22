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
SKIP_VULKAN = not all(tool.is_file() for tool in (GLSLANG, SPIRV_DIS, SPIRV_VAL))
SKIP_REASON = "Vulkan toolchain binaries missing under /usr/bin"

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


def load_mutant_module(rel_path: str, old: str, new: str, tmp: Path) -> ModuleType:
    """Load one mutated sweep module copy from a temporary directory."""
    root = Path(__file__).resolve().parents[1]
    source = (root / rel_path).read_text(encoding="utf-8")
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
            "if pattern.search(window):",
            "if False and pattern.search(window):",
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
            "elif site.feature not in used and not anyof_group_satisfied(\n"
            "            site.feature, used, checked_names\n"
            "        ):"
        )
        self.assert_mutant_kills(
            "scripts/sweep_vulkan_features.py",
            required_branch,
            required_branch.replace("elif site", "elif False and site", 1),
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

        def mutant(_module: ModuleType) -> None:
            root = Path(__file__).resolve().parents[1]
            source = (root / "scripts/sweep_vulkan_features.py").read_text(encoding="utf-8")
            source = source.replace(
                'VK_XML = Path("/usr/share/vulkan/registry/vk.xml")',
                f'VK_XML = Path("{missing}")',
            )
            source = (
                source.rstrip()
                + "\nALLOWLIST, CAPABILITY_MAP, FEATURE_ALLOWLIST = load_maps(VK_XML)\n"
                "DERIVABLE = derivable_features(CAPABILITY_MAP)\n_MAPS_LOADED = True\n"
            )
            with tempfile.TemporaryDirectory() as scratch:
                mutant_path = Path(scratch) / "sweep_vulkan_features_mutant.py"
                mutant_path.write_text(source, encoding="utf-8")
                spec = importlib.util.spec_from_file_location(
                    "sweep_vulkan_features_mutant", mutant_path
                )
                self.assertIsNotNone(spec)
                self.assertIsNotNone(spec.loader)
                module = importlib.util.module_from_spec(spec)
                with self.assertRaises(
                    (FileNotFoundError, sweep_vulkan_features.VulkanFeatureSweepError)
                ):
                    spec.loader.exec_module(module)

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


if __name__ == "__main__":
    unittest.main()
