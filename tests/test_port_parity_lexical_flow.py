"""Regression tests for GLSL lexical flow and physical load anchors."""

import unittest

from scripts.sweep_port_parity import shader_site


class PortParityLexicalFlowTests(unittest.TestCase):
    """Check load provenance after line splicing and directive masking."""

    def test_spliced_load_identifier(self) -> None:
        """A mask use anchors to the spliced load's first line only if it uses the load."""
        for newline in ("\n", "\r\n", "\r"):
            for use, expected in (("px & 0xffu", "fixture.frag:5"), ("0xffu", None)):
                with self.subTest(newline=repr(newline), use=use):
                    source = newline.join(
                        (
                            "#version 460",
                            "layout(set = 0, binding = 0, r32ui) uniform uimage2D img;",
                            "layout(location = 0) out uint color;",
                            "void main() {",
                            "    uint px = imageLo" + chr(92),
                            "ad(img, ivec2(0)).r;",
                            f"    color = {use};",
                            "}",
                            "",
                        )
                    )
                    self.assertEqual(shader_site("fixture.frag", source, "mask"), expected)

    def test_commented_conditional_preserves_feasible_arms(self) -> None:
        """A trailing comment keeps an unknown arm feasible and a false arm excluded."""
        for condition, expected in (("0", "fixture.frag:9"), ("FEATURE", "fixture.frag:6")):
            with self.subTest(condition=condition):
                source = "\n".join(
                    (
                        "#version 460",
                        "layout(set = 0, binding = 0, r32ui) uniform uimage2D img;",
                        "layout(location = 0) out uint color;",
                        "void main() {",
                        f"#if {condition} // conditional load",
                        "    uint dead = imageLoad(img, ivec2(1)).r;",
                        "    color = dead & 0xffu;",
                        "#endif",
                        "    uint px = imageLoad(img, ivec2(0)).r;",
                        "    color = px & 0xffu;",
                        "}",
                        "",
                    )
                )
                self.assertEqual(shader_site("fixture.frag", source, "mask"), expected)

    def test_block_comment_in_if_preserves_live_load(self) -> None:
        """A true condition split by a block comment keeps its load reachable."""
        source = """#version 460
layout(set = 0, binding = 0, r32ui) uniform readonly uimage2D img;
layout(location = 0) out uint color;
void main() {
    color = 0u;
#if 0 /* note
*/ || 1
    ;
    color = imageLoad(img, ivec2(0)).r & 0xffu;
#endif
}
"""
        self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:9")

    def test_block_comment_in_if_excludes_dead_overwrite(self) -> None:
        """A false condition split by a block comment cannot kill the live load."""
        source = """#version 460
layout(set = 0, binding = 0, r32ui) uniform readonly uimage2D img;
layout(location = 0) out uint color;
void main() {
    uint px = imageLoad(img, ivec2(0)).r;
#if 1 /* note
*/ && 0
    ;
    px = 0u;
#endif
    color = px & 0xffu;
}
"""
        self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:5")

    def test_dead_commented_arm_is_not_a_match(self) -> None:
        """A block comment after #if 0 does not make the disabled load match."""
        source = "\n".join(
            (
                "#version 460",
                "layout(set = 0, binding = 0, r32ui) uniform uimage2D img;",
                "layout(location = 0) out uint color;",
                "void main() {",
                "#if 0 /* disabled */",
                "    color = imageLoad(img, ivec2(0)).r & 0xffu;",
                "#endif",
                "    color = 0u;",
                "}",
                "",
            )
        )
        self.assertIsNone(shader_site("fixture.frag", source, "mask"))
