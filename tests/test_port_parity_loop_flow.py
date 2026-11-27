"""Regression tests for loop flow in port-parity shaders."""

import unittest

from scripts.sweep_port_parity import shader_site

_FIXTURE = """#version 460
layout(set = 0, binding = 0, r32ui) uniform uimage2D img;
layout(location = 0) out uint color;
void main() {
    uint px = 0u;
    do {
        color = px & 0xffu;
        px = imageLoad(img, ivec2(0)).r;
    } while (false);
}
"""


class PortParityLoopFlowTests(unittest.TestCase):
    """Check do-loop back edges and physical load anchors."""

    def test_false_tail_does_not_revisit_body(self) -> None:
        """A false tail prevents the load from reaching the earlier mask use."""
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                source = _FIXTURE.replace("\n", newline)
                self.assertIsNone(shader_site("fixture.frag", source, "mask"))

    def test_true_and_unknown_tails_can_revisit_body(self) -> None:
        """True and unknown tails let the load reach the next iteration's mask use."""
        for condition in ("true", "gl_FragCoord.x > 0.0"):
            with self.subTest(condition=condition):
                source = _FIXTURE.replace("while (false)", f"while ({condition})")
                self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:8")

    def test_false_tail_still_reaches_post_loop_use(self) -> None:
        """A false tail still lets the load reach a mask use after the loop."""
        source = _FIXTURE.replace(
            "    } while (false);", "    } while (false);\n    color = px & 0xffu;"
        )
        self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:8")

    def test_spliced_macro_keeps_possible_back_edge_and_physical_anchor(self) -> None:
        """A spliced tail macro preserves the back edge and physical load line."""
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                source = _FIXTURE.replace(
                    "#version 460\n", "#version 460\n#define AGAIN " + chr(92) + "\ntrue\n"
                ).replace("while (false)", "while (AGAIN)")
                self.assertEqual(
                    shader_site("fixture.frag", source.replace("\n", newline), "mask"),
                    "fixture.frag:10",
                )
