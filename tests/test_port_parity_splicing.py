"""Regression tests for physical line splicing in port-parity shaders."""

import unittest

from scripts.sweep_port_parity import shader_site


class PortParitySplicingTests(unittest.TestCase):
    """Check reachable normalization and physical load anchors after line splicing."""

    def test_clamp_requires_load_in_value_argument(self) -> None:
        """Nested commas do not split clamp arguments, and bounds do not count."""
        for newline in ("\n", "\r\n", "\r"):
            for spliced in (False, True):
                read = "imageLoad(img, ivec2(0)).r"
                if spliced:
                    read = "image" + chr(92) + newline + "Load(img, ivec2(0)).r"
                for expr, expected in (
                    (f"clamp({read}, 0u, 7u)", "fixture.frag:7"),
                    (f"clamp((pick(({read}), 0u)), 0u, 7u)", "fixture.frag:7"),
                    (f"clamp(0u, {read}, 0xffffffffu)", None),
                    (f"clamp(0u, 0u, {read})", None),
                    (f"clamp(0u, 0u, (pick(({read}), 0u)))", None),
                ):
                    with self.subTest(newline=repr(newline), spliced=spliced, expr=expr):
                        source = newline.join(
                            (
                                "#version 450",
                                "layout(binding=0,r32ui) readonly uniform uimage2D img;",
                                "layout(location=0) out uint color;",
                                "uint pick(uint x, uint y) { return x + y; }",
                                "void main() {",
                                "    color =",
                                f"        {expr};",
                                "}",
                            )
                        )
                        self.assertEqual(shader_site("fixture.frag", source, "clamp"), expected)

    def test_continued_comments_hide_apparent_directives(self) -> None:
        """A real overwrite kills the load; a commented overwrite does not."""
        for newline in ("\n", "\r\n", "\r"):
            for overwrite in (True, False):
                with self.subTest(newline=repr(newline), overwrite=overwrite):
                    source = newline.join(
                        (
                            "#version 450",
                            "layout(binding=0,r32ui) readonly uniform uimage2D img;",
                            "layout(location=0) out uint color;",
                            "void main() {",
                            "    uint px = imageLoad(img, ivec2(0)).r;",
                            "    // continued comment " + chr(92),
                            "#if 0",
                            "    px = 0u;" if overwrite else "    // px = 0u;",
                            "    // continued comment " + chr(92),
                            "#endif",
                            "    color = px & 0xffu;",
                            "}",
                        )
                    )
                    self.assertEqual(
                        shader_site("fixture.frag", source, "mask"),
                        None if overwrite else "fixture.frag:5",
                    )

    def test_trailing_comment_splice_preserves_blank_line(self) -> None:
        """The blank line ends the comment, leaving the next statement live."""
        for newline in ("\n", "\r\n", "\r"):
            for early_return in (True, False):
                with self.subTest(newline=repr(newline), early_return=early_return):
                    source = newline.join(
                        (
                            "#version 450",
                            "layout(binding=0,r32ui) readonly uniform uimage2D img;",
                            "layout(location=0) out uint color;",
                            "void main() {",
                            "    // comment " + chr(92),
                            "",
                            "    return;" if early_return else "    // return;",
                            "    color = imageLoad(img, ivec2(0)).r & 0xffu;",
                            "}",
                        )
                    )
                    self.assertEqual(
                        shader_site("fixture.frag", source, "mask"),
                        None if early_return else "fixture.frag:8",
                    )

    def test_spliced_directive_preserves_later_load_anchor(self) -> None:
        """A real continued directive masks the dead load, not the later load."""
        source = "\n".join(
            (
                "#version 450",
                "layout(binding=0,r32ui) readonly uniform uimage2D img;",
                "layout(location=0) out uint color;",
                "void main() {",
                "#if " + chr(92),
                "0",
                "    color = imageLoad(img, ivec2(1)).r & 0xffu;",
                "#endif",
                "    color = imageLoad(img, ivec2(0)).r & 0xffu;",
                "}",
            )
        )
        self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:9")
