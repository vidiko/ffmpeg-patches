"""Regression tests for port-parity switch reachability."""

import unittest

from scripts.sweep_port_parity import shader_site

_HEADER = (
    "#version 460",
    "layout(set = 0, binding = 0, r32ui) uniform uimage2D img;",
    "layout(location = 0) out uint color;",
    "void main() {",
)


class PortParitySwitchFlowTests(unittest.TestCase):
    """Check switch entries, fallthrough, and physical load anchors."""

    def test_mixed_integer_labels(self) -> None:
        """A constant selects one entry; an unknown value keeps both entries."""
        for selector, breaker, define, expected in (
            ("0u", "px = 0u; break;", None, None),
            ("0u", "", None, "fixture.frag:5"),
            ("1u", "px = 0u; break;", None, "fixture.frag:5"),
            ("uint(gl_FragCoord.x)", "px = 0u; break;", None, "fixture.frag:5"),
            ("0u", "px = 0u; break;", "#define UNUSED 1", "fixture.frag:6"),
        ):
            with self.subTest(selector=selector, breaker=breaker, define=define):
                header = _HEADER if define is None else (_HEADER[0], define, *_HEADER[1:])
                source = "\n".join(
                    (
                        *header,
                        "    uint px = imageLoad(img, ivec2(0)).r;",
                        f"    switch ({selector}) {{",
                        f"        case 0u: {breaker}",
                        "        case 1: color = px & 0xffu; break;",
                        "    }",
                        "}",
                        "",
                    )
                )
                self.assertEqual(shader_site("fixture.frag", source, "mask"), expected)

    def test_complete_switches_in_alternative_arms(self) -> None:
        """Only an arm with an exit path can reach the load after the group."""
        for newline in ("\n", "\r\n", "\r"):
            for spliced in (False, True):
                for second_default in (True, False):
                    with self.subTest(
                        newline=repr(newline), spliced=spliced, second_default=second_default
                    ):
                        directive = ("#ifd" + chr(92), "ef FLAG") if spliced else ("#ifdef FLAG",)
                        source = newline.join(
                            (
                                *_HEADER,
                                "    uint sel = uint(gl_FragCoord.x);",
                                *directive,
                                "    switch (sel) {",
                                "        case 0u: return;",
                                "        default: return;",
                                "    }",
                                "#else",
                                "    switch (sel) {",
                                "        case 0u: return;",
                                "        default: return;" if second_default else "",
                                "    }",
                                "#endif",
                                "    color = imageLoad(img, ivec2(1)).r & 0xffu;",
                                "}",
                                "",
                            )
                        )
                        self.assertEqual(
                            shader_site("fixture.frag", source, "mask"),
                            None if second_default else f"fixture.frag:{17 + int(spliced)}",
                        )

    def test_default_in_nested_optional_arm(self) -> None:
        """A conditional default cannot remove the unmatched-selector path."""
        source = "\n".join(
            (
                *_HEADER,
                "    switch (uint(gl_FragCoord.x)) {",
                "        case 0u: return;",
                "#ifdef FLAG",
                "        default: return;",
                "#endif",
                "    }",
                "    color = imageLoad(img, ivec2(1)).r & 0xffu;",
                "}",
            )
        )
        self.assertEqual(shader_site("fixture.frag", source, "mask"), "fixture.frag:11")
