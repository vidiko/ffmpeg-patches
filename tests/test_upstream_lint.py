# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Planted upstream-lint defects; no repository gates or credential tests.

Deterministic fixtures stub the pre-commit and semgrep_scan.sh subprocesses,
never their surrounding Git, isolation or reporting logic. Real-tool fixtures
copy base files with git show from the named upstream checkout and skip
explicitly if unavailable.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import signal
import subprocess  # nosec B404 - fixed commands in disposable Git repositories.
import sys
import tempfile
import unittest
import unittest.mock
from dataclasses import FrozenInstanceError
from datetime import date
from pathlib import Path

from tests.helpers import GIT_ENVIRONMENT_NAMES, isolated_git_environment, run_git
from tests.revert_proof_helpers import clone_shallow_side_fix, configure_ssh_signing

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import upstream_lint  # noqa: E402

UPSTREAM = Path(os.environ["UPSTREAM_TREE"]) if os.environ.get("UPSTREAM_TREE") else None
SOURCE = "int ff_value(void)\n{\n    return 1;\n}\n"
RTSP_WITH_CLOSE = (
    "int mux_write_header(SessionHandle *s)\n"
    "{\n"
    "    int ret = ff_rtsp_connect(s);\n"
    "    if (ret < 0)\n"
    "        return ret;\n"
    "    ret = start_step(s);\n"
    "    if (ret < 0) {\n"
    "        ff_rtsp_close_connections(s);\n"
    "        ff_network_close();\n"
    "        return ret;\n"
    "    }\n"
    "    return 0;\n"
    "}\n"
)
RTSP_WITHOUT_CLOSE = RTSP_WITH_CLOSE.replace("        ff_network_close();\n", "")
FAKE_CONFIG = "repos: []\n"
FAKE_MESSAGE = '#!/bin/sh\ngit log --format=%s "$1" | grep -Eq "^[^:]+: .+"\n'
FAKE_PATCHECK = "#!/bin/sh\ncat > patcheck.stdout\nprintf 'patcheck fixture\\n'\n"
DOCSTRING_EMPTY_CLEAN = (
    "Docstring coverage: 100.00% (0/0 covered, counted: 0, covered: 0, threshold: 80%)\n"
)
DOCSTRING_FINDING = (
    "Docstring coverage: 0.00% (0/2 covered, counted: 2, covered: 0, threshold: 80%)\n"
    "libavfilter/vf_x.c:5 ff_alpha\n"
    "libavfilter/vf_x.c:12 ff_beta\n"
)
DOCSTRING_ADVICE = "add a doc comment to each listed function, or pass --docstring-reason"
DASHENC_OPTIONS = (
    "#define OFFSET(x) offsetof(DashContext, x)\n"
    "typedef struct DashContext {\n"
    "    int ignore_io_errors;\n"
    "    int global_sidx;\n"
    "    int single_file;\n"
    "} DashContext;\n"
    "static const AVOption options[] = {\n"
    '    { "ignore_io_errors", "ignore", OFFSET(ignore_io_errors), 0 },\n'
    '    { "global_sidx", "sidx", OFFSET(global_sidx), 0 },\n'
    '    { "single_file", "single", OFFSET(single_file), 0 },\n'
    "};\n"
)
DASHENC_OPTIONS_T9 = (
    "#define OFFSET(x) offsetof(DashContext, x)\n"
    "typedef struct DashContext {\n"
    "    int ignore_io_errors;\n"
    "    int global_sidx;\n"
    "    int single_file;\n"
    "} DashContext;\n"
    "static const AVOption options[] = {\n"
    '    { "ignore_io_errors", "ignore", OFFSET(ignore_io_errors), 0 },\n'
    '    { "none", "no segment list", 0, AV_OPT_TYPE_CONST, { .i64 = 0 }, 0, 0,'
    ' AV_OPT_FLAG_DEPRECATED, "dash" },\n'
    '    { "global_sidx", "sidx", OFFSET(global_sidx), 0 },\n'
    '    { "single_file", "single " "file mode", OFFSET(single_file), 0 },\n'
    "};\n"
)
DASHENC_WRITE_HEAD = "int dash_write(DashContext *c)\n{\n    int ret = 0;\n"
DASHENC_WRITE_TAIL = "    if (c->global_sidx) {\n        ret = 1;\n    }\n    return ret;\n}\n"
DASHENC_GAP2 = "    ;\n    ;\n"
DASHENC_GAP3 = "    ;\n    ;\n    ;\n"
DASHENC_IGNORE_TEST = "    if (!c->ignore_io_errors && ret >= 0) { ret = 0; }\n"
DASHENC_BASE = DASHENC_OPTIONS + DASHENC_WRITE_HEAD + DASHENC_GAP2 + DASHENC_WRITE_TAIL
DASHENC_T1_SOURCE = (
    DASHENC_OPTIONS + DASHENC_WRITE_HEAD + DASHENC_IGNORE_TEST + DASHENC_GAP2 + DASHENC_WRITE_TAIL
)
DASHENC_T9_SOURCE = (
    DASHENC_OPTIONS_T9
    + DASHENC_WRITE_HEAD
    + DASHENC_IGNORE_TEST
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DASHENC_T10_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + "    if (!c->ignore_io_errors) { ret = -1; }\n"
    + "    if (c->ignore_io_errors && ret >= 0) { ret = 0; }\n"
    + "    if (c->global_sidx) {\n"
    + "        ret = 1;\n"
    + "    }\n"
    + "    return ret;\n"
    + "}\n"
)
DASHENC_T3_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + "    if (c->single_file && c->ignore_io_errors && ret >= 0)\n"
    + "        ret = 0;\n"
    + "    return ret;\n"
    + "}\n"
    + "int dash_tail(DashContext *c)\n"
    + "{\n"
    + "    if (c->global_sidx) {\n"
    + "        return 2;\n"
    + "    }\n"
    + "    return 0;\n"
    + "}\n"
)
DASHENC_T4_SOURCE = (
    DASHENC_OPTIONS + DASHENC_WRITE_HEAD + DASHENC_IGNORE_TEST + DASHENC_GAP3 + DASHENC_WRITE_TAIL
)
DASHENC_T5_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + DASHENC_IGNORE_TEST
    + "    /* if (c->global_sidx) */\n"
    + DASHENC_GAP2
    + "    return ret;\n"
    + "}\n"
    + "int dash_tail(DashContext *c)\n"
    + "{\n"
    + "    if (c->global_sidx) {\n"
    + "        return 2;\n"
    + "    }\n"
    + "    return 0;\n"
    + "}\n"
)
DASHENC_NO_TABLE = (
    "typedef struct DashContext { int ignore_io_errors, global_sidx; } DashContext;\n"
    + DASHENC_WRITE_HEAD
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DASHENC_NO_TABLE_T1 = (
    "typedef struct DashContext { int ignore_io_errors, global_sidx; } DashContext;\n"
    + DASHENC_WRITE_HEAD
    + DASHENC_IGNORE_TEST
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DOC_MUXERS_BASE = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_T1 = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "Skip flush failures when the output is not writable.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_T2 = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "Respect @option{global_sidx} when inserting index ranges.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DASHENC_SPLIT_ASSIGN_ADDED = (
    "    if ((c->ignore_io_errors\n         = 0) && c->global_sidx)\n        ret = 0;\n"
)
DASHENC_SPLIT_ASSIGN_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + DASHENC_SPLIT_ASSIGN_ADDED
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DASHENC_SPLIT_COMPARE_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + DASHENC_SPLIT_ASSIGN_ADDED.replace("= 0)", "== 0)")
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DOC_MUXERS_VERBATIM_COMMENT_NAMES_GLOBAL_SIDX = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@verbatim\n"
    "@c global_sidx\n"
    "@end verbatim\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_IGNORE_BLOCK_NAMES_GLOBAL_SIDX = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@ignore\n"
    "Respect global_sidx when inserting index ranges.\n"
    "@end ignore\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_GLOBAL_SIDX_ONLY = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "Write one index box for the whole output.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DASHENC_SUBSCRIPT_READ_ASSIGN_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + "    if ((c->nb_slots[c->ignore_io_errors\n"
    + "         ? 0 : 1] = 1) && c->global_sidx)\n"
    + "        ret = 0;\n"
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DASHENC_CONSTANT_INDEX_ASSIGN_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + "    if ((c->ignore_io_errors[0]\n"
    + "         += 1) && c->global_sidx)\n"
    + "        ret = 0;\n"
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)
DOC_MUXERS_ITEMX_BASE = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "@itemx ignore_errors\n"
    "Ignore I/O errors.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_ITEMX_OMIT_GLOBAL_SIDX = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "@itemx ignore_errors\n"
    "Ignore I/O errors.\n"
    "Skip flush failures when the output is not writable.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_AFTER_EXAMPLE_NAMES_GLOBAL_SIDX = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "Skip flush failures when the output is not writable.\n"
    "@example\n"
    "ffmpeg -i in -ignore_io_errors 1 out.mpd\n"
    "@end example\n"
    "Respect @option{global_sidx} when inserting index ranges.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_EXAMPLE_BASE = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@example\n"
    "ffmpeg -i in -ignore_io_errors 1 out.mpd\n"
    "@end example\n"
    "Keep segment output running.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_AFTER_EXAMPLE_OMIT_GLOBAL_SIDX = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@example\n"
    "ffmpeg -i in -ignore_io_errors 1 out.mpd\n"
    "@end example\n"
    "Keep segment output running.\n"
    "Skip flush failures when the output is not writable.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_T3 = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "Applies only on single-file output.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DOC_MUXERS_T6 = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "May overlap segments when ignore I/O errors is enabled.\n"
    "@item single_file\n"
    "Write one output file.\n"
    "@end table\n"
)
DASHENC_OPTIONS_ALIAS = (
    "#define OFFSET(x) offsetof(DashContext, x)\n"
    "typedef struct DashContext {\n"
    "    int ignore_io_errors;\n"
    "    int global_sidx;\n"
    "} DashContext;\n"
    "static const AVOption options[] = {\n"
    '    { "ignore_io_errors", "ignore", OFFSET(ignore_io_errors), 0 },\n'
    '    { "ignore_errors", "alias", OFFSET(ignore_io_errors), 0 },\n'
    '    { "global_sidx", "sidx", OFFSET(global_sidx), 0 },\n'
    "};\n"
)
DASHENC_ALIAS_BASE = (
    DASHENC_OPTIONS_ALIAS
    + "int dash_write(DashContext *c)\n{\n    int ret = 0;\n    ;\n    ;\n"
    + DASHENC_WRITE_TAIL
)
DASHENC_ALIAS_T1 = (
    DASHENC_OPTIONS_ALIAS
    + "int dash_write(DashContext *c)\n{\n    int ret = 0;\n"
    + "    if (!c->ignore_io_errors && ret >= 0) { ret = 0; }\n"
    + "    ;\n    ;\n"
    + DASHENC_WRITE_TAIL
)
DOC_MUXERS_ALIAS_BASE = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "@item ignore_errors\n"
    "Deprecated alias.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@end table\n"
)
DOC_MUXERS_ALIAS_T1 = (
    "@table @option\n"
    "@item ignore_io_errors\n"
    "Ignore I/O errors.\n"
    "Skip flush failures when the output is not writable.\n"
    "@item ignore_errors\n"
    "Deprecated alias.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@end table\n"
)
DASHENC_COND_T1 = (
    DASHENC_OPTIONS
    + "int dash_write(DashContext *c)\n{\n    int ret = 0;\n"
    + "    if (ret >= 0 &&\n        !c->ignore_io_errors)\n        ret = 0;\n"
    + "    if (c->global_sidx) {\n        ret = 1;\n    }\n    return ret;\n}\n"
)
DASHENC_OPTIONS_FLAGS = (
    "#define OFFSET(x) offsetof(DashContext, x)\n"
    "typedef struct DashContext {\n"
    "    int flags[4];\n"
    "    int global_sidx_extra;\n"
    "    int global_sidx;\n"
    "} DashContext;\n"
    "static const AVOption options[] = {\n"
    '    { "flags", "flags", OFFSET(flags[0]), 0 },\n'
    '    { "global_sidx", "sidx", OFFSET(global_sidx), 0 },\n'
    "};\n"
)
DASHENC_FLAGS_BASE = (
    DASHENC_OPTIONS_FLAGS + "int dash_write(DashContext *c)\n{\n    return c->global_sidx;\n}\n"
)
DASHENC_FLAGS_T1 = (
    DASHENC_OPTIONS_FLAGS
    + "int dash_write(DashContext *c)\n{\n    if (c->flags[0]) { return 1; }\n"
    + "    if (c->global_sidx) { return 2; }\n    return 0;\n}\n"
)
DOC_MUXERS_FLAGS_T1 = (
    "@table @option\n"
    "@item flags\n"
    "Bitmask flags.\n"
    "@item global_sidx\n"
    "Write a global sidx.\n"
    "@end table\n"
)
DASHENC_POST_COND_T1 = (
    DASHENC_OPTIONS
    + "int dash_write(DashContext *c)\n{\n    int ret = 0, ready = 1;\n"
    + "    if (ret >= 0 &&\n        ready) c->ignore_io_errors = 1;\n"
    + "    if (c->global_sidx) {\n        ret = 1;\n    }\n    return ret;\n}\n"
)
TWO_TABLES_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    "};\n"
    "static const AVOption b_options[] = {\n"
    '    { "bar", "bar", OFFSET(bar), 0 },\n'
    "};\n"
)
ONE_TABLE_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    '    { "bar", "bar", OFFSET(bar), 0 },\n'
    "};\n"
)
MUX_WRITE_BASE = (
    "int mux_write(MuxContext *c)\n{\n"
    "    if (c->bar) {\n        return 2;\n    }\n    return 0;\n}\n"
)
MUX_WRITE_T1 = (
    "int mux_write(MuxContext *c)\n{\n"
    "    if (c->foo) {\n        return 1;\n    }\n"
    "    if (c->bar) {\n        return 2;\n    }\n    return 0;\n}\n"
)
DOC_FOO_BAR_BASE = (
    "@table @option\n@item foo\nEnable foo mode.\n@item bar\nEnable bar mode.\n@end table\n"
)
DOC_FOO_BAR_T1 = (
    "@table @option\n"
    "@item foo\n"
    "Enable foo mode.\n"
    "Skip extra header packets.\n"
    "@item bar\n"
    "Enable bar mode.\n"
    "@end table\n"
)
DOC_FOO_BAR_COMMENT_ONLY_BAR = (
    "@table @option\n"
    "@item foo\n"
    "Enable foo mode.\n"
    "@c Also depends on bar when muxing.\n"
    "Skip extra header packets.\n"
    "@item bar\n"
    "Enable bar mode.\n"
    "@end table\n"
)
DOC_FOO_BAR_COMMENT_AND_PLAIN_BAR = (
    "@table @option\n"
    "@item foo\n"
    "Enable foo mode.\n"
    "@c Also depends on bar when muxing.\n"
    "Depends on bar when muxing.\n"
    "Skip extra header packets.\n"
    "@item bar\n"
    "Enable bar mode.\n"
    "@end table\n"
)
BOUNDED_TWO_TABLES_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "#define NB_OPTS 2\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    "};\n"
    "static const AVOption b_options[2] = {\n"
    '    { "bar", "bar", OFFSET(bar), 0 },\n'
    "};\n"
)
BOUNDED_NB_TWO_TABLES_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "#define NB_OPTS 2\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    "};\n"
    "static const AVOption b_options[NB_OPTS] = {\n"
    '    { "bar", "bar", OFFSET(bar), 0 },\n'
    "};\n"
)
BOUNDED_EXPR_TWO_TABLES_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    "};\n"
    "static const AVOption b_options[2 + 1] = {\n"
    '    { "bar", "bar", OFFSET(bar), 0 },\n'
    "};\n"
)
MUX_WRITE_MODE_ASSIGN = (
    "int mux_write(MuxContext *c)\n{\n"
    "    if (c->mode) {\n        return 2;\n    }\n    return 0;\n}\n"
)
MUX_WRITE_MODE_ASSIGN_FOO = (
    "int mux_write(MuxContext *c)\n{\n"
    "    int ready = 1, enabled = 1, available = 1;\n"
    "    if (ready) c->foo = enabled && available;\n"
    "    if (c->mode) {\n        return 2;\n    }\n    return 0;\n}\n"
)
AVOPTION_COMMENT_BAR_BLOCK = (
    "#define OFFSET(x) offsetof(Ctx, x)\n"
    "typedef struct Ctx { int foo, bar; } Ctx;\n"
    "static const AVOption options[] = {\n"
    '    { "foo", "help", OFFSET(foo), 0 },\n'
    '    /* { "bar", "old", OFFSET(bar), 0 }, */\n'
    "};\n"
)
AVOPTION_COMMENT_BAR_LINE = (
    "#define OFFSET(x) offsetof(Ctx, x)\n"
    "typedef struct Ctx { int foo, bar; } Ctx;\n"
    "static const AVOption options[] = {\n"
    '    { "foo", "help", OFFSET(foo), 0 },\n'
    '    // { "bar", "old", OFFSET(bar), 0 },\n'
    "};\n"
)
AVOPTION_HELP_LITERALS = (
    "#define OFFSET(x) offsetof(Ctx, x)\n"
    "typedef struct Ctx { int a_field, b_field; } Ctx;\n"
    "static const AVOption options[] = {\n"
    '    { "a", "http://example.invalid/doc", OFFSET(a_field), 0 },\n'
    '    { "b", "/* not a comment */", OFFSET(b_field), 0 },\n'
    "};\n"
)
AVOPTION_COMMENTED_HEADER_MID = (
    "#define OFFSET(x) offsetof(Ctx, x)\n"
    "typedef struct Ctx { int foo, baz; } Ctx;\n"
    "static const AVOption options[] = {\n"
    '    { "foo", "help", OFFSET(foo), 0 },\n'
    "    /* static const AVOption old_options[] = { */\n"
    '    { "baz", "help", OFFSET(baz), 0 },\n'
    "};\n"
)
ONE_TABLE_COMMENT_BAR = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int bar;\n"
    "} MuxContext;\n"
    "static const AVOption a_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    '    /* { "bar", "bar", OFFSET(bar), 0 }, */\n'
    "};\n"
)
MODE_ALIAS_OPTIONS = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int mode;\n"
    "    int other;\n"
    "} MuxContext;\n"
    "static const AVOption options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    '    { "mode", "mode", OFFSET(mode), 0 },\n'
    '    { "mode_alias", "alias", OFFSET(mode), 0 },\n'
    '    { "other", "other", OFFSET(other), 0 },\n'
    "};\n"
)
MUX_WRITE_MODE = (
    "int mux_write(MuxContext *c)\n{\n"
    "    if (c->mode) {\n        return 2;\n    }\n    return 0;\n}\n"
)
MUX_WRITE_MODE_FOO = (
    "int mux_write(MuxContext *c)\n{\n"
    "    if (c->foo) {\n        return 1;\n    }\n"
    "    if (c->mode) {\n        return 2;\n    }\n    return 0;\n}\n"
)
DOC_MODE_BASE = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_FOO_NAMES_MODE = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Coupled with mode selection.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_FOO_NAMES_ALIAS = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Coupled with mode_alias naming.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_FOO_NAMES_OTHER = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Coupled with the other knob.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_FOO_OMIT = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Skip extra header packets.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_FOO_DUAL_OMIT = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Coupled with mode selection.\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Skip extra header packets.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item mode_alias\n"
    "Alias for mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
INTERPLAY_ALIAS_MUX_STRUCT = (
    "#define OFFSET(x) offsetof(MuxContext, x)\n"
    "typedef struct MuxContext {\n"
    "    int foo;\n"
    "    int mode;\n"
    "} MuxContext;\n"
)
INTERPLAY_ALIAS_W_TABLE = (
    "static const AVOption w_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    '    { "mode", "mode", OFFSET(mode), 0 },\n'
    '    { "mode_alias", "alias", OFFSET(mode), 0 },\n'
    "};\n"
)
INTERPLAY_ALIAS_N_TABLE = (
    'static const AVOption n_options[] = {\n    { "mode", "mode", OFFSET(mode), 0 },\n};\n'
)
INTERPLAY_ALIAS_WN_W_FIRST = (
    INTERPLAY_ALIAS_MUX_STRUCT + INTERPLAY_ALIAS_W_TABLE + INTERPLAY_ALIAS_N_TABLE
)
INTERPLAY_ALIAS_WN_N_FIRST = (
    INTERPLAY_ALIAS_MUX_STRUCT + INTERPLAY_ALIAS_N_TABLE + INTERPLAY_ALIAS_W_TABLE
)
INTERPLAY_ALIAS_P_ROWS = (
    "static const AVOption p_options[] = {\n"
    '    { "foo", "foo", OFFSET(foo), 0 },\n'
    '    { "mode", "mode", OFFSET(mode), 0 },\n'
    "};\n"
)
INTERPLAY_ALIAS_Q_TABLE = (
    "static const AVOption q_options[] = {\n"
    '    { "mode", "mode", OFFSET(mode), 0 },\n'
    '    { "m", "short", OFFSET(mode), 0 },\n'
    "};\n"
)
INTERPLAY_ALIAS_PQ_P_FIRST = (
    INTERPLAY_ALIAS_MUX_STRUCT + INTERPLAY_ALIAS_P_ROWS + INTERPLAY_ALIAS_Q_TABLE
)
INTERPLAY_ALIAS_PQ_Q_FIRST = (
    INTERPLAY_ALIAS_MUX_STRUCT + INTERPLAY_ALIAS_Q_TABLE + INTERPLAY_ALIAS_P_ROWS
)
DOC_MODE_FOO_NAMES_M = (
    "@table @option\n"
    "@item foo\n"
    "Enable the foo flag.\n"
    "Coupled with m selection.\n"
    "@item mode\n"
    "Select mode.\n"
    "@item other\n"
    "Other knob.\n"
    "@end table\n"
)
DOC_MODE_INTERPLAY_BASE = (
    "@table @option\n@item foo\nEnable the foo flag.\n@item mode\nSelect mode.\n@end table\n"
)
DASHENC_IGNORE_TEST_SPACED = "    if (!c-> ignore_io_errors && ret >= 0) { ret = 0; }\n"
DASHENC_T1_SPACED_SOURCE = (
    DASHENC_OPTIONS
    + DASHENC_WRITE_HEAD
    + DASHENC_IGNORE_TEST_SPACED
    + DASHENC_GAP2
    + DASHENC_WRITE_TAIL
)


class RulesTest(unittest.TestCase):
    """Positive, negative and boundary coverage of added-line rules."""

    def findings(self, source: str, added: set[int] | None = None):
        """Check one C source without running external tools."""
        if added is None:
            added = set(range(1, len(source.split("\n")) + 1))
        return upstream_lint._file_rules("libavfilter/vf_x.c", source, added)

    def test_added_tab_fails(self):
        """A planted added TAB fails the mechanical step."""
        count, lines = self.findings("\treturn 1;\n")
        self.assertEqual(count, 1)
        self.assertIn("TAB character", "\n".join(lines))

    def test_added_trailing_whitespace_fails(self):
        """Spaces, TAB and CR at line end all fail, including blank lines."""
        for whitespace in (" ", "\t", "\r", "  "):
            with self.subTest(whitespace=whitespace):
                self.assertGreater(self.findings("return 1;" + whitespace + "\n")[0], 0)
        self.assertEqual(self.findings("  \n")[0], 1)

    def test_function_brace_same_line_fails(self):
        """Single-line function declarations require a separate opening brace."""
        self.assertEqual(self.findings("static int ff_value(void) {\n    return 1;\n}\n")[0], 1)

    def test_control_brace_separate_line_fails(self):
        """Each recognized control header requires its opening brace on that line."""
        for header in (
            "if (x)",
            "for (i = 0; i < 3; i++)",
            "while (x)",
            "switch (x)",
            "else",
            "} else if (x)",
            "do",
        ):
            with self.subTest(header=header):
                count, lines = self.findings(f"    {header}\n    {{\n")
                self.assertEqual(count, 1, lines)

    def test_clean_source_passes(self):
        """K&R function and control braces pass."""
        self.assertEqual(self.findings(SOURCE)[0], 0)
        self.assertEqual(self.findings("    if (x) {\n        ff_value();\n    }\n")[0], 0)

    def test_untouched_tab_passes_and_is_listed(self):
        """An inherited TAB is informational when only a later line is added."""
        count, lines = self.findings("\tff_old();\n    ff_new();\n", {2})
        self.assertEqual(count, 0)
        self.assertEqual(lines, ["pre-existing (untouched): libavfilter/vf_x.c:1: TAB character"])

    def test_untouched_brace_violation_does_not_fail(self):
        """An old function brace is outside the added-line scope."""
        self.assertEqual(self.findings("int ff_value(void) {\n    return 2;\n}\n", {2})[0], 0)

    def test_added_brace_after_untouched_header_fails(self):
        """A changed brace is checked against an unchanged neighboring header."""
        self.assertEqual(self.findings("    if (x)\n    {\n", {2})[0], 1)

    def test_comments_literals_macros_and_initializers_pass(self):
        """Conservative brace matching ignores non-code and ambiguous constructs."""
        source = (
            'const char *s = "int ff_bad(void) {";\n'
            "/* int ff_bad(void) {\n    if (x)\n    {\n*/\n"
            "// int ff_bad(void) {\n"
            "#define FUNCTION(x) int ff_bad(void) {\n"
            "#define MULTILINE(x) \\\n    if (x) \\\n    {\n"
            "const Item items[] = {\n    { 1 },\n};\n"
        )
        self.assertEqual(self.findings(source)[0], 0)

    def test_multiline_and_function_pointer_signatures_are_ignored(self):
        """Unsupported signatures cannot produce speculative brace findings."""
        source = "int ff_value(\n    int x) {\n}\nint ff_apply(int (*fn)(void)) {\n}\n"
        self.assertEqual(self.findings(source)[0], 0)

    def test_patcheck_added_hint_fails_even_with_ansi(self):
        """Colored added-line references in a blocking category fail."""
        output = "double ;\n\x1b[35mpatcheck.stdout\x1b[m:\x1b[32m23\x1b[m:\x1b[m+bad();;\n"
        rc, text = upstream_lint._patcheck_hints(output)
        self.assertEqual(rc, 1)
        self.assertIn("finding:", text)
        self.assertNotIn("\x1b", text)

    def test_patcheck_unlocated_added_hint_fails(self):
        """Patcheck's multiline suggestions can print raw added lines."""
        self.assertEqual(upstream_lint._patcheck_hints("useless if()\n+    if (x)\n")[0], 1)

    def test_patcheck_increment_and_raw_colons_are_added_lines(self):
        """A source increment is not a file header; raw added text keeps its prefix."""
        for line in ("patcheck.stdout:23:+++value;", "+    foo:23:message"):
            with self.subTest(line=line):
                self.assertEqual(upstream_lint._patcheck_hints(f"double ;\n{line}")[0], 1)

    def test_patcheck_printf_hint_requires_review_without_failing(self):
        """Test-program printf hints stay visible without blocking."""
        line = 'patcheck.stdout:23:+    printf("hello");'
        rc, text = upstream_lint._patcheck_hints(f"Please use av_log\n{line}\n")
        self.assertEqual(rc, 0, text)
        self.assertIn(f"hint (review): Please use av_log: {line}", text)

    def test_patcheck_unknown_and_missing_categories_require_review(self):
        """New categories and hits without a header cannot become blockers."""
        for header, category in (
            ("new upstream heuristic\n", "new upstream heuristic"),
            ("", "unknown"),
        ):
            with self.subTest(category=category):
                rc, text = upstream_lint._patcheck_hints(f"{header}+    ff_value();\n")
                self.assertEqual(rc, 0, text)
                self.assertIn(f"hint (review): {category}: +    ff_value();", text)

    def test_patcheck_category_follows_headers_not_context_or_separators(self):
        """Context, blank lines and grep separators preserve the current category."""
        output = (
            "double ;\npatcheck.stdout-22- context\n--\n\n"
            "patcheck.stdout:23:+bad();;\n"
            'Please use av_log\npatcheck.stdout:27:+printf("hello");\n'
        )
        rc, text = upstream_lint._patcheck_hints(output)
        self.assertEqual(rc, 1, text)
        self.assertIn("finding: double ;: patcheck.stdout:23:+bad();;", text)
        self.assertIn("hint (review): Please use av_log: patcheck.stdout:27:", text)

    def test_patcheck_header_requires_an_exact_allow_list_match(self):
        """Similar heuristic names cannot inherit a blocking prefix."""
        rc, text = upstream_lint._patcheck_hints("double ; suggestion\n+bad();;\n")
        self.assertEqual(rc, 0, text)
        self.assertIn("hint (review): double ; suggestion:", text)

    def test_patcheck_context_and_general_hints_are_informational(self):
        """Context, removed lines, file headers and generic advice do not fail."""
        output = (
            "tabs\npatcheck.stdout:23: \told\npatcheck.stdout-24- old\n"
            "patcheck.stdout:25:-removed\npatcheck.stdout:26:+++ b/file.c\n"
            "Missing changelog entry (ignore if minor change)\n"
        )
        rc, text = upstream_lint._patcheck_hints(output)
        self.assertEqual(rc, 0)
        self.assertIn("informational:", text)

    def test_deletion_only_hunk_has_no_added_lines(self):
        """Zero-length new ranges do not accidentally select their neighbor."""
        self.assertEqual(upstream_lint._added_lines("@@ -2 +1,0 @@\n-old\n"), set())
        self.assertEqual(upstream_lint._added_lines("@@ -2 +2,2 @@\n+a\n+b\n"), {2, 3})


class RegressionTestPathTest(unittest.TestCase):
    """Positive, negative and boundary coverage of test and source path predicates."""

    def test_is_test_path(self) -> None:
        """Top-level and nested tests directories match; source directories do not."""
        self.assertTrue(upstream_lint.is_test_path("tests/fate/x.mak"))
        self.assertTrue(upstream_lint.is_test_path("libavutil/tests/x.c"))
        self.assertFalse(upstream_lint.is_test_path("libavfilter/vf_x.c"))

    def test_is_source_path(self) -> None:
        """Library and fftools sources match while test, doc and compat paths do not."""
        for path in ("libavfilter/vf_x.c", "fftools/ffmpeg.c", "libavcodec/x86/x.asm"):
            with self.subTest(path=path):
                self.assertTrue(upstream_lint.is_source_path(path))
        for path in ("libavutil/tests/x.c", "doc/filters.texi", "compat/x.c"):
            with self.subTest(path=path):
                self.assertFalse(upstream_lint.is_source_path(path))

    def test_is_c_source_path(self) -> None:
        """Library and fftools C and header paths match; assembly, tests and others do not."""
        for path in (
            "libavformat/rtsp.c",
            "libavformat/rtsp.h",
            "fftools/ffmpeg.c",
            "fftools/ffmpeg.h",
            "libavcodec/tests.c",
        ):
            with self.subTest(path=path):
                self.assertTrue(upstream_lint.is_c_source_path(path))
        for path in (
            "compat/strtod.c",
            "tools/ismindex.c",
            "doc/filters.texi",
            "libavcodec/tests/x.c",
            "libavformat/tests/rtsp.h",
            "libavcodec/arm/x.S",
            "libavcodec/x86/x.asm",
            "rtsp.c",
        ):
            with self.subTest(path=path):
                self.assertFalse(upstream_lint.is_c_source_path(path))


class FixWordTest(unittest.TestCase):
    """Positive, negative and boundary coverage of fix detection in commit messages."""

    def test_subject_and_body_defect_words(self) -> None:
        """A fix or defect word in the subject or the body returns that word."""
        cases = (
            ("avfilter/vf_x: fix y\n", "fix"),
            ("avformat/dashenc: do not delete y\n\nFix this by skipping y.\n", "Fix"),
            ("avcodec/x: skip absent y\n\nReading y would misalign every field.\n", "misalign"),
            ("avcodec/x: bound y\n\nThe next set was read past the end of it.\n", "past the end"),
            ("avformat/x: enlarge y\n\nGCC reports -Wformat-truncation for y.\n", "truncation"),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.fix_word(message), expected)

    def test_wrapped_defect_phrase_is_found(self) -> None:
        """A defect phrase split by a line break or by hyphens returns that phrase."""
        cases = (
            ("avcodec/x: bound y\n\nThe read goes out of\nbounds.\n", "out of\nbounds"),
            ("avcodec/x: bound y\n\nAn out-of-\nbounds read of y.\n", "out-of-\nbounds"),
            ("avcodec/x: bound y\n\nAn out\n-of-bounds read of y.\n", "out\n-of-bounds"),
            ("avcodec/x: bound y\n\nThe read goes past the\nend of y.\n", "past the\nend"),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.fix_word(message), expected)

    def test_split_phrase_words_stay_whole(self) -> None:
        """Phrase words joined without a separator or with other words between return None."""
        for message in (
            "avcodec/x: bound y\n\nThe read stays outof bounds checks.\n",
            "avcodec/x: bound y\n\nThe read goes out of its\nbounds.\n",
            "avcodec/x: bound y\n\nThe read goes past\nits end.\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.fix_word(message))

    def test_no_defect_word_returns_none(self) -> None:
        """Messages without a whole fix or defect word outside sign-off lines return None."""
        for message in (
            "avfilter/vf_x: update y\n",
            "avfilter/vf_x: update y\n\nRename the helper.\n",
            "avfilter/vf_x: prefix y\n\nKeep the debug fixture.\n",
            "avfilter/vf_x: update y\n\nSigned-off-by: Bug Fixer <fixer@invalid>\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.fix_word(message))

    def test_added_defect_words_and_phrases(self) -> None:
        """Every added memory-safety and UB defect word or phrase matches in the body."""
        words = (
            "uninitialised",
            "uninitialized",
            "use after free",
            "use-after-free",
            "double free",
            "double-free",
            "null dereference",
            "null dereferences",
            "null pointer dereference",
            "null pointer dereferences",
            "division by zero",
            "divide by zero",
            "undefined behaviour",
            "undefined behavior",
            "deadlock",
            "deadlocks",
            "deadlocked",
            "segfault",
            "segfaults",
            "segfaulted",
            "segmentation fault",
            "segmentation faults",
            "memory corruption",
            "heap corruption",
            "stack corruption",
            "OOB",
            "oob",
        )
        for word in words:
            with self.subTest(word=word):
                message = f"avformat/rtsp: check write\n\nAvoid {word} on reply.\n"
                self.assertEqual(upstream_lint.fix_word(message), word)

    def test_wrapped_and_hyphenated_added_defect_phrases(self) -> None:
        """Added multi-word phrases match across line breaks, and free phrases across hyphens."""
        phrases = (
            "use\nafter free",
            "use after\nfree",
            "use-after-free",
            "use-after-\nfree",
            "use\n-after-free",
            "double\nfree",
            "double-free",
            "double-\nfree",
            "double\n-free",
            "null\ndereference",
            "null\ndereferences",
            "null\npointer dereference",
            "null pointer\ndereferences",
            "division\nby zero",
            "division by\nzero",
            "divide\nby zero",
            "divide by\nzero",
            "undefined\nbehaviour",
            "undefined\nbehavior",
            "segmentation\nfault",
            "segmentation\nfaults",
            "memory\ncorruption",
            "heap\ncorruption",
            "stack\ncorruption",
        )
        for phrase in phrases:
            with self.subTest(phrase=phrase):
                message = f"avformat/rtsp: check write\n\nAvoid {phrase} on reply.\n"
                self.assertEqual(upstream_lint.fix_word(message), phrase)

    def test_excluded_and_partial_words_return_none(self) -> None:
        """Excluded concurrency words and isolated parts of defect phrases return None."""
        words = (
            "hang",
            "hangs",
            "race",
            "race condition",
            "data race",
            "infinite loop",
            "free",
            "freed",
            "double",
            "zero",
            "undefined",
            "behaviour",
            "behavior",
            "pointer",
            "initialised",
            "initialized",
            "lock",
        )
        for word in words:
            with self.subTest(word=word):
                message = f"avformat/rtsp: check write\n\nHandle {word} in reply.\n"
                self.assertIsNone(upstream_lint.fix_word(message))

    def test_added_defect_word_in_signoff_returns_none(self) -> None:
        """Added defect words inside Signed-off-by trailers are ignored."""
        for trailer in (
            "Signed-off-by: Uninitialised Segfault <x@invalid>",
            "signed-off-by: Double Free <oob@invalid>",
        ):
            with self.subTest(trailer=trailer):
                message = f"avformat/rtsp: check write\n\n{trailer}\n"
                self.assertIsNone(upstream_lint.fix_word(message))

    def test_hyphenated_uninitialised_and_warning_flags(self) -> None:
        """Sanitizer hyphenated forms match while warning flag prefixes return None."""
        for token, expected in (
            ("use-of-uninitialized-value", "uninitialized"),
            ("use-of-uninitialised-value", "uninitialised"),
        ):
            with self.subTest(token=token):
                message = f"avformat/rtsp: check write\n\nHandle {token} in reply.\n"
                self.assertEqual(upstream_lint.fix_word(message), expected)
        for flag in (
            "-Wmaybe-uninitialized",
            "-Wmaybe-uninitialised",
            "maybe-uninitialized",
            "maybe-uninitialised",
            "-Wsometimes-uninitialized",
            "-Wsometimes-uninitialised",
            "sometimes-uninitialized",
            "sometimes-uninitialised",
        ):
            with self.subTest(flag=flag):
                message = f"avformat/rtsp: check write\n\nHandle {flag} in reply.\n"
                self.assertIsNone(upstream_lint.fix_word(message))


class TestReachTest(unittest.TestCase):
    """Positive, negative and boundary coverage of reach_names and test_words."""

    def test_lavfi_prefix_stripped(self) -> None:
        """Source paths contribute both full stems and lavfi-stripped stems."""
        self.assertEqual(
            upstream_lint.reach_names(["libavfilter/vf_x.c"], ""),
            frozenset({"vf_x", "x"}),
        )

    def test_source_stem_and_hunk_function(self) -> None:
        """Source stems and hunk-header functions are collected while docs are ignored."""
        patch = (
            "diff --git a/libavcodec/aom_film_grain.c b/libavcodec/aom_film_grain.c\n"
            "--- a/libavcodec/aom_film_grain.c\n"
            "+++ b/libavcodec/aom_film_grain.c\n"
            "@@ -4 +4 @@ static int parse_sets(GetBitContext *gb)\n"
            "-    return x;\n"
            "+    return x + 1;\n"
        )
        self.assertEqual(
            upstream_lint.reach_names(["libavcodec/aom_film_grain.c", "doc/x.texi"], patch),
            frozenset({"aom_film_grain", "parse_sets"}),
        )

    def test_added_source_line_supplies_function_without_hunk_name(self) -> None:
        """Added source definitions contribute function names when the hunk header has none."""
        patch = (
            "diff --git a/libavfilter/vf_root.c b/libavfilter/vf_root.c\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/libavfilter/vf_root.c\n"
            "@@ -0,0 +1,4 @@\n"
            "+int ff_value(void)\n"
            "+{\n"
            "+    return 1;\n"
            "+}\n"
        )
        self.assertIn("ff_value", upstream_lint.reach_names(["libavfilter/vf_root.c"], patch))

    def test_control_words_do_not_hide_function_reach_names(self) -> None:
        """Hunk headings and added lines skip control words before real function names."""
        for keyword in ("if", "while", "for", "switch", "return", "sizeof"):
            with self.subTest(keyword=keyword):
                line = f"{keyword} (ff_value(x))"
                self.assertEqual(
                    upstream_lint._hunk_functions([f"@@ -1 +1 @@ {line}"]), ["ff_value"]
                )
                self.assertEqual(upstream_lint._function_names_from_added([line]), ["ff_value"])

    def test_deleted_source_file_keeps_old_path_and_function(self) -> None:
        """Deleted source diffs retain the --- a/ path for hunk function extraction."""
        patch = (
            "diff --git a/libavcodec/old.c b/libavcodec/old.c\n"
            "deleted file mode 100644\n"
            "--- a/libavcodec/old.c\n"
            "+++ /dev/null\n"
            "@@ -1,3 +0,0 @@ int ff_old(void)\n"
            "-x\n"
        )
        self.assertEqual(
            upstream_lint.reach_names(["libavcodec/old.c"], patch),
            frozenset({"old", "ff_old"}),
        )

    def test_test_path_hunk_header_adds_nothing(self) -> None:
        """Hunk headers under test paths do not contribute reachable source names."""
        patch = (
            "diff --git a/libavcodec/tests/x.c b/libavcodec/tests/x.c\n"
            "--- a/libavcodec/tests/x.c\n"
            "+++ b/libavcodec/tests/x.c\n"
            "@@ -1 +1 @@ int main(void)\n"
            "+y\n"
        )
        self.assertEqual(upstream_lint.reach_names(["libavcodec/tests/x.c"], patch), frozenset())

    def test_test_words_from_path_and_added_lines(self) -> None:
        """Changed test diffs yield every word from both the path and added lines."""
        patch = (
            "diff --git a/tests/ref/fate/filter-x b/tests/ref/fate/filter-x\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/tests/ref/fate/filter-x\n"
            "@@ -0,0 +1 @@\n"
            "+0\n"
        )
        self.assertEqual(
            upstream_lint.test_words(patch),
            frozenset({"tests", "ref", "fate", "filter", "x", "0"}),
        )

    def test_source_added_lines_add_no_test_words(self) -> None:
        """Added body lines under source paths do not enter test_words."""
        patch = (
            "diff --git a/libavfilter/vf_x.c b/libavfilter/vf_x.c\n"
            "--- a/libavfilter/vf_x.c\n"
            "+++ b/libavfilter/vf_x.c\n"
            "@@ -1 +1 @@\n"
            "+parse_sets();\n"
        )
        self.assertEqual(upstream_lint.test_words(patch), frozenset())

    def test_body_line_resembling_header_is_not_header(self) -> None:
        """An added source line starting with +++ b/tests/ cannot switch file state."""
        patch = (
            "diff --git a/libavfilter/vf_x.c b/libavfilter/vf_x.c\n"
            "--- a/libavfilter/vf_x.c\n"
            "+++ b/libavfilter/vf_x.c\n"
            "@@ -1 +1 @@\n"
            "+++ b/tests/parse_sets\n"
        )
        self.assertEqual(upstream_lint.test_words(patch), frozenset())

    def test_quoted_non_ascii_test_path_words(self) -> None:
        """Quoted non-ASCII test headers decode so path and added-line words are kept."""
        patch = (
            'diff --git "a/tests/caf\\303\\251_x.c" "b/tests/caf\\303\\251_x.c"\n'
            "new file mode 100644\n"
            "--- /dev/null\n"
            '+++ "b/tests/caf\\303\\251_x.c"\n'
            "@@ -0,0 +1 @@\n"
            "+    return ff_value();\n"
        )
        words = upstream_lint.test_words(patch)
        self.assertIn("ff_value", words)
        self.assertIn("tests", words)

    def test_unquote_git_path_escapes(self) -> None:
        """C-style quote, backslash, tab and UTF-8 octal escapes decode to text."""
        self.assertEqual(
            upstream_lint.unquote_git_path('"b/tests/a\\"b\\\\c\\td.c"'),
            'b/tests/a"b\\c\td.c',
        )
        self.assertEqual(
            upstream_lint.unquote_git_path('"b/tests/caf\\303\\251_x.c"'),
            "b/tests/café_x.c",
        )

    def test_unquote_git_path_unquoted_and_lone_quote(self) -> None:
        """Unquoted paths, a lone quote and the empty string return unchanged."""
        self.assertEqual(upstream_lint.unquote_git_path("b/tests/x.c"), "b/tests/x.c")
        self.assertEqual(upstream_lint.unquote_git_path('"'), '"')
        self.assertEqual(upstream_lint.unquote_git_path(""), "")

    def test_space_path_trailing_tab_hunk_names(self) -> None:
        """Space-containing source headers drop Git's trailing TAB before suffix checks."""
        patch = (
            "diff --git a/libavfilter/vf_a b.c b/libavfilter/vf_a b.c\n"
            "--- a/libavfilter/vf_a b.c\t\n"
            "+++ b/libavfilter/vf_a b.c\t\n"
            "@@ -1 +1 @@ int ff_space(void)\n"
            "-x\n"
            "+y\n"
        )
        self.assertEqual(upstream_lint.reach_names([], patch), frozenset({"ff_space"}))

    def test_binary_test_path_words_from_paths(self) -> None:
        """Explicit test paths supply path words even when a binary diff has no headers."""
        self.assertEqual(
            upstream_lint.test_words("", ["tests/data/filter-x.bin", "libavfilter/vf_x.c"]),
            frozenset({"tests", "data", "filter", "x", "bin"}),
        )

    def test_dev_null_header_keeps_path(self) -> None:
        """A deleted test file retains its --- a/ path across a +++ /dev/null header."""
        patch = (
            "diff --git a/tests/ref/fate/filter-x b/tests/ref/fate/filter-x\n"
            "deleted file mode 100644\n"
            "--- a/tests/ref/fate/filter-x\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-0\n"
        )
        self.assertEqual(
            upstream_lint.test_words(patch),
            frozenset({"tests", "ref", "fate", "filter", "x"}),
        )


FATE_RED = (
    "FATE_SCALE_REFUSE = fate-filter-scale-ipt-c2-refuse-rgb "
    "fate-filter-scale-ipt-c2-refuse-range\n"
    "FATE_SCALE_REFUSE += fate-filter-scale-bt2020c-refuse-rgb\n"
    "FATE_FILTER-$(call ALLYES, TESTSRC2_FILTER FORMAT_FILTER SETPARAMS_FILTER "
    "SCALE_FILTER LAVFI_INDEV WRAPPED_AVFRAME_ENCODER NULL_MUXER) += $(FATE_SCALE_REFUSE)\n"
    "fate-filter-scale-ipt-c2-refuse-rgb: CMD = ! run $(FFMPEG) -nostdin -hide_banner "
    '-f lavfi -i "testsrc2=s=64x64:r=1:d=1,format=yuv420p10le" '
    '-vf "scale,format=gbrp10le" -frames:v 1 -f null none\n'
)
FATE_SOURCES = {"testsrc2": "video", "sine": "audio", "movie": "mixed"}
FILTER_DECLARATIONS = (
    "extern const FFFilter ff_vsrc_testsrc2;\n"
    "extern const FFFilter ff_asrc_sine;\n"
    "extern const FFFilter ff_avsrc_movie;\n"
)


class FateDepsTest(unittest.TestCase):
    """Exercise lavfi dependency parsing without Git or external commands."""

    def check_source(
        self, source: str = FATE_RED, added: set[int] | None = None
    ) -> upstream_lint.Step:
        """Parse one changed FATE file with fixture source declarations."""
        self.assertTrue(hasattr(upstream_lint, "_fate_file"), "fate-deps parser missing")
        if added is None:
            added = set(range(1, len(source.splitlines()) + 1))
        report = upstream_lint._fate_file(
            "tests/fate/filter-video.mak", source, added, FATE_SOURCES
        )
        return upstream_lint._fate_summary(report)

    def test_planted_missing_decoder_fails(self) -> None:
        """The planted encoder dependency cannot satisfy the video decoder."""
        step = self.check_source()
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count("finding:"), 1)
        self.assertIn(":3: fate-filter-scale-ipt-c2-refuse-rgb:", step.output)
        self.assertIn("needs WRAPPED_AVFRAME_DECODER in its registration", step.output)

    def test_decoder_present_passes(self) -> None:
        """Explicit device and decoder dependencies satisfy the registration."""
        step = self.check_source(
            FATE_RED.replace("NULL_MUXER", "WRAPPED_AVFRAME_DECODER NULL_MUXER")
        )
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("1 lavfi video test(s) checked", step.output)
        self.assertIn("0 finding(s)", step.output)

    def test_untouched_gap_is_nonfailing(self) -> None:
        """An inherited dependency gap remains visible without failing."""
        step = self.check_source(added=set())
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("pre-existing (untouched):", step.output)

    def test_non_lavfi_is_not_counted(self) -> None:
        """Ordinary inputs stay outside the lavfi check."""
        step = self.check_source(FATE_RED.replace("-f lavfi", "-f rawvideo"))
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("0 lavfi video test(s) checked", step.output)

    def test_audio_is_skipped(self) -> None:
        """Audio sources do not require the wrapped video decoder."""
        step = self.check_source(FATE_RED.replace('"testsrc2=', '"sine='))
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("1 audio skipped", step.output)

    def test_variables_append_and_group_commands(self) -> None:
        """Appended variable targets and grouped CMD assignments expand together."""
        source = FATE_RED.replace(
            "fate-filter-scale-ipt-c2-refuse-rgb: CMD", "$(FATE_SCALE_REFUSE): CMD"
        )
        step = self.check_source(source, {2})
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count("finding:"), 1)
        self.assertIn("fate-filter-scale-bt2020c-refuse-rgb: lavfi", step.output)
        self.assertIn("3 lavfi video test(s) checked", step.output)

    def test_continuation_line_is_touched(self) -> None:
        """Touching any physical registration line checks its logical line."""
        source = FATE_RED.replace("LAVFI_INDEV ", "LAVFI_INDEV \\\n    ")
        step = self.check_source(source, {4})
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(":3: fate-filter-scale-ipt-c2-refuse-rgb:", step.output)

    def test_conditional_dependency_passes(self) -> None:
        """An enclosing CONFIG decoder condition supplies that dependency."""
        source = FATE_RED.replace(
            "FATE_FILTER-", "ifeq ($(CONFIG_WRAPPED_AVFRAME_DECODER),yes)\nFATE_FILTER-"
        )
        source = source.replace(
            "fate-filter-scale-ipt-c2-refuse-rgb: CMD",
            "endif\nfate-filter-scale-ipt-c2-refuse-rgb: CMD",
        )
        self.assertEqual(self.check_source(source).rc, 0)

    def test_template_command_is_informational(self) -> None:
        """Touched template commands request review without speculative expansion."""
        step = self.check_source("define TEST\n" + FATE_RED + "endef\n$(eval $(call TEST))\n")
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("template not checked", step.output)
        self.assertIn("0 lavfi video test(s) checked", step.output)

    def test_unknown_and_mixed_sources_are_unclassified(self) -> None:
        """Unknown and mixed sources remain informational."""
        for name in ("unknown", "movie"):
            with self.subTest(name=name):
                step = self.check_source(FATE_RED.replace('"testsrc2=', f'"{name}='))
                self.assertEqual(step.rc, 0, step.output)
                self.assertIn("unclassified lavfi source", step.output)
                self.assertIn("1 unclassified", step.output)

    def test_expansion_bound_keeps_unresolved_token(self) -> None:
        """Self-references terminate and remain unresolved after eight passes."""
        token = upstream_lint.FateToken("$(LOOP)", frozenset({1}))
        self.assertEqual(upstream_lint._fate_expand([token], {"LOOP": [token]}), [token])
        self.assertEqual(upstream_lint._fate_expand([token], {}), [token])

    def test_registration_macros_do_not_imply_dependencies(self) -> None:
        """Recognized registration wrappers require explicit device and decoder deps."""
        for middle in (
            "$(call ALLYES, TESTSRC2_FILTER)",
            "$(call TRANSCODE, RAWVIDEO, NUT, TESTSRC2_FILTER)",
            "$(call FILTERFRAMECRC, TESTSRC2, SCALE_FILTER)",
            "$(call ENCMUX, RAWVIDEO, NUT)",
            "$(if $(CONFIG_SMALL),no,$(call ALLYES, TESTSRC2_FILTER))",
            "yes",
        ):
            with self.subTest(middle=middle):
                source = f"FATE_X-{middle} += fate-x\nfate-x: CMD = -f lavfi -i testsrc2\n"
                step = self.check_source(source)
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn("needs LAVFI_INDEV WRAPPED_AVFRAME_DECODER", step.output)

    def test_missing_registration_is_informational(self) -> None:
        """A touched video command without a local registration requests review."""
        step = self.check_source("fate-x: CMD = -f lavfi -i testsrc2\n")
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("registration not found", step.output)

    def test_multiple_registrations_are_checked(self) -> None:
        """A good registration cannot mask a second registration with a gap."""
        source = FATE_RED + "FATE_X-yes += fate-filter-scale-ipt-c2-refuse-rgb\n"
        step = self.check_source(source, {5})
        self.assertEqual(step.output.count("finding:"), 1)
        self.assertIn("pre-existing (untouched)", step.output)

    def test_options_between_format_and_input(self) -> None:
        """Input options and quoted option values preserve source classification."""
        source = FATE_RED.replace(
            "-f lavfi -i", '-f lavfi -thread_queue_size 8 -dumpgraph "a b" -i'
        )
        self.assertEqual(self.check_source(source).rc, 1)

    def test_lavfi_input_scan_stays_linear(self) -> None:
        """A long option run with no `-i` resolves promptly, not by backtracking."""
        command = "-f lavfi " + '-opt "" ' * 5000 + "-vf scale"
        self.assertEqual(upstream_lint._lavfi_inputs(command), [])

    def test_lavfi_input_scan_reads_each_source(self) -> None:
        """The linear scan returns every `-f lavfi` input across option runs."""
        command = '-f lavfi -flags +x -i "testsrc2=s=2x2" -f lavfi -i sine=d=1'
        self.assertEqual(upstream_lint._lavfi_inputs(command), ["testsrc2", "sine"])

    def test_assignment_replacement_and_nested_expansion(self) -> None:
        """Replacement removes stale targets while nested references retain provenance."""
        source = (
            "OLD = fate-old\nOLD := fate-x\nGROUP = $(OLD)\n"
            "FATE_X-yes += $(GROUP)\n$(GROUP): CMD = -f lavfi -i testsrc2\n"
        )
        step = self.check_source(source, {2})
        self.assertEqual(step.rc, 1, step.output)
        self.assertNotIn("fate-old", step.output)
        self.assertIn("1 lavfi video test(s) checked", step.output)

    def test_catalog_declarations_define_source_kinds(self) -> None:
        """Only FFFilter source declarations supply video, audio and mixed names."""
        self.assertEqual(upstream_lint._fate_sources(FILTER_DECLARATIONS), FATE_SOURCES)
        self.assertEqual(upstream_lint._fate_sources("extern const AVFilter ff_vsrc_fake;"), {})

    def test_expansion_stops_at_eight_passes(self) -> None:
        """A chain longer than eight expansions retains its unresolved reference."""
        variables = {
            f"V{index}": [upstream_lint.FateToken(f"$(V{index + 1})", frozenset())]
            for index in range(10)
        }
        result = upstream_lint._fate_expand(
            [upstream_lint.FateToken("$(V0)", frozenset())], variables
        )
        self.assertEqual(result[0].text, "$(V8)")

    def test_explicit_targets_share_command(self) -> None:
        """A multi-target command checks each registered test separately."""
        source = "FATE_X-yes += fate-a fate-b\nfate-a fate-b: CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source)
        self.assertEqual(step.output.count("finding:"), 2)
        self.assertIn("2 lavfi video test(s) checked", step.output)

    def test_nested_conditions_restore_outer_dependencies(self) -> None:
        """Closing inner conditions preserves only still-enclosing dependency tokens."""
        source = (
            "ifdef CONFIG_LAVFI_INDEV\n"
            "ifndef CONFIG_SMALL\n"
            "ifeq ($(CONFIG_WRAPPED_AVFRAME_DECODER),yes)\n"
            "FATE_X-yes += fate-a\nendif\nelse\n"
            "FATE_X-yes += fate-b\nendif\nendif\n"
            "fate-a fate-b: CMD = -f lavfi -i testsrc2\n"
        )
        step = self.check_source(source)
        self.assertEqual(step.output.count("finding:"), 1)
        self.assertIn("fate-b: lavfi video input needs WRAPPED_AVFRAME_DECODER", step.output)

    def test_unrecognized_lines_are_ignored(self) -> None:
        """Only allow-listed statements can register or assign commands."""
        source = "# fate-x: CMD = -f lavfi -i testsrc2\ninclude other.mak\n"
        source += "FATE_X-no += fate-x\nfate-x: CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source)
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("registration not found", step.output)

    def test_branch_polarity_and_else(self) -> None:
        """Only the true dependency branch grants guards, including chained else."""
        registration = "FATE_X-$(call ALLYES, LAVFI_INDEV) += fate-x\n"
        command = "fate-x: CMD = -f lavfi -i testsrc2\n"
        cases = (
            ("ifdef CONFIG_WRAPPED_AVFRAME_DECODER", "else\n", 1),
            ("ifndef CONFIG_WRAPPED_AVFRAME_DECODER", "", 1),
            ("ifneq ($(CONFIG_WRAPPED_AVFRAME_DECODER),yes)", "", 1),
            ("ifeq ($(CONFIG_WRAPPED_AVFRAME_DECODER),)", "", 1),
            ("ifndef CONFIG_WRAPPED_AVFRAME_DECODER", "else\n", 0),
            ("ifneq ($(CONFIG_WRAPPED_AVFRAME_DECODER),)", "", 0),
            ("ifeq ($(CONFIG_WRAPPED_AVFRAME_DECODER),maybe)", "", 1),
            ("ifdef CONFIG_SMALL", "else ifeq ($(CONFIG_WRAPPED_AVFRAME_DECODER),yes)\n", 0),
        )
        for condition, branch, rc in cases:
            with self.subTest(condition=condition, branch=branch):
                source = condition + "\n" + branch + registration + "endif\n" + command
                self.assertEqual(self.check_source(source).rc, rc)
        source = "ifdef CONFIG_SMALL\nelse ifdef CONFIG_WRAPPED_AVFRAME_DECODER\n"
        source += registration + "endif\n" + registration + command
        self.assertEqual(self.check_source(source).rc, 1)

    def test_positive_registration_guard_allowlist(self) -> None:
        """Negative and unknown guards cannot supply dependencies from conditions."""
        command = "fate-x: CMD = -f lavfi -i testsrc2\n"
        cases = (
            ("$(if $(CONFIG_WRAPPED_AVFRAME_DECODER),no,yes)", 1, False),
            (
                "$(if $(CONFIG_SMALL),no,$(call ALLYES, WRAPPED_AVFRAME_DECODER LAVFI_INDEV))",
                0,
                False,
            ),
            ("$(if $(CONFIG_SMALL),$(call ALLYES, WRAPPED_AVFRAME_DECODER LAVFI_INDEV))", 0, False),
            ("$(mystery WRAPPED_AVFRAME_DECODER LAVFI_INDEV)", 1, True),
        )
        for guard, rc, unknown in cases:
            with self.subTest(guard=guard):
                step = self.check_source(f"FATE_X-{guard} += fate-x\n" + command)
                self.assertEqual(step.rc, rc, step.output)
                self.assertEqual("registration guard not classified" in step.output, unknown)
                if guard.startswith("$(if $(CONFIG_WRAPPED"):
                    self.assertIn("needs LAVFI_INDEV WRAPPED_AVFRAME_DECODER", step.output)
        macros = upstream_lint._fate_macros(
            "YES = $(call ALLYES, $(1))\nNO = $(call ALLYES, $(1))\nNO = no\n"
        )
        self.assertEqual(macros, frozenset({"YES"}))
        source = "FATE_X-$(call YES, LAVFI_INDEV WRAPPED_AVFRAME_DECODER) += fate-x\n"
        report = upstream_lint._fate_file(
            "tests/fate/x.mak",
            source + command,
            {1, 2},
            FATE_SOURCES,
            upstream_lint.FateContext(macros=macros),
        )
        self.assertEqual(upstream_lint._fate_summary(report).rc, 0)

    def test_trailing_comments_supply_no_dependencies(self) -> None:
        """Unescaped make comments grant nothing while escaped hashes survive."""
        source = "FATE_X-$(call ALLYES, LAVFI_INDEV) # WRAPPED_AVFRAME_DECODER += fate-x\n"
        step = self.check_source(source + "fate-x: CMD = -f lavfi -i testsrc2\n")
        self.assertNotIn("finding:", step.output)
        source = "ifdef CONFIG_LAVFI_INDEV # WRAPPED_AVFRAME_DECODER\n"
        source += "FATE_X-yes += fate-x\nendif\nfate-x: CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source)
        self.assertEqual(step.rc, 1)
        self.assertIn("needs WRAPPED_AVFRAME_DECODER", step.output)
        lines = upstream_lint._fate_lines("X = a\\#b # WRAPPED_AVFRAME_DECODER\n")
        self.assertEqual(lines[0].text, "X = a\\#b")

    def test_variable_dependencies_and_assignment_flavor(self) -> None:
        """Embedded dependency variables expand and simple assignments freeze values."""
        source = "DEPS = WRAPPED_AVFRAME_DECODER LAVFI_INDEV\n"
        source += "FATE_X-$(call ALLYES, $(DEPS)) += fate-x\nfate-x: CMD = -f lavfi -i testsrc2\n"
        self.assertEqual(self.check_source(source).rc, 0)
        source = "OLD = fate-old\nG := $(OLD)\nG += $(OLD)\nOLD = fate-new\n"
        source += "FATE_X-yes += $(G)\nfate-old: CMD = -f lavfi -i testsrc2\n"
        parsed = upstream_lint._fate_parse(source)
        self.assertIn("fate-old", parsed.registrations)
        self.assertNotIn("fate-new", parsed.registrations)
        source = "OLD = fate-old\nG = $(OLD)\nG += $(OLD)\nOLD = fate-new\n"
        source += "FATE_X-yes += $(G)\nfate-new: CMD = -f lavfi -i testsrc2\n"
        self.assertIn("fate-new", upstream_lint._fate_parse(source).registrations)
        source = "DEPS = LAVFI_INDEV WRAPPED_AVFRAME_DECODER\n"
        source += "FATE_X-$(call ALLYES,$(DEPS)) += fate-x\nfate-x: CMD = -f lavfi -i testsrc2\n"
        self.assertEqual(self.check_source(source).rc, 0)

    def test_total_expansion_budget(self) -> None:
        """Doubling expansions stop before allocating beyond the token budget."""
        source = "V0 = fate-x\n"
        source += "".join(f"V{i} = " + f"$(V{i - 1}) " * 8 + "\n" for i in range(1, 8))
        source += "FATE_X-yes += $(V7)\nfate-x: CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source)
        self.assertIn("expansion over 4096 tokens or 65536 characters", step.output)
        source += "FATE_Y-$(call ALLYES, $(V7)) += fate-y\n"
        self.assertIn(
            "expansion over 4096 tokens or 65536 characters", self.check_source(source).output
        )
        token = upstream_lint.FateToken("$(DEPS)", frozenset({1}))
        leaf = upstream_lint.FateToken("fate-x", frozenset({2}))
        overflow: set[int] = set()
        result = upstream_lint._fate_expand([token], {"DEPS": [leaf] * 4096}, overflow)
        self.assertEqual(len(result), 4096)
        self.assertEqual(overflow, set())
        result = upstream_lint._fate_expand([token], {"DEPS": [leaf] * 4097}, overflow)
        self.assertEqual(result, [token])
        self.assertEqual(overflow, {1})

    def test_adjacent_substitution_character_budget(self) -> None:
        """Adjacent substitutions and stored values obey an inclusive character budget."""
        budget = getattr(upstream_lint, "FATE_CHAR_BUDGET", 65536)
        message = "expansion over 4096 tokens or 65536 characters"
        # Fail safely on an unfixed parser before attempting the explosive chain.
        oversized = "VALUE := " + "x" * (budget + 1) + "\n"
        self.assertIn(message, self.check_source(oversized).output)
        for operator in (":=", "="):
            with self.subTest(operator=operator):
                source = f"V0 {operator} x\n"
                source += "".join(f"V{i} {operator} $(V{i - 1})$(V{i - 1})\n" for i in range(1, 31))
                if operator == "=":
                    # Cross the character limit without extending the eight-pass cap.
                    source += "V30 := $(V30)\n"
                source += "FATE_X-yes += $(V30)\nfate-x: CMD = -f lavfi -i testsrc2\n"
                self.assertIn(message, self.check_source(source).output)
                parsed = upstream_lint._fate_parse(source)
                self.assertTrue(parsed.overflows)
                self.assertTrue(
                    all(
                        sum(len(token.text) for token in value) <= budget
                        for value in parsed.variables.values()
                    )
                )
                source = f"VALUE {operator} " + "x" * budget + "\n"
                parsed = upstream_lint._fate_parse(source)
                self.assertEqual(
                    [token.text for token in parsed.variables["VALUE"]], ["x" * budget]
                )
                self.assertFalse(parsed.overflows)
                source = source.rstrip("\n") + "x\n"
                parsed = upstream_lint._fate_parse(source)
                self.assertIn(1, parsed.overflows)
                self.assertIn(message, self.check_source(source).output)
                self.assertLessEqual(sum(len(t.text) for t in parsed.variables["VALUE"]), budget)
        half = upstream_lint.FateToken("x" * (budget // 2), frozenset({2}))
        token = upstream_lint.FateToken("$(HALF)$(HALF)", frozenset({1}))
        variables = {"HALF": [half]}
        self.assertEqual(
            upstream_lint._fate_expand_pass([token], variables),
            [upstream_lint.FateToken("x" * budget, frozenset({1, 2}))],
        )
        token = upstream_lint.FateToken(token.text + "x", token.lines)
        self.assertIsNone(upstream_lint._fate_expand_pass([token], variables))
        self.assertIsNone(upstream_lint._fate_expand_pass([half, half], {}))
        overflow: set[int] = set()
        upstream_lint._fate_expand([token], variables, overflow)
        self.assertEqual(overflow, {1})

    def test_simple_assignment_keeps_undefined_reference_unresolved(self) -> None:
        """Simple assignments freeze undefined whole and embedded references permanently."""
        for value in ("fate-$(NAME)", "$(NAME)"):
            with self.subTest(value=value):
                source = f"GROUP := {value}\nNAME = new\nFATE_X-yes += $(GROUP)\n"
                source += "fate-: CMD = -f lavfi -i testsrc2\n"
                parsed = upstream_lint._fate_parse(source)
                self.assertNotIn("fate-new", parsed.registrations)
                self.assertNotIn("new", parsed.registrations)
                frozen = value.replace("$(NAME)", "$(:=NAME)")
                self.assertIn(frozen, parsed.registrations)
                step = self.check_source(source)
                self.assertIn(f"unresolved target {frozen}", step.output)
                self.assertIn("1 unresolved", step.output)
        source = "NAME = old\nGROUP := fate-$(NAME)\nNAME = new\n"
        source += "FATE_X-yes += $(GROUP)\nfate-old: CMD = -f lavfi -i testsrc2\n"
        parsed = upstream_lint._fate_parse(source)
        self.assertIn("fate-old", parsed.registrations)
        self.assertNotIn("fate-new", parsed.registrations)
        self.assertIn("0 unresolved", self.check_source(source).output)

    def test_unresolved_target_is_reported(self) -> None:
        """Touched cross-file target references remain visible and counted."""
        source = "FATE_X-yes += $(FATE_GROUP)\n$(FATE_GROUP): CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source)
        self.assertIn("unresolved target $(FATE_GROUP)", step.output)
        self.assertIn("2 unresolved", step.output)
        self.assertNotIn("unresolved target", self.check_source(source, set()).output)

    def test_all_command_variants_checked(self) -> None:
        """A later audio command cannot conceal an earlier video variant."""
        source = "FATE_X-yes += fate-x\nifdef CONFIG_SMALL\n"
        source += "fate-x: CMD = -f lavfi -i testsrc2\nelse\n"
        source += "fate-x: CMD = -f lavfi -i sine\nendif\n"
        self.assertEqual(self.check_source(source).rc, 1)
        self.assertEqual(self.check_source(source.replace("testsrc2", "sine")).rc, 0)

    def test_lavfi_options_fragments_and_chain_sources(self) -> None:
        """Flag options, adjacent quotes and every unlabelled chain preserve video."""
        for value in (
            "-re -i testsrc2",
            '-thread_queue_size ""8 -i testsrc2',
            '-i "sine [a]; testsrc2 [v]"',
        ):
            with self.subTest(value=value):
                source = "FATE_X-yes += fate-x\nfate-x: CMD = -f lavfi " + value + "\n"
                self.assertEqual(self.check_source(source).rc, 1)
        command = "-f lavfi " + '-opt ""8 ' * 5000 + '-i "sine [a]; testsrc2 [v]"'
        self.assertEqual(upstream_lint._lavfi_inputs(command), ["sine", "testsrc2"])
        self.assertEqual(upstream_lint._lavfi_inputs('-f lavfi -i "sine; [a]volume"'), ["sine"])
        source = 'FATE_X-yes += fate-x\nfate-x: CMD = -f lavfi -i "unknown; testsrc2"\n'
        step = self.check_source(source)
        self.assertEqual(step.rc, 1)
        self.assertIn("0 unclassified", step.output)

    def test_registration_specific_touch_and_deletions(self) -> None:
        """Sibling edits stay informational and newly video commands or removals block."""
        source = "FATE_X-yes += fate-x\n"
        source += "FATE_Y-$(call ALLYES, LAVFI_INDEV WRAPPED_AVFRAME_DECODER) += fate-x\n"
        source += "fate-x: CMD = -f lavfi -i testsrc2\n"
        step = self.check_source(source, {2})
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("pre-existing (untouched)", step.output)
        path = "tests/fate/filter-video.mak"
        for base, expected in ((source, 0), (source.replace("-f lavfi", "-f rawvideo"), 1)):
            with self.subTest(base=base):
                head = source.replace("-i testsrc2", "-re -i testsrc2")
                report = upstream_lint._fate_file(
                    path, head, {3}, FATE_SOURCES, upstream_lint.FateContext(base=base)
                )
                self.assertEqual(upstream_lint._fate_summary(report).rc, expected)
        head = "FATE_X-$(call ALLYES, LAVFI_INDEV) += fate-x\nfate-x: CMD = -f lavfi -i testsrc2\n"
        base = head.replace("LAVFI_INDEV", "LAVFI_INDEV WRAPPED_AVFRAME_DECODER")
        report = upstream_lint._fate_file(
            path,
            head,
            set(),
            FATE_SOURCES,
            upstream_lint.FateContext(base=base, deleted=frozenset({1})),
        )
        self.assertEqual(upstream_lint._fate_summary(report).rc, 1)
        for head, touched in (
            ("DEPS = LAVFI_INDEV\nFATE_X-$(call ALLYES, $(DEPS)) += fate-x\n", {1}),
            ("ifndef CONFIG_WRAPPED_AVFRAME_DECODER\nFATE_X-yes += fate-x\nendif\n", {1}),
        ):
            with self.subTest(head=head):
                self.assertEqual(
                    self.check_source(head + "fate-x: CMD = -f lavfi -i testsrc2\n", touched).rc, 1
                )


class DiagnosticCitationTest(unittest.TestCase):
    """Positive, negative and boundary coverage of diagnostic workaround citations."""

    def test_uncited_diagnostic_workaround_returns_flag(self) -> None:
        """An uncited compiler-diagnostic workaround returns the first named flag."""
        message = (
            "avcodec/x: silence -Wmaybe-uninitialized false positive\n\nGCC 14 warns about ctx.\n"
        )
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-Wmaybe-uninitialized")

    def test_gcc_bugzilla_url_satisfies_citation(self) -> None:
        """A GCC Bugzilla URL cites the named compiler diagnostic."""
        message = (
            "avcodec/x: silence -Wmaybe-uninitialized false positive\n\n"
            "GCC 14 warns about ctx.\n"
            "https://gcc.gnu.org/bugzilla/show_bug.cgi?id=109999\n"
        )
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_reproducer_line_satisfies_citation(self) -> None:
        """A Reproducer line with a Compiler Explorer URL cites the diagnostic."""
        message = (
            "avcodec/x: silence -Wmaybe-uninitialized false positive\n\n"
            "GCC 14 warns about ctx.\n"
            "Reproducer: https://godbolt.org/z/abc123\n"
        )
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_flag_without_workaround_wording_returns_none(self) -> None:
        """A compiler flag without workaround wording does not require a citation."""
        message = "avcodec/x: build with -Wall\n\nNo behaviour change.\n"
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_workaround_wording_without_flag_returns_none(self) -> None:
        """Workaround wording without a compiler diagnostic flag passes."""
        message = "avcodec/x: work around a decoder hang\n"
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_signed_off_by_workaround_wording_is_ignored(self) -> None:
        """Signed-off-by trailers cannot supply workaround wording for a body flag."""
        message = "avcodec/x: set flags\n\nUse -Wall.\n\nSigned-off-by: Work Around x@invalid\n"
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_empty_reproducer_line_does_not_cite_diagnostic(self) -> None:
        """A Reproducer prefix with nothing after it on the line does not count."""
        prefix = (
            "avcodec/x: silence -Wmaybe-uninitialized false positive\n\nGCC 14 warns about ctx.\n"
        )
        for trailer in ("Reproducer:", "Reproducer:\n", "Reproducer: \t\nSee above.\n"):
            with self.subTest(trailer=trailer):
                self.assertEqual(
                    upstream_lint.uncited_diagnostic(prefix + trailer), "-Wmaybe-uninitialized"
                )

    def test_hash_flag_detected(self) -> None:
        """Clang flags containing a hash in the suffix are detected."""
        message = "avutil/x: silence -W#warnings\n"
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-W#warnings")

    def test_uppercase_flag_detected(self) -> None:
        """Clang flags containing uppercase letters in the suffix are detected."""
        message = "avutil/x: silence -WCFString-literal\n"
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-WCFString-literal")

    def test_plus_flag_detected_whole(self) -> None:
        """Flags containing plus signs return the whole flag token."""
        message = "avcodec/x: silence -Wc++11-compat\n"
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-Wc++11-compat")

    def test_lowercase_w_not_a_flag(self) -> None:
        """Lowercase -w is a general compiler option, not a named diagnostic flag."""
        message = "avcodec/x: silence warnings with -w\n"
        self.assertIsNone(upstream_lint.uncited_diagnostic(message))

    def test_wrapped_false_positive_detected(self) -> None:
        """Line-wrapped false positive wording still triggers the citation check."""
        message = (
            "avcodec/x: avoid -Wmaybe-uninitialized\n\nGCC reports a false\npositive for ctx.\n"
        )
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-Wmaybe-uninitialized")

    def test_wrapped_work_around_detected(self) -> None:
        """Line-wrapped work around wording still triggers the citation check."""
        message = (
            "avcodec/x: init ctx for -Wmaybe-uninitialized\n\nThis is a work\naround for GCC 14.\n"
        )
        self.assertEqual(upstream_lint.uncited_diagnostic(message), "-Wmaybe-uninitialized")


class ClaimScopeTest(unittest.TestCase):
    """Positive, negative and boundary coverage of verification and scope claims."""

    def test_passes_all_fate_tests_claim_detected(self) -> None:
        """Blanket FATE pass claims return the matched verification phrase."""
        message = "avcodec/x: update y\n\nPasses all FATE tests.\n"
        self.assertEqual(upstream_lint.unverified_claim(message), "Passes all FATE tests")

    def test_fully_verified_claim_detected(self) -> None:
        """Blanket verification claims return the matched phrase."""
        message = "avcodec/x: update y\n\nFully verified on x86.\n"
        self.assertEqual(upstream_lint.unverified_claim(message), "Fully verified")

    def test_specific_command_and_platform_passes(self) -> None:
        """Naming the concrete test command and platform is not flagged."""
        message = "avcodec/x: update y\n\nTested with make fate on x86-64 Linux.\n"
        self.assertIsNone(upstream_lint.unverified_claim(message))

    def test_no_regression_test_explanation_passes(self) -> None:
        """Explaining why there is no regression test is not a no-regressions claim."""
        message = "avcodec/x: fix y\n\nNo regression test: the path needs hardware.\n"
        self.assertIsNone(upstream_lint.unverified_claim(message))

    def test_signed_off_by_verification_words_ignored(self) -> None:
        """Signed-off-by trailers are excluded from verification-claim matching."""
        message = "avcodec/x: update y\n\nSigned-off-by: Fully Tested <x@invalid>\n"
        self.assertIsNone(upstream_lint.unverified_claim(message))

    def test_both_loops_scope_claim_detected(self) -> None:
        """A both-loops commit message returns its multi-site scope phrase."""
        message = "avcodec/x: silence a warning in both loops\n"
        self.assertEqual(upstream_lint.scope_claim(message), "both loops")

    def test_all_three_callers_scope_claim_detected(self) -> None:
        """A quantified callers phrase within two words returns the scope match."""
        message = "avcodec/x: check all three callers\n"
        self.assertEqual(upstream_lint.scope_claim(message), "all three callers")

    def test_ordinary_single_site_message_passes(self) -> None:
        """Messages without multi-site quantifiers return None."""
        self.assertIsNone(upstream_lint.scope_claim("avcodec/x: rename y\n"))

    def test_source_hunks_counts_only_non_test_source_files(self) -> None:
        """Source hunks count library sources while ignoring docs, tests and a
        deletion without its old path.
        """
        two_source = "+++ b/libavcodec/x.c\n@@ -3 +3 @@\n-a\n+b\n@@ -9 +9 @@\n-c\n+d\n"
        self.assertEqual(upstream_lint.source_hunks(two_source), 2)
        source_and_doc = (
            "+++ b/libavcodec/x.c\n@@ -3 +3 @@\n-a\n+b\n+++ b/doc/x.texi\n@@ -3 +3 @@\n-c\n+d\n"
        )
        self.assertEqual(upstream_lint.source_hunks(source_and_doc), 1)
        test_and_deleted = (
            "+++ b/libavcodec/tests/x.c\n@@ -3 +3 @@\n-a\n+b\n+++ /dev/null\n@@ -3 +0,0 @@\n-c\n"
        )
        self.assertEqual(upstream_lint.source_hunks(test_and_deleted), 0)

    def test_scope_claim_matches_across_line_breaks(self) -> None:
        """Line-wrapped quantified site phrases still match across newlines."""
        first = "avcodec/x: update y\n\nCheck all three\ncallers before returning.\n"
        self.assertEqual(upstream_lint.scope_claim(first), "all three\ncallers")
        second = "avcodec/x: update y\n\nUpdate both call\nsites in the decoder.\n"
        self.assertEqual(upstream_lint.scope_claim(second), "both call\nsites")

    def test_every_and_each_take_singular_site_nouns(self) -> None:
        """Singular site nouns after every or each return their scope phrase."""
        cases = (
            ("avcodec/x: clamp y in each branch\n", "each branch"),
            ("avcodec/x: free frame on every error path\n", "every error path"),
            ("avcodec/x: check return value at each site\n", "each site"),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.scope_claim(message), expected)

    def test_every_and_each_take_plural_branches(self) -> None:
        """Plural branches after every or each return their scope phrase within two words."""
        cases = (
            ("avcodec/x: clamp y in each of the branches\n", "each of the branches"),
            ("avcodec/x: reset state in each of these branches\n", "each of these branches"),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.scope_claim(message), expected)
        self.assertIsNone(
            upstream_lint.scope_claim("avcodec/x: reset state in every one of these branches\n")
        )

    def test_scope_claim_two_word_boundary(self) -> None:
        """At most two intervening words separate the quantifier from its noun."""
        hit = "avcodec/x: check all three inner callers\n"
        self.assertEqual(upstream_lint.scope_claim(hit), "all three inner callers")
        too_far = "avcodec/x: check all of the three callers\n"
        self.assertIsNone(upstream_lint.scope_claim(too_far))
        non_site = "avcodec/x: both decoders use the same table\n"
        self.assertIsNone(upstream_lint.scope_claim(non_site))

    def test_scope_claim_ignores_signoff_in_any_case(self) -> None:
        """Signed-off-by lines in any letter case are excluded from scope matching."""
        for prefix in ("Signed-off-by", "signed-off-by"):
            with self.subTest(prefix=prefix):
                message = f"avcodec/x: update y\n\n{prefix}: Both Loops <x@invalid>\n"
                self.assertIsNone(upstream_lint.scope_claim(message))

    def test_lowercase_signoff_verification_words_ignored(self) -> None:
        """Lowercase signed-off-by trailers cannot trigger verification claims."""
        message = "avcodec/x: update y\n\nsigned-off-by: Fully Tested <x@invalid>\n"
        self.assertIsNone(upstream_lint.unverified_claim(message))

    def test_negated_and_argued_claims_pass(self) -> None:
        """Negated verification phrases and argued safety statements pass."""
        messages = (
            "avcodec/x: fix y\n\nNo regression testing is possible without hardware.\n",
            "avcodec/x: free buffer\n\nFreeing here is completely safe because p is NULL.\n",
            "avcodec/x: fix y\n\nThis fallback path was never fully tested by FATE.\n",
            "avcodec/x: fix y\n\nThis path has not been fully tested.\n",
            "avcodec/x: fix y\n\nThis path cannot be fully tested without hardware.\n",
            "avcodec/x: fix y\n\nIt is 100% safe since p is NULL.\n",
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.unverified_claim(message))

    def test_negation_must_precede_the_claim(self) -> None:
        """An earlier negation or test note does not excuse a blanket claim."""
        first = "avcodec/x: fix y\n\nThis is not slow and fully tested.\n"
        self.assertEqual(upstream_lint.unverified_claim(first), "fully tested")
        second = "avcodec/x: fix y\n\nNo regression testing; all FATE tests pass.\n"
        self.assertEqual(upstream_lint.unverified_claim(second), "all FATE tests pass")

    def test_more_blanket_claims_detected(self) -> None:
        """Expanded blanket test, verification and regression phrases fail."""
        cases = (
            ("avcodec/x: update y\n\nEvery test passed.\n", "Every test passed"),
            ("avcodec/x: update y\n\nAll unit tests pass.\n", "All unit tests pass"),
            ("avcodec/x: update y\n\nThoroughly verified.\n", "Thoroughly verified"),
            (
                "avcodec/x: optimize loop\n\nRuns 2x faster with no performance regressions.\n",
                "no performance regressions",
            ),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.unverified_claim(message), expected)

    def test_no_regressions_and_100_percent_safe_detected(self) -> None:
        """Unargued no-regressions and 100%-safe claims return their phrase."""
        first = "avcodec/x: fix y\n\nNo regressions.\n"
        self.assertEqual(upstream_lint.unverified_claim(first), "No regressions")
        second = "avcodec/x: fix y\n\n100% safe.\n"
        self.assertEqual(upstream_lint.unverified_claim(second), "100% safe")

    def test_speed_claim_detected(self) -> None:
        """An encode or decode speed claim without an end-to-end figure returns its phrase."""
        benchmark_claim = (
            "avcodec/x: paint maps once\n\nThe map painter benchmark ran seven rounds, "
            "so encoding is 10x faster.\n"
        )
        cases = (
            (
                benchmark_claim,
                "encoding is 10x faster",
            ),
            ("avcodec/x: cache maps\n\nThis gives faster encoding.\n", "faster encoding"),
            ("avcodec/x: cache maps\n\nThis speeds up the encoder.\n", "speeds up the encoder"),
            ("avcodec/x: cache maps\n\nAn end-to-end speedup of 4%.\n", "end-to-end speedup"),
            ("avcodec/x: cache maps\n\nDecoding speed-up for 4K.\n", "Decoding speed-up"),
            ("avcodec/x: cache maps\n\nThe decoder is faster.\n", "decoder is faster"),
        )
        for message, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(upstream_lint.speed_claim(message), expected)

    def test_speed_claim_with_end_to_end_figure_passes(self) -> None:
        """A speed claim next to an fps, -benchmark, speed= or hyperfine figure passes."""
        claim = "avcodec/x: cache maps\n\nEncoding is faster: {}.\n"
        for figure in (
            "120 fps instead of 100 fps",
            "ffmpeg -benchmark reports bench: utime=4.1s",
            "speed=1.5x instead of speed=1.2x",
            "hyperfine shows 4.1 s against 4.5 s",
            "118.5 frames/s",
        ):
            with self.subTest(figure=figure):
                self.assertIsNone(upstream_lint.speed_claim(claim.format(figure)))

    def test_speed_claim_negated_or_off_topic_passes(self) -> None:
        """Negated speed wording and speed words without an encode or decode word pass."""
        for message in (
            "avcodec/x: cache maps\n\nThis does not make encoding faster.\n",
            "avcodec/x: cache maps\n\nThe helper runs without an end-to-end speedup.\n",
            "avcodec/x: paint maps 10x faster\n\nThe map painter is quicker.\n",
            "avcodec/x: cache maps\n\nNothing here changes.\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.speed_claim(message))

    def test_speed_negation_must_share_the_sentence(self) -> None:
        """A negation in an earlier sentence does not excuse a later speed claim."""
        message = "avcodec/x: cache maps\n\nThe old path did not cache. Encoding is faster.\n"
        self.assertEqual(upstream_lint.speed_claim(message), "Encoding is faster")

    def test_speed_claim_decimal_in_negation_passes(self) -> None:
        """Decimal points inside numbers do not end the negation window of speed claims."""
        for message in (
            "No 1.5x encoding speedup is claimed.",
            "Not 2.0x faster encoding here.",
            "It does not claim 3.25% encoding speedup.",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.speed_claim(message))

    def test_speed_claim_sentence_end_after_negation_detected(self) -> None:
        """Non-decimal full stops and other sentence marks still end the negation window."""
        cases = (
            ("No change. Encoding speedup of 2x.", "Encoding speedup"),
            ("Not in 1.2. Encoding speedup of 2x.", "Encoding speedup"),
            ("Not in 1.2.3. Encoding speedup of 2x.", "Encoding speedup"),
            ("Not in 1.2.Encoding speedup of 2x.", "Encoding speedup"),
            ("Not 2.Faster encoding now.", "Faster encoding"),
            ("No change in 3._x. Encoding speedup of 2x.", "Encoding speedup"),
            ("Not in 1.2.This gives faster encoding.", "faster encoding"),
            ("Not 2.This gives faster encoding.", "faster encoding"),
            ("No change in 3._x, encoding speedup of 2x.", "encoding speedup"),
            ("Not in x_.2x faster encoding.", "faster encoding"),
            ("Encoding speedup of 1.5x.", "Encoding speedup"),
            ("No .5x encoding speedup is claimed.", "encoding speedup"),
            ("Not here.2x faster encoding.", "faster encoding"),
            ("No 1..5x encoding speedup is claimed.", "encoding speedup"),
            ("No 1;5x encoding speedup is claimed.", "encoding speedup"),
            ("No 1!5x encoding speedup is claimed.", "encoding speedup"),
            ("No 1?5x encoding speedup is claimed.", "encoding speedup"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(upstream_lint.speed_claim(message), expected)

    def test_speed_claim_decimal_negation_boundaries(self) -> None:
        """Window-boundary decimals and multi-dot numbers do not end speed negation."""
        dot_at_start = "Version 1.5 of this encoder patch does not claim any new encoding speedup."
        window_start = dot_at_start.index("encoding speedup") - 48
        self.assertEqual(dot_at_start[window_start - 1 : window_start + 2], "1.5")
        self.assertIsNone(upstream_lint.speed_claim(dot_at_start))
        digit_at_start = (
            "Version 1.5 of this encoder patch does not claim any real encoding speedup."
        )
        after_dot = digit_at_start.index("encoding speedup") - 48
        self.assertEqual(digit_at_start[after_dot - 2 : after_dot + 1], "1.5")
        self.assertIsNone(upstream_lint.speed_claim(digit_at_start))
        for message in (
            "No 1.2.3 encoding speedup is claimed.",
            "Not in 1.2.3 is faster encoding claimed.",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.speed_claim(message))

    def test_speed_claim_finding_names_the_fix(self) -> None:
        """The claim-scope finding for a speed claim asks for an end-to-end figure."""
        findings = upstream_lint._unverified_findings(
            "0123456789abcdef", "avcodec/x: cache maps\n\nEncoding is faster.\n"
        )
        expected_finding = (
            '0123456789ab: claims "Encoding is faster" without an end-to-end measurement; '
            "name an ffmpeg -benchmark or fps result, or drop the claim"
        )
        self.assertEqual(
            findings,
            [expected_finding],
        )

    def test_source_hunks_reads_headers_outside_hunk_bodies(self) -> None:
        """Added +++ and removed --- C lines inside a hunk do not reset headers."""
        added_plus = (
            "diff --git a/libavcodec/x.c b/libavcodec/x.c\n"
            "--- a/libavcodec/x.c\n"
            "+++ b/libavcodec/x.c\n"
            "@@ -3 +3 @@\n"
            "-a\n"
            "+++ ptr;\n"
            "@@ -9 +9 @@\n"
            "-c\n"
            "+d\n"
        )
        self.assertEqual(upstream_lint.source_hunks(added_plus), 2)
        removed_minus = added_plus.replace("-a\n+++ ptr;\n", "--- ptr;\n+a\n")
        self.assertEqual(upstream_lint.source_hunks(removed_minus), 2)

    def test_source_hunks_counts_deleted_source_files(self) -> None:
        """Deleted library sources count their hunks while deleted tests do not."""
        deleted_and_modified = (
            "diff --git a/libavcodec/old.c b/libavcodec/old.c\n"
            "deleted file mode 100644\n"
            "--- a/libavcodec/old.c\n"
            "+++ /dev/null\n"
            "@@ -1,4 +0,0 @@\n"
            "-int ff_old(void) { return 0; }\n"
            "diff --git a/libavcodec/new.c b/libavcodec/new.c\n"
            "--- a/libavcodec/new.c\n"
            "+++ b/libavcodec/new.c\n"
            "@@ -3 +3 @@\n"
            "-return 1;\n"
            "+return 2;\n"
        )
        self.assertEqual(upstream_lint.source_hunks(deleted_and_modified), 2)
        second = (
            "diff --git a/libavcodec/x.c b/libavcodec/x.c\n"
            "--- a/libavcodec/x.c\n"
            "+++ b/libavcodec/x.c\n"
            "@@ -3 +3 @@\n"
            "-a\n"
            "+b\n"
            "diff --git a/libavcodec/y.c b/libavcodec/y.c\n"
            "--- a/libavcodec/y.c\n"
            "+++ /dev/null\n"
            "@@ -3 +0,0 @@\n"
            "-c\n"
        )
        self.assertEqual(upstream_lint.source_hunks(second), 2)
        deleted_test = second.replace("libavcodec/y.c", "libavcodec/tests/y.c")
        self.assertEqual(upstream_lint.source_hunks(deleted_test), 1)

    def test_source_hunks_decodes_quoted_headers(self) -> None:
        """Quoted non-ASCII source headers count for deleted and changed files alike."""
        deleted = (
            'diff --git "a/libavcodec/caf\\303\\251.c" "b/libavcodec/caf\\303\\251.c"\n'
            "deleted file mode 100644\n"
            '--- "a/libavcodec/caf\\303\\251.c"\n'
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-int ff_old(void) { return 0; }\n"
        )
        self.assertEqual(upstream_lint.source_hunks(deleted), 1)
        changed = (
            'diff --git "a/libavcodec/caf\\303\\251.c" "b/libavcodec/caf\\303\\251.c"\n'
            '--- "a/libavcodec/caf\\303\\251.c"\n'
            '+++ "b/libavcodec/caf\\303\\251.c"\n'
            "@@ -3 +3 @@\n"
            "-a\n"
            "+b\n"
        )
        self.assertEqual(upstream_lint.source_hunks(changed), 1)
        quoted_test = deleted.replace("libavcodec/caf", "libavcodec/tests/caf")
        self.assertEqual(upstream_lint.source_hunks(quoted_test), 0)

    def test_source_hunks_fftools_added_and_empty(self) -> None:
        """Context-bearing fftools diffs and added files count; empty diffs give 0."""
        fftools = (
            "diff --git a/fftools/ffmpeg.c b/fftools/ffmpeg.c\n"
            "--- a/fftools/ffmpeg.c\n"
            "+++ b/fftools/ffmpeg.c\n"
            "@@ -3,2 +3,2 @@\n"
            " a\n"
            "-b\n"
            "+c\n"
        )
        self.assertEqual(upstream_lint.source_hunks(fftools), 1)
        added_file = (
            "diff --git a/libavcodec/n.c b/libavcodec/n.c\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/libavcodec/n.c\n"
            "@@ -0,0 +1,2 @@\n"
            "+a\n"
            "+b\n"
        )
        self.assertEqual(upstream_lint.source_hunks(added_file), 1)
        self.assertEqual(upstream_lint.source_hunks(""), 0)


class ErrorScopeClaimTest(unittest.TestCase):
    """Positive, negative and boundary coverage of error-handling scope claims."""

    def test_dashenc_before_reword_body_is_flagged(self) -> None:
        """Loose retain-or-stays wording does not qualify an error-handling subject."""
        message = (
            "avformat/dashenc: propagate output close errors\n\n"
            "Other rename sites retain their existing error handling.\n"
            "The sticky AVIO error stays.\n"
        )
        self.assertEqual(upstream_lint.error_scope_claim(message), "propagate output close errors")

    def test_dashenc_remain_outside_sentence_qualifies(self) -> None:
        """A remain-outside sentence split across lines qualifies the subject claim."""
        message = (
            "avformat/dashenc: propagate output close errors\n\n"
            "Other rename sites retain their existing error handling.\n"
            "Errors reported only by the single-file close in dash_free() and\n"
            "damaged segments left by ignored multi-file streaming write failures\n"
            "remain outside this change.\n"
        )
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_hlsplaylist_unchanged_behavior_qualifies(self) -> None:
        """As-on-master and unchanged-behavior sentences qualify playlist error subjects."""
        message = (
            "avformat/hlsplaylist: return playlist write errors\n\n"
            "The fail label still overwrites ret with hlsenc_io_close's\n"
            "result, as on master; close, retry and trailer behavior are unchanged.\n"
        )
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_unchanged_without_scope_noun_is_flagged(self) -> None:
        """An unchanged sentence without a scope noun does not qualify."""
        message = "avfilter/vf_x: propagate write errors\n\nOutput is unchanged.\n"
        self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")

    def test_no_other_error_path_remains_qualifies(self) -> None:
        """A no-other-error-path completeness sentence qualifies the subject."""
        message = "avfilter/vf_x: report write errors\n\nNo other error path remains.\n"
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_subject_without_error_noun_is_not_a_claim(self) -> None:
        """Subjects that propagate timestamps without an error noun pass."""
        self.assertIsNone(upstream_lint.error_scope_claim("avformat/x: propagate timestamps\n"))

    def test_negated_error_subject_is_not_a_claim(self) -> None:
        """A negated return-errors subject is not treated as a claim."""
        self.assertIsNone(
            upstream_lint.error_scope_claim("avformat/x: do not return write errors\n")
        )

    def test_signoff_remain_outside_does_not_qualify(self) -> None:
        """A Signed-off-by line carrying remain-outside text does not qualify."""
        message = (
            "avfilter/vf_x: propagate write errors\n\n"
            "Signed-off-by: Paths remain outside this change <x@invalid>\n"
        )
        self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")

    def test_member_access_dot_does_not_split_qualifying_sentence(self) -> None:
        """A dot inside an identifier keeps one qualification sentence intact."""
        message = (
            "avfilter/vf_x: propagate write errors\n\n"
            "Close errors in pkg.dash_free() remain outside this change.\n"
        )
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_error_scope_finding_names_the_fix(self) -> None:
        """The claim-scope finding for an error subject asks for an exclusion sentence."""
        findings = upstream_lint._unverified_findings(
            "0123456789abcdef", "avfilter/vf_x: propagate write errors\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertIn('subject claims error handling ("propagate write errors")', findings[0])
        self.assertIn("remain outside this change", findings[0])

    def test_avutil_check_av_strerror_failures_flagged(self) -> None:
        """A check-verb summary after an area error prefix is still a claim."""
        message = "avutil/error: check av_strerror() failures\n"
        self.assertEqual(upstream_lint.error_scope_claim(message), "check av_strerror() failures")

    def test_nvenc_avoid_surface_not_claim(self) -> None:
        """An allow-listed word out of verb position makes no claim."""
        message = "avcodec/nvenc: avoid invalid surface destruction after init error\n"
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_fix_leak_and_return_write_errors_flagged(self) -> None:
        """A return-verb clause after and still claims when error nouns follow."""
        message = "avcodec/x: fix a leak and return write errors\n"
        self.assertEqual(upstream_lint.error_scope_claim(message), "return write errors")

    def test_propagate_write_errors_no_prefix_flagged(self) -> None:
        """A subject summary without an area prefix can still claim error handling."""
        message = "propagate write errors\n"
        self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")

    def test_returned_and_catch_inflections_flagged(self) -> None:
        """Past-tense returned and every inflection of catch claim error handling."""
        cases = (
            ("avcodec/foo: returned encode errors\n", "returned encode errors"),
            ("avcodec/foo: catch write errors\n", "catch write errors"),
            ("avcodec/foo: catches write errors\n", "catches write errors"),
            ("avcodec/foo: caught write errors\n", "caught write errors"),
            ("avcodec/foo: catching write errors\n", "catching write errors"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(upstream_lint.error_scope_claim(message), expected)

    def test_nominal_error_handling_claims_flagged(self) -> None:
        """Closed-list nominal verbs before error or failure handling nouns are claims."""
        cases = (
            ("avcodec/foo: add error checks\n", "add error checks"),
            ("avcodec/foo: fix error propagation\n", "fix error propagation"),
            ("avcodec/foo: fix error handling in init\n", "fix error handling in init"),
            ("avcodec/foo: improve failure reporting\n", "improve failure reporting"),
            ("avcodec/foo: rework error checking\n", "rework error checking"),
            ("avcodec/foo: complete failure check\n", "complete failure check"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(upstream_lint.error_scope_claim(message), expected)

    def test_surface_noun_adjunct_not_flagged(self) -> None:
        """A leading surface noun adjunct is not treated as an error-handling verb."""
        subject = "avcodec/foo: surface format check after init failure\n"
        self.assertIsNone(upstream_lint.error_scope_claim(subject))

    def test_earlier_clause_negation_does_not_suppress_claim(self) -> None:
        """Negation in an earlier clause does not suppress a later affirmative claim."""
        cases = (
            (
                "avcodec/foo: do not leak frame and return write errors\n",
                "return write errors",
            ),
            (
                "avcodec/foo: fix non-monotonic PTS without B-frames and propagate decode errors\n",
                "propagate decode errors",
            ),
            ("avcodec/foo: do not crash, check init failure\n", "check init failure"),
            ("avcodec/foo: never block; report decode errors\n", "report decode errors"),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                self.assertEqual(upstream_lint.error_scope_claim(message), expected)

    def test_same_clause_negations_not_flagged(self) -> None:
        """Negation before the verb inside the same clause suppresses that clause."""
        for message in (
            "avformat/foo: do not report errors twice\n",
            "avformat/foo: never propagate benign EOF errors\n",
            "avformat/foo: without checking write errors, free frame\n",
            "avformat/foo: don't return encode errors\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_clause_bound_stops_cross_clause_noun_pairing(self) -> None:
        """An error noun in a later clause does not pair with a verb in an earlier clause."""
        for message in (
            "avcodec/foo: check frame size and avoid error log spam\n",
            "avcodec/foo: check frame size and avoid init failure\n",
            "avcodec/foo: check frame size, do not return write errors\n",
            "avcodec/foo: return 0; log write failure\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_post_verb_clause_nonclaims_not_flagged(self) -> None:
        """Post-verb no-error, instead-of, unchanged and no-more-than clauses make no claim."""
        for message in (
            "avcodec/foo: return the error code of foo unchanged\n",
            "avcodec/foo: return 0 when no error occurred\n",
            "avcodec/foo: return 0 when no failure occurred\n",
            "avcodec/foo: report errors no more than once\n",
            "avcodec/foo: return 0 instead of error on empty packet\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_error_compound_nouns_not_flagged(self) -> None:
        """Closed-list compound nouns after error do not count as failure claims."""
        for message in (
            "avcodec/foo: check error resilience flags\n",
            "avcodec/foo: handle error concealment in B-frames\n",
            "avcodec/foo: forward error callback pointer to context\n",
            "avcodec/foo: check if error callback is set\n",
            "avcodec/foo: return standard error string from table\n",
            "avcodec/foo: check error message format\n",
            "avcodec/foo: return error text for status\n",
            "avcodec/foo: report error log level\n",
            "avcodec/foo: return error name from code\n",
            "avcodec/foo: check error table bounds\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.error_scope_claim(message))
        self.assertEqual(
            upstream_lint.error_scope_claim("avcodec/foo: report error message on write failure\n"),
            "report error message on write failure",
        )

    def test_multiple_leading_prefixes_skipped(self) -> None:
        """Every leading area prefix without spaces is skipped before reading the summary."""
        for message in (
            "check: fix typo in failure message\n",
            "avcodec/x: check: fix typo in failure message\n",
            "avutil/error: document av_strerror() return value\n",
            "avcodec/error_resilience: return early on skip\n",
        ):
            with self.subTest(message=message):
                self.assertIsNone(upstream_lint.error_scope_claim(message))
        self.assertEqual(
            upstream_lint.error_scope_claim("avcodec/x: subsys: propagate write errors\n"),
            "propagate write errors",
        )

    def test_abbreviation_and_colon_keep_qualifying_sentence_intact(self) -> None:
        """Abbreviation dots and colons keep one scope sentence intact while semicolons split."""
        for body in (
            "Other error paths, e.g. close, remain outside this change.",
            "Other error paths, i.e. close, remain outside this change.",
            "Other error paths (cf. close) remain outside this change.",
            "Other error paths vs. master remain outside this change.",
            "Other error paths, close, etc. remain outside this change.",
            "Other error paths: close and flush remain outside this change.",
        ):
            with self.subTest(body=body):
                message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
                self.assertIsNone(upstream_lint.error_scope_claim(message))
        split_semicolon = (
            "avfilter/vf_x: propagate write errors\n\nThis stays out of scope; error handling.\n"
        )
        self.assertEqual(upstream_lint.error_scope_claim(split_semicolon), "propagate write errors")

    def test_exclamation_question_split_flags_unqualified_claim(self) -> None:
        """Exclamation and question marks split sentences so missing qualification is flagged."""
        for body in (
            "Errors are reported! Output remains unchanged.",
            "Errors are reported? Output remains unchanged.",
        ):
            with self.subTest(body=body):
                message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
                self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")

    def test_exclamation_question_split_qualifies_error_scope(self) -> None:
        """Split qualification sentences after exclamation or question marks qualify the claim."""
        for body in (
            "Is this right? Other error paths remain outside this change.",
            "Errors are reported! Other error paths remain outside this change.",
            "Other error paths remain outside this change!",
        ):
            with self.subTest(body=body):
                message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_in_word_exclamation_question_do_not_split(self) -> None:
        """In-word exclamation and question marks do not split qualification sentences."""
        body = "Other error paths in a?b and x!=y remain outside this change."
        sentences = upstream_lint._qualification_sentences(body)
        self.assertEqual(len(sentences), 1)
        self.assertEqual(
            sentences[0],
            "Other error paths in a?b and x!=y remain outside this change",
        )
        message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
        self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_bare_unchanged_without_other_marker_does_not_qualify(self) -> None:
        """Bare unchanged, as-before and as-on-master phrases require an other-scope word."""
        for body in (
            "The error message text is unchanged.",
            "Error messages are unchanged.",
            "Log an error as before when opening the file.",
            "On failure, free the context as on master.",
        ):
            with self.subTest(body=body):
                message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
                self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")
        for body in (
            "Other error paths are unchanged.",
            "Remaining error paths behave as on master.",
            "The rest of the error handling is unchanged.",
            "Existing failure handling works as before.",
        ):
            with self.subTest(body=body):
                message = f"avfilter/vf_x: propagate write errors\n\n{body}\n"
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_quoted_diff_and_trailer_lines_do_not_qualify(self) -> None:
        """Quoted lines, hunk blocks, -by trailers and address or URL trailers do not qualify."""
        for line in (
            "> error handling is unchanged",
            "> Other error paths remain outside this change.",
            "@@ -1 +1 @@\n+ // Other error paths remain outside this change.",
            "diff --git a/x b/x\n- // Other error paths remain outside this change.",
            "Reviewed-by: Other error paths remain outside this change <x@invalid>",
            "Suggested-by: Other error paths remain outside this change",
            "Cc: Other error paths remain outside this change <x@invalid>",
            "Link: https://example.invalid/other-error-paths-remain-outside-this-change",
        ):
            with self.subTest(line=line):
                message = f"avfilter/vf_x: propagate write errors\n\n{line}\n"
                self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")

    def test_unchanged_behaviour_nouns_qualify(self) -> None:
        """Named behaviour, path, case and site nouns qualify conditional unchanged phrases."""
        for body in (
            "Read paths are unchanged.",
            "Seek cases are unchanged.",
            "Flush path is unchanged.",
            "Close case works as before.",
            "Retry site behaves as on master.",
            "Close sites are unchanged.",
            "Trailer behavior is unchanged.",
            "Trailer behaviour is unchanged.",
        ):
            with self.subTest(body=body):
                message = f"avformat/x: return write errors\n\n{body}\n"
                self.assertIsNone(upstream_lint.error_scope_claim(message))
        unchanged_message = (
            "avformat/x: return write errors\n\nThe error message text is unchanged.\n"
        )
        self.assertEqual(upstream_lint.error_scope_claim(unchanged_message), "return write errors")

    def test_body_bullets_qualify(self) -> None:
        """Body bullet lines outside quoted hunk blocks qualify error-handling subjects."""
        for line in (
            "- Other close and flush error paths are unchanged.",
            "+ Other close and flush error paths are unchanged.",
        ):
            with self.subTest(line=line):
                message = f"avfilter/vf_x: propagate write errors\n\n{line}\n"
                self.assertIsNone(upstream_lint.error_scope_claim(message))

    def test_quoted_hunk_blocks_dropped_until_empty_line(self) -> None:
        """Quoted diff and hunk blocks drop every line until the next empty line."""
        for hunk in (
            "@@ -1 +1 @@\n+ Other error paths are unchanged.",
            "diff --git a/x b/x\n- Other error paths are unchanged.",
            "@@ -1 +1 @@ Other error paths are unchanged.\n+Other error paths are unchanged.",
            "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n Other error paths are unchanged.",
        ):
            with self.subTest(hunk=hunk):
                message = f"avfilter/vf_x: propagate write errors\n\n{hunk}\n"
                self.assertEqual(upstream_lint.error_scope_claim(message), "propagate write errors")
        after_empty = (
            "avfilter/vf_x: propagate write errors\n\n"
            "@@ -1 +1 @@\n"
            "+ Ignored hunk line.\n\n"
            "Other error paths are unchanged.\n"
        )
        self.assertIsNone(upstream_lint.error_scope_claim(after_empty))
        after_diff_empty = (
            "avfilter/vf_x: propagate write errors\n\n"
            "diff --git a/x b/x\n"
            "- Ignored hunk line.\n\n"
            "Other error paths are unchanged.\n"
        )
        self.assertIsNone(upstream_lint.error_scope_claim(after_diff_empty))


class DocTermTest(unittest.TestCase):
    """Positive, negative and boundary coverage of doc terms the added code requires."""

    def test_yuv_wording_for_non_rgb_code_is_found(self) -> None:
        """Added docs saying YUV for a non-RGB code test name the missing case."""
        for code in (
            "    if (s->src_format.color_family != ZIMG_COLOR_RGB &&",
            "    if (!(desc->flags & AV_PIX_FMT_FLAG_RGB))",
        ):
            with self.subTest(code=code):
                findings = upstream_lint.doc_term_findings(code, "kept for YUV input only.")
                self.assertEqual(len(findings), 1)
                self.assertTrue(findings[0].startswith("non-RGB input: added code has "))
                self.assertIn("say non-RGB or name gray", findings[0])

    def test_reversed_operand_non_rgb_code_is_found(self) -> None:
        """A non-RGB test with the RGB constant as the left operand is found as well."""
        for code in (
            "    if (ZIMG_COLOR_RGB != s->src_format.color_family &&",
            "    if (!(AV_PIX_FMT_FLAG_RGB & desc->flags))",
        ):
            with self.subTest(code=code):
                findings = upstream_lint.doc_term_findings(code, "kept for YUV input only.")
                self.assertEqual(len(findings), 1)
                self.assertTrue(findings[0].startswith("non-RGB input: added code has "))
                self.assertIn("say non-RGB or name gray", findings[0])

    def test_range_comparison_without_unspecified_is_found(self) -> None:
        """Added docs naming a range option for a range comparison must say unspecified."""
        code = "        s->src_format.pixel_range != convert_range(in->color_range)))"
        findings = upstream_lint.doc_term_findings(code, "@option{rangein} too,")
        self.assertEqual(len(findings), 1)
        self.assertIn('unspecified range: added code has "pixel_range !="', findings[0])

    def test_named_cases_pass(self) -> None:
        """Docs that say non-RGB, gray or how an unspecified range is treated pass."""
        code = (
            "    if (!(desc->flags & AV_PIX_FMT_FLAG_RGB) && in->color_range != AVCOL_RANGE_JPEG)"
        )
        for docs in (
            "kept for non-RGB input. An unspecified\nrange counts as limited.",
            "kept for YUV and gray input; an unknown range is treated as limited.",
        ):
            with self.subTest(docs=docs):
                self.assertEqual(upstream_lint.doc_term_findings(code, docs), [])

    def test_missing_code_or_wording_passes(self) -> None:
        """No finding without the code behaviour or without the triggering doc wording."""
        for code, docs in (
            ("    return 1;", "kept for YUV input; @option{rangein} too."),
            ("    if (!(desc->flags & AV_PIX_FMT_FLAG_RGB))", ""),
            ("    if (in->color_range == AVCOL_RANGE_JPEG)", "kept for every input."),
            ("    if (s->src_format.color_family == ZIMG_COLOR_RGB)", "kept for YUV input."),
            ("    if (ZIMG_COLOR_RGB == s->src_format.color_family)", "kept for YUV input."),
            ("    if (AV_PIX_FMT_FLAG_RGB & desc->flags)", "kept for YUV input."),
        ):
            with self.subTest(code=code, docs=docs):
                self.assertEqual(upstream_lint.doc_term_findings(code, docs), [])

    def test_doc_path_is_texinfo_under_doc(self) -> None:
        """Only Texinfo files below the top-level doc directory count as docs."""
        self.assertTrue(upstream_lint.is_doc_path("doc/filters.texi"))
        for name in ("filters.texi", "doc/filters.txt", "libavfilter/doc/x.texi"):
            with self.subTest(name=name):
                self.assertFalse(upstream_lint.is_doc_path(name))

    def test_avoption_field_map_offset_maps_name(self) -> None:
        """AVOption rows with OFFSET map the structure field to the quoted name."""
        raw = DASHENC_OPTIONS
        mapping = upstream_lint.avoption_field_map(raw)
        self.assertEqual(mapping.get("global_sidx"), ["global_sidx"])
        self.assertEqual(mapping.get("ignore_io_errors"), ["ignore_io_errors"])

    def test_avoption_field_map_const_without_offset_ignored(self) -> None:
        """A constant table row without OFFSET maps nothing and does not steal the next field."""
        raw = DASHENC_OPTIONS_T9
        mapping = upstream_lint.avoption_field_map(raw)
        self.assertNotIn("none", mapping)
        self.assertEqual(mapping.get("global_sidx"), ["global_sidx"])

    def test_avoption_field_map_adjacent_help_literals(self) -> None:
        """Two adjacent string literals in the help column still map the OFFSET field."""
        raw = DASHENC_OPTIONS_T9
        mapping = upstream_lint.avoption_field_map(raw)
        self.assertEqual(mapping.get("single_file"), ["single_file"])

    def test_avoption_field_map_null_help(self) -> None:
        """NULL help text before OFFSET still maps the structure field."""
        raw = (
            "#define OFFSET(x) offsetof(Ctx, x)\n"
            "typedef struct Ctx { int foo_field; } Ctx;\n"
            "static const AVOption options[] = {\n"
            '    { "foo", NULL, OFFSET(foo_field), 0 },\n'
            "};\n"
        )
        mapping = upstream_lint.avoption_field_map(raw)
        self.assertEqual(mapping.get("foo_field"), ["foo"])

    def test_avoption_field_map_shared_field_lists_both_names(self) -> None:
        """Each public name for one OFFSET field is kept in table order."""
        mapping = upstream_lint.avoption_field_map(DASHENC_OPTIONS_ALIAS)
        self.assertEqual(mapping.get("ignore_io_errors"), ["ignore_io_errors", "ignore_errors"])

    def test_avoption_tables_two_tables_stay_separate(self) -> None:
        """Each AVOption table header starts its own field-to-names mapping."""
        tables = upstream_lint.avoption_tables(TWO_TABLES_OPTIONS)
        self.assertEqual(tables, [{"foo": ["foo"]}, {"bar": ["bar"]}])
        self.assertNotIn("bar", tables[0])
        self.assertNotIn("foo", tables[1])

    def test_texi_strip_comments_whole_line(self) -> None:
        """A whole-line @c comment naming mode is removed."""
        self.assertEqual(upstream_lint.texi_strip_comments("@c mode controls output"), "")

    def test_texi_strip_comments_trailing_comment(self) -> None:
        """A trailing @c comment is removed and preceding text is kept."""
        text = "\\input texinfo @c -*- texinfo -*-"
        self.assertEqual(upstream_lint.texi_strip_comments(text), "\\input texinfo")

    def test_texi_strip_comments_at_comment_command(self) -> None:
        """A whole-line @comment command is removed."""
        self.assertEqual(upstream_lint.texi_strip_comments("@comment mode is internal only"), "")

    def test_texi_strip_comments_doubled_at_sign(self) -> None:
        """@@c keeps the mode token because the at-sign is escaped."""
        self.assertEqual(upstream_lint.texi_strip_comments("@@c mode"), "@@c mode")

    def test_texi_strip_comments_triple_at_comment(self) -> None:
        """@@@c leaves two literal at-signs before the comment command."""
        self.assertEqual(upstream_lint.texi_strip_comments("@@@c mode"), "@@")

    def test_texi_strip_comments_quad_at_not_comment(self) -> None:
        """@@@@c keeps the line because only literal at-sign pairs precede c."""
        self.assertEqual(upstream_lint.texi_strip_comments("@@@@c mode"), "@@@@c mode")

    def test_texi_strip_comments_spaced_pair_before_comment(self) -> None:
        """text @@ @c keeps the escaped pair and drops the trailing comment."""
        self.assertEqual(upstream_lint.texi_strip_comments("text @@ @c mode"), "text @@")

    def test_texi_strip_comments_inline_commands_preserved(self) -> None:
        """@code and @center lines keep mode because @c is not a comment command."""
        for text in ("@code{mode}", "@center mode"):
            with self.subTest(text=text.strip()):
                self.assertIn("mode", upstream_lint.texi_strip_comments(text))

    def _assert_stripped(self, text: str, expected: str, named: bool) -> None:
        """Assert the exact texi_strip_comments output and whether mode is named in it."""
        stripped = upstream_lint.texi_strip_comments(text)
        self.assertEqual(stripped, expected)
        self.assertIs(upstream_lint.option_named_in_text("mode", stripped), named)

    def test_texi_strip_comments_verbatim_keeps_comment_line(self) -> None:
        """H1 v1: a @c line inside @verbatim is printed literally and stays."""
        text = "Text.\n@verbatim\n@c mode\n@end verbatim\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_plain_comment_line_removed(self) -> None:
        """H1 v2: a @c line outside any block is still removed."""
        self._assert_stripped("Text.\n@c mode\n", "Text.\n\n", False)

    def test_texi_strip_comments_comment_after_verbatim_removed(self) -> None:
        """H1 v3: a @c line after the @end verbatim line is still removed."""
        text = "@verbatim\nx\n@end verbatim\n@c mode\n"
        self._assert_stripped(text, "@verbatim\nx\n@end verbatim\n\n", False)

    def test_texi_strip_comments_example_comment_removed(self) -> None:
        """H1 v4: @example is not a raw block, so its @c line is removed."""
        text = "@example\n@c mode\n@end example\n"
        self._assert_stripped(text, "@example\n\n@end example\n", False)

    def test_texi_strip_comments_verb_text_literal(self) -> None:
        """H1 v5: @c inside @verb{|...|} is literal text and stays."""
        text = "Use @verb{|@c mode|} here.\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_verbatim_trailing_comment_kept(self) -> None:
        """H1 v6: a trailing @c text inside @verbatim stays on the line."""
        text = "@verbatim\nrun --x @c mode\n@end verbatim\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_ignore_block_dropped(self) -> None:
        """H2 i1: the @ignore opener, body and @end ignore line are dropped."""
        text = "Text.\n@ignore\nmode\n@end ignore\n"
        self._assert_stripped(text, "Text.\n", False)

    def test_texi_strip_comments_example_body_kept(self) -> None:
        """H2 i2: an @example body is shown and stays searchable."""
        text = "@example\nmode\n@end example\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_ignore_in_verbatim_literal(self) -> None:
        """H2 i3: @ignore lines inside @verbatim are literal text and stay."""
        text = "@verbatim\n@ignore\nmode\n@end ignore\n@end verbatim\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_text_after_ignore_kept(self) -> None:
        """H2 i4: text after the @end ignore line stays."""
        text = "@ignore\nx\n@end ignore\nmode later\n"
        self._assert_stripped(text, "mode later\n", True)

    def test_texi_strip_comments_nested_ignore_needs_own_end(self) -> None:
        """H2 i5: a nested @ignore needs its own @end, so mode stays dropped."""
        text = "@ignore\n@ignore\nx\n@end ignore\nmode\n@end ignore\nafter\n"
        self._assert_stripped(text, "after\n", False)

    def test_texi_strip_comments_macro_body_kept(self) -> None:
        """H2 i6: a @macro body keeps the line by line handling and stays."""
        text = "@macro m\nmode\n@end macro\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_conditional_body_kept(self) -> None:
        """H2 i7: an @iftex body is shown in some output and stays."""
        text = "@iftex\nmode\n@end iftex\n"
        self._assert_stripped(text, text, True)

    def test_texi_strip_comments_ignore_opener_text_dropped(self) -> None:
        """H2 i8: text after @ignore on the opener line belongs to the dropped block."""
        self._assert_stripped("@ignore mode\n@end ignore\n", "", False)

    def _tested_per_line(self, lines: list[str]) -> list[list[str]]:
        """Return the fields foo and mode tested per line after the whole-text filter."""
        fields = frozenset(("foo", "mode"))
        code = upstream_lint._code_lines("\n".join(lines))
        spans = upstream_lint._condition_spans(code)
        filtered = upstream_lint._lines_without_assignment_targets(code)
        return [
            sorted(upstream_lint._option_fields_tested(line, fields, spans=spans.get(number, ())))
            for number, line in enumerate(filtered, 1)
        ]

    def test_assignment_filter_split_assignment_not_a_test(self) -> None:
        """H3 a1: a target whose = sits on the next line is not an option test."""
        lines = ["if ((c->foo", "     = enabled) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [[], ["mode"]])

    def test_assignment_filter_split_comparison_stays_a_test(self) -> None:
        """H3 a2: a == on the next line keeps the field a test."""
        lines = ["if ((c->foo", "     == enabled) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [["foo"], ["mode"]])

    def test_assignment_filter_split_compound_on_index_not_a_test(self) -> None:
        """H3 a3: += on the next line after an indexed target is not a test."""
        lines = ["if ((c->foo[0]", "     += 1) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [[], ["mode"]])

    def test_assignment_filter_operator_on_first_line_not_a_test(self) -> None:
        """H3 a4: an operator on the same line keeps working."""
        lines = ["if ((c->foo =", "     enabled) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [[], ["mode"]])

    def test_assignment_filter_split_inequality_stays_a_test(self) -> None:
        """H3 a5: != on the next line keeps the field a test."""
        lines = ["while (c->foo", "       != c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [["foo"], ["mode"]])

    def test_assignment_filter_comment_before_operator_not_a_test(self) -> None:
        """H3 a6: a blanked comment between the target and = does not hide the assignment."""
        lines = ["if ((c->foo /* x */", "     = enabled) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [[], ["mode"]])

    def test_assignment_filter_blank_line_before_operator_not_a_test(self) -> None:
        """H3 a7: a blank line between the target and = does not hide the assignment."""
        lines = ["if ((c->foo", "", "     = enabled) && c->mode)"]
        self.assertEqual(self._tested_per_line(lines), [[], [], ["mode"]])

    def test_assignment_filter_keeps_line_count_and_lengths(self) -> None:
        """The whole-text filter keeps the line count and every line length on a1, a3, a7."""
        for lines in (
            ["if ((c->foo", "     = enabled) && c->mode)"],
            ["if ((c->foo[0]", "     += 1) && c->mode)"],
            ["if ((c->foo", "", "     = enabled) && c->mode)"],
        ):
            with self.subTest(lines=lines):
                filtered = upstream_lint._lines_without_assignment_targets(lines)
                self.assertEqual(len(filtered), len(lines))
                self.assertEqual([len(line) for line in filtered], [len(line) for line in lines])

    def _tested_fields_per_line(self, lines: list[str], fields: frozenset[str]) -> list[list[str]]:
        """Return the requested fields tested per line after the whole-text filter."""
        code = upstream_lint._code_lines("\n".join(lines))
        spans = upstream_lint._condition_spans(code)
        filtered = upstream_lint._lines_without_assignment_targets(code)
        return [
            sorted(upstream_lint._option_fields_tested(line, fields, spans=spans.get(number, ())))
            for number, line in enumerate(filtered, 1)
        ]

    def test_assignment_filter_b1_split_subscript_read_is_a_test(self) -> None:
        """H1 b1: a split subscript read inside an assignment target counts as a test."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[c->foo", "             ? 0 : 1] = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["foo"], ["mode"]])

    def test_assignment_filter_b2_subscript_read_is_a_test(self) -> None:
        """H1 b2: a one-line subscript read inside an assignment target counts as a test."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[c->foo ? 0 : 1] = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["foo", "mode"]])

    def test_assignment_filter_b3_constant_index_target_not_a_test(self) -> None:
        """H1 b3: a constant-index assignment target stays excluded."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[0] = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["mode"]])

    def test_assignment_filter_b4_compound_operator_subscript_read_is_a_test(self) -> None:
        """H1 b4: a subscript read on a compound assignment target counts as a test."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[c->foo] += 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["foo", "mode"]])

    def test_assignment_filter_b5_comparison_subscript_read_stays_a_test(self) -> None:
        """H1 b5: a comparison with a subscript read keeps all three fields tested."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if (c->slots[c->foo] == c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["foo", "mode", "slots"]])

    def test_assignment_filter_b6_option_target_indexed_by_option(self) -> None:
        """H1 b6: an option target indexed by another option tests only the index option."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->foo[c->mode] = 1) && c->x)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["mode"]])

    def test_assignment_filter_b7_plain_member_target_not_a_test(self) -> None:
        """H1 b7: a plain member assignment target without a subscript is not a test."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->foo = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["mode"]])

    def test_assignment_filter_b8_nested_subscript_read_is_a_test(self) -> None:
        """H1 b8: one nested subscript level excludes the target while keeping inner reads."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[c->idx[c->foo]] = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["foo", "mode"]])

    def test_assignment_filter_b9_nested_constant_index_target_not_a_test(self) -> None:
        """H1 b9: one nested constant-index subscript still excludes the assigned target."""
        fields = frozenset(("foo", "mode", "slots"))
        lines = ["if ((c->slots[c->idx[0]] = 1) && c->mode)"]
        self.assertEqual(self._tested_fields_per_line(lines, fields), [["mode"]])

    def test_text_without_assignment_targets_t1_subscript_read(self) -> None:
        """H2 t1: the single-line filter blanks member and operator while keeping [c->foo]."""
        self.assertEqual(
            upstream_lint._text_without_assignment_targets("c->slots[c->foo] = 1"),
            "c       [c->foo]   1",
        )

    def test_text_without_assignment_targets_t2_constant_index(self) -> None:
        """H2 t2: the single-line filter blanks member and operator while keeping [0]."""
        self.assertEqual(
            upstream_lint._text_without_assignment_targets("c->slots[0] = 1"),
            "c       [0]   1",
        )

    def test_text_without_assignment_targets_t3_comparison_unchanged(self) -> None:
        """H2 t3: the single-line filter leaves an == comparison unchanged."""
        self.assertEqual(
            upstream_lint._text_without_assignment_targets("c->slots[c->foo] == 1"),
            "c->slots[c->foo] == 1",
        )

    def test_text_without_assignment_targets_t4_nested_subscript_read(self) -> None:
        """H2 t4: the single-line filter blanks member and operator around a nested subscript."""
        self.assertEqual(
            upstream_lint._text_without_assignment_targets("c->slots[c->idx[c->foo]] = 1"),
            "c       [c->idx[c->foo]]   1",
        )

    def test_assignment_filter_subscript_keeps_line_count_and_lengths(self) -> None:
        """The whole-text filter keeps the line count and every line length on b1, b2, b8."""
        for lines in (
            ["if ((c->slots[c->foo", "             ? 0 : 1] = 1) && c->mode)"],
            ["if ((c->slots[c->foo ? 0 : 1] = 1) && c->mode)"],
            ["if ((c->slots[c->idx[c->foo]] = 1) && c->mode)"],
        ):
            with self.subTest(lines=lines):
                filtered = upstream_lint._lines_without_assignment_targets(lines)
                self.assertEqual(len(filtered), len(lines))
                self.assertEqual([len(line) for line in filtered], [len(line) for line in lines])

    def test_avoption_tables_bounded_header_separates_tables(self) -> None:
        """An explicit array bound on the second table keeps foo and bar apart."""
        tables = upstream_lint.avoption_tables(BOUNDED_TWO_TABLES_OPTIONS)
        self.assertEqual(tables, [{"foo": ["foo"]}, {"bar": ["bar"]}])
        self.assertNotIn("bar", tables[0])
        self.assertNotIn("foo", tables[1])

    def test_avoption_tables_bounded_macro_and_expr_headers(self) -> None:
        """Macro and expression array bounds still start separate AVOption tables."""
        for label, source in (
            ("nb_opts", BOUNDED_NB_TWO_TABLES_OPTIONS),
            ("expr", BOUNDED_EXPR_TWO_TABLES_OPTIONS),
        ):
            with self.subTest(bound=label):
                tables = upstream_lint.avoption_tables(source)
                self.assertEqual(len(tables), 2)
                self.assertEqual(tables[0].get("foo"), ["foo"])
                self.assertEqual(tables[1].get("bar"), ["bar"])

    def test_option_fields_tested_assign_in_if_outside_condition(self) -> None:
        """foo on the left of an assignment after an if condition is not tested."""
        line = "    if (ready) c->foo = enabled && available;"
        fields = frozenset({"ready", "foo"})
        spans = upstream_lint._condition_spans([line])
        tested = upstream_lint._option_fields_tested(line, fields, spans=spans.get(1, ()))
        self.assertNotIn("foo", tested)

    def test_option_fields_tested_assign_without_if(self) -> None:
        """foo on the left of a bare assignment with boolean logic is not tested."""
        line = "    c->foo = enabled && available;"
        tested = upstream_lint._option_fields_tested(line, frozenset({"foo"}))
        self.assertEqual(tested, frozenset())

    def test_option_fields_tested_compound_assign_not_counted(self) -> None:
        """foo on the left of a compound assignment is not tested."""
        line = "    c->foo |= a && b;"
        tested = upstream_lint._option_fields_tested(line, frozenset({"foo"}))
        self.assertEqual(tested, frozenset())

    def test_option_fields_tested_equality_reads_still_counted(self) -> None:
        """foo and bar on the right of an assignment with == and && are tested."""
        line = "    ok = c->foo == 1 && c->bar;"
        tested = upstream_lint._option_fields_tested(line, frozenset({"foo", "bar"}))
        self.assertEqual(tested, frozenset({"foo", "bar"}))

    def test_avoption_field_map_ignores_block_commented_row(self) -> None:
        """A block-commented AVOption row does not register its quoted option name."""
        mapping = upstream_lint.avoption_field_map(AVOPTION_COMMENT_BAR_BLOCK)
        self.assertEqual(mapping.get("foo"), ["foo"])
        self.assertNotIn("bar", mapping)

    def test_avoption_field_map_ignores_line_commented_row(self) -> None:
        """A line-commented AVOption row does not register its quoted option name."""
        mapping = upstream_lint.avoption_field_map(AVOPTION_COMMENT_BAR_LINE)
        self.assertEqual(mapping.get("foo"), ["foo"])
        self.assertNotIn("bar", mapping)

    def test_avoption_field_map_keeps_help_literals_with_comment_markers(self) -> None:
        """Help strings with slashes or block-comment text stay mapped with their names."""
        mapping = upstream_lint.avoption_field_map(AVOPTION_HELP_LITERALS)
        self.assertEqual(mapping.get("a_field"), ["a"])
        self.assertEqual(mapping.get("b_field"), ["b"])

    def test_avoption_tables_ignores_commented_header_mid_table(self) -> None:
        """A commented-out AVOption header between live rows keeps one table."""
        tables = upstream_lint.avoption_tables(AVOPTION_COMMENTED_HEADER_MID)
        self.assertEqual(len(tables), 1)
        self.assertEqual(tables[0].get("foo"), ["foo"])
        self.assertEqual(tables[0].get("baz"), ["baz"])

    def test_option_fields_tested_continuation_in_if_condition(self) -> None:
        """A continuation line inside an if condition counts as testing option fields."""
        line = "        !c->ignore_io_errors)"
        fields = frozenset({"ignore_io_errors"})
        code_lines = [
            "int f() {",
            "    if (ret >= 0 &&",
            line,
            "        ret = 0;",
            "}",
        ]
        cond = upstream_lint._condition_spans(code_lines)
        tested = upstream_lint._option_fields_tested(line, fields, spans=cond.get(3, ()))
        self.assertEqual(tested, frozenset({"ignore_io_errors"}))

    def test_option_fields_tested_plain_assignment_not_counted(self) -> None:
        """A plain assignment line reading an option field is not an option test."""
        line = "    c->ignore_io_errors = 1;"
        cond = upstream_lint._condition_spans([line])
        tested = upstream_lint._option_fields_tested(
            line, frozenset({"ignore_io_errors"}), spans=cond.get(1, ())
        )
        self.assertEqual(tested, frozenset())

    def test_option_fields_tested_indexed_member(self) -> None:
        """An indexed structure member matches a field name ending with an index."""
        line = "    if (c->flags[0]) {"
        tested = upstream_lint._option_fields_tested(line, frozenset({"flags[0]"}))
        self.assertEqual(tested, frozenset({"flags[0]"}))

    def test_option_fields_tested_longer_identifier_not_matched(self) -> None:
        """A longer identifier does not match a shorter option field name."""
        line = "    if (c->global_sidx_extra) {"
        tested = upstream_lint._option_fields_tested(line, frozenset({"global_sidx"}))
        self.assertEqual(tested, frozenset())

    def test_option_fields_tested_whitespace_after_arrow(self) -> None:
        """Spaces or a tab between -> and the member name still count as an option test."""
        fields = frozenset({"ignore_io_errors"})
        spaced = upstream_lint._option_fields_tested("    if (c-> ignore_io_errors) {", fields)
        tabbed = upstream_lint._option_fields_tested("    if (c->\tignore_io_errors) {", fields)
        self.assertEqual(spaced, frozenset({"ignore_io_errors"}))
        self.assertEqual(tabbed, frozenset({"ignore_io_errors"}))

    def test_option_fields_tested_whitespace_keeps_member_boundary(self) -> None:
        """Whitespace after -> still requires an exact member name or indexed match."""
        fields = frozenset({"ignore_io_errors", "flags[0]"})
        longer = upstream_lint._option_fields_tested(
            "    if (c-> ignore_io_errors_extra) {", fields
        )
        indexed = upstream_lint._option_fields_tested("    if (c-> flags[0]) {", fields)
        self.assertEqual(longer, frozenset())
        self.assertEqual(indexed, frozenset({"flags[0]"}))

    def test_option_fields_tested_post_continuation_assign_ignored(self) -> None:
        """An assignment after a multiline condition closes is not an option test."""
        fields = frozenset({"ignore_io_errors", "global_sidx"})
        code_lines = [
            "    if (ready &&",
            "        enabled) c->ignore_io_errors = 1;",
            "    if (c->global_sidx) {",
        ]
        spans = upstream_lint._condition_spans(code_lines)
        second = upstream_lint._option_fields_tested(code_lines[1], fields, spans=spans.get(2, ()))
        third = upstream_lint._option_fields_tested(code_lines[2], fields, spans=spans.get(3, ()))
        self.assertEqual(second, frozenset())
        self.assertEqual(third, frozenset({"global_sidx"}))

    def test_option_fields_tested_same_line_post_if_assign_ignored(self) -> None:
        """An assignment after a single-line if condition closes is not counted."""
        line = "    if (c->global_sidx) c->ignore_io_errors = 1;"
        fields = frozenset({"global_sidx", "ignore_io_errors"})
        spans = upstream_lint._condition_spans([line])
        tested = upstream_lint._option_fields_tested(line, fields, spans=spans.get(1, ()))
        self.assertEqual(tested, frozenset({"global_sidx"}))

    def test_option_fields_tested_continuation_operator_stays_in_span(self) -> None:
        """Boolean operators inside a continued condition do not admit post-close code."""
        fields = frozenset({"ignore_io_errors"})
        code_lines = [
            "    if (ret >= 0 &&",
            "        enabled && ready) c->ignore_io_errors = 1;",
        ]
        spans = upstream_lint._condition_spans(code_lines)
        tested = upstream_lint._option_fields_tested(code_lines[1], fields, spans=spans.get(2, ()))
        self.assertEqual(tested, frozenset())

    def test_option_fields_tested_nested_parens_in_condition(self) -> None:
        """Nested parentheses keep the outer condition open until its matching close."""
        fields = frozenset({"ignore_io_errors", "single_file"})
        code_lines = [
            "    if (ret >= 0 && (ready ||",
            "        !c->ignore_io_errors)) c->single_file = 1;",
        ]
        spans = upstream_lint._condition_spans(code_lines)
        tested = upstream_lint._option_fields_tested(code_lines[1], fields, spans=spans.get(2, ()))
        self.assertEqual(tested, frozenset({"ignore_io_errors"}))

    def test_option_fields_tested_ternary_outside_condition(self) -> None:
        """A ternary expression on a line with no if or while condition counts."""
        line = "    ret = c->ignore_io_errors ? 0 : -1;"
        fields = frozenset({"ignore_io_errors"})
        spans = upstream_lint._condition_spans([line])
        tested = upstream_lint._option_fields_tested(line, fields, spans=spans.get(1, ()))
        self.assertEqual(tested, frozenset({"ignore_io_errors"}))

    def test_option_fields_tested_assign_inside_condition_span(self) -> None:
        """An assignment target inside an if condition span is not an option test."""
        line = "if ((c->foo = enabled) && ready)"
        fields = frozenset({"foo", "bar", "mode"})
        spans = upstream_lint._condition_spans([line]).get(1, ())
        self.assertEqual(spans, [(4, 31)])
        self.assertEqual(
            upstream_lint._option_fields_tested(line, fields, spans=spans),
            frozenset(),
        )

    def test_option_fields_tested_assign_in_condition_keeps_rhs_read(self) -> None:
        """A right-hand field read inside a condition assignment still counts as tested."""
        line = "if ((c->foo = c->bar) && ready)"
        fields = frozenset({"foo", "bar", "mode"})
        spans = upstream_lint._condition_spans([line]).get(1, ())
        self.assertEqual(
            upstream_lint._option_fields_tested(line, fields, spans=spans),
            frozenset({"bar"}),
        )

    def test_option_fields_tested_equality_inside_condition_span(self) -> None:
        """An equality comparison inside an if condition span stays an option test."""
        line = "if (c->foo == 1 && ready)"
        fields = frozenset({"foo", "bar", "mode"})
        spans = upstream_lint._condition_spans([line]).get(1, ())
        self.assertEqual(
            upstream_lint._option_fields_tested(line, fields, spans=spans),
            frozenset({"foo"}),
        )

    def test_option_fields_tested_outside_only_boolean_assign_filtered(self) -> None:
        """A bare assignment with boolean operators outside conditions is not a test."""
        line = "c->foo = enabled && ready;"
        fields = frozenset({"foo", "bar", "mode"})
        spans = upstream_lint._condition_spans([line]).get(1, ())
        self.assertEqual(spans, ())
        self.assertEqual(
            upstream_lint._option_fields_tested(line, fields, spans=spans),
            frozenset(),
        )

    def test_option_pairs_between_skips_same_field_aliases(self) -> None:
        """No option name pair is formed between two names of the same OFFSET field."""
        field_map = {
            "ignore_io_errors": ["ignore_io_errors", "ignore_errors"],
            "global_sidx": ["global_sidx"],
        }
        pairs = upstream_lint._option_pairs_between(
            frozenset({"ignore_io_errors"}),
            frozenset({"ignore_io_errors"}),
            field_map,
        )
        self.assertEqual(pairs, [])

    def test_texi_option_name_strips_inline_command(self) -> None:
        """@option{NAME} on an item line yields NAME."""
        self.assertEqual(upstream_lint.texi_option_name("@option{global_sidx}"), "global_sidx")

    def test_texi_option_name_plain_token(self) -> None:
        """A bare item token is returned unchanged."""
        self.assertEqual(upstream_lint.texi_option_name("ignore_io_errors"), "ignore_io_errors")

    def test_texi_option_name_var_command(self) -> None:
        """@var{NAME} on an item line yields NAME."""
        self.assertEqual(upstream_lint.texi_option_name("@var{range}"), "range")

    def test_texi_entry_ranges_one_table(self) -> None:
        """Each @item line starts a range through the next boundary."""
        lines = DOC_MUXERS_BASE.splitlines()
        ranges = upstream_lint.texi_entry_ranges(lines)
        self.assertEqual(len(ranges), 3)
        self.assertEqual(ranges[0][2], "ignore_io_errors")

    def test_texi_entry_ranges_no_items(self) -> None:
        """Prose with no @item lines yields no ranges."""
        self.assertEqual(upstream_lint.texi_entry_ranges(["plain text"]), [])

    def test_texi_entry_ranges_itemx_boundary(self) -> None:
        """An @itemx line ends the previous entry and opens the next."""
        lines = ["@item a\n", "text\n", "@itemx b\n", "more\n", "@end table\n"]
        ranges = upstream_lint.texi_entry_ranges(lines)
        self.assertEqual(len(ranges), 2)
        self.assertEqual(ranges[0][2], "a")
        self.assertEqual(ranges[1][2], "b")

    def test_texi_entry_ranges_consecutive_itemx_shares_entry(self) -> None:
        """Consecutive @item and @itemx headings share start, end and entry text."""
        lines = [
            "@table @option",
            "@item foo",
            "@itemx foo_alias",
            "Sets the frame rate.",
            "@end table",
        ]
        expected_text = "@item foo\n@itemx foo_alias\nSets the frame rate."
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (2, 4, "foo", expected_text),
                (2, 4, "foo_alias", expected_text),
            ],
        )

    def test_texi_entry_ranges_three_consecutive_headings_share_entry(self) -> None:
        """Three consecutive @item and @itemx headings share one range and description."""
        lines = ["@table @option", "@item a", "@itemx b", "@itemx c", "Shared.", "@end table"]
        expected_text = "@item a\n@itemx b\n@itemx c\nShared."
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (2, 5, "a", expected_text),
                (2, 5, "b", expected_text),
                (2, 5, "c", expected_text),
            ],
        )

    def test_texi_entry_ranges_itemx_after_prose_keeps_distinct_ranges(self) -> None:
        """An @itemx line after body text starts a separate range and text."""
        lines = ["@item a", "text", "@itemx b", "more", "@end table"]
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (1, 2, "a", "@item a\ntext"),
                (3, 4, "b", "@itemx b\nmore"),
            ],
        )

    def test_texi_entry_ranges_inner_example_end_stays_in_entry(self) -> None:
        """An inner @end example line keeps the example and following prose in the entry."""
        lines = [
            "@table @option",
            "@item foo",
            "Sets the frame rate.",
            "@example",
            "ffmpeg -i in -foo 2 out",
            "@end example",
            "Depends on mode.",
            "@item bar",
            "Other.",
            "@end table",
        ]
        foo_text = (
            "@item foo\nSets the frame rate.\n@example\n"
            "ffmpeg -i in -foo 2 out\n@end example\nDepends on mode."
        )
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (2, 7, "foo", foo_text),
                (8, 9, "bar", "@item bar\nOther."),
            ],
        )

    def test_texi_entry_ranges_nested_itemize_items_stay_in_entry(self) -> None:
        """@item lines inside an @itemize block stay inside the enclosing option entry."""
        lines = [
            "@table @option",
            "@item foo",
            "Modes:",
            "@itemize",
            "@item fast",
            "@item slow",
            "@end itemize",
            "Depends on mode.",
            "@item bar",
            "Other.",
            "@end table",
        ]
        foo_text = (
            "@item foo\nModes:\n@itemize\n@item fast\n@item slow\n@end itemize\nDepends on mode."
        )
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (2, 8, "foo", foo_text),
                (9, 10, "bar", "@item bar\nOther."),
            ],
        )

    def test_texi_entry_ranges_nested_table_items_stay_in_entry(self) -> None:
        """@item and @end table of a nested @table stay inside the outer option entry."""
        lines = [
            "@table @option",
            "@item foo",
            "Values:",
            "@table @samp",
            "@item auto",
            "Pick one.",
            "@end table",
            "Depends on mode.",
            "@item bar",
            "Other.",
            "@end table",
        ]
        foo_text = (
            "@item foo\nValues:\n@table @samp\n@item auto\nPick one.\n@end table\nDepends on mode."
        )
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [
                (2, 8, "foo", foo_text),
                (9, 10, "bar", "@item bar\nOther."),
            ],
        )

    def test_texi_entry_ranges_raw_block_commands_stay_literal(self) -> None:
        """@item and @end table lines inside @verbatim stay literal entry text."""
        lines = [
            "@table @option",
            "@item foo",
            "@verbatim",
            "@item fake",
            "@end table",
            "@end verbatim",
            "Depends on mode.",
            "@end table",
        ]
        foo_text = "@item foo\n@verbatim\n@item fake\n@end table\n@end verbatim\nDepends on mode."
        self.assertEqual(
            upstream_lint.texi_entry_ranges(lines),
            [(2, 7, "foo", foo_text)],
        )

    def test_option_named_in_text_underscore_matches_hyphen(self) -> None:
        """Underscores in the option name may match hyphenated Texinfo wording."""
        self.assertTrue(upstream_lint.option_named_in_text("global_sidx", "see global-sidx layout"))

    def test_option_named_in_text_underscore_matches_space(self) -> None:
        """Underscores in the option name may match space-separated Texinfo wording."""
        self.assertTrue(upstream_lint.option_named_in_text("global_sidx", "see global sidx layout"))

    def test_option_named_in_text_plain_name(self) -> None:
        """A bare option name embedded in prose is found."""
        self.assertTrue(
            upstream_lint.option_named_in_text("global_sidx", "Respect global_sidx ranges.")
        )

    def test_option_named_in_text_hyphen_suffix_not_named(self) -> None:
        """A name followed by a hyphen is not treated as the option name."""
        self.assertFalse(upstream_lint.option_named_in_text("global", "toggle global-sidx"))

    def test_option_named_in_text_word_prefix_not_named(self) -> None:
        """A name preceded by a word character is not treated as the option name."""
        self.assertFalse(upstream_lint.option_named_in_text("sidx", "the globalsidx flag"))

    def test_option_interplay_findings_reports_coupled_tests(self) -> None:
        """Coupled AVOption tests with under-documented entries yield interplay findings."""
        tree = Path("/fixture/tree")
        head = "HEAD"
        range_patch = "diff --git a/libavformat/dashenc.c\n"
        doc_entries = {"ignore_io_errors": ["Ignore I/O errors.\nSkip flush failures."]}
        with (
            unittest.mock.patch.object(
                upstream_lint, "_patch_files", return_value=[("libavformat/dashenc.c", ["@@"], 0)]
            ),
            unittest.mock.patch.object(upstream_lint, "_added_lines", return_value={15}),
            unittest.mock.patch.object(upstream_lint, "_git", return_value=DASHENC_T1_SOURCE),
        ):
            findings = upstream_lint.option_interplay_findings(tree, head, range_patch, doc_entries)
        self.assertEqual(len(findings), 1)
        self.assertIn("ignore_io_errors near global_sidx", findings[0])

    def test_option_interplay_findings_named_neighbour_passes(self) -> None:
        """Findings are omitted when the changed entry names the neighbour option."""
        tree = Path("/fixture/tree")
        doc_entries = {
            "ignore_io_errors": ["Ignore errors; respects global_sidx placement."],
        }
        with (
            unittest.mock.patch.object(
                upstream_lint, "_patch_files", return_value=[("libavformat/dashenc.c", ["@@"], 0)]
            ),
            unittest.mock.patch.object(upstream_lint, "_added_lines", return_value={15}),
            unittest.mock.patch.object(upstream_lint, "_git", return_value=DASHENC_T1_SOURCE),
        ):
            findings = upstream_lint.option_interplay_findings(tree, "HEAD", "patch", doc_entries)
        self.assertEqual(findings, [])

    def test_option_interplay_findings_no_doc_change_passes(self) -> None:
        """No finding when the neighbour option's Texinfo entry did not gain lines."""
        tree = Path("/fixture/tree")
        doc_entries: dict[str, str] = {}
        with (
            unittest.mock.patch.object(
                upstream_lint, "_patch_files", return_value=[("libavformat/dashenc.c", ["@@"], 0)]
            ),
            unittest.mock.patch.object(upstream_lint, "_added_lines", return_value={15}),
            unittest.mock.patch.object(upstream_lint, "_git", return_value=DASHENC_T1_SOURCE),
        ):
            findings = upstream_lint.option_interplay_findings(tree, "HEAD", "patch", doc_entries)
        self.assertEqual(findings, [])

    def test_interplay_pairs_alias_maps_nearby_scalar(self) -> None:
        """Pair generation lists every option name for a shared field near a scalar test."""
        code_lines = upstream_lint._code_lines(DASHENC_ALIAS_T1)
        tables = upstream_lint.avoption_tables(DASHENC_ALIAS_T1)
        added = {line for line, text in enumerate(code_lines, 1) if text.strip().startswith("if ")}
        pairs = upstream_lint._interplay_pairs(code_lines, added, tables)
        names = {(option_a, option_b) for _line, option_a, option_b in pairs}
        self.assertIn(("ignore_io_errors", "global_sidx"), names)
        self.assertIn(("ignore_errors", "global_sidx"), names)
        self.assertNotIn(("ignore_io_errors", "ignore_errors"), names)
        self.assertNotIn(("ignore_errors", "ignore_io_errors"), names)
        self.assertNotIn(("ignore_io_errors", "ignore_io_errors"), names)
        self.assertNotIn(("ignore_errors", "ignore_errors"), names)

    def test_interplay_pairs_distinct_tables_yield_no_pair(self) -> None:
        """Fields from separate AVOption tables do not form an interplay pair."""
        source = TWO_TABLES_OPTIONS + MUX_WRITE_T1
        code_lines = upstream_lint._code_lines(source)
        tables = upstream_lint.avoption_tables(source)
        added = {line for line, text in enumerate(code_lines, 1) if "c->foo" in text}
        self.assertTrue(added)
        self.assertEqual(upstream_lint._interplay_pairs(code_lines, added, tables), [])

    def test_neighbour_alias_group_for_pair_table_order_independent(self) -> None:
        """Pair neighbour groups ignore table order and unrelated tables."""
        want_wn = frozenset({"mode", "mode_alias"})
        want_pq = frozenset({"mode"})
        for label, source, expect in (
            ("wn_w_first", INTERPLAY_ALIAS_WN_W_FIRST, want_wn),
            ("wn_n_first", INTERPLAY_ALIAS_WN_N_FIRST, want_wn),
            ("pq_p_first", INTERPLAY_ALIAS_PQ_P_FIRST, want_pq),
            ("pq_q_first", INTERPLAY_ALIAS_PQ_Q_FIRST, want_pq),
        ):
            with self.subTest(order=label):
                tables = upstream_lint.avoption_tables(source)
                group = upstream_lint._neighbour_alias_group_for_pair(tables, "foo", "mode")
                self.assertEqual(group, expect)


WRAP_TEXT = (
    "@section libsvtav1\n"
    "@table @option\n"
    "@item qpfile @var{filename}\n"
    "SVT-AV1 applies the maps only with CRF or constant-QP rate control, so\n"
    "the option is refused unless the effective rate-control mode is 0, and\n"
    "both. Internal\n"
    "scaling, a @samp{superres-mode} other than 0, is refused too, because\n"
    "SVT-AV1 would apply the map to the scaled frame with the full layout.\n"
    "@end table\n"
)


class DocWrapTest(unittest.TestCase):
    """Positive, negative and boundary coverage of early line breaks in added docs."""

    def wrap(self, before: str, line: str, after: str) -> list[str]:
        """Check the middle line of a three-line filled paragraph."""
        return upstream_lint.wrap_findings("doc/x.texi", [before, line, after], {2})

    def test_early_break_is_found(self) -> None:
        """An added line ending a filled paragraph line early names the line and widths."""
        lines = WRAP_TEXT.splitlines()
        findings = upstream_lint.wrap_findings("doc/encoders.texi", lines, {6})
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            findings[0].startswith(
                'doc/encoders.texi:6: "both. Internal" ends a filled paragraph line early (14 of '
            ),
            findings[0],
        )

    def test_unadded_or_full_lines_pass(self) -> None:
        """A short line that was not added and full added lines pass."""
        lines = WRAP_TEXT.splitlines()
        for added in (set(), {4, 5, 7, 8}, {1, 9}, {0, 10}):
            with self.subTest(added=added):
                self.assertEqual(upstream_lint.wrap_findings("doc/x.texi", lines, added), [])

    def test_sentence_end_passes(self) -> None:
        """A short line ending a sentence or forcing a break passes; a comma does not."""
        after = "y " + "z" * 58
        for end in (".", ":", ";", "!", "?", "@*"):
            with self.subTest(end=end):
                self.assertEqual(self.wrap("x" * 60, "a" * 20 + end, after), [])
        self.assertEqual(len(self.wrap("x" * 60, "a" * 20 + ",", after)), 1)

    def test_half_width_boundary(self) -> None:
        """A line under half its neighbours' width fails; exactly half passes."""
        after = "y " + "z" * 58
        self.assertEqual(len(self.wrap("x" * 60, "a" * 29, after)), 1)
        self.assertEqual(self.wrap("x" * 60, "a" * 30, after), [])

    def test_neighbour_width_boundary(self) -> None:
        """Neighbours of WRAP_MIN_NEIGHBOUR columns are checked; one column less is not."""
        width = upstream_lint.WRAP_MIN_NEIGHBOUR
        after = "y " + "z" * (width - 2)
        self.assertEqual(len(self.wrap("x" * width, "a" * 20, after)), 1)
        self.assertEqual(self.wrap("x" * (width - 1), "a" * 20, after), [])

    def test_next_word_fit_boundary(self) -> None:
        """The break fails only when the next word fits on the line before."""
        self.assertEqual(len(self.wrap("x" * 60, "a" * 20, "y" * 39 + " " + "z" * 50)), 1)
        self.assertEqual(self.wrap("x" * 60, "a" * 20, "y" * 40 + " " + "z" * 50), [])

    def test_inline_command_counts_as_one_word(self) -> None:
        """A next line opening with an inline command counts up to its closing brace."""
        after = "@option{svtav1-params}, is refused too, because SVT-AV1 would apply"
        self.assertEqual(len(self.wrap("x" * 60, "a" * 20, after)), 1)
        self.assertEqual(self.wrap("x" * 60, "a" * 37, after), [])

    def test_unlisted_block_passes(self) -> None:
        """Lines inside a block missing from TEXI_FILLED are not filled prose."""
        body = ["x" * 60, "a" * 20, "y " + "z" * 58]
        for block, expected in (("example", 0), ("verbatim", 0), ("itemize", 1), ("table", 1)):
            with self.subTest(block=block):
                lines = [f"@{block}", *body, f"@end {block}"]
                findings = upstream_lint.wrap_findings("doc/x.texi", lines, {3})
                self.assertEqual(len(findings), expected)

    def test_texi_prose_flags(self) -> None:
        """Command lines and lines inside unlisted blocks are not prose; inline starts are."""
        lines = [
            "@table @option",
            "@item a",
            "@code{a} sets b",
            "@c note",
            "",
            "@example",
            "a b",
            "@end example",
            "plain",
            "@end table",
        ]
        expected = [False, False, True, False, False, False, False, False, True, False]
        self.assertEqual(upstream_lint.texi_prose(lines), expected)

    def test_raw_block_end_of_other_block_is_text(self) -> None:
        """An @end line of an outer block inside a raw block is literal text."""
        for opener in ("verbatim", "ignore", "macro foo", "rmacro foo", "linemacro foo"):
            name = opener.split()[0]
            lines = [
                "@table @option",
                "@item a",
                "Text one.",
                f"@{opener}",
                "@end table",
                "literal",
                f"@end {name}",
                "Text after.",
                "@end table",
            ]
            expected = [False, False, True, False, False, False, False, True, False]
            with self.subTest(opener=opener):
                self.assertEqual(upstream_lint.texi_prose(lines), expected)

    def test_raw_block_nesting(self) -> None:
        """A raw block nests only the openers texi2any counts inside it."""
        cases = {
            "same name": ["@verbatim", "@verbatim", "@end verbatim", "a b", "@end verbatim"],
            "indented opener": ["@ignore", "  @ignore", "@end ignore", "a b", "@end ignore"],
            "longer name": ["@verbatim", "@verbatimx", "a b", "@end verbatim"],
            "other raw block": ["@ignore", "@verbatim", "a b", "@end ignore"],
        }
        for outer, inner in (("macro", "linemacro"), ("linemacro", "rmacro"), ("rmacro", "macro")):
            body = [f"@{inner} g", f"@end {outer}", "a b", f"@end {inner}"]
            cases[f"{inner} in {outer}"] = [f"@{outer} f", *body, f"@end {outer}"]
        for name, lines in cases.items():
            with self.subTest(case=name):
                flags = upstream_lint.texi_prose([*lines, "plain"])
                self.assertEqual(flags, [False] * len(lines) + [True])

    def test_raw_block_end_line_boundaries(self) -> None:
        """A raw block ends on @end and its name after leading blanks, before trailing text."""
        cases = {
            "leading blanks": (["@verbatim", "x y", "  @end verbatim", "plain"], 3),
            "trailing text": (["@verbatim", "x y", "@end verbatim @c note", "plain"], 3),
            "longer name": (["@verbatim", "@end verbatim-x", "x y", "@end verbatim", "p"], 4),
        }
        for name, (lines, first_prose) in cases.items():
            with self.subTest(case=name):
                expected = [index >= first_prose for index in range(len(lines))]
                self.assertEqual(upstream_lint.texi_prose(lines), expected)

    CODE_PARAGRAPH = (
        "@code{x} starts a prose line that is long enough to count",
        "Each neighbour in this filled paragraph is sixty-six columns wide,",
        "short",
        "and the following prose line is also sixty-six columns wide here.",
    )

    def test_raw_block_end_adds_no_block_name(self) -> None:
        """An @end inside a raw block adds no block name; one outside still does."""
        for opener in ("verbatim", "ignore", "macro foo", "rmacro foo", "linemacro foo"):
            name = opener.split()[0]
            lines = [f"@{opener}", "@end code", f"@end {name}", "", *self.CODE_PARAGRAPH]
            with self.subTest(opener=opener):
                self.assertEqual(upstream_lint.texi_prose(lines), [False] * 4 + [True] * 4)
                findings = upstream_lint.wrap_findings("doc/x.texi", lines, {7})
                self.assertEqual(len(findings), 1)
                self.assertIn('"short" ends a filled paragraph line early', findings[0])
        outside = ["@end code", "", *self.CODE_PARAGRAPH]
        self.assertEqual(upstream_lint.texi_prose(outside), [False] * 6)
        self.assertEqual(upstream_lint.wrap_findings("doc/x.texi", outside, {5}), [])

    def test_nested_and_mixed_raw_block_end_names(self) -> None:
        """Nested raw blocks hide inner @end names unless an outside @end names them."""
        nested = {
            "verbatim": [
                "@verbatim",
                "@verbatim",
                "@end code",
                "@end verbatim",
                "@end code",
                "@end verbatim",
            ],
            "ignore": [
                "@ignore",
                "  @ignore",
                "@end code",
                "@end ignore",
                "@end code",
                "@end ignore",
            ],
            "macro": [
                "@macro f",
                "@rmacro g",
                "@end macro",
                "@end code",
                "@end rmacro",
                "@end code",
                "@end macro",
            ],
        }
        for case, raw in nested.items():
            lines = [*raw, "", *self.CODE_PARAGRAPH]
            short_line = len(raw) + 4
            with self.subTest(case=case):
                self.assertEqual(
                    upstream_lint.texi_prose(lines), [False] * (len(raw) + 1) + [True] * 4
                )
                findings = upstream_lint.wrap_findings("doc/x.texi", lines, {short_line})
                self.assertEqual(len(findings), 1)
        mixed = (
            (
                "after",
                ["@verbatim", "@end code", "@end verbatim", "", *self.CODE_PARAGRAPH, "@end code"],
                7,
            ),
            (
                "before",
                ["@ignore", "@end code", "@end ignore", "@end code", "", *self.CODE_PARAGRAPH],
                8,
            ),
        )
        for case, lines, short_line in mixed:
            with self.subTest(case=case):
                self.assertEqual(upstream_lint.texi_prose(lines), [False] * len(lines))
                findings = upstream_lint.wrap_findings("doc/x.texi", lines, {short_line})
                self.assertEqual(findings, [])


class TestProgramTest(unittest.TestCase):
    """Positive, negative and boundary coverage of new registered lib*/tests programs."""

    def test_registered_new_program_is_found(self) -> None:
        """A new lib*/tests C file listed by a TESTPROGS assignment of its Makefile is found."""
        multiline_makefile = (
            "TESTPROGS = avcodec                                    \\\n"
            "            aom_film_grain                             \\\n"
            "            golomb\n"
        )
        for makefile in (
            "TESTPROGS-$(CONFIG_ITUT_T35)              += aom_film_grain\n",
            multiline_makefile,
            "TESTPROGS += aom_film_grain # needs a sample\n",
            "TESTPROGS-yes += golomb aom_film_grain\n",
            "TESTPROGS := golomb aom_film_grain\n",
        ):
            with self.subTest(makefile=makefile):
                found = upstream_lint.registered_test_programs(
                    ["libavcodec/tests/aom_film_grain.c"], {"libavcodec/Makefile": makefile}
                )
                self.assertEqual(found, ["libavcodec/tests/aom_film_grain.c"])

    def test_unregistered_or_other_library_passes(self) -> None:
        """No finding without the stem as a TESTPROGS word in the same library Makefile."""
        program = ["libavcodec/tests/aom_film_grain.c"]
        for path, makefile in (
            ("libavutil/Makefile", "TESTPROGS += aom_film_grain\n"),
            ("libavcodec/Makefile", "TESTPROGS += aom_film_grain_sets\n"),
            ("libavcodec/x86/Makefile", "TESTPROGS += aom_film_grain\n"),
            ("libavcodec/Makefile", "OBJS-$(CONFIG_ITUT_T35) += aom_film_grain.o\n"),
            ("libavcodec/Makefile", "OBJS += aom_film_grain.o\n"),
            ("libavcodec/Makefile", "# TESTPROGS += aom_film_grain\n"),
            ("libavcodec/Makefile", "TESTPROGS += golomb # aom_film_grain next\n"),
            ("libavcodec/Makefile", "TESTPROGS += golomb # see \\\naom_film_grain\n"),
            ("libavcodec/Makefile", "TOOLS = golomb \\\n    aom_film_grain\n"),
        ):
            with self.subTest(path=path, makefile=makefile):
                found = upstream_lint.registered_test_programs(program, {path: makefile})
                self.assertEqual(found, [])
        self.assertEqual(upstream_lint.registered_test_programs(program, {}), [])

    def test_testprogs_names_reads_only_testprogs_words(self) -> None:
        """TESTPROGS words come from joined logical lines with make comments dropped."""
        makefile = (
            "OBJS += golomb.o\n"
            "TESTPROGS = avcodec \\\n"
            "            jpeg2000dwt # utf8 \\\n"
            "            bitstream_be\n"
            "TESTPROGSX += x\n"
            "TESTPROGS-$(CONFIG_GOLOMB) += golomb\n"
        )
        self.assertEqual(
            upstream_lint.testprogs_names(makefile), frozenset({"avcodec", "jpeg2000dwt", "golomb"})
        )
        self.assertEqual(upstream_lint.testprogs_names(""), frozenset())

    def test_test_program_path_is_c_under_lib_tests(self) -> None:
        """Only C files directly below a lib*/tests directory count as test programs."""
        self.assertTrue(upstream_lint.is_test_program_path("libavcodec/tests/x.c"))
        for name in (
            "libavcodec/tests/x.h",
            "libavcodec/tests/sub/x.c",
            "tests/api/x.c",
            "libavcodec/x.c",
            "tools/tests/x.c",
        ):
            with self.subTest(name=name):
                self.assertFalse(upstream_lint.is_test_program_path(name))


class DocstringsStepTest(unittest.TestCase):
    """Positive, negative and boundary coverage of the docstrings step and reader."""

    def run_step(self, returncode: int, stdout: str, waiver: str = "") -> upstream_lint.Step:
        """Run _docstrings with _run stubbed to return the chosen status and output."""
        stub = upstream_lint.RunResult((), returncode, stdout)
        with unittest.mock.patch.object(upstream_lint, "_run", return_value=stub):
            return upstream_lint._docstrings(Path("/fixture/ffmpeg"), "base", "head", waiver)

    def test_coverage_pass_returns_zero(self) -> None:
        """Exit 0 with a valid first-line coverage summary returns step rc 0."""
        covered = (
            "Docstring coverage: 85.71% (6/7 covered, counted: 7, covered: 6, threshold: 80%)\n"
        )
        for stdout in (DOCSTRING_EMPTY_CLEAN, covered):
            with self.subTest(stdout=stdout):
                expected = stdout.rstrip("\n")
                self.assertEqual(
                    upstream_lint.docstring_result(0, stdout),
                    upstream_lint.Step("docstrings", 0, expected),
                )
                step = self.run_step(0, stdout)
                self.assertEqual(step, upstream_lint.Step("docstrings", 0, expected))

    def test_coverage_finding_returns_one_with_functions_and_advice(self) -> None:
        """Exit 1 with a coverage summary keeps the function lines and appends advice."""
        expected = f"{DOCSTRING_FINDING.rstrip()}\n{DOCSTRING_ADVICE}"
        self.assertEqual(
            upstream_lint.docstring_result(1, DOCSTRING_FINDING),
            upstream_lint.Step("docstrings", 1, expected),
        )
        step = self.run_step(1, DOCSTRING_FINDING)
        self.assertEqual(step.rc, 1)
        self.assertEqual(step.output, expected)
        self.assertIn("libavfilter/vf_x.c:5 ff_alpha", step.output)
        self.assertIn("libavfilter/vf_x.c:12 ff_beta", step.output)

    def test_blank_or_whitespace_waiver_returns_one(self) -> None:
        """An empty or whitespace-only --docstring-reason leaves a finding at rc 1."""
        for reason in ("", " ", " \t\n "):
            with self.subTest(reason=reason):
                step = self.run_step(1, DOCSTRING_FINDING, reason)
                self.assertEqual(step.rc, 1)
                self.assertNotIn("waived:", step.output)
                self.assertTrue(step.output.endswith(DOCSTRING_ADVICE))

    def test_non_blank_waiver_waives_finding(self) -> None:
        """A non-blank --docstring-reason returns rc 0 with the waived header line."""
        expected = f"waived: internal wrappers\n{DOCSTRING_FINDING.rstrip()}"
        self.assertEqual(
            upstream_lint.docstring_result(1, DOCSTRING_FINDING, "  internal wrappers  "),
            upstream_lint.Step("docstrings", 0, expected),
        )
        step = self.run_step(1, DOCSTRING_FINDING, "internal wrappers")
        self.assertEqual(step.rc, 0)
        self.assertEqual(step.output, expected)

    def test_hook_refusal_returns_two(self) -> None:
        """Exit 1 starting with a praetor hooks refusal fails closed with rc 2."""
        refusal = "praetor hooks: installing the engine failed\n"
        for reason in ("", "cannot waive refusal"):
            with self.subTest(reason=reason):
                step = self.run_step(1, refusal, reason)
                self.assertEqual(step.rc, 2)
                self.assertIn("1", step.output.splitlines()[0])
                self.assertIn("praetor hooks: installing the engine failed", step.output)
                self.assertNotIn("waived:", step.output)

    def test_engine_error_exit_two_returns_two_even_when_waived(self) -> None:
        """Exit 2 with an [ERROR] line returns rc 2 even when a waiver is supplied."""
        error = "[ERROR] cannot read base revision\n"
        for reason in ("", "not a finding"):
            with self.subTest(reason=reason):
                step = self.run_step(2, error, reason)
                self.assertEqual(step.rc, 2)
                self.assertIn("2", step.output.splitlines()[0])
                self.assertIn("[ERROR] cannot read base revision", step.output)
                self.assertNotIn("waived:", step.output)

    def test_timeout_exit_returns_two(self) -> None:
        """A timed-out engine run with exit 124 fails closed with rc 2."""
        for stdout in ("\ncommand timed out\n", f"{DOCSTRING_EMPTY_CLEAN}command timed out\n"):
            with self.subTest(stdout=stdout):
                step = self.run_step(124, stdout, "not waivable")
                self.assertEqual(step.rc, 2)
                self.assertIn("124", step.output.splitlines()[0])
                self.assertNotIn("waived:", step.output)

    def test_zero_exit_without_coverage_line_returns_two(self) -> None:
        """Exit 0 without the allow-listed coverage line fails closed with rc 2."""
        for stdout in ("", "ok\n", "Docstring coverage: ok\n"):
            with self.subTest(stdout=stdout):
                step = self.run_step(0, stdout)
                self.assertEqual(step.rc, 2)
                self.assertIn("0", step.output.splitlines()[0])

    def test_non_first_coverage_line_returns_two(self) -> None:
        """A coverage summary preceded by another line fails closed with rc 2."""
        cases = (
            (0, f"praetor hooks: running engine on PATH\n{DOCSTRING_EMPTY_CLEAN}"),
            (1, f"\n{DOCSTRING_FINDING}"),
        )
        for returncode, stdout in cases:
            with self.subTest(returncode=returncode):
                step = self.run_step(returncode, stdout, "not a finding")
                self.assertEqual(step.rc, 2)
                self.assertNotIn("waived:", step.output)

    def test_step_passes_expected_argv_and_cwd_to_run(self) -> None:
        """The step runs engine.sh via bash from REPO_ROOT with DOCSTRINGS_TIMEOUT."""
        tree = Path("/fixture/ffmpeg")
        stub = upstream_lint.RunResult((), 0, DOCSTRING_EMPTY_CLEAN)
        with unittest.mock.patch.object(upstream_lint, "_run", return_value=stub) as run:
            step = upstream_lint._docstrings(tree, "base_rev", "head_rev", "")
        self.assertEqual(step.rc, 0)
        self.assertEqual(upstream_lint.DOCSTRINGS_TIMEOUT, 300)
        run.assert_called_once_with(
            [
                "bash",
                str(upstream_lint.REPO_ROOT / ".config" / "lefthook" / "engine.sh"),
                "docstrings",
                "check",
                f"--path={tree}",
                "--base=base_rev",
                "--head=head_rev",
            ],
            upstream_lint.REPO_ROOT,
            timeout=upstream_lint.DOCSTRINGS_TIMEOUT,
        )


class FixtureTest(unittest.TestCase):
    """Shared disposable Git fixture; stub pre-commit, semgrep_scan.sh and the Praetor engine."""

    def setUp(self) -> None:
        """Create a minimal committed base without inheriting template hooks."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "tree"
        self.root.mkdir()
        template = Path(directory.name) / "template"
        template.mkdir()
        self.git("init", "-q", f"--template={template}")
        self.write(upstream_lint.CONFIG, FAKE_CONFIG)
        self.write("tools/check_commit_msg.sh", FAKE_MESSAGE)
        self.write("tools/patcheck", FAKE_PATCHECK)
        self.write("libavfilter/vf_x.c", SOURCE)
        self.write("libavutil/attributes.h", "#define av_fixture_tag\n")
        self.write("libavfilter/allfilters.c", FILTER_DECLARATIONS)
        self.commit("avfilter/vf_x: initial fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.real_run = upstream_lint._run
        self.hook_rc = 0
        self.hook_effect = lambda cwd: None
        self.hook_calls = []
        self.c_rules_rc = 0
        self.c_rules_stdout = ""
        self.c_rules_json: str | None = ""
        self.c_rules_calls: list[tuple[list[str], Path, float]] = []
        self.engine_rc = 0
        self.engine_output = DOCSTRING_EMPTY_CLEAN
        self.engine_calls = []

    def git(self, *args: str) -> str:
        """Run bounded fixture Git commands with explicit author and signing settings."""
        result = subprocess.run(  # nosec B603 B607 - fixed Git, fixture-only arguments.
            [
                "git",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *args,
            ],
            cwd=self.root,
            env=isolated_git_environment(),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout

    def write(self, name, source):
        """Write one fixture path, creating its parent directories."""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def commit(self, subject="avfilter/vf_x: update y"):
        """Commit fixture changes; never touch the implementation repository."""
        self.git("add", ".")
        self.git("commit", "-qm", subject)

    def command(
        self, argv: list[str], cwd: Path, data: str | None = None, timeout: float = 60
    ) -> upstream_lint.RunResult:
        """Stub hooks, scans and the engine with full default path coverage; bound the rest."""
        if Path(argv[0]).name == upstream_lint.PRE_COMMIT:
            self.hook_calls.append((argv, Path(argv[3]).read_text(encoding="utf-8")))
            self.hook_effect(Path(cwd))
            return upstream_lint.RunResult(tuple(argv), self.hook_rc, "fixture pre-commit\n")
        if len(argv) >= 2 and argv[0] == "bash" and Path(argv[1]) == upstream_lint.SEMGREP_SCAN:
            self.c_rules_calls.append((argv, Path(cwd), timeout))
            if self.c_rules_json is not None:
                json_arg = next(item for item in argv if item.startswith("--json-output="))
                Path(json_arg.removeprefix("--json-output=")).write_text(
                    self.c_rules_json
                    or json.dumps({"paths": {"scanned": argv[5:]}, "results": [], "errors": []}),
                    encoding="utf-8",
                )
            return upstream_lint.RunResult(tuple(argv), self.c_rules_rc, self.c_rules_stdout)
        if argv[:2] == ["bash", str(upstream_lint.REPO_ROOT / upstream_lint.ENGINE_SCRIPT)]:
            self.engine_calls.append((argv, Path(cwd)))
            return upstream_lint.RunResult(tuple(argv), self.engine_rc, self.engine_output)
        return self.real_run(argv, cwd, data, timeout)

    def check(self, *args: str) -> tuple[int, str]:
        """Capture the complete gate report with controlled hook and engine results."""
        output = io.StringIO()
        with (
            unittest.mock.patch.object(
                upstream_lint, "_pre_commit", return_value="/fixture/bin/pre-commit"
            ),
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.command),
            contextlib.redirect_stdout(output),
        ):
            rc = upstream_lint.main(["--tree", str(self.root), "--base", self.base, *args])
        return rc, output.getvalue()


class PipelineTest(FixtureTest):
    """Run Git and base tools in a throwaway repository; stub external hooks and engine."""

    def test_command_environment_is_independent_of_path_bound(self) -> None:
        """Lowering the path bound to one still accepts every fixture environment entry."""
        environment = {"FIXTURE_FIRST": "first", "FIXTURE_LAST": "last"}
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
            result = upstream_lint._command_environment(environment, self.root)
        self.assertEqual(
            result,
            {**environment, "PRE_COMMIT_NO_CONCURRENCY": "1", "PWD": str(self.root.resolve())},
        )

    def test_clean_commit_passes_and_collects_all_steps(self) -> None:
        """A correctly named clean commit passes every collected check."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        for name in (
            "pre-commit",
            "commit-msg",
            "patcheck",
            "developer.texi",
            "fate-deps",
            "regression-test",
            "revert-proof",
            "diagnostic-citation",
            "claim-scope",
            "doc-terms",
            "doc-wrap",
            "test-program",
            "c-rules",
            "docstrings",
        ):
            self.assertIn(f"step: {name} rc: 0", output)

    def test_c_rules_finding_on_added_line_fails(self) -> None:
        """A c-rules finding touching an added source line fails the step and pipeline."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit()
        self.c_rules_rc = 1
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": ["libavfilter/vf_x.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavfilter/vf_x.c",
                        "start": {"line": 3},
                        "end": {"line": 3},
                        "extra": {"message": "call ff_network_close() before returning"},
                    }
                ],
                "errors": [],
            }
        )
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: c-rules rc: 1", output)
        expected_finding = (
            "finding: libavfilter/vf_x.c:3: "
            "ffmpeg-rtsp-connect-failure-without-network-close: "
            "call ff_network_close() before returning"
        )
        self.assertIn(
            expected_finding,
            output,
        )
        self.assertIn("fix the flagged path, or pass --c-rule-reason", output)
        self.assertIn("step: test-program rc: 0", output)

    def test_c_rules_waiver_passes(self) -> None:
        """A non-blank --c-rule-reason waives a c-rules finding and prints the reason."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit()
        self.c_rules_rc = 1
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": ["libavfilter/vf_x.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavfilter/vf_x.c",
                        "start": {"line": 3},
                        "end": {"line": 3},
                        "extra": {"message": "call ff_network_close() before returning"},
                    }
                ],
                "errors": [],
            }
        )
        rc, output = self.check("--c-rule-reason", "caller owns network teardown")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: c-rules rc: 0\nwaived: caller owns network teardown", output)

    def test_c_rules_renamed_source_tracks_only_changed_lines(self) -> None:
        """A pure rename leaves pre-existing matches untouched; editing inside one fails."""
        self.write("libavformat/rtsp_old.c", RTSP_WITHOUT_CLOSE)
        self.commit("avformat/rtsp: add mux helper")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.c_rules_rc = 1
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtsp_new.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavformat/rtsp_new.c",
                        "start": {"line": 8},
                        "end": {"line": 9},
                        "extra": {"message": "call ff_network_close() before returning"},
                    }
                ],
                "errors": [],
            }
        )
        self.git("mv", "libavformat/rtsp_old.c", "libavformat/rtsp_new.c")
        self.commit("avformat/rtsp: rename mux helper")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertEqual(self.c_rules_calls[0][0][5:], ["libavformat/rtsp_new.c"])
        self.assertIn("pre-existing (untouched): libavformat/rtsp_new.c:8:", output)

        self.git("reset", "--hard", self.base)
        self.c_rules_calls.clear()
        self.git("mv", "libavformat/rtsp_old.c", "libavformat/rtsp_new.c")
        self.write(
            "libavformat/rtsp_new.c",
            RTSP_WITHOUT_CLOSE.replace(
                "        return ret;\n    }\n", "        return -1;\n    }\n"
            ),
        )
        self.commit("avformat/rtsp: rename and adjust return")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertEqual(self.c_rules_calls[0][0][5:], ["libavformat/rtsp_new.c"])
        self.assertIn("step: c-rules rc: 1", output)
        self.assertIn("finding: libavformat/rtsp_new.c:8:", output)

    def test_c_rules_deletion_only_hunks_and_span_boundaries(self) -> None:
        """Deletions inside or directly after a match span fail; before start_line passes."""
        self.c_rules_rc = 1
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtsp.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavformat/rtsp.c",
                        "start": {"line": 8},
                        "end": {"line": 9},
                        "extra": {"message": "call ff_network_close() before returning"},
                    }
                ],
                "errors": [],
            }
        )
        after_end = RTSP_WITHOUT_CLOSE.replace(
            "        return ret;\n", "        return ret;\n        /* after match */\n"
        )
        before_start = RTSP_WITHOUT_CLOSE.replace(
            "        ff_rtsp_close_connections(s);\n",
            "        /* before match */\n        ff_rtsp_close_connections(s);\n",
        )
        saved_base = self.base
        for label, base_source, expected_rc, marker in (
            ("inside", RTSP_WITH_CLOSE, 1, "finding: libavformat/rtsp.c:8:"),
            ("after-end", after_end, 1, "finding: libavformat/rtsp.c:8:"),
            ("before-start", before_start, 0, "pre-existing (untouched): libavformat/rtsp.c:8:"),
        ):
            with self.subTest(case=label):
                self.git("reset", "--hard", saved_base)
                self.write("libavformat/rtsp.c", base_source)
                self.commit("avformat/rtsp: add mux helper")
                self.base = self.git("rev-parse", "HEAD").strip()
                self.write("libavformat/rtsp.c", RTSP_WITHOUT_CLOSE)
                self.commit("avformat/rtsp: trim mux helper")
                rc, output = self.check()
                self.assertEqual(rc, expected_rc, output)
                self.assertIn(f"step: c-rules rc: {expected_rc}", output)
                self.assertIn(marker, output)

    def test_fix_without_test_fails(self) -> None:
        """A source fix commit with no changed test path in the range fails."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)
        for name in ("pre-commit", "commit-msg", "patcheck", "developer.texi", "fate-deps"):
            self.assertIn(f"step: {name} rc: 0", output)

    def test_fix_with_test_passes(self) -> None:
        """A source fix accompanied by a test file in the same commit passes."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("tests/ref/fate/filter-x", "0\n")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_unrelated_test_control_word_does_not_reach_source_guard(self) -> None:
        """A shared C control word cannot make an unrelated test reach a source fix."""
        source = "libavfilter/vf_x.c"
        self.write(
            source, SOURCE.replace("    return 1;", "    if (1) {\n        return 2;\n    }")
        )
        self.commit("avfilter/vf_x: fix missing guard")
        self.write("tests/ref/fate/filter-unrelated", "if (other_case)\n")
        self.commit("tests/fate: add unrelated guard")
        head = self.git("rev-parse", "HEAD").strip()
        step = upstream_lint._regression_test(self.root, self.base, head, "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("test paths changed but none names", step.output)
        self.assertIn("vf_x", step.output)

    def test_fix_with_test_in_later_commit_passes(self) -> None:
        """A test added in a separate commit within the same range satisfies the check."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix y")
        self.write("tests/ref/fate/filter-x", "0\n")
        self.commit("tests/fate: add filter-x")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_body_fix_without_test_fails(self) -> None:
        """A source commit whose body says fix fails without a changed test path."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: do not delete y\n\nFix this by skipping y.")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)
        self.assertIn(": avfilter/vf_x: do not delete y: fixes C or assembly sources", output)

    def test_body_defect_word_without_test_fails(self) -> None:
        """A source commit whose body names a defect fails without a changed test path."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: skip absent y\n\nReading y would misalign every field.")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)

    def test_body_uninitialised_defect_word_requires_test_or_waiver(self) -> None:
        """An uninitialised-reply body fails without a test and passes when waived or neutral."""
        subject = "avformat/rtsp: check command write before using replies"
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit(
            f"{subject}\n\nIgnoring that error can make callers inspect an uninitialised reply."
        )
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)
        rc, output = self.check(
            "--no-test-reason",
            "needs a live RTSP server",
            "--no-revert-proof-reason",
            "needs a live RTSP server",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)
        self.assertIn("step: regression-test rc: 0\nwaived: needs a live RTSP server\n", output)
        self.assertIn("step: revert-proof rc: 0\nwaived: needs a live RTSP server\n", output)
        self.git("commit", "--amend", "-qm", f"{subject}\n\nRename the reply helper.")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_hyphenated_uninitialized_subject_requires_test_or_waiver(self) -> None:
        """A use-of-uninitialized-value subject fails without a test unless waived."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avformat/x: use-of-uninitialized-value in keybuffer")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)
        rc, output = self.check(
            "--no-test-reason",
            "reproducer requires MemorySanitizer",
            "--no-revert-proof-reason",
            "reproducer requires MemorySanitizer",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)
        self.assertIn(
            "step: regression-test rc: 0\nwaived: reproducer requires MemorySanitizer\n", output
        )
        self.assertIn(
            "step: revert-proof rc: 0\nwaived: reproducer requires MemorySanitizer\n", output
        )
        self.git("commit", "--amend", "-qm", "avformat/x: clear keybuffer")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_wrapped_body_defect_phrase_without_test_fails(self) -> None:
        """A source commit whose body wraps a defect phrase fails without a changed test path."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: bound y\n\nThe read goes out of\nbounds.")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)

    def test_body_without_defect_word_passes(self) -> None:
        """A source commit whose subject and body name no defect needs no test path."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update y\n\nRename the helper.")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_body_fix_waiver_passes(self) -> None:
        """A non-blank --no-test-reason waives a source commit whose body says fix."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: do not delete y\n\nFix this by skipping y.")
        rc, output = self.check(
            "--no-test-reason",
            "hardware-only path",
            "--no-revert-proof-reason",
            "hardware-only path",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0\nwaived: hardware-only path\n", output)
        self.assertIn("step: revert-proof rc: 0\nwaived: hardware-only path\n", output)

    def test_fix_waiver_passes(self) -> None:
        """A non-blank --no-test-reason waives a source fix without a test path."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check(
            "--no-test-reason",
            "hardware-only path",
            "--no-revert-proof-reason",
            "hardware-only path",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0\nwaived: hardware-only path\n", output)
        self.assertIn("step: revert-proof rc: 0\nwaived: hardware-only path\n", output)

    def test_blank_waiver_fails(self) -> None:
        """Whitespace-only --no-test-reason does not waive a missing regression test."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-test-reason", "  ")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)

    def test_fix_outside_sources_passes(self) -> None:
        """A fix commit touching only documentation does not require a test path."""
        self.write("doc/x.texi", "fixed wording\n")
        self.commit("doc/x: fix a typo")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_fix_with_unreaching_test_fails(self) -> None:
        """A source fix fails when changed tests name neither its file nor function."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("libavutil/tests/film_grain_params.c", "int main(void)\n{\n    return 0;\n}\n")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)
        self.assertIn("test paths changed but none names ff_value, vf_x, x", output)

    def test_fix_with_test_naming_function_passes(self) -> None:
        """A source fix passes when an added test line names the changed function."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write(
            "libavutil/tests/film_grain_params.c",
            "int main(void)\n{\n    return ff_value();\n}\n",
        )
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_unreached_fix_waiver_passes(self) -> None:
        """A non-blank --no-test-reason waives an unreached source fix commit."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("libavutil/tests/film_grain_params.c", "int main(void)\n{\n    return 0;\n}\n")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check(
            "--no-test-reason",
            "the parser runs only behind a hardware decoder",
            "--no-revert-proof-reason",
            "the parser runs only behind a hardware decoder",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn(
            "step: regression-test rc: 0\nwaived: the parser runs only behind a hardware decoder\n",
            output,
        )
        self.assertIn(
            "step: revert-proof rc: 0\nwaived: the parser runs only behind a hardware decoder\n",
            output,
        )

    def test_unreached_fix_blank_waiver_fails(self) -> None:
        """Whitespace-only --no-test-reason does not waive an unreached source fix."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("libavutil/tests/film_grain_params.c", "int main(void)\n{\n    return 0;\n}\n")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-test-reason", "  ")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: regression-test rc: 1", output)

    def test_one_unreached_fix_of_two_fails(self) -> None:
        """Each fix commit in the range must be reached by the changed tests."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix y")
        self.write("tests/ref/fate/filter-x", "0\n")
        self.write("libavfilter/vf_y.c", SOURCE.replace("ff_value", "ff_other"))
        self.commit("avfilter/vf_y: fix z")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn(
            "avfilter/vf_y: fix z: test paths changed but none names ff_other, vf_y, y", output
        )
        self.assertNotIn("avfilter/vf_x: fix y: test paths changed", output)

    def test_fix_with_binary_test_fixture_passes(self) -> None:
        """A source fix passes when a binary test fixture path names the fixed stem."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("tests/data/filter-x.bin", "\x00\x01\x02")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_fix_with_quoted_test_path_passes(self) -> None:
        """A source fix passes when a non-ASCII quoted test file names the function."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write("tests/café_x.c", "int main(void)\n{\n    return ff_value();\n}\n")
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_fix_with_noprefix_config_passes(self) -> None:
        """A source fix passes even when repository config sets diff.noprefix=true."""
        self.git("config", "diff.noprefix", "true")
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.write(
            "libavutil/tests/film_grain_params.c",
            "int main(void)\n{\n    return ff_value();\n}\n",
        )
        self.commit("avfilter/vf_x: fix y")
        rc, output = self.check("--no-revert-proof-reason", "regression-test fixture")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)

    def test_uncited_diagnostic_workaround_fails(self) -> None:
        """An uncited compiler-diagnostic workaround fails only its own step."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: silence -Wmaybe-uninitialized false positive")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: diagnostic-citation rc: 1", output)
        for name in ("pre-commit", "commit-msg", "patcheck", "developer.texi", "fate-deps"):
            self.assertIn(f"step: {name} rc: 0", output)

    def test_cited_diagnostic_workaround_passes(self) -> None:
        """A compiler-diagnostic workaround with an upstream bug URL passes."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        message = (
            "avfilter/vf_x: silence -Wmaybe-uninitialized false positive\n\n"
            "https://gcc.gnu.org/bugzilla/show_bug.cgi?id=109999"
        )
        self.commit(message)
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: diagnostic-citation rc: 0", output)

    def test_verification_claim_fails(self) -> None:
        """A blanket verification claim fails claim-scope while other steps pass."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update y\n\nPasses all FATE tests.")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)
        for name in (
            "pre-commit",
            "commit-msg",
            "patcheck",
            "developer.texi",
            "fate-deps",
            "regression-test",
            "revert-proof",
            "diagnostic-citation",
        ):
            self.assertIn(f"step: {name} rc: 0", output)

    def test_verification_claim_is_not_waived(self) -> None:
        """Passing --claim-reason cannot waive a blanket verification claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update y\n\nPasses all FATE tests.")
        rc, output = self.check("--claim-reason", "ran fate")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)

    def test_single_hunk_scope_claim_fails(self) -> None:
        """A multi-site claim backed by one source hunk fails without a waiver."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: clamp y in both loops")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)

    def test_single_hunk_each_of_the_branches_claim_fails(self) -> None:
        """A claim about each of the branches backed by one source hunk fails without a waiver."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: clamp y in each of the branches")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn("changes 1 source hunk", output)

    def test_scope_claim_waiver_passes(self) -> None:
        """A non-blank --claim-reason waives a single-hunk scope claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: clamp y in both loops")
        rc, output = self.check("--claim-reason", "the second loop is generated from one macro")
        self.assertEqual(rc, 0, output)
        self.assertIn("waived: the second loop is generated from one macro", output)

    def test_blank_scope_waiver_fails(self) -> None:
        """Whitespace-only --claim-reason does not waive a single-hunk scope claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: clamp y in both loops")
        rc, output = self.check("--claim-reason", "  ")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)

    def test_two_hunk_scope_claim_passes(self) -> None:
        """A multi-site claim backed by two source hunks passes without a waiver."""
        self.write(
            "libavfilter/vf_x.c",
            SOURCE.replace("ff_value", "ff_first") + "\nint ff_other(void)\n{\n    return 3;\n}\n",
        )
        self.commit("avfilter/vf_x: update both functions")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: claim-scope rc: 0", output)

    def test_doc_terms_omission_fails(self) -> None:
        """Added docs saying YUV for added non-RGB code fail the doc-terms step."""
        self.write(
            "libavfilter/vf_x.c", SOURCE.replace("1", "!(desc->flags & AV_PIX_FMT_FLAG_RGB)")
        )
        self.write("doc/filters.texi", "@item keep\nKeep the light level for YUV input.\n")
        self.commit("avfilter/vf_x: keep the light level")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn(
            'non-RGB input: added code has "!(desc->flags & AV_PIX_FMT_FLAG_RGB)"', output
        )

    def test_doc_terms_waiver_passes(self) -> None:
        """A non-blank --doc-reason waives the doc-terms step and prints the reason."""
        self.write(
            "libavfilter/vf_x.c", SOURCE.replace("1", "!(desc->flags & AV_PIX_FMT_FLAG_RGB)")
        )
        self.write("doc/filters.texi", "@item keep\nKeep the light level for YUV input.\n")
        self.commit("avfilter/vf_x: keep the light level")
        rc, output = self.check("--doc-reason", "gray input is rejected earlier")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0\nwaived: gray input is rejected earlier", output)

    def test_doc_terms_named_case_passes(self) -> None:
        """Added docs that say non-RGB for added non-RGB code pass the doc-terms step."""
        self.write(
            "libavfilter/vf_x.c", SOURCE.replace("1", "!(desc->flags & AV_PIX_FMT_FLAG_RGB)")
        )
        self.write("doc/filters.texi", "@item keep\nKeep the light level for non-RGB input.\n")
        self.commit("avfilter/vf_x: keep the light level")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_comment_only_passes(self) -> None:
        """An added comment that names the RGB test is not added non-RGB code."""
        self.write(
            "libavfilter/vf_x.c",
            SOURCE.replace(
                "    return 1;", "    /* was !(desc->flags & AV_PIX_FMT_FLAG_RGB) */\n    return 1;"
            ),
        )
        self.write("doc/filters.texi", "@item keep\nKeep the light level for YUV input.\n")
        self.commit("avfilter/vf_x: keep the light level")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_added_line_inside_comment_passes(self) -> None:
        """An added line inside an existing block comment is read as comment text."""
        self.write("libavfilter/vf_x.c", "/*\n * Light level.\n */\n" + SOURCE)
        self.commit("avfilter/vf_x: describe the light level")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(
            "libavfilter/vf_x.c",
            "/*\n * Light level.\n * The old test was !(desc->flags & AV_PIX_FMT_FLAG_RGB).\n */\n"
            + SOURCE,
        )
        self.write("doc/filters.texi", "@item keep\nKeep the light level for YUV input.\n")
        self.commit("avfilter/vf_x: keep the light level")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_fails(self) -> None:
        """Added ignore_io_errors tests near global_sidx without naming it fail doc-terms."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("option interplay", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_avoption_const_before_offset(self) -> None:
        """A const AVOption row without OFFSET must not remap the following field."""
        self.write("libavformat/dashenc.c", DASHENC_OPTIONS_T9)
        self.write("doc/muxers.texi", DOC_MUXERS_BASE)
        self.commit("libavformat/dashenc: option table with const row")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T9_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_two_added_lines_once(self) -> None:
        """Two added lines testing the same pair report option interplay only once."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T10_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: dual ignore I/O guards")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertEqual(output.count("option interplay:"), 1)

    def test_doc_terms_option_interplay_named_passes(self) -> None:
        """Docs that name global_sidx waive the ignore_io_errors interplay finding."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T2)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_same_line_passes(self) -> None:
        """single-file wording in the entry waives interplay on the same added line."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T3_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T3)
        self.commit("libavformat/dashenc: single file guard")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_window_passes(self) -> None:
        """global_sidx four lines away from the added test stays outside the window."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T4_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_comment_passes(self) -> None:
        """A comment-only global_sidx mention in the window is not an option test."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T5_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_wrong_entry_passes(self) -> None:
        """Doc additions in another entry do not trigger ignore_io_errors interplay."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T6)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_waiver_passes(self) -> None:
        """A non-blank --doc-reason waives an option-interplay doc-terms finding."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check("--doc-reason", "global_sidx layout is documented elsewhere")
        self.assertEqual(rc, 0, output)
        self.assertIn("waived: global_sidx layout is documented elsewhere", output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_no_table_passes(self) -> None:
        """Source without an AVOption table produces no option-interplay finding."""
        self.write("libavformat/dashenc.c", DASHENC_NO_TABLE)
        self.write("doc/muxers.texi", DOC_MUXERS_BASE)
        self.commit("libavformat/dashenc: writer without options")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_NO_TABLE_T1)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_shared_field_alias_fails(self) -> None:
        """Only the first alias name doc entry changes between base and T1."""
        self.write("libavformat/dashenc.c", DASHENC_ALIAS_BASE)
        self.write("doc/muxers.texi", DOC_MUXERS_ALIAS_BASE)
        self.commit("libavformat/dashenc: alias option table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_ALIAS_T1)
        self.write("doc/muxers.texi", DOC_MUXERS_ALIAS_T1)
        self.commit("libavformat/dashenc: alias guard")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertEqual(output.count("option interplay:"), 1)
        self.assertIn("ignore_io_errors near global_sidx", output)
        self.assertNotIn("ignore_errors near", output)
        self.assertNotIn("ignore_io_errors near ignore_errors", output)
        self.assertNotIn("ignore_errors near ignore_io_errors", output)

    def test_doc_terms_option_interplay_multiline_if_fails(self) -> None:
        """An added continuation line inside a multiline if still couples with global_sidx."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_COND_T1)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: multiline ignore guard")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_indexed_flags_fails(self) -> None:
        """An indexed flags member coupled with global_sidx yields option interplay."""
        self.write("libavformat/dashenc.c", DASHENC_FLAGS_BASE)
        self.write("doc/muxers.texi", DOC_MUXERS_FLAGS_T1)
        self.commit("libavformat/dashenc: flags option table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_FLAGS_T1)
        self.write(
            "doc/muxers.texi",
            DOC_MUXERS_FLAGS_T1.replace(
                "Bitmask flags.\n", "Bitmask flags.\nApplies when segment indices shift.\n"
            ),
        )
        self.commit("libavformat/dashenc: guard flags and global sidx")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("flags near global_sidx", output)

    def test_doc_terms_option_interplay_dual_entry_omit_first_fails(self) -> None:
        """A later changed entry cannot waive a finding from an earlier omitting entry."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        omit_first = (
            "@table @option\n"
            "@item ignore_io_errors\n"
            "Ignore transport failures only.\n"
            "@item global_sidx\n"
            "Write a global sidx.\n"
            "@end table\n"
            "@table @option\n"
            "@item ignore_io_errors\n"
            "Ignore I/O errors.\n"
            "Respects global_sidx placement.\n"
            "@item global_sidx\n"
            "Write a global sidx.\n"
            "@end table\n"
        )
        self.write("doc/muxers.texi", omit_first)
        self.commit("libavformat/dashenc: dual ignore_io_errors docs")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_dual_entry_omit_last_fails(self) -> None:
        """An earlier naming entry cannot waive a finding from a later omitting entry."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        omit_last = (
            "@table @option\n"
            "@item ignore_io_errors\n"
            "Ignore I/O errors.\n"
            "Respects global_sidx placement.\n"
            "@item global_sidx\n"
            "Write a global sidx.\n"
            "@end table\n"
            "@table @option\n"
            "@item ignore_io_errors\n"
            "Ignore transport failures only.\n"
            "@item global_sidx\n"
            "Write a global sidx.\n"
            "@end table\n"
        )
        self.write("doc/muxers.texi", omit_last)
        self.commit("libavformat/dashenc: dual ignore_io_errors docs reversed")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_separate_tables_passes(self) -> None:
        """Fields from different AVOption tables in one file do not trigger interplay."""
        self.write("libavformat/dashenc.c", TWO_TABLES_OPTIONS + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: two option tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", TWO_TABLES_OPTIONS + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_T1)
        self.commit("libavformat/dashenc: guard foo mode")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_shared_table_control_fails(self) -> None:
        """The same foo and bar tests fail when both belong to one AVOption table."""
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: single option table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_T1)
        self.commit("libavformat/dashenc: guard foo mode")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("option interplay:", output)
        self.assertIn("foo near bar", output)

    def test_doc_terms_option_interplay_texi_comment_names_neighbour_fails(self) -> None:
        """A neighbour named only in an entry @c line does not waive interplay."""
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: single option table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_COMMENT_ONLY_BAR)
        self.commit("libavformat/dashenc: foo docs comment bar")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("foo near bar", output)

    def test_doc_terms_option_interplay_texi_comment_and_plain_passes(self) -> None:
        """Plain prose naming the neighbour waives interplay when @c also names it."""
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: single option table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", ONE_TABLE_OPTIONS + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_COMMENT_AND_PLAIN_BAR)
        self.commit("libavformat/dashenc: foo docs name bar")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_bounded_tables_passes(self) -> None:
        """Bounded AVOption headers keep foo and bar tests in separate tables."""
        self.write("libavformat/dashenc.c", BOUNDED_TWO_TABLES_OPTIONS + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: bounded option tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", BOUNDED_TWO_TABLES_OPTIONS + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_T1)
        self.commit("libavformat/dashenc: guard foo mode")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_assign_near_mode_passes(self) -> None:
        """Assigning foo near a mode test does not couple them under doc-terms."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_ASSIGN)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode assign base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_ASSIGN_FOO)
        self.write(
            "doc/muxers.texi",
            DOC_MODE_BASE.replace(
                "Enable the foo flag.\n", "Enable the foo flag.\nExtra guard text.\n"
            ),
        )
        self.commit("libavformat/dashenc: assign foo near mode")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_post_continuation_assign_passes(self) -> None:
        """An assignment after a continued condition closes does not trigger interplay."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_POST_COND_T1)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: set ignore flag after ready check")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_commented_avoption_row_passes(self) -> None:
        """A commented-out AVOption row does not couple a live foo test with bar."""
        self.write("libavformat/dashenc.c", ONE_TABLE_COMMENT_BAR + MUX_WRITE_BASE)
        self.write("doc/muxers.texi", DOC_FOO_BAR_BASE)
        self.commit("libavformat/dashenc: table with commented bar row")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", ONE_TABLE_COMMENT_BAR + MUX_WRITE_T1)
        self.write("doc/muxers.texi", DOC_FOO_BAR_T1)
        self.commit("libavformat/dashenc: guard foo mode")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_spaced_arrow_fails(self) -> None:
        """Whitespace after -> still couples ignore_io_errors with global_sidx under doc-terms."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SPACED_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_T1)
        self.commit("libavformat/dashenc: spaced ignore guard")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_mode_alias_name_mode_passes(self) -> None:
        """A foo doc entry naming mode waives interplay with the mode_alias neighbour."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode alias table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_MODE)
        self.commit("libavformat/dashenc: guard foo near mode")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_mode_alias_name_alias_passes(self) -> None:
        """A foo doc entry naming mode_alias waives interplay with the mode neighbour."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode alias table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_ALIAS)
        self.commit("libavformat/dashenc: guard foo naming alias")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_mode_alias_omit_fails(self) -> None:
        """A foo entry omitting every mode alias still reports foo near mode pairs."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode alias table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_OMIT)
        self.commit("libavformat/dashenc: guard foo omitting mode")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("foo near mode", output)
        self.assertIn("foo near mode_alias", output)

    def test_doc_terms_option_interplay_mode_alias_wrong_field_fails(self) -> None:
        """Naming a third field in the foo entry does not waive mode alias interplay."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode alias table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_OTHER)
        self.commit("libavformat/dashenc: guard foo naming other")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)

    def test_doc_terms_option_interplay_mode_alias_dual_entry_fails(self) -> None:
        """One foo entry naming mode cannot waive another changed foo entry omitting it."""
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE)
        self.write("doc/muxers.texi", DOC_MODE_BASE)
        self.commit("libavformat/dashenc: mode alias table")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", MODE_ALIAS_OPTIONS + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_DUAL_OMIT)
        self.commit("libavformat/dashenc: dual foo docs")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)

    def test_doc_terms_option_interplay_two_table_alias_w_n_w_first_passes(self) -> None:
        """Foo naming mode_alias passes when the pairing table lists mode_alias near mode."""
        src = INTERPLAY_ALIAS_WN_W_FIRST + MUX_WRITE_MODE
        self.write("libavformat/dashenc.c", src)
        self.write("doc/muxers.texi", DOC_MODE_INTERPLAY_BASE)
        self.commit("libavformat/dashenc: interplay w then n tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", INTERPLAY_ALIAS_WN_W_FIRST + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_ALIAS)
        self.commit("libavformat/dashenc: foo names mode_alias")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_two_table_alias_w_n_n_first_passes(self) -> None:
        """Table order cannot shrink the neighbour alias group for foo near mode pairs."""
        src = INTERPLAY_ALIAS_WN_N_FIRST + MUX_WRITE_MODE
        self.write("libavformat/dashenc.c", src)
        self.write("doc/muxers.texi", DOC_MODE_INTERPLAY_BASE)
        self.commit("libavformat/dashenc: interplay n then w tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", INTERPLAY_ALIAS_WN_N_FIRST + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_ALIAS)
        self.commit("libavformat/dashenc: foo names mode_alias rev")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)
        self.assertNotIn("option interplay:", output)

    def test_doc_terms_option_interplay_two_table_alias_p_q_p_first_fails(self) -> None:
        """Foo naming m fails when the pairing table lists only mode near foo."""
        src = INTERPLAY_ALIAS_PQ_P_FIRST + MUX_WRITE_MODE
        self.write("libavformat/dashenc.c", src)
        self.write("doc/muxers.texi", DOC_MODE_INTERPLAY_BASE)
        self.commit("libavformat/dashenc: interplay p then q tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", INTERPLAY_ALIAS_PQ_P_FIRST + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_M)
        self.commit("libavformat/dashenc: foo names m")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("foo near mode", output)

    def test_doc_terms_option_interplay_two_table_alias_p_q_q_first_fails(self) -> None:
        """Table order cannot widen the neighbour alias group for foo near mode pairs."""
        src = INTERPLAY_ALIAS_PQ_Q_FIRST + MUX_WRITE_MODE
        self.write("libavformat/dashenc.c", src)
        self.write("doc/muxers.texi", DOC_MODE_INTERPLAY_BASE)
        self.commit("libavformat/dashenc: interplay q then p tables")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", INTERPLAY_ALIAS_PQ_Q_FIRST + MUX_WRITE_MODE_FOO)
        self.write("doc/muxers.texi", DOC_MODE_FOO_NAMES_M)
        self.commit("libavformat/dashenc: foo names m rev")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("foo near mode", output)

    def test_doc_terms_option_interplay_shared_itemx_description_fails(self) -> None:
        """Editing only the shared description of an @item/@itemx group checks the first name."""
        self.write("libavformat/dashenc.c", DASHENC_BASE)
        self.write("doc/muxers.texi", DOC_MUXERS_ITEMX_BASE)
        self.commit("libavformat/dashenc: itemx option fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_ITEMX_OMIT_GLOBAL_SIDX)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_prose_after_example_named_passes(self) -> None:
        """Naming global_sidx in prose after an @example block satisfies option interplay."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_AFTER_EXAMPLE_NAMES_GLOBAL_SIDX)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_edit_after_example_omit_fails(self) -> None:
        """Editing only prose after an @example block while omitting global_sidx fails."""
        self.write("libavformat/dashenc.c", DASHENC_BASE)
        self.write("doc/muxers.texi", DOC_MUXERS_EXAMPLE_BASE)
        self.commit("libavformat/dashenc: option table with example")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", DASHENC_T1_SOURCE)
        self.write("doc/muxers.texi", DOC_MUXERS_AFTER_EXAMPLE_OMIT_GLOBAL_SIDX)
        self.commit("libavformat/dashenc: ignore I/O errors")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def _interplay_check(self, source: str, doc: str) -> tuple[int, str]:
        """Commit the dashenc base, then a source and doc change, and return the check result."""
        self._write_dashenc_fixture()
        self.commit("libavformat/dashenc: option table fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavformat/dashenc.c", source)
        self.write("doc/muxers.texi", doc)
        self.commit("libavformat/dashenc: ignore I/O errors")
        return self.check()

    def test_doc_terms_option_interplay_split_assignment_passes(self) -> None:
        """An assignment whose operator sits on the next line is not an option test."""
        rc, output = self._interplay_check(DASHENC_SPLIT_ASSIGN_SOURCE, DOC_MUXERS_T1)
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_split_comparison_fails(self) -> None:
        """A comparison whose operator sits on the next line is still an option test."""
        rc, output = self._interplay_check(DASHENC_SPLIT_COMPARE_SOURCE, DOC_MUXERS_T1)
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_verbatim_comment_names_neighbour_passes(self) -> None:
        """A @c global_sidx line inside @verbatim is printed text and names the neighbour."""
        doc = DOC_MUXERS_VERBATIM_COMMENT_NAMES_GLOBAL_SIDX
        rc, output = self._interplay_check(DASHENC_T1_SOURCE, doc)
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_ignore_block_names_neighbour_fails(self) -> None:
        """Text inside @ignore never prints, so it does not name the neighbour."""
        doc = DOC_MUXERS_IGNORE_BLOCK_NAMES_GLOBAL_SIDX
        rc, output = self._interplay_check(DASHENC_T1_SOURCE, doc)
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_window_lines_read_filtered_text(self) -> None:
        """Window lines read the filtered text, so a split assignment pairs nothing."""
        rc, output = self._interplay_check(DASHENC_SPLIT_ASSIGN_SOURCE, DOC_MUXERS_GLOBAL_SIDX_ONLY)
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def test_doc_terms_option_interplay_subscript_read_in_target_fails(self) -> None:
        """An option read inside the subscript of a split assignment target counts as a test."""
        rc, output = self._interplay_check(DASHENC_SUBSCRIPT_READ_ASSIGN_SOURCE, DOC_MUXERS_T1)
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-terms rc: 1", output)
        self.assertIn("added code tests ignore_io_errors near global_sidx", output)

    def test_doc_terms_option_interplay_constant_index_target_passes(self) -> None:
        """A constant-index option assignment target split across lines is not a test."""
        rc, output = self._interplay_check(DASHENC_CONSTANT_INDEX_ASSIGN_SOURCE, DOC_MUXERS_T1)
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-terms rc: 0", output)

    def _write_dashenc_fixture(self) -> None:
        """Write the dashenc and muxers fixture files shared by option-interplay tests."""
        self.write("libavformat/dashenc.c", DASHENC_BASE)
        self.write("doc/muxers.texi", DOC_MUXERS_BASE)

    def test_speed_claim_fails(self) -> None:
        """An encode speed claim without an end-to-end figure fails claim-scope."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        message = (
            "avfilter/vf_x: paint maps once\n\n"
            "The map painter benchmark ran seven rounds, so encoding is faster."
        )
        self.commit(message)
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn('claims "encoding is faster" without an end-to-end measurement', output)

    def test_speed_claim_is_not_waived(self) -> None:
        """Passing --claim-reason cannot waive an encode speed claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: paint maps once\n\nEncoding is faster.")
        rc, output = self.check("--claim-reason", "helper benchmark")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)

    def test_speed_claim_with_fps_passes(self) -> None:
        """An encode speed claim with an fps figure passes claim-scope."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: paint maps once\n\nEncoding runs at 120 fps, not 100 fps.")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: claim-scope rc: 0", output)

    def test_error_scope_claim_fails(self) -> None:
        """An error-handling subject without a scope sentence fails claim-scope."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: propagate write errors")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn('subject claims error handling ("propagate write errors")', output)

    def test_error_scope_claim_is_not_waived(self) -> None:
        """Passing --claim-reason cannot waive an error-handling scope claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: propagate write errors")
        rc, output = self.check("--claim-reason", "only one path changed")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)

    def test_error_scope_remain_outside_passes(self) -> None:
        """A body sentence that leaves close-path errors outside passes claim-scope."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit(
            "avfilter/vf_x: propagate write errors\n\n"
            "Errors from the close path remain outside this change."
        )
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: claim-scope rc: 0", output)

    def test_doc_wrap_fails(self) -> None:
        """An added doc line that ends a filled paragraph line early fails doc-wrap."""
        self.write("doc/encoders.texi", WRAP_TEXT)
        self.commit("doc/encoders: describe qpfile")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-wrap rc: 1", output)
        self.assertIn('doc/encoders.texi:6: "both. Internal" ends a filled paragraph', output)

    def test_doc_wrap_waiver_passes(self) -> None:
        """A non-blank --doc-reason waives the doc-wrap step and prints the reason."""
        self.write("doc/encoders.texi", WRAP_TEXT)
        self.commit("doc/encoders: describe qpfile")
        rc, output = self.check("--doc-reason", "the break keeps a table aligned")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-wrap rc: 0\nwaived: the break keeps a table aligned", output)

    def test_doc_wrap_blank_waiver_fails(self) -> None:
        """A whitespace-only --doc-reason does not waive the doc-wrap step."""
        self.write("doc/encoders.texi", WRAP_TEXT)
        self.commit("doc/encoders: describe qpfile")
        rc, output = self.check("--doc-reason", "  ")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: doc-wrap rc: 1", output)

    def test_doc_wrap_filled_or_unchanged_passes(self) -> None:
        """A filled paragraph passes, and so does an early break the range did not add."""
        self.write("doc/encoders.texi", WRAP_TEXT.replace("both. Internal\n", "both.\n"))
        self.commit("doc/encoders: describe qpfile")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-wrap rc: 0", output)
        self.write("doc/encoders.texi", WRAP_TEXT)
        self.commit("doc/encoders: describe qpfile scaling")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("doc/encoders.texi", WRAP_TEXT.replace("full layout", "full-size layout"))
        self.commit("doc/encoders: name the layout")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: doc-wrap rc: 0", output)

    def test_test_program_fails(self) -> None:
        """A new lib*/tests program registered in its Makefile fails the test-program step."""
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.write("libavcodec/Makefile", "TESTPROGS += x_grain\n")
        self.commit("avcodec/tests: add x_grain")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: test-program rc: 1", output)
        self.assertIn("libavcodec/tests/x_grain.c: new TESTPROGS program", output)

    def test_test_program_waiver_passes(self) -> None:
        """A non-blank --test-program-reason waives the test-program step and prints it."""
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.write("libavcodec/Makefile", "TESTPROGS += x_grain\n")
        self.commit("avcodec/tests: add x_grain")
        rc, output = self.check("--test-program-reason", "no sample reaches the payload")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: test-program rc: 0\nwaived: no sample reaches the payload", output)

    def test_test_program_continuation_line_fails(self) -> None:
        """A new program added to a backslash-continued TESTPROGS list fails the step."""
        self.write("libavcodec/Makefile", "TESTPROGS = golomb \\\n            rangecoder\n")
        self.commit("avcodec: list test programs")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.write(
            "libavcodec/Makefile",
            "TESTPROGS = golomb \\\n            x_grain \\\n            rangecoder\n",
        )
        self.commit("avcodec/tests: add x_grain")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("libavcodec/tests/x_grain.c: new TESTPROGS program", output)

    def test_test_program_other_makefile_entry_passes(self) -> None:
        """An OBJS entry or a comment naming the new file's stem is not a registration."""
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.write("libavcodec/Makefile", "OBJS += x_grain.o\n# x_grain needs a sample\n")
        self.commit("avcodec/tests: add x_grain")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: test-program rc: 0", output)

    def test_unregistered_test_file_passes(self) -> None:
        """A new lib*/tests C file without a head library Makefile passes."""
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.commit("avcodec/tests: add x_grain")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: test-program rc: 0", output)

    def test_existing_test_program_edit_passes(self) -> None:
        """Editing a program and Makefile line that exist at base is not a new program."""
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 0;\n}\n")
        self.write("libavcodec/Makefile", "TESTPROGS += x_grain\n")
        self.commit("avcodec/tests: add x_grain")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavcodec/tests/x_grain.c", "int main(void)\n{\n    return 1;\n}\n")
        self.write("libavcodec/Makefile", "TESTPROGS += golomb x_grain\n")
        self.commit("avcodec/tests: extend x_grain")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: test-program rc: 0", output)

    def test_docstrings_finding_fails(self) -> None:
        """An unwaived docstrings engine finding fails its step and the overall run."""
        self.engine_rc = 1
        self.engine_output = DOCSTRING_FINDING
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: docstrings rc: 1", output)
        self.assertIn("libavfilter/vf_x.c:5 ff_alpha", output)
        self.assertIn(DOCSTRING_ADVICE, output)

    def test_docstrings_waiver_passes(self) -> None:
        """A non-blank --docstring-reason waives a docstrings finding in the report."""
        self.engine_rc = 1
        self.engine_output = DOCSTRING_FINDING
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit()
        rc, output = self.check("--docstring-reason", "internal static wrappers")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: docstrings rc: 0\nwaived: internal static wrappers", output)
        self.assertIn("libavfilter/vf_x.c:5 ff_alpha", output)

    def test_renamed_two_hunk_scope_claim_passes(self) -> None:
        """A renamed file with two source hunks satisfies a multi-site scope claim."""
        grown = "".join(f"int ff_f{i}(void)\n{{\n    return {i};\n}}\n\n" for i in range(8))
        self.write("libavfilter/vf_x.c", grown)
        self.commit("avfilter/vf_x: grow fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("mv", "libavfilter/vf_x.c", "libavfilter/vf_y.c")
        updated = grown.replace("return 1;", "return 11;").replace("return 6;", "return 66;")
        self.write("libavfilter/vf_y.c", updated)
        self.commit("avfilter/vf_y: update both functions")
        _, output = self.check()
        self.assertIn("step: claim-scope rc: 0", output)

    def test_renamed_single_hunk_scope_claim_fails(self) -> None:
        """A renamed file with one source hunk still fails a multi-site scope claim."""
        grown = "".join(f"int ff_f{i}(void)\n{{\n    return {i};\n}}\n\n" for i in range(8))
        self.write("libavfilter/vf_x.c", grown)
        self.commit("avfilter/vf_x: grow fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("mv", "libavfilter/vf_x.c", "libavfilter/vf_y.c")
        self.write("libavfilter/vf_y.c", grown.replace("return 1;", "return 11;"))
        self.commit("avfilter/vf_y: clamp y in both loops")
        _, output = self.check()
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn("changes 1 source hunk", output)

    def test_quoted_source_deletion_scope_claim_fails(self) -> None:
        """Deleting a quoted non-ASCII source path in one hunk fails a multi-site claim."""
        self.write("libavfilter/café.c", "int ff_old(void)\n{\n    return 0;\n}\n")
        self.commit("avfilter/café: add fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("rm", "-q", "libavfilter/café.c")
        self.commit("avfilter/café: drop both functions")
        _, output = self.check()
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn("changes 1 source hunk", output)

    def test_unverified_claim_with_waived_scope_claim_fails(self) -> None:
        """Waiving a scope claim still fails when the commit makes a blanket claim."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: clamp y in both loops\n\nPasses all FATE tests.")
        rc, output = self.check("--claim-reason", "one macro")
        self.assertEqual(rc, 1, output)
        self.assertIn("step: claim-scope rc: 1", output)
        self.assertIn('claims "Passes all FATE tests"', output)
        self.assertIn("waived: one macro", output)

    def test_claim_scope_commit_cap(self) -> None:
        """Exceeding MAX_CLAIM_COMMITS fails the claim-scope step with rc 2."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: first update")
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 3"))
        self.commit("avfilter/vf_x: second update")
        with unittest.mock.patch.object(upstream_lint, "MAX_CLAIM_COMMITS", 1):
            _, output = self.check()
        self.assertIn("step: claim-scope rc: 2", output)
        self.assertIn("MAX_CLAIM_COMMITS=1: 2", output)

    def test_fate_missing_decoder_fails(self) -> None:
        """A committed lavfi video dependency gap fails without losing other steps."""
        self.write("tests/fate/filter-video.mak", FATE_RED)
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: fate-deps rc: 1", output)
        for name in ("pre-commit", "commit-msg", "patcheck", "developer.texi"):
            self.assertIn(f"step: {name} rc: 0", output)

    def test_fate_decoder_present_passes(self) -> None:
        """A committed registration with both dependencies passes the pipeline."""
        self.write(
            "tests/fate/filter-video.mak",
            FATE_RED.replace("NULL_MUXER", "WRAPPED_AVFRAME_DECODER NULL_MUXER"),
        )
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: fate-deps rc: 0", output)

    def test_fate_missing_allfilters_is_error(self) -> None:
        """A needed source catalog missing at head fails the step explicitly."""
        self.git("rm", "libavfilter/allfilters.c")
        self.write("tests/fate/filter-video.mak", FATE_RED)
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: fate-deps rc: 2", output)
        self.assertIn("libavfilter/allfilters.c", output)
        self.assertIn("FATE dependencies: wrapped_avframe decoder", output)

    def test_fate_deleted_dependency_continuation(self) -> None:
        """Deleting a dependency continuation blocks until the guard is restored."""
        path = "tests/fate/filter-video.mak"
        good = (
            "FATE_X-$(call ALLYES, LAVFI_INDEV \\\n"
            " WRAPPED_AVFRAME_DECODER \\\n NULL_MUXER) += fate-x\n"
            "fate-x: CMD = -f lavfi -i testsrc2\n"
        )
        self.write(path, good)
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(path, good.replace(" WRAPPED_AVFRAME_DECODER \\\n", ""))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: fate-deps rc: 1", output)
        self.write(path, good)
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)

    def test_fate_macro_catalog_and_missing_file(self) -> None:
        """Head macro definitions grant only ALLYES wrappers and missing catalogs fail."""
        self.write("tests/Makefile", "ALLYES = $(strip $(1))\nVIDEO = $(call ALLYES, $(1))\n")
        video_makefile = (
            "FATE_X-$(call VIDEO, LAVFI_INDEV WRAPPED_AVFRAME_DECODER) += fate-x\n"
            "fate-x: CMD = -f lavfi -i testsrc2\n"
        )
        self.write(
            "tests/fate/filter-video.mak",
            video_makefile,
        )
        indirect_makefile = (
            "GUARD = $(call VIDEO, LAVFI_INDEV WRAPPED_AVFRAME_DECODER)\n"
            "FATE_Y-$(GUARD) += fate-y\nfate-y: CMD = -f lavfi -i testsrc2\n"
        )
        self.write(
            "tests/fate/other.mak",
            indirect_makefile,
        )
        self.commit()
        with unittest.mock.patch.object(upstream_lint, "_git", wraps=upstream_lint._git) as git:
            rc, output = self.check()
        self.assertEqual(rc, 0, output)
        catalog_reads = [
            call for call in git.call_args_list if call.args[-1].endswith(":tests/Makefile")
        ]
        self.assertEqual(len(catalog_reads), 1)
        self.git("rm", "tests/Makefile")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: fate-deps rc: 2", output)
        self.assertIn("tests/Makefile", output)

    def test_bad_subject_fails_without_skipping_other_checks(self):
        """The base commit-message checker rejects the planted bad subject."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("fix stuff")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: commit-msg rc: 1", output)
        self.assertIn("step: developer.texi rc: 0", output)

    def test_added_tab_and_trailing_space_fail(self):
        """Added C whitespace defects fail even if all upstream tools exit zero."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("    return 1;", "\treturn 2; "))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("TAB character", output)
        self.assertIn("trailing whitespace", output)

    def test_inherited_tab_is_nonfailing_and_listed(self):
        """A tabbed line inherited from the base stays informational."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("    return 1;", "\treturn 1;"))
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(
            "libavfilter/vf_x.c", "/* updated */\n" + self.git("show", "HEAD:libavfilter/vf_x.c")
        )
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("pre-existing (untouched)", output)

    def test_only_c_and_h_added_lines_are_checked(self):
        """Non-C files and removed violations do not enter mechanical rules."""
        self.write("notes.txt", "\ttrailing \n")
        self.write("libavfilter/vf_x.h", "int ff_value(void);\n")
        self.commit()
        self.assertEqual(self.check()[0], 0)

    def test_base_tools_and_config_cannot_be_replaced_by_head(self):
        """A branch cannot silently substitute its own upstream policy files."""
        self.write(upstream_lint.CONFIG, "broken: branch config\n")
        self.write("tools/check_commit_msg.sh", "exit 1\n")
        self.write("tools/patcheck", "exit 1\n")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertEqual(self.hook_calls[0][1], FAKE_CONFIG)
        self.assertEqual(self.hook_calls[0][0][-3], self.base)

    def test_precommit_failure_still_collects_other_steps(self):
        """A hook failure retains its rc and cannot short-circuit later checks."""
        self.hook_rc = 7
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: pre-commit rc: 7", output)
        self.assertIn("step: developer.texi rc: 0", output)

    def test_precommit_timeout_still_collects_other_steps(self):
        """A bounded hook timeout retains rc 124 while later checks still run."""
        self.hook_rc = 124
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: pre-commit rc: 124", output)
        self.assertIn("step: developer.texi rc: 0", output)

    def test_patcheck_zero_exit_with_added_hint_fails(self):
        """A zero process exit cannot hide an allow-listed double semicolon."""
        program = (
            "#!/bin/sh\ncat > patcheck.stdout\nprintf 'double ;\\npatcheck.stdout:23:+bad();;\\n'\n"
        )
        self.write(
            "tools/patcheck",
            program,
        )
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1;", "return 1;;"))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: commit-msg rc: 0", output)
        self.assertIn("step: patcheck rc: 1\ncommand rc: 0", output)
        self.assertFalse((self.root / "patcheck.stdout").exists())

    def test_patcheck_zero_exit_with_printf_hint_passes(self):
        """Added printf output stays a review hint in the complete report."""
        program = (
            "#!/bin/sh\ncat > patcheck.stdout\n"
            "printf 'Please use av_log\\npatcheck.stdout:23:+printf(\"hello\");\\n'\n"
        )
        self.write(
            "tools/patcheck",
            program,
        )
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavfilter/vf_x.c", SOURCE.replace("    return 1;", '    printf("hello");'))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: patcheck rc: 0\ncommand rc: 0", output)
        self.assertIn("hint (review): Please use av_log: patcheck.stdout:23:+printf", output)

    def test_deletion_only_does_not_select_inherited_violation(self):
        """Deleting a clean neighbor does not promote an old TAB to a finding."""
        self.write("libavfilter/vf_x.c", "\tint inherited;\n\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavfilter/vf_x.c", "\tint inherited;\n")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("pre-existing (untouched)", output)

    def test_added_header_tab_fails(self):
        """Headers enter the mechanical scope just like C sources."""
        self.write("libavfilter/vf_x.h", "\tint ff_value(void);\n")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("libavfilter/vf_x.h:1: TAB character", output)

    def test_paths_with_spaces_are_checked(self):
        """NUL-separated path discovery avoids parsing quoted diff headers."""
        self.write("libavfilter/with spaces.c", "\tint ff_value;\n")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("with spaces.c:1: TAB character", output)

    def test_fixer_edits_fail_and_discard_index_and_new_files(self):
        """A zero-exit fixer still fails and leaves the original clean checkout."""

        def modify(cwd):
            (cwd / "libavfilter/vf_x.c").write_text("changed\n", encoding="utf-8")
            (cwd / "new-file.txt").write_text("generated\n", encoding="utf-8")
            self.git("-C", str(cwd), "add", "libavfilter/vf_x.c")

        self.hook_effect = modify
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("fixer modified files", output)
        self.assertEqual((self.root / "libavfilter/vf_x.c").read_text(encoding="utf-8"), SOURCE)
        self.assertFalse((self.root / "new-file.txt").exists())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_fixer_edits_discard_after_command_error(self):
        """The finally path discards files if launching or waiting for a hook fails."""

        def modify(cwd):
            (cwd / "libavfilter/vf_x.c").write_text("changed\n", encoding="utf-8")
            raise OSError("planted hook error")

        self.hook_effect = modify
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: pre-commit rc: 2", output)
        self.assertIn("step: developer.texi rc: 0", output)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_hook_ignored_artifact_never_touches_source_tree(self):
        """Ignored hook output stays inside the discarded detached worktree."""
        self.write(".gitignore", "ignored.out\n")
        self.commit()
        worktrees = self.git("worktree", "list", "--porcelain")
        hook_trees = []

        def modify(cwd):
            hook_trees.append(cwd)
            (cwd / "ignored.out").write_text("generated\n", encoding="utf-8")

        self.hook_effect = modify
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertFalse((self.root / "ignored.out").exists())
        self.assertNotEqual(hook_trees[0], self.root)
        self.assertFalse(hook_trees[0].exists())
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees)

    def test_deleted_c_path_passes(self):
        """Deleted C files count toward the cap without requiring a head blob."""
        self.git("rm", "libavfilter/vf_x.c")
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)

    def test_path_cap_boundary_passes(self):
        """Exactly the permitted number of changed paths still runs the hooks."""
        self.write("one.txt", "one\n")
        self.commit()
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
            rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertEqual(len(self.hook_calls), 1)

    def test_deadline_exhausted_during_hook_cleans_worktree(self):
        """Hook-budget exhaustion preserves cleanup time and fails the run."""
        worktrees = self.git("worktree", "list", "--porcelain")
        now = upstream_lint.time.monotonic()
        elapsed = [0]
        hook_trees = []

        def expire(cwd):
            hook_trees.append(cwd)
            elapsed[0] = upstream_lint.RUN_TIMEOUT - upstream_lint.CLEANUP_TIMEOUT

        self.hook_effect = expire
        with unittest.mock.patch.object(
            upstream_lint.time, "monotonic", side_effect=lambda: now + elapsed[0]
        ):
            rc, output = self.check()
        self.assertNotEqual(rc, 0, output)
        self.assertIn("overall deadline exhausted", output)
        self.assertFalse(hook_trees[0].exists())
        self.assertEqual(self.git("worktree", "list", "--porcelain"), worktrees)

    def test_over_cap_paths_refused(self):
        """Exceeding the path cap refuses the run before any hook executes."""
        self.write("one.txt", "one\n")
        self.write("two.txt", "two\n")
        self.commit()
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1, create=True):
            rc, output = self.check()
        self.assertEqual(rc, 2, output)
        self.assertIn("changed paths exceed MAX_PATHS=1", output)
        self.assertEqual(self.hook_calls, [])

    def test_deadline_exhausted_refuses_run(self):
        """An exhausted overall budget fails before launching a subprocess."""
        with unittest.mock.patch.object(upstream_lint, "RUN_TIMEOUT", 0, create=True):
            rc, output = self.check()
        self.assertEqual(rc, 2, output)
        self.assertIn("overall deadline exhausted", output)
        self.assertEqual(self.hook_calls, [])

    def test_dirty_worktree_index_and_untracked_files_are_refused(self):
        """All dirty states fail before hooks run and preserve the user's text."""
        for state in ("unstaged", "staged", "untracked"):
            with self.subTest(state=state):
                name = "new.txt" if state == "untracked" else "libavfilter/vf_x.c"
                self.write(name, "user edit\n")
                if state == "staged":
                    self.git("add", name)
                rc, output = self.check()
                self.assertEqual(rc, 2, output)
                self.assertIn("dirty tree refused", output)
                self.assertEqual(self.hook_calls, [])
                self.assertEqual((self.root / name).read_text(encoding="utf-8"), "user edit\n")

    def test_different_head_is_refused_before_hooks(self):
        """Hooks cannot inspect a checkout that differs from the requested head."""
        self.write("notes.txt", "new\n")
        self.commit()
        rc, output = self.check("--head", self.base)
        self.assertEqual(rc, 2)
        self.assertIn("checked-out HEAD", output)
        self.assertEqual(self.hook_calls, [])

    def test_missing_tool_is_collected_and_report_is_written(self):
        """A missing base tool fails its own step and still produces a full report."""
        self.git("rm", "tools/patcheck")
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        report = self.root.parent / "reports" / "report.txt"
        rc, output = self.check("--report", str(report))
        self.assertEqual(rc, 1)
        self.assertIn("step: patcheck rc: 2", output)
        self.assertIn("step: developer.texi rc: 0", output)
        self.assertEqual(report.read_text(encoding="utf-8"), output)


class RealToolsTest(FixtureTest):
    """Replay the required planted cases with the actual upstream base tools.

    Pre-commit itself stays stubbed under the implementation lane restriction;
    no hook repositories are fetched and no network-dependent tests are needed.
    The dispatcher runs the real upstream gate, including remote hooks.
    """

    def setUp(self) -> None:
        """Copy upstream files at its pinned HEAD, or name the missing source."""
        if UPSTREAM is None:
            self.skipTest("UPSTREAM_TREE unset; real upstream fixtures require an FFmpeg checkout")
        if not UPSTREAM.is_dir():
            self.skipTest(f"upstream fixture source unavailable: {UPSTREAM}")
        super().setUp()
        self.upstream_head = subprocess.run(  # nosec B603 B607 - read-only revision lookup.
            ["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
            env=isolated_git_environment(),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
        for name in (upstream_lint.CONFIG, "tools/check_commit_msg.sh", "tools/patcheck"):
            result = subprocess.run(  # nosec B603 B607 - read-only git show, fixed source paths.
                ["git", "-C", str(UPSTREAM), "show", f"{self.upstream_head}:{name}"],
                env=isolated_git_environment(),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            self.write(name, result.stdout)
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()

    def test_added_tab_fails(self):
        """An added C TAB fails using real upstream tools plus mechanical rules."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("    return 1;", "\treturn 2;"))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("TAB character", output)

    def test_added_trailing_whitespace_fails(self):
        """Added trailing whitespace fails with the actual base's patcheck."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1;", "return 2; "))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("trailing whitespace", output)

    def test_bad_subject_fails(self):
        """The real upstream subject checker rejects 'fix stuff'."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("fix stuff")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertRegex(output, r"step: commit-msg rc: [1-9]")

    def test_clean_commit_passes(self):
        """The requested area-prefixed subject and clean C change pass."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update y")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)

    def test_inherited_tab_passes_and_is_listed(self):
        """A base TAB outside added lines stays informational with real tools."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("    return 1;", "\treturn 1;"))
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavfilter/vf_x.c", "\n" + self.git("show", "HEAD:libavfilter/vf_x.c"))
        self.commit()
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("pre-existing (untouched)", output)


class RunnerTest(unittest.TestCase):
    """Exercise real subprocess deadlines and byte-preserving Git output."""

    def test_git_result_rejects_timeout_with_zero_exit(self) -> None:
        """A timed-out Git result is refused even if the child raced to exit zero."""
        result = upstream_lint.RunResult(("git", "show"), 0, "partial", timed_out=True)
        with (
            unittest.mock.patch.object(upstream_lint, "_run", return_value=result),
            self.assertRaisesRegex(RuntimeError, r"rc=0.*timed out"),
        ):
            upstream_lint._git_result(Path.cwd(), "show", "HEAD:config")

    def test_non_allow_listed_executable_refused(self) -> None:
        """Unknown executable basenames return rc 2 without invoking Popen."""
        with unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen:
            popen.return_value.__enter__.return_value.communicate.return_value = (b"", None)
            result = upstream_lint._run(["/unused/not-allowed"], Path.cwd())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.started)
        self.assertIn("executable refused", result.stdout)
        popen.assert_not_called()
        self.assertIsInstance(result, upstream_lint.RunResult)
        self.assertEqual(result.args, ("/unused/not-allowed",))

    def test_source_has_no_completed_process_token(self) -> None:
        """The runner uses its own result type throughout its source."""
        source = Path(upstream_lint.__file__).read_text(encoding="utf-8")
        self.assertNotIn("CompletedProcess", source)

    def test_result_is_frozen_and_slotted(self) -> None:
        """Command results cannot mutate or acquire arbitrary attributes."""
        result = upstream_lint.RunResult(("git",), 0, "ok")
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            result.returncode = 1

    def test_descendant_pipe_timeout_is_reported(self) -> None:
        """A second timeout retains partial output and returns rc 124."""
        argv = ["git", "--version"]
        for partial, expected in ((b"partial\xff", "partial\ufffd"), (None, "initial")):
            with self.subTest(partial=partial):
                process = unittest.mock.MagicMock(pid=123)
                process.communicate.side_effect = [
                    subprocess.TimeoutExpired(argv, 1, output=b"initial"),
                    subprocess.TimeoutExpired(argv, upstream_lint.REAP_TIMEOUT, output=partial),
                ]
                with (
                    unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen,
                    unittest.mock.patch.object(upstream_lint.os, "killpg") as killpg,
                ):
                    popen.return_value.__enter__.return_value = process
                    result = upstream_lint._run(argv, Path.cwd(), timeout=1)
                self.assertIsInstance(result, upstream_lint.RunResult)
                self.assertEqual(result.returncode, 124)
                self.assertEqual(result.args, tuple(argv))
                self.assertIn(expected, result.stdout)
                self.assertIn("command timed out (descendant kept the pipe open)", result.stdout)
                self.assertEqual(process.communicate.call_count, 2)
                self.assertEqual(
                    process.communicate.call_args.kwargs["timeout"], upstream_lint.REAP_TIMEOUT
                )
                killpg.assert_called_once_with(process.pid, upstream_lint.signal.SIGKILL)

    def test_child_environment_excludes_git_overrides(self) -> None:
        """Caller Git overrides cannot redirect subprocess repositories or config."""
        overrides = dict.fromkeys(GIT_ENVIRONMENT_NAMES, "planted repository override")
        overrides |= dict.fromkeys(
            ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"), "fixture"
        )
        overrides |= {"GIT_CONFIG_KEY_0": "fixture.key", "GIT_CONFIG_VALUE_0": "fixture"}
        process = unittest.mock.MagicMock()
        process.communicate.return_value = (b"ok\n", None)
        process.returncode = 0
        with (
            unittest.mock.patch.dict(os.environ, overrides),
            unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen,
        ):
            popen.return_value.__enter__.return_value = process
            result = upstream_lint._run(["git", "--version"], Path.cwd())
            environment = popen.call_args.kwargs["env"]
            self.assertEqual(environment["PATH"], os.environ["PATH"])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(overrides.keys().isdisjoint(environment))
        self.assertEqual(environment["PRE_COMMIT_NO_CONCURRENCY"], "1")

    def test_command_environment_above_bound_is_refused(self) -> None:
        """An oversized fixture environment fails before any command starts."""
        environment = {f"FIXTURE_{i}": str(i) for i in range(upstream_lint.MAX_ENV_ENTRIES)}
        environment["REQUIRED_LAST"] = "present"
        with self.assertRaises(ValueError) as caught:
            upstream_lint._command_environment(environment, Path.cwd())
        self.assertIn(f"MAX_ENV_ENTRIES={upstream_lint.MAX_ENV_ENTRIES}", str(caught.exception))
        self.assertIn(str(upstream_lint.MAX_ENV_ENTRIES + 1), str(caught.exception))

    def test_command_environment_exact_bound_preserves_last_entry(self) -> None:
        """The exact environment bound accepts and preserves the final required entry."""
        environment = {f"FIXTURE_{i}": str(i) for i in range(upstream_lint.MAX_ENV_ENTRIES - 1)}
        environment["REQUIRED_LAST"] = "present"
        result = upstream_lint._command_environment(environment, Path.cwd())
        self.assertEqual(result["REQUIRED_LAST"], "present")
        self.assertEqual(len(result), upstream_lint.MAX_ENV_ENTRIES + 2)

    def test_command_environment_overflow_returns_usage_error(self) -> None:
        """The runner reports environment overflow as usage error without spawning."""
        environment = {f"FIXTURE_{i}": str(i) for i in range(upstream_lint.MAX_ENV_ENTRIES + 1)}
        command_environment = upstream_lint._command_environment
        with (
            unittest.mock.patch.object(
                upstream_lint,
                "_command_environment",
                side_effect=lambda source, cwd: command_environment(environment, cwd),
            ),
            unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen,
        ):
            result = upstream_lint._run(["git", "--version"], Path.cwd())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(
            result.stdout,
            f"command environment exceeds MAX_ENV_ENTRIES={upstream_lint.MAX_ENV_ENTRIES}: "
            f"{len(environment)}",
        )
        popen.assert_not_called()

    def test_fixture_git_uses_isolated_environment(self) -> None:
        """Fixture Git receives the shared isolation helper's environment."""
        fixture = FixtureTest()
        fixture.root = Path.cwd()
        environment = {"PATH": os.environ["PATH"]}
        with (
            unittest.mock.patch(
                __name__ + ".isolated_git_environment", return_value=environment
            ) as isolated,
            unittest.mock.patch.object(subprocess, "run") as run,
        ):
            fixture.git("status")
        isolated.assert_called_once_with()
        self.assertEqual(run.call_args.kwargs["env"], environment)

    def test_command_timeout_uses_remaining_overall_budget(self):
        """A later command shares the deadline rather than restarting its budget."""
        process = unittest.mock.MagicMock()
        process.communicate.return_value = (b"ok\n", None)
        process.returncode = 0
        token = upstream_lint._DEADLINE.set(100)
        self.addCleanup(upstream_lint._DEADLINE.reset, token)
        with (
            unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen,
            unittest.mock.patch.object(upstream_lint.time, "monotonic", return_value=75),
        ):
            popen.return_value.__enter__.return_value = process
            result = upstream_lint._run(["git", "--version"], Path.cwd(), timeout=60)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(process.communicate.call_args.kwargs["timeout"], 15)

    def test_timeout_exit_race_preserves_real_status(self):
        """A process gone before killpg is reaped with its actual return code."""
        process = unittest.mock.MagicMock(pid=123)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["git"], 1),
            (b"finished\n", None),
        ]
        process.returncode = 7
        with (
            unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen,
            unittest.mock.patch.object(upstream_lint.os, "killpg", side_effect=ProcessLookupError),
        ):
            popen.return_value.__enter__.return_value = process
            result = upstream_lint._run(["git", "--version"], Path.cwd(), timeout=1)
        self.assertEqual(result.returncode, 7)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, "finished\n")
        self.assertEqual(process.communicate.call_count, 2)

    def test_completed_command_is_not_timed_out(self) -> None:
        """An ordinary completed command retains a false timeout marker."""
        process = unittest.mock.MagicMock()
        process.communicate.return_value = (b"finished\n", None)
        process.returncode = 7
        with unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen:
            popen.return_value.__enter__.return_value = process
            result = upstream_lint._run(["git", "--version"], Path.cwd(), timeout=1)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.timed_out)
        self.assertEqual(process.communicate.call_count, 1)

    def test_timeout_returns_failure(self):
        """A planted slow subprocess is killed and reported with rc 124."""
        with tempfile.TemporaryDirectory() as directory:
            result = upstream_lint._run(
                ["bash", "-c", "sleep 5"],
                Path(directory),
                timeout=0.05,
            )
        self.assertEqual(result.returncode, 124)
        self.assertIn("command timed out", result.stdout)

    def test_carriage_returns_are_preserved(self):
        """Text-mode newline normalization cannot hide trailing CR violations."""
        with tempfile.TemporaryDirectory() as directory:
            result = upstream_lint._run(
                ["bash", "-c", "printf 'line\\r\\n'"],
                Path(directory),
            )
        self.assertEqual(result.stdout, "line\r\n")

    def test_git_settings_applies_command_line_config(self) -> None:
        """Per-invocation -c settings expose values without persisting repository config."""
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            run_git(tree, "init", "-q", preserve_config=True)
            hooks = tree / "hooks-empty"
            hooks.mkdir()
            setting = f"core.hooksPath={hooks}"
            result = upstream_lint._run(
                ["git", "config", "--get", "core.hooksPath"],
                tree,
                git_settings=(setting,),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), str(hooks))
            missing = upstream_lint._run(["git", "config", "--get", "core.hooksPath"], tree)
            self.assertEqual(missing.returncode, 1)

    def test_git_settings_with_attr_source_prepend_globals(self) -> None:
        """Both keywords insert globals before the subcommand and leave the input argv intact."""
        argv = ["git", "status", "--porcelain"]
        original = list(argv)
        process = unittest.mock.MagicMock()
        process.communicate.return_value = (b"", None)
        process.returncode = 0
        with unittest.mock.patch.object(upstream_lint.subprocess, "Popen") as popen:
            popen.return_value.__enter__.return_value = process
            result = upstream_lint._run(
                argv,
                Path.cwd(),
                git_attr_source="deadbeef",
                git_settings=("core.hooksPath=/tmp/empty",),
            )
        self.assertEqual(argv, original)
        self.assertEqual(result.args[0], "git")
        status_index = result.args.index("status")
        for prefix in ("-c", "core.hooksPath=/tmp/empty", "--no-replace-objects"):
            self.assertIn(prefix, result.args)
        config_index = result.args.index("-c")
        attr_index = next(
            index for index, value in enumerate(result.args) if value.startswith("--attr-source=")
        )
        self.assertLess(config_index, status_index)
        self.assertLess(attr_index, status_index)

    def test_reap_timeout_pid_guards(self) -> None:
        """Prove _reap_timeout guards against invalid and current-group PIDs."""

        def run_with(pid: int | bool) -> tuple[unittest.mock.Mock, unittest.mock.Mock]:
            mock_killpg = unittest.mock.Mock()
            fake_process = unittest.mock.Mock(
                pid=pid,
                communicate=unittest.mock.Mock(return_value=(b"", None)),
                returncode=0,
            )
            with (
                unittest.mock.patch.object(upstream_lint, "_remaining", return_value=1.0),
                unittest.mock.patch.object(upstream_lint.os, "killpg", mock_killpg),
            ):
                result = upstream_lint._reap_timeout(fake_process, ["x"])
            self.assertEqual(result.returncode, 0)
            return mock_killpg, fake_process.kill

        for bad_pid in (0, 1, True):
            with self.subTest(bad_pid=bad_pid):
                mock_killpg, kill = run_with(bad_pid)
                mock_killpg.assert_not_called()
                kill.assert_not_called()

        with self.subTest(bad_pid=os.getpgrp()):
            mock_killpg, kill = run_with(os.getpgrp())
            mock_killpg.assert_not_called()
            kill.assert_called_once_with()

        good_pid = 4242 if os.getpgrp() != 4242 else 4243
        mock_killpg, kill = run_with(good_pid)
        mock_killpg.assert_called_once_with(good_pid, signal.SIGKILL)
        kill.assert_not_called()

        boundary_pid = 2
        mock_killpg, kill = run_with(boundary_pid)
        mock_killpg.assert_called_once_with(boundary_pid, signal.SIGKILL)
        kill.assert_not_called()


class PreCommitResolutionTest(unittest.TestCase):
    """Resolve portable pre-commit paths without executing hooks."""

    def test_environment_override_is_ignored(self) -> None:
        """An executable override cannot replace PATH discovery."""
        with (
            unittest.mock.patch.dict(
                os.environ, {"UPSTREAM_LINT_PRE_COMMIT": "/fixture/evil/pre-commit"}
            ),
            unittest.mock.patch(
                "shutil.which", return_value="/fixture/pipx/bin/pre-commit"
            ) as which,
        ):
            executable = upstream_lint._pre_commit()
        self.assertEqual(executable, "/fixture/pipx/bin/pre-commit")
        which.assert_called_once_with("pre-commit")

    def test_path_discovery_is_used_without_override(self) -> None:
        """PATH discovery supports user, pipx and virtual environment installs."""
        with unittest.mock.patch(
            "shutil.which", return_value="/fixture/pipx/bin/pre-commit"
        ) as which:
            executable = upstream_lint._pre_commit()
        self.assertEqual(executable, "/fixture/pipx/bin/pre-commit")
        which.assert_called_once_with("pre-commit")

    def test_missing_executable_fails_precommit_step(self) -> None:
        """Missing pre-commit on PATH produces a clear failure before launch."""
        tree = Path.cwd()
        with (
            unittest.mock.patch("shutil.which", return_value=None),
            unittest.mock.patch.object(upstream_lint, "_base_file", return_value=tree / "config"),
            unittest.mock.patch.object(upstream_lint, "_git", return_value=""),
            unittest.mock.patch.object(upstream_lint, "_run") as run,
        ):
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            step = upstream_lint._collect(
                "pre-commit", lambda: upstream_lint._precommit(tree, "base", "head", tree)
            )
        self.assertNotEqual(step.rc, 0)
        self.assertNotIn("UPSTREAM_LINT_PRE_COMMIT", step.output)
        self.assertIn("pre-commit", step.output)
        self.assertIn("PATH", step.output)
        run.assert_not_called()

    def test_resolved_absolute_path_is_allowed(self) -> None:
        """The executable allow-list accepts a discovered absolute path."""
        with unittest.mock.patch("shutil.which", return_value="/fixture/user/bin/pre-commit"):
            executable = upstream_lint._pre_commit()
        upstream_lint._validate_executable([executable, "run"])


def _isolate_test_tmpdir(case: unittest.TestCase) -> None:
    """Isolate temporary directories in a cleanup-managed folder per test."""
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    environment = unittest.mock.patch.dict(os.environ, {"TMPDIR": directory.name})
    case.addCleanup(environment.stop)
    environment.start()


class _CRulesBlankingMixin:
    """Shared exact-byte and newline-offset assertion for c-rules scratch blanking."""

    def assert_blanked(self, source: bytes, expected: bytes) -> None:
        """Assert exact scratch bytes, byte length and every newline offset."""
        blanked = upstream_lint._c_rules_blank(source, {b"av_fixture_tag"})
        self.assertEqual(blanked, expected)
        self.assertEqual(len(blanked), len(source))
        self.assertEqual(
            [index for index, byte in enumerate(blanked) if byte == 10],
            [index for index, byte in enumerate(source) if byte == 10],
        )


class _CRulesFixtureMixin:
    """Shared fixture source and symlink helpers for tree-backed c-rules tests."""

    def allocation_source(self) -> str:
        """Return a one-line allocation finding that overlaps a committed symlink hunk."""
        return (
            "void fixture(void) { unsigned char *buffer = av_malloc(8); "
            "unsigned char *dst = buffer ? buffer + 4 : NULL; "
            "if (!buffer) { fail(); } }\n"
        )

    def commit_linked_source(self, internal: bool = False) -> Path:
        """Commit a requested symlink with its target inside the disposable fixture parent."""
        target = self.root / "fixtures/linked.c" if internal else self.root.parent / "outside.c"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.allocation_source(), encoding="utf-8")
        source = self.root / "libavfilter/vf_x.c"
        source.unlink()
        source.symlink_to("before.c")
        self.commit("avfilter/vf_x: establish linked source")
        self.base = self.git("rev-parse", "HEAD").strip()
        source.unlink()
        source.symlink_to(target)
        self.commit()
        return target


@unittest.skipUnless(shutil.which(os.environ.get("SEMGREP") or "semgrep"), "semgrep not installed")
class CRulesScratchTest(_CRulesBlankingMixin, _CRulesFixtureMixin, FixtureTest):
    """Exercise scratch preparation and real scanner results on synthetic sources."""

    def setUp(self) -> None:
        """Isolate scanner temporary files in a cleanup-managed directory per test."""
        super().setUp()
        _isolate_test_tmpdir(self)

    def scan_source(self, source: str) -> upstream_lint.Step:
        """Commit one synthetic source and run only the real c-rules step."""
        self.write("libavfilter/vf_x.c", source)
        self.commit()
        return upstream_lint._c_rules(self.root, self.base, "HEAD", "")

    def _r5_allocation(self) -> bytes:
        """Return the fourth review's allocation finding without an attribute prefix."""
        return (
            b"void fixture(void) {\n"
            b"    unsigned char *buffer = av_malloc(8);\n"
            b"    unsigned char *dst = buffer ? buffer + 4 : NULL;\n"
            b"    if (!buffer) { fail(); }\n}\n"
        )

    def _r5_scan(
        self,
        source: bytes,
        unread: tuple[upstream_lint.UnreadWaiver, ...] = (),
        header_requested: bool = False,
    ) -> tuple[upstream_lint.Step, dict[str, bytes]]:
        """Run the real step on review-style touched paths and retain scratch bytes."""
        name = "libavfilter/vf_x.c"
        (self.root / name).write_bytes(source)
        paths = [name, "libavutil/attributes.h"] if header_requested else [name]
        captured: dict[str, bytes] = {}

        def capture(argv, cwd, data=None, timeout=60):
            """Capture every accepted scratch source before running the real scanner."""
            self.assertEqual(argv[:2], ["bash", str(upstream_lint.SEMGREP_SCAN)])
            (cwd / ".git").mkdir(exist_ok=True)
            captured.update({path: (cwd / path).read_bytes() for path in argv[5:]})
            return self.real_run(argv, cwd, data, timeout)

        with (
            unittest.mock.patch.object(
                upstream_lint,
                "_c_rules_touched",
                return_value={path: set(range(1, 100)) for path in paths},
            ),
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=capture),
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "", unread)
        return step, captured

    def _r5_assert_copy(self, source: bytes, copies: dict[str, bytes]) -> None:
        """Require the scanned function to retain exact bytes, length and newline offsets."""
        blanked = copies["libavfilter/vf_x.c"]
        self.assertEqual(blanked, source)
        self.assertEqual(len(blanked), len(source))
        self.assertEqual(
            [index for index, byte in enumerate(blanked) if byte in (10, 13)],
            [index for index, byte in enumerate(source) if byte in (10, 13)],
        )

    def _r6_assert_unread(self, source: bytes, waived: bool = False) -> None:
        """Require token splices to use the exact existing unread and dated-waiver report."""
        name = "libavfilter/vf_x.c"
        waiver = upstream_lint.UnreadWaiver(name, "fixture", "B", date(2026, 11, 23), False)
        step, copies = self._r5_scan(source, (waiver,) if waived else ())
        reason = "line splice inside code between two non-blank bytes is not supported"
        self.assertEqual(step.rc, 0 if waived else 1, step.output)
        self.assertEqual(copies, {})
        self.assertEqual(step.output.count(reason), 1)
        self.assertEqual(step.output.count(name), 3)
        self.assertIn(f"informational: {name}: {reason}", step.output)
        self.assertIn(f"unread: {name}:", step.output)
        self.assertIn(f"{'waived' if waived else 'no waiver'}: {name}:", step.output)
        self.assertNotIn("finding:", step.output)

    def _r6_assert_scanned(self, source: bytes, line: int, path_count: int = 1) -> None:
        """Require boundary controls to retain the exact scratch bytes and physical finding."""
        step, copies = self._r5_scan(source)
        self._r5_assert_copy(source, copies)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"finding: libavfilter/vf_x.c:{line}:", step.output)
        self.assertEqual(step.output.count("finding:"), 1)
        self.assertEqual(step.output.count("libavfilter/vf_x.c"), path_count)
        self.assertNotIn("unread:", step.output)
        self.assertNotIn("line splice inside code", step.output)

    def test_r6_identifier_splice(self) -> None:
        """The review's LF-split allocator is unread instead of silently hiding its finding."""
        source = self._r5_allocation().replace(b"av_malloc(", b"av_mal\\\nloc(")
        self._r6_assert_unread(source)

    def test_r6_identifier_crlf(self) -> None:
        """The review's CRLF-split allocator is unread with the same exact diagnostic."""
        source = self._r5_allocation().replace(b"av_malloc(", b"av_mal\\\r\nloc(")
        self._r6_assert_unread(source)

    def test_r6_two_splices(self) -> None:
        """The review's adjacent splice run is checked across both removed newlines."""
        source = self._r5_allocation().replace(b"av_malloc(", b"av_mal\\\n\\\nloc(")
        self._r6_assert_unread(source)

    def test_r6_code_token_boundaries(self) -> None:
        """Non-blank code splices also fail closed beside operators and noncode boundaries."""
        for suffix in (b"a+\\\nb;\n", b'"a"\\\n"b";\n', b"/* end */\\\nint x;\n"):
            with self.subTest(suffix=suffix):
                self._r6_assert_unread(self._r5_allocation() + suffix)

    def test_r6_token_splices_waived(self) -> None:
        """A live dated unread waiver applies to each of the three split allocator shapes."""
        for splice in (b"\\\n", b"\\\r\n", b"\\\n\\\n"):
            with self.subTest(splice=splice):
                source = self._r5_allocation().replace(b"av_malloc(", b"av_mal" + splice + b"loc(")
                self._r6_assert_unread(source, waived=True)

    def test_r6_attributes_token_splice(self) -> None:
        """An incidental header with a code-token splice contributes no words and is named once."""
        reason = "line splice inside code between two non-blank bytes is not supported"
        for splice in (b"\\\n", b"\\\r\n", b"\\\n\\\n"):
            with self.subTest(splice=splice):
                header = b"#define av_malloc\nint sp" + splice + b"lit;\n"
                (self.root / "libavutil/attributes.h").write_bytes(header)
                self.assertEqual(
                    upstream_lint._c_rules_attributes(self.root),
                    (set(), [f"informational: libavutil/attributes.h: {reason}"]),
                )
                step, copies = self._r5_scan(self._r5_allocation())
                self._r5_assert_copy(self._r5_allocation(), copies)
                self.assertEqual(step.rc, 1, step.output)
                self.assertEqual(step.output.count("libavutil/attributes.h"), 1)
                self.assertEqual(step.output.count(reason), 1)
                self.assertEqual(step.output.count("libavfilter/vf_x.c"), 1)
                self.assertIn("finding: libavfilter/vf_x.c:3:", step.output)

    def test_r6_requested_header_token_splice(self) -> None:
        """A requested unsupported header uses unread waivers without duplicating its reason."""
        name = "libavutil/attributes.h"
        reason = "line splice inside code between two non-blank bytes is not supported"
        (self.root / name).write_bytes(b"#define av_fixture_tag\nint sp\\\nlit;\n")
        waiver = upstream_lint.UnreadWaiver(name, "fixture", "B", date(2026, 11, 23), False)
        for unread in ((), (waiver,)):
            with self.subTest(unread=unread):
                step, copies = self._r5_scan(b"int clean;\n", unread, header_requested=True)
                self.assertEqual(step.rc, 0 if unread else 1, step.output)
                self.assertEqual(copies, {"libavfilter/vf_x.c": b"int clean;\n"})
                self.assertEqual(step.output.count(name), 3)
                self.assertEqual(step.output.count(reason), 1)
                self.assertIn(f"unread: {name}:", step.output)
                self.assertIn(f"{'waived' if unread else 'no waiver'}: {name}:", step.output)

    def test_r6_boundary_code_blank_before(self) -> None:
        """Boundary control: a blank before a code splice preserves bytes and findings."""
        source = self._r5_allocation().replace(
            b"    if (!buffer)", b"    a + \\\nb;\n    if (!buffer)"
        )
        self._r6_assert_scanned(source, 3)

    def test_r6_boundary_code_blank_after(self) -> None:
        """Boundary control: a blank after a code splice preserves bytes and findings."""
        source = self._r5_allocation().replace(
            b"    if (!buffer)", b"    a +\\\n b;\n    if (!buffer)"
        )
        self._r6_assert_scanned(source, 3)

    def test_r6_boundary_string_splice(self) -> None:
        """Boundary control: a token splice inside a string literal remains supported."""
        source = b'const char *s = "av_fix\\\nture_tag";\n' + self._r5_allocation()
        self._r6_assert_scanned(source, 5)

    def test_r6_boundary_character_splice(self) -> None:
        """Boundary control: a splice inside a character literal remains supported."""
        source = b"int c = 'a\\\n';\n" + self._r5_allocation()
        self._r6_assert_scanned(source, 5)

    def test_r6_boundary_block_comment_splice(self) -> None:
        """Boundary control: a token splice inside a block comment remains supported."""
        source = b"/* av_fix\\\nture_tag */\n" + self._r5_allocation()
        self._r6_assert_scanned(source, 5)

    def test_r6_boundary_define_splice(self) -> None:
        """Boundary control: a token splice inside a multiline define remains supported."""
        source = b"#define KEEP av_fix\\\nture_tag\n" + self._r5_allocation()
        self._r6_assert_scanned(source, 5)

    def test_r6_boundary_backslash_eof(self) -> None:
        """Boundary control: a final backslash without a newline is not a splice."""
        source = self._r5_allocation() + b"#define KEEP av_fixture_tag \\"
        self._r6_assert_scanned(source, 3)

    def test_r6_boundary_splice_eof(self) -> None:
        """Boundary control: a splice at EOF has no following byte and stays supported."""
        source = self._r5_allocation() + b"#define KEEP av_fixture_tag \\\n"
        self._r6_assert_scanned(source, 3)

    def test_r6_boundary_splice_offset_zero(self) -> None:
        """Boundary control: the review's leading splice has no preceding byte."""
        source = b"\\\n/* prefix */ #define KEEP av_fixture_tag\n" + self._r5_allocation()
        self._r6_assert_scanned(source, 5)

    def test_r6_boundary_unsplit_allocation(self) -> None:
        """Boundary control: an unsplit allocation reports the line-three finding and rc one."""
        self._r6_assert_scanned(self._r5_allocation(), 3)

    def test_r5_split_comment_opener(self) -> None:
        """Phase 2 hides commented allocation definitions across repeated LF and CRLF splices."""
        for newline in (b"\n", b"\r\n"):
            for count in (1, 3):
                with self.subTest(newline=newline, count=count):
                    header = b"/" + (b"\\" + newline) * count
                    header += b"*" + newline + b"#define av_malloc" + newline + b"*/" + newline
                    (self.root / "libavutil/attributes.h").write_bytes(header)
                    names, notices = upstream_lint._c_rules_attributes(self.root)
                    source = self._r5_allocation()
                    step, copies = self._r5_scan(source)
                    self._r5_assert_copy(source, copies)
                    self.assertEqual(names, set())
                    self.assertEqual(notices, [])
                    self.assertEqual(step.rc, 1, step.output)
                    self.assertIn("finding: libavfilter/vf_x.c:3:", step.output)

    def test_r5_boundary_plain_comment_opener(self) -> None:
        """Boundary control: an ordinary comment opener hides the allocation definition."""
        (self.root / "libavutil/attributes.h").write_bytes(b"/*\n#define av_malloc\n*/\n")
        self.assertEqual(upstream_lint._c_rules_attributes(self.root), (set(), []))
        source = self._r5_allocation()
        step, copies = self._r5_scan(source)
        self._r5_assert_copy(source, copies)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("finding: libavfilter/vf_x.c:3:", step.output)

    def test_r5_bare_cr_source_unread(self) -> None:
        """A bare CR directive boundary is unread and never reaches the scanner."""
        source = (b"#define KEEP av_fixture_tag\n" + self._r5_allocation()).replace(b"\n", b"\r")
        step, copies = self._r5_scan(source)
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(copies, {})
        self.assertEqual(step.output.count("bare CR line endings are not supported"), 1)
        self.assertIn("unread: libavfilter/vf_x.c:", step.output)
        self.assertIn("no waiver: libavfilter/vf_x.c:", step.output)

    def test_r5_bare_cr_source_waived(self) -> None:
        """The existing dated unread waiver applies to a bare CR source."""
        source = (b"#define KEEP av_fixture_tag\n" + self._r5_allocation()).replace(b"\n", b"\r")
        waiver = upstream_lint.UnreadWaiver(
            "libavfilter/vf_x.c", "fixture", "B", date(2026, 11, 23), False
        )
        step, copies = self._r5_scan(source, (waiver,))
        self.assertEqual(step.rc, 0, step.output)
        self.assertEqual(copies, {})
        self.assertEqual(step.output.count("bare CR line endings are not supported"), 1)
        self.assertIn("unread: libavfilter/vf_x.c:", step.output)
        self.assertIn("waived: libavfilter/vf_x.c:", step.output)

    def test_r5_bare_cr_attributes_header(self) -> None:
        """A bare CR attributes header contributes no words and is diagnosed exactly once."""
        (self.root / "libavutil/attributes.h").write_bytes(b"#define av_malloc\r")
        names, notices = upstream_lint._c_rules_attributes(self.root)
        self.assertEqual(names, set())
        self.assertEqual(
            notices,
            ["informational: libavutil/attributes.h: bare CR line endings are not supported"],
        )
        for requested in (False, True):
            with self.subTest(requested=requested):
                source = self._r5_allocation()
                step, copies = self._r5_scan(source, header_requested=requested)
                self._r5_assert_copy(source, copies)
                self.assertEqual(set(copies), {"libavfilter/vf_x.c"})
                self.assertEqual(step.rc, 1, step.output)
                self.assertEqual(step.output.count("libavutil/attributes.h:"), 1 + 2 * requested)
                self.assertEqual(step.output.count("bare CR line endings are not supported"), 1)
                self.assertIn("finding: libavfilter/vf_x.c:3:", step.output)

    def test_r5_boundary_supported_line_endings(self) -> None:
        """Boundary control: LF and CRLF directive boundaries retain the allocation finding."""
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                source = (b"#define KEEP token\n" + self._r5_allocation()).replace(b"\n", newline)
                step, copies = self._r5_scan(source)
                self._r5_assert_copy(source, copies)
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn("finding: libavfilter/vf_x.c:4:", step.output)
                self.assertNotIn("unread:", step.output)

    def escaping_header(self) -> Path:
        """Establish an unchanged escaping header in the disposable fixture base."""
        target = self.root.parent / "outside.h"
        target.write_bytes(b"#define av_fixture_tag\n")
        header = self.root / "libavutil/attributes.h"
        header.unlink()
        header.symlink_to(target)
        self.commit("avutil/attributes: establish escaping fixture header")
        self.base = self.git("rev-parse", "HEAD").strip()
        return target

    def assert_header_escape(self, step: upstream_lint.Step) -> None:
        """Require an unwaivable escape status and exactly one header diagnostic."""
        self.assertEqual(step.rc, 2, step.output)
        self.assertEqual(step.output.count("libavutil/attributes.h"), 1, step.output)
        self.assertIn("resolves outside the checked tree", step.output)

    def test_r3_escaping_header_keeps_finding(self) -> None:
        """An escaping header fails closed without suppressing another source's finding."""
        self.escaping_header()
        step = self.scan_source(self.allocation_source())
        self.assert_header_escape(step)
        self.assertIn("finding: libavfilter/vf_x.c:1:", step.output)

    def test_r3_escaping_header_cannot_be_waived(self) -> None:
        """Neither a finding reason nor a dated unread waiver excuses a header escape."""
        self.escaping_header()
        self.write("libavfilter/vf_x.c", self.allocation_source())
        self.commit()
        waiver = upstream_lint.UnreadWaiver(
            "libavutil/attributes.h", "fixture", "B", date(2026, 11, 23), False
        )
        step = upstream_lint._c_rules(self.root, self.base, "HEAD", "fixture", (waiver,))
        self.assert_header_escape(step)
        self.assertIn("finding: libavfilter/vf_x.c:1:", step.output)

    def test_r3_escaping_header_keeps_unread_status(self) -> None:
        """A header escape retains both findings and unread statuses for other requested sources."""
        self.escaping_header()
        name, other = "libavfilter/vf_unread.c", "libavfilter/vf_x.c"
        self.write(name, "int unread;\n")
        self.write(other, self.allocation_source())
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": [name, other]},
                "results": [
                    {
                        "path": other,
                        "check_id": "ffmpeg-null-ternary-after-allocation",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {"message": "fixture finding"},
                    }
                ],
                "errors": [{"type": "Syntax error", "path": name}],
            }
        )
        with (
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.command),
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_touched", return_value={name: {1}, other: {1}}
            ),
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assert_header_escape(step)
        self.assertIn(f"unread: {name}:", step.output)
        self.assertIn(f"no waiver: {name}:", step.output)
        self.assertIn(f"finding: {other}:1:", step.output)

    def test_r3_requested_directory_keeps_other_finding(self) -> None:
        """An unread directory does not suppress scanning an ordinary requested source."""
        self.write("libavfilter/vf_x.c", self.allocation_source())
        with unittest.mock.patch.object(
            upstream_lint, "_c_rules_touched", return_value={".": {1}, "libavfilter/vf_x.c": {1}}
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("unread: .:", step.output)
        self.assertIn("no waiver: .:", step.output)
        self.assertIn("finding: libavfilter/vf_x.c:1:", step.output)

    def test_d3_escaping_source_cannot_be_waived(self) -> None:
        """An escaping source is never read or scanned and neither waiver can excuse it."""
        target = self.commit_linked_source()
        waiver = upstream_lint.UnreadWaiver(
            "libavfilter/vf_x.c", "fixture", "B", date(2026, 11, 23), False
        )
        real_read = Path.read_bytes

        def read(path):
            """Reject any attempted read of the escaping requested source."""
            self.assertNotEqual(path.resolve(), target)
            return real_read(path)

        for reason, unread in (("", ()), ("fixture", ()), ("fixture", (waiver,))):
            with self.subTest(reason=reason, unread=unread):
                with unittest.mock.patch.object(Path, "read_bytes", read):
                    step = upstream_lint._c_rules(self.root, self.base, "HEAD", reason, unread)
                self.assertEqual(step.rc, 2, step.output)
                self.assertEqual(step.output.count("libavfilter/vf_x.c"), 1, step.output)
                self.assertIn("resolves outside the checked tree", step.output)
                self.assertNotIn("ffmpeg-null-ternary-after-allocation", step.output)

    def test_d3_escaping_source_keeps_other_findings(self) -> None:
        """Rejecting one source still scans and reports an ordinary requested source."""
        self.commit_linked_source()
        self.write("libavfilter/vf_other.c", self.allocation_source())
        self.commit()
        step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 2, step.output)
        self.assertEqual(step.output.count("libavfilter/vf_x.c"), 1, step.output)
        self.assertIn("resolves outside the checked tree", step.output)
        self.assertIn("finding: libavfilter/vf_other.c:1:", step.output)
        self.assertNotIn("finding: libavfilter/vf_x.c:", step.output)

    def test_d3_internal_source_symlink_is_scanned(self) -> None:
        """A requested symlink resolving inside the tree retains normal finding status."""
        self.commit_linked_source(internal=True)
        step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("finding: libavfilter/vf_x.c:1:", step.output)
        self.assertNotIn("resolves outside", step.output)

    def test_d3_escaping_header_is_not_read(self) -> None:
        """An escaping header is never read, contributes no attributes and fails the step closed."""
        target = self.escaping_header()
        source = b"av_fixture_tag int code;\n"
        self.write("libavfilter/vf_x.c", source.decode("ascii"))
        real_read = Path.read_bytes

        def read(path):
            """Reject any attempted read through the escaping attributes header."""
            self.assertNotEqual(path.resolve(), target)
            return real_read(path)

        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.object(Path, "read_bytes", read):
                prepared = upstream_lint._c_rules_scan_root(
                    self.root, ["libavfilter/vf_x.c"], directory
                )
            blanked = (prepared[0] / "libavfilter/vf_x.c").read_bytes()
        self.assertEqual(blanked, source)
        self.assertEqual(len(blanked), len(source))
        self.assertEqual(
            [index for index, byte in enumerate(blanked) if byte == 10],
            [index for index, byte in enumerate(source) if byte == 10],
        )
        self.assertEqual(len(prepared[1]), 1)
        self.assertIn("libavutil/attributes.h", prepared[1][0])
        self.assertIn("resolves outside the checked tree", prepared[1][0])
        with unittest.mock.patch.object(Path, "read_bytes", read):
            step = self.scan_source("void clean(void) { av_malloc(8); }\n")
        self.assert_header_escape(step)

    def test_r4_unsupported_source_classified_from_single_read(self) -> None:
        """Scratch preparation classifies an unsupported source without reading it a second time."""
        supported = "libavfilter/vf_ok.c"
        planted = "libavfilter/vf_x.c"
        self.write(supported, "int ok(void) { return 0; }\n")
        self.write(planted, "int unread(void) { return 0; }\n")
        self.commit()
        supported_path = self.root / supported
        planted_path = self.root / planted
        real_read = upstream_lint._c_rules_read_source
        counts: dict[Path, int] = {}

        def read_once(path: Path) -> bytes:
            """Fail only the first read of the planted source and delegate every other read."""
            counts[path] = counts.get(path, 0) + 1
            if path == planted_path and counts[path] == 1:
                raise ValueError("fixture unsupported")
            return real_read(path)

        with (
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_read_source", side_effect=read_once
            ),
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_scan", wraps=upstream_lint._c_rules_scan
            ) as scan,
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count(f"unread: {planted}:"), 1, step.output)
        self.assertIn(f"no waiver: {planted}:", step.output)
        scan_paths = scan.call_args.args[1]
        self.assertNotIn(planted, scan_paths)
        self.assertIn(supported, scan_paths)
        self.assertEqual(counts.get(supported_path), 1)
        self.assertEqual(counts.get(planted_path), 1)

    def test_unreadable_source_classified_unread_without_scan_failure(self) -> None:
        """Scratch preparation classifies an unreadable source unread and omits it from scanning."""
        supported = "libavfilter/vf_ok.c"
        planted = "libavfilter/vf_x.c"
        self.write(supported, "int ok(void) { return 0; }\n")
        self.write(planted, "int unread(void) { return 0; }\n")
        self.commit()
        planted_path = self.root / planted
        real_read = upstream_lint._c_rules_read_source

        def fail_planted(path: Path) -> bytes:
            """Raise PermissionError for the planted source and delegate every other read."""
            if path == planted_path:
                raise PermissionError("fixture unread")
            return real_read(path)

        with (
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_read_source", side_effect=fail_planted
            ),
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_scan", wraps=upstream_lint._c_rules_scan
            ) as scan,
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count(f"unread: {planted}:"), 1, step.output)
        self.assertIn(f"no waiver: {planted}:", step.output)
        self.assertNotIn("command rc:", step.output)
        scan_paths = scan.call_args.args[1]
        self.assertNotIn(planted, scan_paths)
        self.assertIn(supported, scan_paths)

    def test_attribute_parser_failure_is_blanked(self) -> None:
        """A discovered attribute cannot make an otherwise clean step exit two."""
        source = (
            "av_fixture_tag SampleContext *make_sample(void) { return NULL; }\n"
            "void trigger(void) { av_malloc(8); }\n"
        )
        step = self.scan_source(source)
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("0 finding(s)", step.output)
        self.assertEqual((self.root / "libavfilter/vf_x.c").read_text(encoding="utf-8"), source)

    def test_missing_attributes_header_is_reported(self) -> None:
        """An absent attributes header is named even when the scan has no findings."""
        (self.root / "libavutil/attributes.h").unlink()
        step = self.scan_source("void trigger(void) { av_malloc(8); }\n")
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("missing libavutil/attributes.h", step.output)

    def test_finding_after_attribute_keeps_original_coordinates(self) -> None:
        """Blanking preserves the byte offset, line and column of a later ternary."""
        line = "    av_fixture_tag unsigned char *dst = buffer ? buffer + 4 : NULL;"
        source = (
            "void fixture(void) {\n    unsigned char *buffer = av_malloc(8);\n"
            + line
            + "\n    if (!buffer) { fail(); }\n}\n"
        )
        self.write("libavfilter/vf_x.c", source)
        self.commit()
        captured = []

        def capture(argv, cwd, data=None, timeout=60):
            """Retain scanner JSON before the scratch directory is removed."""
            result = self.real_run(argv, cwd, data, timeout)
            if argv[:2] != ["bash", str(upstream_lint.SEMGREP_SCAN)]:
                return result
            path = next(
                arg.removeprefix("--json-output=")
                for arg in argv
                if arg.startswith("--json-output=")
            )
            captured.extend(json.loads(Path(path).read_text(encoding="utf-8"))["results"])
            return result

        with unittest.mock.patch.object(upstream_lint, "_run", side_effect=capture):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(len(captured), 1)
        start = captured[0]["start"]
        self.assertEqual(start["line"], 3)
        self.assertEqual(start["col"], line.index("buffer ?") + 1)
        self.assertEqual(start["offset"], source.index("buffer ?"))

    def _scan_with_unreadable_header(self) -> tuple[upstream_lint.Step, list[str]]:
        """Run _c_rules with PermissionError on attributes.h and return step plus scanned paths."""
        header = self.root / "libavutil/attributes.h"
        real_read = upstream_lint._c_rules_read_source
        real_scan = upstream_lint._c_rules_scan
        scanned_paths: list[str] = []

        def read_source(path: Path) -> bytes:
            """Raise PermissionError on the attributes header and delegate other paths."""
            if path == header:
                raise PermissionError("fixture unread")
            return real_read(path)

        def record_scan(scan_root, paths, json_path, unread_paths):
            """Record accepted scanner paths before delegating to the real scanner."""
            scanned_paths.extend(paths)
            return real_scan(scan_root, paths, json_path, unread_paths)

        with (
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_read_source", side_effect=read_source
            ),
            unittest.mock.patch.object(upstream_lint, "_c_rules_scan", side_effect=record_scan),
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        return step, scanned_paths

    def test_unreadable_attributes_header_preserves_sibling_scan(self) -> None:
        """An unreadable attributes header skips blanking, flags changes and scans siblings."""
        notice = (
            "informational: libavutil/attributes.h: could not be read; attribute blanking skipped"
        )
        self.write("libavfilter/vf_x.c", self.allocation_source())
        self.commit("avfilter/vf_x: update source only")
        unchanged_step, unchanged_paths = self._scan_with_unreadable_header()
        self.assertEqual(unchanged_step.rc, 1, unchanged_step.output)
        self.assertEqual(unchanged_step.output.count(notice), 1, unchanged_step.output)
        self.assertNotIn("unread: libavutil/attributes.h:", unchanged_step.output)
        self.assertEqual(unchanged_paths, ["libavfilter/vf_x.c"])
        self.assertIn("finding: libavfilter/vf_x.c:1:", unchanged_step.output)
        self.write("libavutil/attributes.h", "#define av_fixture_tag\n#define av_extra\n")
        self.commit("avutil/attributes: touch header")
        step, scanned_paths = self._scan_with_unreadable_header()
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count(notice), 1, step.output)
        self.assertEqual(step.output.count("unread: libavutil/attributes.h:"), 1, step.output)
        self.assertIn("no waiver: libavutil/attributes.h:", step.output)
        self.assertNotIn("command rc:", step.output)
        self.assertNotIn("libavutil/attributes.h", scanned_paths)
        self.assertIn("libavfilter/vf_x.c", scanned_paths)
        self.assertIn("finding: libavfilter/vf_x.c:1:", step.output)


class CRulesTreeTest(_CRulesBlankingMixin, _CRulesFixtureMixin, FixtureTest):
    """Exercise tree-backed c-rules discovery and containment without running Semgrep."""

    def setUp(self) -> None:
        """Isolate temporary files in a cleanup-managed directory per test."""
        super().setUp()
        _isolate_test_tmpdir(self)

    def test_r5_spliced_directive_tokens(self) -> None:
        """Logical directives recognize definitions and comment prefixes across splices."""
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                splice = b"\\" + newline
                prefix = b"/" + splice + b"* leading *" + splice + b"/ " + splice
                directive = prefix + b"#def" + splice + b"ine av_fixture_tag" + newline
                (self.root / "libavutil/attributes.h").write_bytes(directive)
                self.assertEqual(
                    upstream_lint._c_rules_attributes(self.root), ({b"av_fixture_tag"}, [])
                )
                self.assert_blanked(
                    directive + b"av_fixture_tag int code;" + newline,
                    directive + b"               int code;" + newline,
                )

    def test_r3_spliced_header_comment(self) -> None:
        """A definition on a spliced comment line contributes no attribute words."""
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                header = self.root / "libavutil/attributes.h"
                prefix = b"// continued " + bytes([92]) + newline
                header.write_bytes(
                    prefix + b"#define av_buffer" + newline + b"#define av_fixture_tag\n"
                )
                names, notices = upstream_lint._c_rules_attributes(self.root)
                self.assertEqual(names, {b"av_fixture_tag"})
                self.assertEqual(notices, [])

    def test_d1_attribute_discovery_ignores_noncode(self) -> None:
        """Only real object-like attribute definitions are discovered."""
        self.write(
            "libavutil/attributes.h",
            "/*\n#define av_buffer\n*/\n"
            'const char *text = "\\\n#define av_string\\\n";\n'
            "#define av_mark\n",
        )
        names, notices = upstream_lint._c_rules_attributes(self.root)
        self.assertEqual(names, {b"av_mark"})
        self.assertEqual(notices, [])

    def test_d3_scratch_target_cannot_escape(self) -> None:
        """An absolute in-tree source cannot redirect a scratch write outside its root."""
        name = str(self.root / "libavfilter/vf_x.c")
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.object(Path, "write_bytes") as write:
                prepared = upstream_lint._c_rules_scan_root(self.root, [name], directory)
            write.assert_not_called()
        self.assertEqual(len(prepared[1]), 1)
        self.assertIn(upstream_lint._waiver_text(name), prepared[1][0])
        self.assertIn("resolves outside the scratch root", prepared[1][0])

    def test_r3_requested_directories_are_unread(self) -> None:
        """Requested root and subdirectories use the existing unread waiver rules."""
        for name in (".", "libavfilter"):
            waiver = upstream_lint.UnreadWaiver(name, "fixture", "B", date(2026, 11, 23), False)
            for reason, unread, rc in (("", (), 1), ("fixture", (), 1), ("", (waiver,), 0)):
                with self.subTest(name=name, reason=reason, unread=unread):
                    with unittest.mock.patch.object(
                        upstream_lint, "_c_rules_touched", return_value={name: {1}}
                    ):
                        step = upstream_lint._c_rules(self.root, self.base, "HEAD", reason, unread)
                    self.assertIsInstance(step, upstream_lint.Step)
                    self.assertEqual(step.rc, rc, step.output)
                    self.assertIn(f"unread: {name}:", step.output)
                    self.assertIn(f"{'waived' if unread else 'no waiver'}: {name}:", step.output)

    def test_r3_requested_header_directory_is_unread(self) -> None:
        """A requested attributes-header directory reaches the ordinary unread report."""
        name = "libavutil/attributes.h"
        header = self.root / name
        header.unlink()
        header.mkdir()
        with unittest.mock.patch.object(
            upstream_lint, "_c_rules_touched", return_value={name: {1}}
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertIsInstance(step, upstream_lint.Step)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"unread: {name}:", step.output)
        self.assertIn(f"no waiver: {name}:", step.output)

    def test_d3_escaping_source_keeps_unread_status(self) -> None:
        """Rejecting one source retains unread and waiver statuses for another source."""
        self.commit_linked_source()
        name = "libavfilter/vf_unread.c"
        self.write(name, "int unread;\n")
        self.commit()
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": [name]},
                "results": [],
                "errors": [{"type": "Syntax error", "path": name}],
            }
        )
        with unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.command):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "")
        self.assertEqual(step.rc, 2, step.output)
        self.assertEqual(step.output.count("libavfilter/vf_x.c"), 1, step.output)
        self.assertIn("resolves outside the checked tree", step.output)
        self.assertIn(f"unread: {name}:", step.output)
        self.assertIn(f"no waiver: {name}:", step.output)

    def test_scanner_failure_reports_preparation_unread(self) -> None:
        """Rejected scanner output keeps preparation unread paths and drops payload paths."""
        directory, source = "libavfilter", "libavfilter/vf_x.c"
        self.write(source, "int ordinary;\n")
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": [source]},
                "results": [],
                "errors": [
                    {"type": "Syntax error", "path": source},
                    {"type": "Unexpected error", "path": source},
                ],
            }
        )
        waiver = upstream_lint.UnreadWaiver(directory, "fixture", "B", date(2026, 11, 23), False)
        for unread in ((), (waiver,)):
            with self.subTest(unread=unread):
                with (
                    unittest.mock.patch.object(
                        upstream_lint,
                        "_c_rules_touched",
                        return_value={directory: {1}, source: {1}},
                    ),
                    unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.command),
                ):
                    step = upstream_lint._c_rules(self.root, self.base, "HEAD", "", unread)
                self.assertEqual(step.rc, 2, step.output)
                self.assertIn(f"unread: {directory}:", step.output)
                self.assertIn(f"{'waived' if unread else 'no waiver'}: {directory}:", step.output)
                self.assertNotIn(source, step.output)

    def test_scanner_failure_keeps_candidate_waivers_open(self) -> None:
        """Scanner failure omits scan-candidate paths from the unread waiver report."""
        directory, source = "libavfilter", "libavfilter/vf_x.c"
        untouched = "libavutil/none.c"
        self.write(source, "int ordinary;\n")
        self.c_rules_json = json.dumps(
            {
                "paths": {"scanned": [source]},
                "results": [],
                "errors": [
                    {"type": "Syntax error", "path": source},
                    {"type": "Unexpected error", "path": source},
                ],
            }
        )
        waivers = (
            upstream_lint.UnreadWaiver(source, "fixture", "B", date(2026, 11, 23), False),
            upstream_lint.UnreadWaiver(untouched, "fixture", "B", date(2026, 11, 23), False),
            upstream_lint.UnreadWaiver(directory, "fixture", "B", date(2026, 11, 23), False),
        )
        with (
            unittest.mock.patch.object(
                upstream_lint,
                "_c_rules_touched",
                return_value={directory: {1}, source: {1}},
            ),
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.command),
        ):
            step = upstream_lint._c_rules(self.root, self.base, "HEAD", "", waivers)
        self.assertEqual(step.rc, 2, step.output)
        self.assertIn(f"waived: {directory}:", step.output)
        self.assertIn(f"unused waiver: {untouched}", step.output)
        self.assertNotIn(source, step.output)


class CRulesBlankingTest(_CRulesBlankingMixin, unittest.TestCase):
    """Pin discovery, lexical boundaries, scope and unread-source preservation."""

    def test_r5_phase2_delimiters(self) -> None:
        """Spliced quotes, line-comment openers and block closers retain only noncode words."""
        for newline in (b"\n", b"\r\n"):
            splice = b"\\" + newline
            cases = (
                b'"' + splice + b"\\" + splice + b'"av_fixture_tag";',
                b"/" + splice * 2 + b"/ av_fixture_tag",
                b"/* av_fixture_tag *" + splice * 2 + b"/",
            )
            for prefix in cases:
                with self.subTest(newline=newline, prefix=prefix):
                    self.assert_blanked(
                        prefix + newline + b"av_fixture_tag int code;" + newline,
                        prefix + newline + b"               int code;" + newline,
                    )

    def test_r5_boundary_nonnewline_backslash(self) -> None:
        """Boundary control: a backslash before an asterisk does not form a comment opener."""
        self.assert_blanked(
            b"/\\* av_fixture_tag */\nav_fixture_tag int code;\n",
            b"/\\*                */\n               int code;\n",
        )

    def test_r3_spliced_line_comments(self) -> None:
        """LF and CRLF splices keep the next physical line inside a line comment."""
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                comment = b"// continued " + bytes([92]) + newline + b"av_fixture_tag" + newline
                self.assert_blanked(
                    comment + b"av_fixture_tag int code;\n",
                    comment + b"               int code;\n",
                )

    def test_r3_boundary_spliced_literals(self) -> None:
        """Boundary control: spliced strings and characters retain every literal byte."""
        for quote in (b'"', b"'"):
            for newline in (b"\n", b"\r\n"):
                with self.subTest(quote=quote, newline=newline):
                    literal = (
                        quote + b"continued " + bytes([92]) + newline + b"av_fixture_tag" + quote
                    )
                    self.assert_blanked(
                        literal + b";\nav_fixture_tag int code;\n",
                        literal + b";\n               int code;\n",
                    )

    def test_r3_unterminated_block_comment(self) -> None:
        """An unterminated block comment masks through the end of the source."""
        for suffix in (b"", b"\n", b"\\"):
            with self.subTest(suffix=suffix):
                tail = b"/* av_fixture_tag\nav_fixture_tag" + suffix
                self.assert_blanked(
                    b"av_fixture_tag int code;\n" + tail,
                    b"               int code;\n" + tail,
                )

    def test_r3_unterminated_literals(self) -> None:
        """Unterminated strings and characters mask through EOF including a trailing escape."""
        for quote in (b'"', b"'"):
            for suffix in (b"", b"\\"):
                with self.subTest(quote=quote, suffix=suffix):
                    tail = quote + b"av_fixture_tag\nav_fixture_tag" + suffix
                    self.assert_blanked(
                        b"av_fixture_tag int code;\n" + tail,
                        b"               int code;\n" + tail,
                    )

    def test_r3_boundary_unspliced_line_comment(self) -> None:
        """Boundary control: an unspliced line comment ends at its physical newline."""
        self.assert_blanked(
            b"// av_fixture_tag\nav_fixture_tag int code;\n",
            b"// av_fixture_tag\n               int code;\n",
        )

    def test_r3_comment_prefixed_directive(self) -> None:
        """A comment-prefixed directive protects its spliced physical continuation."""
        directive = b"/* leading */ #define KEEP \\\n    av_fixture_tag int keep;\n"
        self.assert_blanked(
            directive + b"av_fixture_tag int code;\n",
            directive + b"               int code;\n",
        )

    def test_r3_directive_spanning_block_comment(self) -> None:
        """A directive continues across block comments and stops after their closing line."""
        for middle in (b"", b"av_fixture_tag\n"):
            with self.subTest(middle=middle):
                directive = b"#define KEEP /* open\n" + middle + b"*/ av_fixture_tag int keep;\n"
                self.assert_blanked(
                    directive + b"av_fixture_tag int code;\n",
                    directive + b"               int code;\n",
                )

    def test_r3_boundary_hash_after_code(self) -> None:
        """Boundary control: a hash after ordinary code cannot start a directive."""
        self.assert_blanked(
            b"int x; # y \\\nav_fixture_tag int code;\n",
            b"int x; # y \\\n               int code;\n",
        )

    def test_r3_boundary_hash_after_literal(self) -> None:
        """Boundary control: masking a literal cannot turn a later hash into a directive."""
        for quote in (b'"', b"'"):
            with self.subTest(quote=quote):
                prefix = b"/* leading */ " + quote + b"literal" + quote + b" # y "
                prefix += bytes([92, 10])
                self.assert_blanked(
                    prefix + b"av_fixture_tag int code;\n",
                    prefix + b"               int code;\n",
                )

    def test_d1_attributes_only_in_code(self) -> None:
        """Attribute words inside literals and comments remain byte-identical."""
        tail = (
            b'const char *text = "av_fixture_tag";\n'
            b"int marker = 'x';\nint multichar = 'av_fixture_tag';\n"
            b"/* av_fixture_tag\n   av_fixture_tag */\n"
            b"// av_fixture_tag\n"
        )
        self.assert_blanked(
            b"av_fixture_tag int code;\n" + tail,
            b"               int code;\n" + tail,
        )

    def test_d1_macro_discovery_ignores_noncode(self) -> None:
        """Commented and quoted function macros cannot blank standalone calls."""
        source = (
            b"/*\n#define BUILD(x, n) int x;\n*/\nBUILD(x, 1)\n"
            b'const char *text = "\\\n#define QUOTED(x) x\\\n";\nQUOTED(x)\n'
        )
        self.assert_blanked(source, source)

    def test_d2_two_line_directive_and_code_boundary(self) -> None:
        """A directive continuation is preserved and following code is blanked."""
        directive = b"#define KEEP \\\n    av_fixture_tag int keep;\n"
        self.assert_blanked(
            directive + b"av_fixture_tag int code;\n",
            directive + b"               int code;\n",
        )

    def test_d2_three_line_directive(self) -> None:
        """Every physical line of a three-line directive stays identical."""
        source = b"#define KEEP \\\n    av_fixture_tag \\\n    av_fixture_tag int keep;\n"
        self.assert_blanked(source, source)

    def test_d2_commented_hash_does_not_start_directive(self) -> None:
        """A hash inside a block comment cannot exempt following ordinary code."""
        prefix = b"/*\n#define KEEP \\\n*/ "
        self.assert_blanked(
            prefix + b"av_fixture_tag int code;\n",
            prefix + b"               int code;\n",
        )

    def test_attribute_discovery_and_byte_preservation(self) -> None:
        """Only discovered object macros are blanked outside directive lines."""
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "libavutil").mkdir()
            header = (
                b"# define av_mark\n#define attribute_hint 1\n"
                b"#define av_call(x) x\n#define other 1\n"
            )
            (tree / "libavutil/attributes.h").write_bytes(header)
            names, notices = upstream_lint._c_rules_attributes(tree)
        self.assertEqual(names, {b"av_mark", b"attribute_hint"})
        self.assertEqual(notices, [])
        source = b"#define KEEP av_mark\r\n\xff av_mark av_mark_extra attribute_hint av_call(1)\r\n"
        expected = (
            b"#define KEEP av_mark\r\n\xff         av_mark_extra                av_call(1)\r\n"
        )
        blanked = upstream_lint._c_rules_blank(source, names)
        self.assertEqual(blanked, expected)
        self.assertEqual(len(blanked), len(source))

    def test_only_standalone_file_scope_macro_calls_are_blanked(self) -> None:
        """Local macro discovery requires balanced calls and leaves directives and bodies intact."""
        removed = ["  BUILD(alpha, nested(1))", 'BUILD("(", beta)']
        retained = [
            "#define BUILD(name, arg) int name(void) { return arg; }",
            "#define KEEP BUILD(directive, 1)",
            "BUILD(with_semicolon, 1);",
            "UNKNOWN(1)",
            "BUILD(1)(2)",
            "BUILD(unbalanced, (1)",
            "BUILD(comment, 1) /* tail */",
            "/* prefix */ BUILD(comment, 1)",
            "void fixture(void) {",
            "  BUILD(local, 1)",
            "}",
        ]
        source = "\n".join(retained[:2] + removed + retained[2:]) + "\n"
        expected = (
            "\n".join(retained[:2] + [" " * len(line) for line in removed] + retained[2:]) + "\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(source.encode(), set()), expected.encode())

    def test_open_declaration_retains_macro_call_until_completed(self) -> None:
        """Open declarations retain macro call lines while completed declarations blank them."""
        open_decl = b"#define VALUE(x) (x)\nstatic int n =\n    VALUE(1)\n    ;\n"
        self.assertEqual(upstream_lint._c_rules_blank(open_decl, set()), open_decl)
        completed = b"#define VALUE(x) (x)\nstatic int a;\nVALUE(1)\n"
        expected = b"#define VALUE(x) (x)\nstatic int a;\n        \n"
        self.assertEqual(upstream_lint._c_rules_blank(completed, set()), expected)

    def test_unclosed_comment_with_paren_after_call_is_retained(self) -> None:
        """A trailing comment opener with a parenthesis keeps the macro call line intact."""
        source = b"#define BUILD(x) (x)\nBUILD(x) /* note )\n still comment */\n"
        blanked = upstream_lint._c_rules_blank(source, set())
        self.assertEqual(blanked, source)
        self.assertIn(b"/*", blanked)
        self.assertIn(b"*/", blanked)

    def test_unread_requested_path_is_classified_unread(self) -> None:
        """A read failure classifies the path unread without writing a scratch file or link."""
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "tree"
            (tree / "libavutil").mkdir(parents=True)
            (tree / "libavutil/attributes.h").write_bytes(b"#define av_mark\n")
            source = tree / "libavutil/unread.c"
            real_read = Path.read_bytes

            def read(path):
                """Plant an inaccessible requested source without affecting the header."""
                if path == source:
                    raise PermissionError("fixture unread source")
                return real_read(path)

            with unittest.mock.patch.object(Path, "read_bytes", read):
                root, notices, escaped, unread = upstream_lint._c_rules_scan_root(
                    tree, ["libavutil/unread.c"], directory
                )
            target = root / "libavutil/unread.c"
            self.assertFalse(target.exists())
            self.assertFalse(target.is_symlink())
            self.assertEqual(unread, ["libavutil/unread.c"])
            self.assertEqual(notices, ["informational: libavutil/unread.c: could not be read"])
            self.assertEqual(escaped, [])

    def test_conditional_arms_track_entry_boundary(self) -> None:
        """Conditional arms restart from the entry boundary and require all paths closed."""
        d1_source = (
            b"#define VALUE(x) (x)\nstatic int n =\n#if A\n    0;\n#else\n"
            b"    VALUE(1)\n    ;\n#endif\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(d1_source, set()), d1_source)
        elif_source = d1_source.replace(b"#else\n", b"#elif B\n    1;\n#else\n")
        self.assertEqual(upstream_lint._c_rules_blank(elif_source, set()), elif_source)
        all_boundary = (
            b"#define VALUE(x) (x)\n#if A\nstatic int n = 0;\n#else\n"
            b"static int n = 1;\n#endif\nVALUE(1)\n"
        )
        expected_all = all_boundary[: -len(b"VALUE(1)\n")] + b"        \n"
        self.assertEqual(upstream_lint._c_rules_blank(all_boundary, set()), expected_all)
        no_else = b"#define VALUE(x) (x)\nstatic int n =\n#if A\n    0\n#endif\n    ;\nVALUE(1)\n"
        expected_no_else = no_else[: -len(b"VALUE(1)\n")] + b"        \n"
        self.assertEqual(upstream_lint._c_rules_blank(no_else, set()), expected_no_else)
        no_else_open = (
            b"#define VALUE(x) (x)\nstatic int n =\n#if A\n    0;\n#endif\n    VALUE(1)\n    ;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(no_else_open, set()), no_else_open)

    def test_closing_brace_sets_boundary_only_for_function_body(self) -> None:
        """Non-function closing braces keep declarations open while function bodies close."""
        typedef_source = b"#define NAME(x) x\ntypedef struct { int x; }\nNAME(Foo)\n;\nFoo value;\n"
        self.assertEqual(upstream_lint._c_rules_blank(typedef_source, set()), typedef_source)
        init_source = b"#define CALL(x) (x)\nstatic int a[] = { 1, 2 }\nCALL(1)\n;\n"
        self.assertEqual(upstream_lint._c_rules_blank(init_source, set()), init_source)
        completed_struct = b"#define CALL(x) (x)\nstruct s { int x; };\nCALL(1)\n"
        expected_struct = b"#define CALL(x) (x)\nstruct s { int x; };\n       \n"
        self.assertEqual(upstream_lint._c_rules_blank(completed_struct, set()), expected_struct)
        split_func = b"#define CALL(x) (x)\nint f(void)\n{\n    return 0;\n}\nCALL(1)\n"
        expected_split = split_func[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(split_func, set()), expected_split)
        inline_func = b"#define CALL(x) (x)\nint f(void) {\n    return 0;\n}\nCALL(1)\n"
        expected_inline = inline_func[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(inline_func, set()), expected_inline)

    def test_conditional_arms_record_every_arm_state(self) -> None:
        """Every conditional arm must close at a boundary or function header to blank calls."""
        open_arm = (
            b"#define VALUE(x) (x)\n#if A\nstatic int n =\n#else\n"
            b"static int n = 1;\n#endif\n    VALUE(1)\n    ;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(open_arm, set()), open_arm)
        struct_arm = (
            b"#define CALL(x) (x)\n#if A\nstruct s {\n#else\nint f(void) {\n"
            b"#endif\n    int x;\n}\nCALL(1)\n;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(struct_arm, set()), struct_arm)
        header_arm = (
            b"#define CALL(x) (x)\n#if A\nstruct s\n#else\nint f(void)\n"
            b"#endif\n{\n    int x;\n}\nCALL(1)\n;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(header_arm, set()), header_arm)
        all_headers = (
            b"#define CALL(x) (x)\n#if A\nint f(int a)\n#else\nint f(void)\n"
            b"#endif\n{\n    return 0;\n}\nCALL(1)\n"
        )
        expected_headers = all_headers[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(all_headers, set()), expected_headers)

    def test_conditional_without_else_keeps_entry_header_state(self) -> None:
        """Conditionals without an else arm preserve non-function entry header state."""
        body_source = (
            b"#define CALL(x) (x)\nstruct s {\n#if A\n    int x; }; int f(void) {\n"
            b"#endif\n    int y;\n}\nCALL(1)\n;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(body_source, set()), body_source)
        header_source = (
            b"#define CALL(x) (x)\nstruct s\n#if A\nint f(void)\n"
            b"#endif\n{\n    int x;\n}\nCALL(1)\n;\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(header_source, set()), header_source)

    def test_conditional_without_else_keeps_inner_macro_call(self) -> None:
        """Conditionals without else keep inner macro calls and blank file-scope controls."""
        source = (
            b"#define CALL(x) int value##x;\n"
            b"void f(void) {\n"
            b"#if A\n"
            b"}\n"
            b"#endif\n"
            b"CALL(1)\n"
            b"#if !A\n"
            b"}\n"
            b"#endif\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(source, set()), source)
        define = b"#define CALL(x) int value##x;\n"
        elif_case = (
            define
            + b"void f(void) {\n#if A\n}\n#elif B\n}\n#endif\n"
            + b"CALL(1)\n#if !A && !B\n}\n#endif\n"
        )
        kept = (
            define + b"void f(void) {\n#if A\n}\n#endif\nCALL(1)\n#if A\n#else\n}\n#endif\n",
            define + b"void f(void) {\n#ifdef A\n}\n#endif\nCALL(1)\n#ifndef A\n}\n#endif\n",
            elif_case,
            define + b"void f(void) {\n#if A\n}\n#endif\nCALL(1)\n",
        )
        for index in range(len(kept)):
            self.assertEqual(upstream_lint._c_rules_blank(kept[index], set()), kept[index])
        control = define + b"void f(void) {\n}\nCALL(1)\n"
        expected = control[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
        self.assertEqual(upstream_lint._c_rules_blank(control, set()), expected)

    def test_depths_count_entry_arm_without_else(self) -> None:
        """Conditionals without else include the entry depth in arm-end comparisons."""
        define = b"#define CALL(x) int value##x;\n"
        bot_example = define + b"void f(void) {\n#if A\n}\n#endif\nCALL(1)\n#if !A\n}\n#endif\n"
        elif_no_else = define + b"void f(void) {\n#if A\n}\n#elif B\n}\n#endif\nCALL(1)\n"
        for index in range(2):
            source = bot_example if index == 0 else elif_no_else
            code, directives, directive_lines = upstream_lint._c_lex_lines(
                source.decode("latin-1"), positions=True
            )
            lines = source.split(b"\n")
            mapped = upstream_lint._c_rules_directive_words(
                lines, code, directives, directive_lines
            )
            depths = upstream_lint._c_rules_depths(lines, code, mapped)
            first_endif = lines.index(b"#endif")
            self.assertTrue(all(depth >= 0 for depth in depths[:first_endif]))
            self.assertEqual(depths[first_endif:], [-1] * (len(lines) - first_endif))
        control = define + b"#if A\nint x;\n#endif\nCALL(1)\n"
        ctrl_code, ctrl_dirs, ctrl_dir_lines = upstream_lint._c_lex_lines(
            control.decode("latin-1"), positions=True
        )
        ctrl_lines = control.split(b"\n")
        ctrl_mapped = upstream_lint._c_rules_directive_words(
            ctrl_lines, ctrl_code, ctrl_dirs, ctrl_dir_lines
        )
        ctrl_depths = upstream_lint._c_rules_depths(ctrl_lines, ctrl_code, ctrl_mapped)
        self.assertEqual(len(ctrl_depths), len(ctrl_lines))
        self.assertTrue(all(depth >= 0 for depth in ctrl_depths))

    def test_conditional_directive_mismatch_disables_blanking(self) -> None:
        """Duplicate else and elif-after-else directives disable subsequent macro blanking."""
        duplicate_else = (
            b"#define CALL(x) (x)\nint a;\n#if A\nint b;\n#else\nint c;\n"
            b"#else\nint d;\n#endif\nCALL(1)\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(duplicate_else, set()), duplicate_else)
        elif_after_else = (
            b"#define CALL(x) (x)\nint a;\n#if A\nint b;\n#else\nint c;\n"
            b"#elif B\nint d;\n#endif\nCALL(1)\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(elif_after_else, set()), elif_after_else)

    def test_conditional_arms_track_shared_starting_depth(self) -> None:
        """Conditional arms restart from the entry depth and disable blanking on divergence."""
        c3_source = (
            b"#define CALL(x) (x)\nint f(void)\n{\n#if A\n    return 1;\n}\n#else\n"
            b"    return 2;\n}\n#endif\nint g(void)\n{\n    CALL(1)\n    ;\n}\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(c3_source, set()), c3_source)
        c3_boundary = c3_source.replace(b"{\n    CALL(1)\n", b"{\n    int x = 0;\n    CALL(1)\n")
        self.assertEqual(upstream_lint._c_rules_blank(c3_boundary, set()), c3_boundary)
        elif_source = c3_boundary.replace(b"#if A\n", b"#ifdef A\n").replace(
            b"#else\n", b"#elif B\n    return 3;\n}\n#else\n"
        )
        self.assertEqual(upstream_lint._c_rules_blank(elif_source, set()), elif_source)
        ifndef_source = c3_boundary.replace(b"#if A\n", b"#ifndef A\n")
        self.assertEqual(upstream_lint._c_rules_blank(ifndef_source, set()), ifndef_source)
        diverged_first_closes = (
            b"#define CALL(x) (x)\nint f(void)\n{\n#if A\n    return 1;\n}\n#else\n"
            b"    return 2;\n#endif\n}\nCALL(1)\n"
        )
        self.assertEqual(
            upstream_lint._c_rules_blank(diverged_first_closes, set()), diverged_first_closes
        )
        diverged_second_closes = (
            b"#define CALL(x) (x)\nint f(void)\n{\n#if A\n    return 1;\n#else\n"
            b"    return 2;\n}\n#endif\nCALL(1)\n"
        )
        self.assertEqual(
            upstream_lint._c_rules_blank(diverged_second_closes, set()), diverged_second_closes
        )
        balanced_zero = (
            b"#define CALL(x) (x)\n#if A\nint f(void) { return 1; }\n#else\n"
            b"int f(void) { return 2; }\n#endif\nCALL(1)\n"
        )
        expected_zero = balanced_zero[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(balanced_zero, set()), expected_zero)

    def test_conditional_arms_closing_function_blank_following_macro_call(self) -> None:
        """All conditional arms closing a function return to file scope for macro blanking."""
        source = (
            b"#define CALL(x) (x)\nint f(void)\n{\n#if A\n    return 1;\n}\n#else\n"
            b"    return 2;\n}\n#endif\nCALL(1)\n"
        )
        expected = source[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(source, set()), expected)
        elif_source = source.replace(b"#else\n", b"#elif B\n    return 3;\n}\n#else\n")
        elif_expected = elif_source[: -len(b"CALL(1)\n")] + b"       \n"
        self.assertEqual(upstream_lint._c_rules_blank(elif_source, set()), elif_expected)

    def test_conditional_directive_fail_safe_preserves_macro_calls(self) -> None:
        """Raw directive mismatches and unbalanced conditionals disable macro blanking only."""
        comment_else = b"#define CALL(x) (x)\n/* comment\n#else\n*/\nCALL(1)\n"
        self.assertEqual(upstream_lint._c_rules_blank(comment_else, set()), comment_else)
        nested_comment_else = (
            b"#define CALL(x) (x)\n#if A\n/* comment\n#else\n*/\n#endif\nCALL(1)\n"
        )
        self.assertEqual(
            upstream_lint._c_rules_blank(nested_comment_else, set()), nested_comment_else
        )
        unbalanced_directives = (b"#elif A", b"#else", b"#endif", b"#if A")
        for index in range(len(unbalanced_directives)):
            directive = unbalanced_directives[index]
            unbalanced = b"#define CALL(x) (x)\nCALL(1)\n" + directive + b"\nav_mark CALL(1)\n"
            expected = b"#define CALL(x) (x)\nCALL(1)\n" + directive + b"\n        CALL(1)\n"
            self.assertEqual(
                upstream_lint._c_rules_blank(unbalanced, {b"av_mark"}),
                expected,
            )

    def test_unreadable_attributes_header_skips_blanking_with_notice(self) -> None:
        """An OSError reading attributes.h returns an empty set and one informational notice."""
        notice = (
            "informational: libavutil/attributes.h: could not be read; attribute blanking skipped"
        )
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "tree"
            header = tree / "libavutil/attributes.h"
            header.parent.mkdir(parents=True)
            header.write_bytes(b"#define av_mark\n")
            real_read = upstream_lint._c_rules_read_source

            def read_source(path: Path) -> bytes:
                """Raise PermissionError on the attributes header and delegate other paths."""
                if path == header:
                    raise PermissionError("fixture unread")
                return real_read(path)

            with unittest.mock.patch.object(
                upstream_lint, "_c_rules_read_source", side_effect=read_source
            ):
                names, notices = upstream_lint._c_rules_attributes(tree)
        self.assertEqual(names, set())
        self.assertEqual(notices, [notice])

    def test_attributed_declaration_heads_do_not_open_function_body(self) -> None:
        """Attributed type heads retain declarators while plain function heads blank calls."""
        unchanged_cases = (
            (
                b"#define NAME(x) x\ntypedef struct __attribute__((packed)) { int x; }\n"
                b"NAME(Foo)\n;\nFoo value;\n"
            ),
            (
                b"#define NAME(x) x\ntypedef struct __attribute__((packed))\n{ int x; }\n"
                b"NAME(Foo)\n;\nFoo value;\n"
            ),
            b"#define NAME(x) x\nstruct __attribute__((packed)) { int x; }\nNAME(v)\n;\n",
            (
                b"#define CALL(x) (x)\n#if A\nstruct __attribute__((packed))\n#else\n"
                b"int f(void)\n#endif\n{ int x; }\nCALL(1)\n"
            ),
        )
        for index in range(len(unchanged_cases)):
            source = unchanged_cases[index]
            self.assert_blanked(source, source)
        blanked_cases = (
            b"#define CALL(x) (x)\nint f(void) {\n    return 0;\n}\nCALL(1)\n",
            b"#define CALL(x) (x)\nint f(void)\n{\n    return 0;\n}\nCALL(1)\n",
        )
        for index in range(len(blanked_cases)):
            source = blanked_cases[index]
            expected = source[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
            self.assert_blanked(source, expected)

    def test_type_returning_function_heads_open_function_body(self) -> None:
        """Type-returning, attributed and multi-line function heads open bodies and blank calls."""
        cases = (
            (
                b"#define CALL(x) (x)\nstatic enum AVPixelFormat f(void)\n"
                b"{\n    return 0;\n}\nCALL(1)\n"
            ),
            b"#define CALL(x) (x)\nstatic struct S *f(void) {\n    return 0;\n}\nCALL(1)\n",
            (
                b"#define CALL(x) (x)\nstatic enum E f(void) { return 0; }\n"
                b"static int g(void)\n{\n    return 0;\n}\nCALL(1)\n"
            ),
            (
                b"#define CALL(x) (x)\nstatic int __attribute__((noinline)) f(void)\n"
                b"{\n    return 0;\n}\nCALL(1)\n"
            ),
            (
                b"#define CALL(x) (x)\nstatic int f(int a,\n    int b)\n"
                b"{\n    return a;\n}\nCALL(1)\n"
            ),
        )
        for index in range(len(cases)):
            source = cases[index]
            expected = source[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
            self.assert_blanked(source, expected)

    def test_attribute_groups_never_open_function_body(self) -> None:
        """Multi-line, alternate-spelling and split-arm attribute groups retain declarators."""
        cases = (
            (
                b"#define NAME(x) x\ntypedef struct __attribute__((\n    packed))\n"
                b"{ int x; }\nNAME(Foo)\n;\nFoo value;\n"
            ),
            b"#define NAME(x) x\nstruct __attribute((packed)) { int x; }\nNAME(v)\n;\n",
            b"#define NAME(x) x\nstruct __declspec(align(16)) { int x; }\nNAME(v)\n;\n",
            (
                b"#define NAME(x) x\n#if A\ntypedef struct __attribute__((packed\n#else\n"
                b"typedef struct __attribute__((packed))\n#endif\n))\n{ int x; }\nNAME(Foo)\n;\n"
            ),
        )
        for index in range(len(cases)):
            source = cases[index]
            self.assert_blanked(source, source)

    def test_broken_attribute_group_ends_at_statement(self) -> None:
        """Statement terminators close broken attribute groups before later functions."""
        source = (
            b"#define CALL(x) (x)\nstruct __attribute__((packed);\nint f(void)\n"
            b"{\n    return 0;\n}\nCALL(1)\n"
        )
        expected = source[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
        self.assert_blanked(source, expected)

    def test_compound_literal_initializer_keeps_terminator_macro(self) -> None:
        """Compound-literal initializers retain trailing macros without masking functions."""
        unchanged = (
            b"#define END(x) ;\nstatic int *p = (int[]){ 1 }\nEND(p)\nint after;\n",
            b"#define END(x) ;\nstatic int *p = (int[])\n{ 1 }\nEND(p)\n",
            b"#define END(x) ;\n#if A\nstatic int *p = (int[])\n#endif\n{ 1 }\nEND(p)\n",
            b"#define END(x) ;\n#if A\nstatic int *p =\n#endif\n(int[]){ 1 }\nEND(p)\n",
        )
        for index in range(len(unchanged)):
            self.assert_blanked(unchanged[index], unchanged[index])
        blanked_cases = (
            (
                b"#define CALL(x) (x)\nDEFINE_PAIR(a = 1, b = 2)\nstatic int f(void)\n"
                b"{\n    return 0;\n}\nCALL(1)\n"
            ),
            (
                b"#define CALL(x) (x)\nstatic const int t[] = { 1 };\nstatic int g(void)\n"
                b"{\n    return 0;\n}\nCALL(1)\n"
            ),
        )
        for index in range(len(blanked_cases)):
            source = blanked_cases[index]
            expected = source[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
            self.assert_blanked(source, expected)

    def test_comment_close_before_macro_call_is_kept(self) -> None:
        """Comment closers before known macro calls keep the line unblanked."""
        kept = b"#define BUILD(x) x\n/* open\nnote(*/ BUILD(x)\nint after;\n"
        self.assert_blanked(kept, kept)
        blanked = b"#define BUILD(x) x\nint before;\nBUILD(x)\nint after;\n"
        expected = (
            b"#define BUILD(x) x\nint before;\n" + b" " * len(b"BUILD(x)") + b"\nint after;\n"
        )
        self.assert_blanked(blanked, expected)

    def test_macro_supplied_function_header_is_kept(self) -> None:
        """Macro calls followed by an opening brace keep the function header line."""
        header_cases = (
            (
                b"#define DECL(x) int x(void)\n#define CALL(x) (x)\n"
                b"DECL(f)\n{\n    return 0;\n}\nCALL(1)\n"
            ),
            (
                b"#define DECL(x) int x(void)\n#define CALL(x) (x)\n"
                b"DECL(f)\n\n/* header comment */\n{\n    return 0;\n}\nCALL(1)\n"
            ),
        )
        for index in range(len(header_cases)):
            source = header_cases[index]
            expected = source[: -len(b"CALL(1)\n")] + b" " * len(b"CALL(1)") + b"\n"
            self.assert_blanked(source, expected)
        plain = b"#define DECLARE(x) int x;\nDECLARE(a)\nint b;\n"
        expected_plain = b"#define DECLARE(x) int x;\n" + b" " * len(b"DECLARE(a)") + b"\nint b;\n"
        self.assert_blanked(plain, expected_plain)

    def test_split_directive_disables_macro_blanking(self) -> None:
        """Spliced directive names that disagree with the lexer disable macro-call blanking."""
        split_else = b"#el\\\nse\n"
        plain_else = b"#else\n"
        g1_source = (
            b"#define VALUE(x) (x)\nstatic int n =\n#if A\n0;\n" + split_else + b"VALUE(1)\n;\n"
            b"#endif\nint after;\n"
        )
        self.assert_blanked(g1_source, g1_source)
        hash_splice = b"#\\\nelse\n"
        g1_hash = (
            b"#define VALUE(x) (x)\nstatic int n =\n#if A\n0;\n" + hash_splice + b"VALUE(1)\n;\n"
            b"#endif\nint after;\n"
        )
        self.assert_blanked(g1_hash, g1_hash)
        call_body = b"CALL(1)"
        call_line = call_body + b"\n"
        attr_line = b"int av_fixture_tag a;\n"
        split_fixture = (
            b"#define CALL(x) (x)\n"
            + attr_line
            + b"#if A\nint b;\n"
            + split_else
            + b"int c;\n#endif\n"
            + call_line
            + b"int d;\n"
        )
        blanked_attr = b"int " + b" " * len(b"av_fixture_tag") + b" a;\n"
        expected_split = (
            b"#define CALL(x) (x)\n"
            + blanked_attr
            + b"#if A\nint b;\n"
            + split_else
            + b"int c;\n#endif\n"
            + call_line
            + b"int d;\n"
        )
        self.assert_blanked(split_fixture, expected_split)
        plain_control = (
            b"#define CALL(x) (x)\n"
            + attr_line
            + b"#if A\nint b;\n"
            + plain_else
            + b"int c;\n#endif\n"
            + call_line
            + b"int d;\n"
        )
        expected_control = (
            b"#define CALL(x) (x)\n"
            + blanked_attr
            + b"#if A\nint b;\n"
            + plain_else
            + b"int c;\n#endif\n"
            + b" " * len(call_body)
            + b"\nint d;\n"
        )
        self.assert_blanked(plain_control, expected_control)

    def test_macro_header_across_conditional_arms_is_kept(self) -> None:
        """Macro headers are kept only along one preprocessor continuation after the call."""
        g2_source = (
            b"#define DECL(x) int x(void)\nDECL(f)\n#if A\n;\n#else\n{ return 0; }\n"
            b"#endif\nint after;\n"
        )
        self.assert_blanked(g2_source, g2_source)
        g2_variant = (
            b"#define DECL(x) int x(void)\n#define DECL2(x) int x(int)\n#if A\nDECL(f)\n"
            b"#else\nDECL2(f)\n#endif\n{\n    return 0;\n}\n"
        )
        self.assert_blanked(g2_variant, g2_variant)
        blanked_if = b"#define DEFINE(x) int x;\n#if CONFIG_X\nDEFINE(foo)\n#endif\nint b;\n"
        expected_if = (
            b"#define DEFINE(x) int x;\n#if CONFIG_X\n"
            + b" " * len(b"DEFINE(foo)")
            + b"\n#endif\nint b;\n"
        )
        self.assert_blanked(blanked_if, expected_if)
        blanked_else_body = (
            b"#define DEFINE(x) int x;\n#if CONFIG_X\nDEFINE(foo)\n#else\n{ }\n#endif\nint b;\n"
        )
        expected_else_body = (
            b"#define DEFINE(x) int x;\n#if CONFIG_X\n"
            + b" " * len(b"DEFINE(foo)")
            + b"\n#else\n{ }\n#endif\nint b;\n"
        )
        self.assert_blanked(blanked_else_body, expected_else_body)
        nested = b"#define DECLARE(x) int x;\nDECLARE(a)\n#if A\nint b;\n#endif\n"
        self.assert_blanked(nested, nested)

    def test_directive_positions_must_match_lexed_positions(self) -> None:
        """Directive start lines from the lexer must match physical directive line starts."""
        h1_source = (
            b"#define VALUE(x) (x)\n"
            b"static int n =\n"
            b"#if A\n"
            b"#define KEEP \\\n"
            b"#else\n"
            b"0;\n"
            b"/* arm */ #else\n"
            b"VALUE(1)\n"
            b";\n"
            b"#endif\n"
        )
        self.assert_blanked(h1_source, h1_source)
        spliced_define = b"#define LONG \\\n  1\n#define CALL(x) int x;\nCALL(a)\nint b;\n"
        expected_spliced = (
            b"#define LONG \\\n"
            b"  1\n"
            b"#define CALL(x) int x;\n" + b" " * len(b"CALL(a)") + b"\nint b;\n"
        )
        blanked = upstream_lint._c_rules_blank(spliced_define, set())
        self.assertEqual(blanked, expected_spliced)
        continued_hash = b"#define CALL(x) int x;\n#define KEEP \\\n#else\nCALL(a)\nint b;\n"
        self.assertEqual(upstream_lint._c_rules_blank(continued_hash, set()), continued_hash)
        call_body = b"CALL(1)"
        attr_line = b"int av_fixture_tag a;\n"
        plain_control = (
            b"#define CALL(x) (x)\n"
            + attr_line
            + b"#if A\nint b;\n#else\nint c;\n#endif\n"
            + call_body
            + b"\nint d;\n"
        )
        blanked_attr = b"int " + b" " * len(b"av_fixture_tag") + b" a;\n"
        expected_control = (
            b"#define CALL(x) (x)\n"
            + blanked_attr
            + b"#if A\nint b;\n#else\nint c;\n#endif\n"
            + b" " * len(call_body)
            + b"\nint d;\n"
        )
        self.assert_blanked(plain_control, expected_control)

    def test_macro_call_before_parameter_list_is_kept(self) -> None:
        """Macro calls with a parameter-list continuation stay in the scratch copy."""
        h2_source = b"#define DECL(x) static int x\nDECL(f)\n(void)\n{ return 0; }\n"
        self.assertEqual(upstream_lint._c_rules_blank(h2_source, set()), h2_source)
        param_list = b"#define DECL(x) static int x\nDECL(f)\n    (int a);\nint b;\n"
        self.assertEqual(upstream_lint._c_rules_blank(param_list, set()), param_list)
        plain = b"#define DECLARE(x) int x;\nDECLARE(a)\nint b;\n"
        expected_plain = b"#define DECLARE(x) int x;\n" + b" " * len(b"DECLARE(a)") + b"\nint b;\n"
        blanked = upstream_lint._c_rules_blank(plain, set())
        self.assertEqual(blanked, expected_plain)

    def test_arm_joins_skip_nested_conditionals(self) -> None:
        """Precomputed arm joins skip sibling arms and nested conditionals when walking tails."""
        source = b"#if A\n#if B\n#else\n#endif\n#elif C\n#else\n#endif\n#ifdef D\n#else\n"
        lines = source.split(b"\n")
        code, directives, directive_lines = upstream_lint._c_lex_lines(
            source.decode("latin-1"), positions=True
        )
        mapped = upstream_lint._c_rules_directive_words(lines, code, directives, directive_lines)
        if mapped is None:
            self.fail("directive word map missing for nested conditional fixture")
        joins = upstream_lint._c_rules_arm_joins(mapped, len(lines))
        self.assertEqual(joins[2], 3)
        self.assertEqual(joins[4], 6)
        self.assertEqual(joins[5], 6)
        self.assertEqual(joins[8], -1)
        tail_source = b"#define CALL(x) int x;\n#if A\nCALL(a)\n#else\n{\n#endif\nint b;\n"
        tail_lines = tail_source.split(b"\n")
        tail_decoded = tail_source.decode("latin-1")
        tail_code, tail_dirs, tail_dir_lines = upstream_lint._c_lex_lines(
            tail_decoded, positions=True
        )
        tail_mapped = upstream_lint._c_rules_directive_words(
            tail_lines, tail_code, tail_dirs, tail_dir_lines
        )
        if tail_mapped is None:
            self.fail("directive word map missing for blank-call tail fixture")
        tail_joins = upstream_lint._c_rules_arm_joins(tail_mapped, len(tail_lines))
        self.assertTrue(
            upstream_lint._c_rules_blank_call_tail(tail_code, tail_mapped, 3, tail_joins)
        )
        wrong_joins = list(tail_joins)
        wrong_joins[3] = 3
        self.assertFalse(
            upstream_lint._c_rules_blank_call_tail(tail_code, tail_mapped, 3, wrong_joins)
        )

    def test_long_conditional_chain_blanks_each_call(self) -> None:
        """Each macro call in a long elif chain is blanked along the same rule as a line walk."""
        count = 300
        parts = [b"#define CALL(x) int x;\n", b"#if A0\n", b"CALL(a0)\n"]
        for index in range(1, count):
            parts.append(f"#elif A{index}\n".encode("ascii"))
            parts.append(f"CALL(a{index})\n".encode("ascii"))
        parts.append(b"#endif\nint z;\n")
        source = b"".join(parts)
        lines = source.split(b"\n")
        blanked_lines = upstream_lint._c_rules_blank(source, set()).split(b"\n")
        for index in range(len(lines)):
            stripped = lines[index].strip()
            if stripped.startswith(b"CALL("):
                self.assertEqual(blanked_lines[index], b" " * len(lines[index]))
            else:
                self.assertEqual(blanked_lines[index], lines[index])

    def test_directive_words_without_positions_fail_closed(self) -> None:
        """Empty directive line list without positions yields no directive word map."""
        text = "#if A\nint a;\n#endif\n"
        lines = text.encode("latin-1").split(b"\n")
        code, directives, _ = upstream_lint._c_lex_lines(text)
        self.assertIsNone(upstream_lint._c_rules_directive_words(lines, code, directives, []))
        code2, directives2, directive_lines2 = upstream_lint._c_lex_lines(text, positions=True)
        mapped = upstream_lint._c_rules_directive_words(lines, code2, directives2, directive_lines2)
        if mapped is None:
            self.fail("expected directive word map with positions=True")
        self.assertEqual(mapped[0], b"if")
        self.assertEqual(mapped[2], b"endif")

    def test_directive_positions_counted_once(self) -> None:
        """Directive physical start lines use one running newline scan over the source."""
        source = (
            "int x = 0; \\\n"
            "tail\n"
            "#define D0 0\n"
            "#define D1 \\\n"
            " 1\n"
            "#define D2 2\n"
            "#define D3 \\\n"
            " 3\n"
            "#define D4 4\n"
        )
        expect = [2, 3, 5, 6, 8]
        with_pos = upstream_lint._c_lex_lines(source, positions=True)
        without_pos = upstream_lint._c_lex_lines(source)
        self.assertEqual(with_pos[2], expect)
        self.assertEqual(without_pos[2], [])
        self.assertEqual(with_pos[0], without_pos[0])
        self.assertEqual(with_pos[1], without_pos[1])

    def test_mechanical_check_skips_directive_positions(self) -> None:
        """Only c-rules blanking asks the lexer for directive physical positions."""
        calls: list[bool] = []

        sample = "int a;\n#define M 1\n"
        original = upstream_lint._c_lex_lines

        def wrapped(*args: object, **kwargs: object) -> tuple[list[str], list[str], list[int]]:
            calls.append(bool(kwargs.get("positions", False)))
            return original(*args, **kwargs)

        calls.clear()
        with unittest.mock.patch.object(upstream_lint, "_c_lex_lines", wraps=wrapped):
            upstream_lint._code_lines(sample)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "t.c"
                path.write_bytes(b"int x;\n")
                upstream_lint._c_rules_read_source(path)
            with tempfile.TemporaryDirectory() as tmp:
                tree = Path(tmp)
                (tree / "libavutil").mkdir()
                (tree / "libavutil" / "attributes.h").write_bytes(b"#define av_cold\n")
                upstream_lint._c_rules_attributes(tree)
            self.assertTrue(all(not flag for flag in calls), calls)
            calls.clear()
            upstream_lint._c_rules_blank(sample.encode("latin-1"), set())
            self.assertEqual(sum(calls), 1)
            self.assertTrue(calls[0])

    def test_macro_call_before_declarator_continuation_is_kept(self) -> None:
        """Macro invocations kept when the next code continues the declarator."""
        cases = (
            b"#define DECL(x) static int x\nDECL(table)\n[4];\n",
            b"#define DECL(x) static int x\nDECL(value)\n= 0;\n",
            b"#define DECL(x) static int x\nDECL(a)\n, b;\n",
            b"#define DECL(x) static int x\nDECL(a)\n;\n",
            b"#define TYPE(x) x\nTYPE(int)\n*ptr;\n",
            b"#define DECLARE(x) int x;\nDECLARE(a)\n[[maybe_unused]] int b;\n",
        )
        for source in cases:
            self.assertEqual(upstream_lint._c_rules_blank(source, set()), source)
        blank_call = b" " * len(b"DECLARE(a)") + b"\n"
        controls = (
            (
                b"#define DECLARE(x) int x;\nDECLARE(a)\nint b;\n",
                b"#define DECLARE(x) int x;\n" + blank_call + b"int b;\n",
            ),
            (
                b"#define DECLARE(x) int x;\nDECLARE(a)\nstatic const int b = 1;\n",
                b"#define DECLARE(x) int x;\n" + blank_call + b"static const int b = 1;\n",
            ),
            (
                b'#define DECLARE(x) int x;\nDECLARE(a)\n_Static_assert(1, "x");\n',
                b"#define DECLARE(x) int x;\n" + blank_call + b'_Static_assert(1, "x");\n',
            ),
            (
                b"#define DECLARE(x) int x;\nDECLARE(a)\n",
                b"#define DECLARE(x) int x;\n" + blank_call,
            ),
        )
        for source, expected in controls:
            self.assertEqual(upstream_lint._c_rules_blank(source, set()), expected)

    def test_call_tail_reads_attribute_projection(self) -> None:
        """Call-tail walks attribute-projected code so attribute-only lines are skipped."""
        tag = b"av_fixture_tag"
        sp = b" " * len(tag)
        reviewer = (
            b"#define DECL(x) static int x\n"
            b"#if A\n"
            b"DECL(f)\n"
            b"#else\n"
            b"DECL(g)\n"
            b"#endif\n" + tag + b"\n"
            b"(void)\n"
            b"{ return 0; }\n"
        )
        expected_reviewer = (
            b"#define DECL(x) static int x\n"
            b"#if A\n"
            b"DECL(f)\n"
            b"#else\n"
            b"DECL(g)\n"
            b"#endif\n" + sp + b"\n"
            b"(void)\n"
            b"{ return 0; }\n"
        )
        self.assert_blanked(reviewer, expected_reviewer)
        plain = b"#define DECL(x) static int x\nDECL(f)\n" + tag + b"\n(void)\n{ return 0; }\n"
        expected_plain = (
            b"#define DECL(x) static int x\nDECL(f)\n" + sp + b"\n(void)\n{ return 0; }\n"
        )
        self.assert_blanked(plain, expected_plain)
        inline_attr = b"#define DECL(x) static int x\nDECL(f)\n" + tag + b" (void)\n{ return 0; }\n"
        expected_inline = (
            b"#define DECL(x) static int x\nDECL(f)\n" + sp + b" (void)\n{ return 0; }\n"
        )
        self.assert_blanked(inline_attr, expected_inline)

    def test_call_tail_attribute_projection_controls(self) -> None:
        """Declaration macros and unconfigured-attribute calls blank across arms."""
        tag = b"av_fixture_tag"
        sp = b" " * len(tag)
        reviewer = (
            b"#define DECL(x) static int x\n"
            b"#if A\n"
            b"DECL(f)\n"
            b"#else\n"
            b"DECL(g)\n"
            b"#endif\n" + tag + b"\n"
            b"(void)\n"
            b"{ return 0; }\n"
        )
        declare_control = (
            b"#define DECLARE(x) int x;\n"
            b"#if A\n"
            b"DECLARE(f)\n"
            b"#else\n"
            b"DECLARE(g)\n"
            b"#endif\n" + tag + b"\nint b;\n"
        )
        dc_blank = b" " * len(b"DECLARE(f)")
        dc_blank2 = b" " * len(b"DECLARE(g)")
        expected_declare = (
            b"#define DECLARE(x) int x;\n"
            b"#if A\n" + dc_blank + b"\n"
            b"#else\n" + dc_blank2 + b"\n"
            b"#endif\n" + sp + b"\nint b;\n"
        )
        self.assert_blanked(declare_control, expected_declare)
        no_attr = upstream_lint._c_rules_blank(reviewer, set())
        na_blank_f = b" " * len(b"DECL(f)")
        na_blank_g = b" " * len(b"DECL(g)")
        expected_no_attr = (
            b"#define DECL(x) static int x\n"
            b"#if A\n" + na_blank_f + b"\n"
            b"#else\n" + na_blank_g + b"\n"
            b"#endif\n" + tag + b"\n"
            b"(void)\n"
            b"{ return 0; }\n"
        )
        self.assertEqual(no_attr, expected_no_attr)


class CRulesTest(unittest.TestCase):
    """Unit coverage of the c-rules allow-list, argv, working directory and waiver."""

    def setUp(self) -> None:
        """Set default stub state for one changed C source with added lines 11 and 12."""
        self.tree = Path("/fixture/ffmpeg")
        self.diff_names = "libavformat/rtspenc.c\0"
        self.patches = {"libavformat/rtspenc.c": "@@ -10,0 +11,2 @@\n+a\n+b\n"}
        self.stub_rc = 0
        self.stub_stdout = ""
        self.stub_json: str | None = json.dumps(
            {"paths": {"scanned": ["libavformat/rtspenc.c"]}, "results": [], "errors": []}
        )
        self.calls: list[tuple[list[str], Path, float]] = []

    def fake_git(self, tree: Path, *args: str) -> str:
        """Return stubbed changed-path or zero-context diff output for _c_rules."""
        if "--name-only" in args:
            return self.diff_names
        if args[-1] in self.patches:
            return self.patches[args[-1]]
        names = [name for name in self.diff_names.split("\0") if name]
        sections = [
            f"diff --git a/{name} b/{name}\n{self.patches.get(name, '')}".rstrip("\n")
            for name in names
        ]
        return "\n".join(sections) + ("\n" if sections else "")

    def fake_run(
        self, argv: list[str], cwd: Path, data: str | None = None, timeout: float = 60
    ) -> upstream_lint.RunResult:
        """Write stubbed JSON when configured and return the chosen RunResult."""
        self.calls.append((argv, cwd, timeout))
        if self.stub_json is not None:
            json_arg = next(item for item in argv if item.startswith("--json-output="))
            Path(json_arg.removeprefix("--json-output=")).write_text(
                self.stub_json, encoding="utf-8"
            )
        return upstream_lint.RunResult(tuple(argv), self.stub_rc, self.stub_stdout)

    def run_c_rules(
        self, waiver: str = "", unread: tuple[upstream_lint.UnreadWaiver, ...] = ()
    ) -> upstream_lint.Step:
        """Execute _c_rules with identity scan-root, Git and scanner fixtures."""
        with (
            unittest.mock.patch.object(
                upstream_lint,
                "_c_rules_scan_root",
                side_effect=lambda tree, paths, directory: (tree, [], [], []),
            ),
            unittest.mock.patch.object(upstream_lint, "_git", side_effect=self.fake_git),
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.fake_run),
        ):
            return upstream_lint._collect(
                "c-rules",
                lambda: (
                    upstream_lint._c_rules(self.tree, "base", "head", waiver, unread)
                    if unread
                    else upstream_lint._c_rules(self.tree, "base", "head", waiver)
                ),
            )

    def test_scan_root_controls_scanner_cwd(self) -> None:
        """The scanner uses the helper root while keeping requested paths relative."""
        sentinel = Path("/fixture/scratch-sources")
        with (
            unittest.mock.patch.object(upstream_lint, "_git", side_effect=self.fake_git),
            unittest.mock.patch.object(upstream_lint, "_run", side_effect=self.fake_run),
            unittest.mock.patch.object(
                upstream_lint, "_c_rules_scan_root", return_value=(sentinel, [], [], [])
            ) as prepare,
        ):
            step = upstream_lint._c_rules(self.tree, "base", "head", "")
        self.assertEqual(step.rc, 0, step.output)
        self.assertEqual(self.calls[0][1], sentinel)
        self.assertEqual(self.calls[0][0][5:], ["libavformat/rtspenc.c"])
        self.assertEqual(prepare.call_args.args[:2], (self.tree, ["libavformat/rtspenc.c"]))

    def inter_hunk_fixture(self) -> FixtureTest:
        """Create real Git hunks around an unchanged defect with context fusion enabled."""
        fixture = FixtureTest()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.git("config", "diff.interHunkContext", "2")
        source = (
            "int ff_value(void)\n{\n    ff_first();\n    ff_second();\n"
            "    ff_third();\n    ff_fourth();\n    ff_before(1);\n"
            "\tff_old();\n    ff_between();\n    return 1;\n}\n"
        )
        fixture.write("libavfilter/vf_x.c", source)
        fixture.commit("avfilter/vf_x: add inherited defect")
        fixture.base = fixture.git("rev-parse", "HEAD").strip()
        fixture.write(
            "libavfilter/vf_x.c",
            source.replace("ff_before(1)", "ff_before(2)").replace("return 1", "return 2"),
        )
        fixture.commit()
        return fixture

    def test_inter_hunk_context_keeps_c_rule_match_untouched(self) -> None:
        """Configured context fusion cannot turn an unchanged Semgrep match into a finding."""
        fixture = self.inter_hunk_fixture()
        fixture.c_rules_rc = 1
        fixture.c_rules_json = json.dumps(
            {
                "paths": {"scanned": ["libavfilter/vf_x.c"]},
                "results": [
                    {
                        "check_id": "inherited-defect",
                        "path": "libavfilter/vf_x.c",
                        "start": {"line": 8},
                        "end": {"line": 8},
                        "extra": {"message": "inherited match"},
                    }
                ],
                "errors": [],
            }
        )
        with unittest.mock.patch.object(upstream_lint, "_run", side_effect=fixture.command):
            step = upstream_lint._c_rules(fixture.root, fixture.base, "HEAD", "")
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("pre-existing (untouched): libavfilter/vf_x.c:8:", step.output)

    def test_inter_hunk_context_keeps_line_rule_defect_untouched(self) -> None:
        """Configured context fusion cannot mark an unchanged TAB line as added."""
        fixture = self.inter_hunk_fixture()
        step = upstream_lint._mechanical(fixture.root, fixture.base, "HEAD")
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("pre-existing (untouched): libavfilter/vf_x.c:8: TAB character", step.output)

    def test_requested_path_missing_from_scanned_is_unwaivable(self) -> None:
        """Every requested path must be scanned even when a waiver is supplied."""
        self.diff_names += "libavformat/rtsp.h\0"
        self.patches["libavformat/rtsp.h"] = "@@ -1,0 +2 @@\n+x\n"
        self.stub_json = json.dumps(
            {"paths": {"scanned": ["libavformat/rtspenc.c"]}, "results": [], "errors": []}
        )
        for waiver in ("", "caller closes network"):
            with self.subTest(waiver=waiver):
                step = self.run_c_rules(waiver)
                self.assertEqual(step.rc, 2, step.output)
                self.assertNotIn("waived:", step.output)

    def test_invalid_scanned_paths_is_unwaivable(self) -> None:
        """Missing or malformed scan coverage gives rc 2 with or without a waiver."""
        for coverage in (
            {},
            {"paths": None},
            {"paths": []},
            {"paths": {}},
            {"paths": {"scanned": None}},
            {"paths": {"scanned": "libavformat/rtspenc.c"}},
            {"paths": {"scanned": {"libavformat/rtspenc.c": True}}},
            {"paths": {"scanned": ["libavformat/rtspenc.c", 7]}},
        ):
            self.stub_json = json.dumps({"results": [], "errors": [], **coverage})
            for waiver in ("", "caller closes network"):
                with self.subTest(coverage=coverage, waiver=waiver):
                    step = self.run_c_rules(waiver)
                    self.assertEqual(step.rc, 2, step.output)
                    self.assertNotIn("waived:", step.output)

    def test_no_changed_source_makes_no_run_call(self) -> None:
        """No changed library or fftools C or header source returns rc 0 without _run."""
        for names in ("", "doc/x.texi\0libavcodec/tests/x.c\0libavcodec/x86/x.asm\0"):
            with self.subTest(names=names):
                self.diff_names = names
                step = self.run_c_rules()
                self.assertEqual(step.rc, 0, step.output)
                self.assertIn("no added or modified C or header source", step.output)
                self.assertEqual(self.calls, [])

    def test_argv_working_directory_and_timeout(self) -> None:
        """Scan argv disables the target size limit and preserves tree and timeout settings."""
        self.diff_names = "libavformat/rtspenc.c\0libavformat/rtsp.h\0"
        self.patches["libavformat/rtsp.h"] = "@@ -1,0 +2,1 @@\n+x\n"
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c", "libavformat/rtsp.h"]},
                "results": [],
                "errors": [],
            }
        )
        step = self.run_c_rules()
        self.assertEqual(step.rc, 0, step.output)
        self.assertEqual(len(self.calls), 1)
        argv, cwd, timeout = self.calls[0]
        self.assertEqual(cwd, self.tree)
        self.assertEqual(timeout, 300)
        self.assertEqual(timeout, upstream_lint.C_RULES_TIMEOUT)
        self.assertEqual(
            argv[:3],
            [
                "bash",
                str(upstream_lint.REPO_ROOT / "scripts" / "semgrep_scan.sh"),
                f"--rules={upstream_lint.REPO_ROOT / '.semgrep-ffmpeg.yml'}",
            ],
        )
        self.assertTrue(argv[3].startswith("--json-output="))
        self.assertFalse(Path(argv[3].removeprefix("--json-output=")).parent.exists())
        self.assertEqual(argv[4], "--max-target-bytes=0")
        self.assertEqual(argv[5:], ["libavformat/rtspenc.c", "libavformat/rtsp.h"])

    def test_exit_zero_empty_results_passes(self) -> None:
        """Exit status 0 with empty results and errors lists returns step rc 0."""
        step = self.run_c_rules()
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("0 finding(s)", step.output)

    def test_exit_one_result_on_added_line_fails(self) -> None:
        """A result whose line range meets an added line gives a finding and step rc 1."""
        self.stub_rc = 1
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavformat/rtspenc.c",
                        "start": {"line": 10},
                        "end": {"line": 11},
                        "extra": {"message": "first message line\nsecond detail line"},
                    }
                ],
                "errors": [],
            }
        )
        step = self.run_c_rules()
        self.assertEqual(step.rc, 1, step.output)
        expected_finding = (
            "finding: libavformat/rtspenc.c:10: "
            "ffmpeg-rtsp-connect-failure-without-network-close: first message line"
        )
        self.assertIn(
            expected_finding,
            step.output,
        )
        self.assertNotIn("second detail line", step.output)
        self.assertIn("fix the flagged path, or pass --c-rule-reason", step.output)

    def test_rules_path_prefix_stripped_from_check_id(self) -> None:
        """A check_id prefixed with the dotted rules path reports the bare rule id."""
        rule = "ffmpeg-rtsp-connect-failure-without-network-close"
        self.stub_rc = 1
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c"]},
                "results": [
                    {
                        "check_id": f"home.user.checkout.{rule}",
                        "path": "libavformat/rtspenc.c",
                        "start": {"line": 11},
                        "end": {"line": 11},
                        "extra": {"message": "missing ff_network_close()"},
                    }
                ],
                "errors": [],
            }
        )
        step = self.run_c_rules()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(
            f"finding: libavformat/rtspenc.c:11: {rule}: missing ff_network_close()", step.output
        )
        self.assertNotIn("home.user", step.output)

    def test_result_on_untouched_line_passes_and_lists_preexisting(self) -> None:
        """A result outside added lines is listed as pre-existing without failing."""
        self.stub_rc = 1
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavformat/rtspenc.c",
                        "start": {"line": 3},
                        "end": {"line": 5},
                        "extra": {"message": "missing ff_network_close()"},
                    }
                ],
                "errors": [],
            }
        )
        step = self.run_c_rules()
        self.assertEqual(step.rc, 0, step.output)
        expected_finding = (
            "pre-existing (untouched): libavformat/rtspenc.c:3: "
            "ffmpeg-rtsp-connect-failure-without-network-close: missing ff_network_close()"
        )
        self.assertIn(
            expected_finding,
            step.output,
        )
        self.assertNotIn("finding:", step.output)

    def test_partial_parsing_error_is_informational(self) -> None:
        """PartialParsing errors produce informational file lines without failing."""
        for error_type in ("PartialParsing", ["PartialParsing", [{"path": "libavformat/rtsp.c"}]]):
            with self.subTest(error_type=error_type):
                self.stub_json = json.dumps(
                    {
                        "paths": {"scanned": ["libavformat/rtspenc.c"]},
                        "results": [],
                        "errors": [{"type": error_type, "path": "libavformat/rtsp.c"}],
                    }
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 0, step.output)
                self.assertIn("informational: libavformat/rtsp.c: PartialParsing", step.output)

    def syntax_error_payload(self, **changes: object) -> dict[str, object]:
        """Build the measured unread-file error with allow-listed scalar metadata."""
        error = {
            "type": "Syntax error",
            "path": "libavformat/rtspenc.c",
            "code": 3,
            "level": "warn",
            "message": "the rules could not parse this source",
        }
        error.update(changes)
        return {
            "paths": {"scanned": ["libavformat/rtspenc.c"]},
            "results": [],
            "errors": [error],
        }

    def assert_unread_reported(self) -> None:
        """Require a visible unread-file failure before testing a rejected variant."""
        self.stub_json = json.dumps(self.syntax_error_payload())
        step = self.run_c_rules()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("unread: libavformat/rtspenc.c:", step.output)

    def test_unread_requested_file_fails(self) -> None:
        """An unread requested file fails visibly for scanner exits zero and one."""
        for status in range(2):
            with self.subTest(status=status):
                self.stub_rc = status
                self.stub_json = json.dumps(self.syntax_error_payload())
                step = self.run_c_rules()
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn(
                    (
                        "unread: libavformat/rtspenc.c: rules could not read this file; "
                        "touched lines need a check by hand"
                    ),
                    step.output,
                )
                self.assertNotIn("0 finding(s)", step.output)
                self.assertNotIn("waived:", step.output)

    def test_unread_requested_file_waived_with_reason(self) -> None:
        """A free reason no longer waives an unread file; blank reasons also fail."""
        self.stub_json = json.dumps(self.syntax_error_payload())
        reasons = ("  touched lines checked by hand  ", "   ")
        for index in range(len(reasons)):
            step = self.run_c_rules(reasons[index])
            self.assertEqual(step.rc, 1, step.output)
            self.assertIn("unread: libavformat/rtspenc.c:", step.output)
            self.assertIn("no waiver: libavformat/rtspenc.c:", step.output)
            self.assertNotIn("waived:", step.output)

    def test_unread_file_and_real_finding_both_reported(self) -> None:
        """Unread files, touched findings and partial notes remain visible together."""
        self.diff_names += "libavformat/rtsp.c\0"
        self.patches["libavformat/rtsp.c"] = "@@ -10,0 +11 @@\n+x\n"
        payload = self.syntax_error_payload()
        payload["paths"] = {"scanned": ["libavformat/rtspenc.c", "libavformat/rtsp.c"]}
        payload["results"] = [
            {
                "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                "path": "libavformat/rtsp.c",
                "start": {"line": 11},
                "end": {"line": 11},
                "extra": {"message": "missing ff_network_close()"},
            }
        ]
        payload["errors"].append({"type": "PartialParsing", "path": "libavformat/rtsp.c"})
        self.stub_rc = 1
        self.stub_json = json.dumps(payload)
        reasons = ("", "checked both paths by hand")
        for index in range(len(reasons)):
            with self.subTest(reason=reasons[index]):
                step = self.run_c_rules(reasons[index])
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn("unread: libavformat/rtspenc.c:", step.output)
                self.assertIn("finding: libavformat/rtsp.c:11:", step.output)
                self.assertIn("missing ff_network_close()", step.output)
                self.assertIn("informational: libavformat/rtsp.c: PartialParsing", step.output)
                if index:
                    self.assertIn("waived: checked both paths by hand", step.output)

    def test_unread_unrequested_path_is_unwaivable(self) -> None:
        """A syntax error outside the requested paths stays non-waivable rc two."""
        self.assert_unread_reported()
        self.stub_json = json.dumps(self.syntax_error_payload(path="libavformat/rtsp.c"))
        reasons = ("", "checked by hand")
        for index in range(len(reasons)):
            step = self.run_c_rules(reasons[index])
            self.assertEqual(step.rc, 2, step.output)
            self.assertNotIn("waived:", step.output)

    def test_unread_missing_path_is_unwaivable(self) -> None:
        """A syntax error without a file path stays non-waivable rc two."""
        self.assert_unread_reported()
        payload = self.syntax_error_payload()
        del payload["errors"][0]["path"]
        self.stub_json = json.dumps(payload)
        reasons = ("", "checked by hand")
        for index in range(len(reasons)):
            step = self.run_c_rules(reasons[index])
            self.assertEqual(step.rc, 2, step.output)
            self.assertNotIn("waived:", step.output)

    def test_unread_unknown_type_is_unwaivable(self) -> None:
        """An unknown error type on a requested path stays non-waivable rc two."""
        self.assert_unread_reported()
        self.stub_json = json.dumps(self.syntax_error_payload(type="FutureError"))
        reasons = ("", "checked by hand")
        for index in range(len(reasons)):
            step = self.run_c_rules(reasons[index])
            self.assertEqual(step.rc, 2, step.output)
            self.assertNotIn("waived:", step.output)

    def test_unread_invalid_metadata_is_unwaivable(self) -> None:
        """Reject empty paths, unknown fields and metadata types outside the allow-list."""
        self.assert_unread_reported()
        variants = (
            {"path": ""},
            {"path": ["libavformat/rtspenc.c"]},
            {"type": ["Syntax error"]},
            {"code": "3"},
            {"code": True},
            {"code": 3.0},
            {"code": 4},
            {"level": ["warn"]},
            {"level": "error"},
            {"message": {"text": "syntax error"}},
            {"unexpected": "value"},
            {"unexpected": []},
        )
        for index in range(len(variants)):
            self.stub_json = json.dumps(self.syntax_error_payload(**variants[index]))
            reasons = ("", "checked by hand")
            for reason in range(len(reasons)):
                with self.subTest(variant=variants[index], reason=reasons[reason]):
                    step = self.run_c_rules(reasons[reason])
                    self.assertEqual(step.rc, 2, step.output)
                    self.assertNotIn("waived:", step.output)

    def test_unread_error_code_exact_integer_boundary(self) -> None:
        """Accept only built-in integer code three, preserving the missing-key default."""

        class IntegerSubclass(int):
            """Represent an ordinary integer subclass at the metadata boundary."""

        path = "libavformat/rtspenc.c"
        requested = frozenset({path})
        cases = (
            ("int three", 3, path),
            ("true", True, None),
            ("false", False, None),
            ("float", 3.0, None),
            ("string", "3", None),
            ("none", None, None),
            ("other int", 4, None),
            ("subclass three", IntegerSubclass(3), None),
            ("subclass other", IntegerSubclass(4), None),
        )
        for index in range(len(cases)):
            label, code, expected = cases[index]
            with self.subTest(case=label):
                error = self.syntax_error_payload(code=code)["errors"][0]
                self.assertEqual(upstream_lint._syntax_error_path(error, requested), expected)
        error = self.syntax_error_payload()["errors"][0]
        del error["code"]
        self.assertEqual(upstream_lint._syntax_error_path(error, requested), path)

    def test_multiple_unread_files_each_reported_once(self) -> None:
        """Every unread requested file gets one review line despite duplicate errors."""
        self.diff_names += "libavformat/rtsp.c\0"
        self.patches["libavformat/rtsp.c"] = "@@ -10,0 +11 @@\n+x\n"
        payload = self.syntax_error_payload()
        payload["paths"] = {"scanned": ["libavformat/rtspenc.c", "libavformat/rtsp.c"]}
        payload["errors"] += [
            payload["errors"][0],
            {"type": "Syntax error", "path": "libavformat/rtsp.c"},
        ]
        self.stub_json = json.dumps(payload)
        step = self.run_c_rules()
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(step.output.count("unread: libavformat/rtspenc.c:"), 1)
        self.assertEqual(step.output.count("unread: libavformat/rtsp.c:"), 1)

    def test_unread_collector_requires_requested_paths(self) -> None:
        """A reader without requested paths or an unread collector cannot hide unread files."""
        raw = self.syntax_error_payload()
        requested = frozenset({"libavformat/rtspenc.c"})
        unread: list[str] = []
        parsed = upstream_lint._read_semgrep_lists(
            raw["results"], raw["errors"], requested, unread_paths=unread
        )
        self.assertEqual(parsed, ([], []))
        self.assertEqual(unread, ["libavformat/rtspenc.c"])
        self.assertIsNone(
            upstream_lint._read_semgrep_lists(raw["results"], raw["errors"], requested)
        )
        self.assertIsNone(
            upstream_lint._read_semgrep_lists(raw["results"], raw["errors"], unread_paths=[])
        )

    def test_other_error_type_gives_rc_two(self) -> None:
        """An unrequested syntax error gives step rc 2 with command status and output."""
        self.stub_stdout = "rule parse error\n"
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c"]},
                "results": [],
                "errors": [{"type": "Syntax error", "path": "libavformat/rtsp.c"}],
            }
        )
        step = self.run_c_rules()
        self.assertEqual(step.rc, 2, step.output)
        self.assertTrue(step.output.startswith("command rc: 0\nrule parse error"))

    def test_unexpected_exit_statuses_give_rc_two(self) -> None:
        """Exit statuses 2, 127 and 124 give step rc 2 naming the exit status and output."""
        for status, text in (
            (2, "fatal config error\n"),
            (127, "semgrep: command not found\n"),
            (124, "command timed out\n"),
        ):
            with self.subTest(status=status):
                self.stub_rc = status
                self.stub_stdout = text
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)
                self.assertTrue(step.output.startswith(f"command rc: {status}\n{text}"))

    def test_warning_line_gives_rc_two(self) -> None:
        """A semgrep_scan: warning line in output gives step rc 2 even on exit 0 or 1."""
        for status in (0, 1):
            with self.subTest(status=status):
                self.stub_rc = status
                self.stub_stdout = (
                    "Rule demo contains warning\n"
                    "semgrep_scan: a rule in .semgrep-ffmpeg.yml draws the warning above\n"
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)
                self.assertTrue(step.output.startswith(f"command rc: {status}\n"))
                self.assertIn("semgrep_scan:", step.output)

    def test_missing_json_file_gives_rc_two(self) -> None:
        """A missing JSON output file gives step rc 2 naming the exit status and output."""
        self.stub_json = None
        self.stub_stdout = "no json written\n"
        step = self.run_c_rules()
        self.assertEqual(step.rc, 2, step.output)
        self.assertTrue(step.output.startswith("command rc: 0\nno json written"))

    def test_unparseable_json_gives_rc_two(self) -> None:
        """Unparseable or structurally invalid JSON payloads give step rc 2."""
        self.stub_stdout = "scan finished\n"
        for payload in (
            "{not-json",
            "[]",
            json.dumps({"paths": {"scanned": ["libavformat/rtspenc.c"]}, "results": []}),
            json.dumps(
                {"paths": {"scanned": ["libavformat/rtspenc.c"]}, "results": [{}], "errors": []}
            ),
        ):
            with self.subTest(payload=payload):
                self.stub_json = payload
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)
                self.assertTrue(step.output.startswith("command rc: 0\nscan finished"))

    def test_waiver_on_rc_one_and_rc_two(self) -> None:
        """A non-blank reason waives rc 1 with waived: first; blank fails; rc 2 stays 2."""
        self.stub_rc = 1
        self.stub_json = json.dumps(
            {
                "paths": {"scanned": ["libavformat/rtspenc.c"]},
                "results": [
                    {
                        "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                        "path": "libavformat/rtspenc.c",
                        "start": {"line": 11},
                        "end": {"line": 12},
                        "extra": {"message": "call ff_network_close()"},
                    }
                ],
                "errors": [],
            }
        )
        waived = self.run_c_rules("caller closes network")
        self.assertEqual(waived.rc, 0, waived.output)
        self.assertEqual(waived.output.splitlines()[0], "waived: caller closes network")
        self.assertIn("finding: libavformat/rtspenc.c:11:", waived.output)
        self.assertNotIn("pass --c-rule-reason", waived.output)

        blank = self.run_c_rules("   ")
        self.assertEqual(blank.rc, 1, blank.output)
        self.assertNotIn("waived:", blank.output)

        self.stub_rc = 127
        self.stub_stdout = "semgrep: not found\n"
        unwaivable = self.run_c_rules("caller closes network")
        self.assertEqual(unwaivable.rc, 2, unwaivable.output)
        self.assertNotIn("waived:", unwaivable.output)

    def test_empty_rule_id_gives_unwaivable_rc_two(self) -> None:
        """A check_id whose final dotted segment is empty gives non-waivable rc 2."""
        self.stub_rc = 1
        self.stub_stdout = "scan finished\n"
        for check_id in ("rules.", "."):
            with self.subTest(check_id=check_id):
                self.stub_json = json.dumps(
                    {
                        "paths": {"scanned": ["libavformat/rtspenc.c"]},
                        "results": [
                            {
                                "check_id": check_id,
                                "path": "libavformat/rtspenc.c",
                                "start": {"line": 11},
                                "end": {"line": 12},
                                "extra": {"message": "call ff_network_close()"},
                            }
                        ],
                        "errors": [],
                    }
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)
                waived = self.run_c_rules("caller closes network")
                self.assertEqual(waived.rc, 2, waived.output)
                self.assertNotIn("waived:", waived.output)

    def test_unscanned_result_path_gives_unwaivable_rc_two(self) -> None:
        """A result path absent from the scanned path list gives non-waivable rc 2."""
        self.stub_rc = 1
        self.stub_stdout = "scan finished\n"
        for result_path in (
            "libavformat/rtsp.c",
            "./libavformat/rtspenc.c",
            "/fixture/ffmpeg/libavformat/rtspenc.c",
        ):
            with self.subTest(result_path=result_path):
                self.stub_json = json.dumps(
                    {
                        "paths": {"scanned": ["libavformat/rtspenc.c"]},
                        "results": [
                            {
                                "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                                "path": result_path,
                                "start": {"line": 11},
                                "end": {"line": 12},
                                "extra": {"message": "call ff_network_close()"},
                            }
                        ],
                        "errors": [],
                    }
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)
                waived = self.run_c_rules("caller closes network")
                self.assertEqual(waived.rc, 2, waived.output)
                self.assertNotIn("waived:", waived.output)

    def test_semgrep_span_boundaries_give_rc_two(self) -> None:
        """Boolean, zero and inverted start/end line numbers give step rc 2."""
        self.stub_rc = 1
        for start_line, end_line in ((True, 11), (11, True), (0, 11), (12, 11)):
            with self.subTest(start=start_line, end=end_line):
                self.stub_json = json.dumps(
                    {
                        "paths": {"scanned": ["libavformat/rtspenc.c"]},
                        "results": [
                            {
                                "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                                "path": "libavformat/rtspenc.c",
                                "start": {"line": start_line},
                                "end": {"line": end_line},
                                "extra": {"message": "call ff_network_close()"},
                            }
                        ],
                        "errors": [],
                    }
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)

    def test_partial_parsing_boundaries_give_rc_two(self) -> None:
        """Empty error paths, non-matching list types and string errors give rc 2."""
        for error_entry in (
            {"type": "PartialParsing", "path": ""},
            {"type": [], "path": "libavformat/rtspenc.c"},
            {"type": ["Syntax error"], "path": "libavformat/rtspenc.c"},
            {"type": "PartialParsing", "path": ["libavformat/rtspenc.c"]},
            "PartialParsing",
        ):
            with self.subTest(error=error_entry):
                self.stub_json = json.dumps(
                    {
                        "paths": {"scanned": ["libavformat/rtspenc.c"]},
                        "results": [],
                        "errors": [error_entry],
                    }
                )
                step = self.run_c_rules()
                self.assertEqual(step.rc, 2, step.output)


class UnreadWaiverTest(unittest.TestCase):
    """Fixture-only dated unread-file waivers with a fixed injected run date."""

    def setUp(self) -> None:
        """Create the scanner stub and a category C waiver entered on November 9."""
        self.fixture = CRulesTest()
        self.fixture.setUp()
        self.entry = {
            "path": "libavformat/rtspenc.c",
            "rule": "c-rules-unread",
            "reason": "touched lines checked by hand",
            "category": "C",
            "entered": "2026-11-09",
        }
        self.today = date(2026, 11, 18)

    def run_case(
        self,
        entries: list[dict[str, object]] | None = None,
        *,
        reason: str = "",
        unread: bool = True,
    ) -> upstream_lint.Step:
        """Parse CLI waivers and collect only the c-rules step with scanner fixtures."""
        entries = entries if entries is not None else [self.entry]
        values = [json.dumps(entries[index]) for index in range(len(entries))]
        return self.run_values(values, reason=reason, unread=unread)

    def run_values(
        self,
        values: list[str],
        *,
        reason: str = "",
        unread: bool = True,
        report: Path | None = None,
    ) -> upstream_lint.Step:
        """Capture CLI output, exit status and preparation with raw waiver arguments."""
        argv = ["--tree", ".", "--base", "base", "--c-rule-reason", reason]
        for index in range(len(values)):
            argv.extend(["--c-rule-unread-waiver", values[index]])
        if report is not None:
            argv.extend(["--report", str(report)])
        if unread:
            self.fixture.stub_json = json.dumps(self.fixture.syntax_error_payload())
        captured: list[upstream_lint.Step] = []

        def checks(tree, base, head, waivers):
            """Capture one c-rules result without running any other pipeline step."""
            captured.append(
                self.fixture.run_c_rules(waivers.c_rule, getattr(waivers, "unread", ()))
            )
            return captured

        self.clock = unittest.mock.Mock(return_value=self.today)
        self.preparation = unittest.mock.Mock(return_value=("base", "head"))
        output = io.StringIO()
        with (
            unittest.mock.patch.object(upstream_lint, "_prepare", self.preparation),
            unittest.mock.patch.object(upstream_lint, "_checks", side_effect=checks),
            unittest.mock.patch.object(upstream_lint, "_TODAY", self.clock, create=True),
            contextlib.redirect_stdout(output),
        ):
            self.process_rc = upstream_lint.main(argv)
        self.output = output.getvalue()
        return captured[0]

    def assert_usage(self, entries: list[dict[str, object]], field: str) -> None:
        """Require field-specific exit two before any preparation or scanner call."""
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as caught:
            self.run_case(entries)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn(field, output.getvalue())
        self.assertNotIn("unrecognized arguments", output.getvalue())
        self.assertEqual(self.fixture.calls, [])

    def assert_value_usage(self, values: list[str], expected: str) -> str:
        """Require a bounded usage error before preparation or scanner execution."""
        output = io.StringIO()
        with (
            unittest.mock.patch.object(sys, "argv", ["upstream_lint.py"]),
            contextlib.redirect_stderr(output),
            self.assertRaises(SystemExit) as caught,
        ):
            usage = upstream_lint._parser().format_usage()
            self.run_values(values)
        self.assertEqual(caught.exception.code, 2)
        message = output.getvalue().splitlines()[-1]
        self.assertIn(expected, message)
        self.assertLessEqual(len(message), 256)
        self.assertLessEqual(len(output.getvalue()), len(usage) + 257)
        self.assertEqual(output.getvalue().count("error:"), 1)
        self.preparation.assert_not_called()
        self.assertEqual(self.fixture.calls, [])
        return message

    def test_date_source_called_once(self) -> None:
        """All waivers use exactly one reading of the injectable date source."""
        self.run_case([])
        self.clock.assert_called_once_with()

    def test_live_waiver(self) -> None:
        """One exact live waiver passes and prints its category, expiry and reason."""
        step = self.run_case()
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("waived: libavformat/rtspenc.c: category C, expires 2026-11-19", step.output)
        self.assertIn(self.entry["reason"], step.output)

    def test_expired_waiver(self) -> None:
        """An expired exception fails even with the legacy free reason supplied."""
        self.today = date(2026, 11, 20)
        step = self.run_case(reason="checked by hand")
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("expired: libavformat/rtspenc.c: category C, expired 2026-11-19", step.output)
        self.assertNotIn("waived:", step.output)

    def test_expiry_day_and_day_after(self) -> None:
        """Expiry day passes; the following day fails with the same expiry date."""
        for day in range(19, 21):
            with self.subTest(day=day):
                self.today = date(2026, 11, day)
                step = self.run_case()
                self.assertEqual(step.rc, day - 19, step.output)
                self.assertIn("2026-11-19", step.output)

    def test_no_waiver(self) -> None:
        """An unread file needs an exact dated waiver and names the missing path."""
        step = self.run_case([])
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("no waiver: libavformat/rtspenc.c", step.output)

    def test_free_reason_alone(self) -> None:
        """The free finding reason cannot excuse an unread file."""
        step = self.run_case([], reason="checked by hand")
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("no waiver: libavformat/rtspenc.c", step.output)

    def test_two_unread_files_one_waiver(self) -> None:
        """One waiver leaves the second unread path failing and explicitly unwaived."""
        self.fixture.diff_names += "libavformat/rtsp.c\0"
        self.fixture.patches["libavformat/rtsp.c"] = "@@ -10,0 +11 @@\n+x\n"
        payload = self.fixture.syntax_error_payload()
        payload["paths"] = {"scanned": [self.entry["path"], "libavformat/rtsp.c"]}
        payload["errors"].append({"type": "Syntax error", "path": "libavformat/rtsp.c"})
        self.fixture.stub_json = json.dumps(payload)
        step = self.run_case(unread=False)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("waived: libavformat/rtspenc.c: category C", step.output)
        self.assertIn("no waiver: libavformat/rtsp.c:", step.output)

    def test_two_live_waivers(self) -> None:
        """Repeating the option grants a separate live waiver to each unread file."""
        self.fixture.diff_names += "libavformat/rtsp.c\0"
        self.fixture.patches["libavformat/rtsp.c"] = "@@ -10,0 +11 @@\n+x\n"
        payload = self.fixture.syntax_error_payload()
        payload["paths"] = {"scanned": [self.entry["path"], "libavformat/rtsp.c"]}
        payload["errors"].append({"type": "Syntax error", "path": "libavformat/rtsp.c"})
        self.fixture.stub_json = json.dumps(payload)
        step = self.run_case(
            [self.entry, {**self.entry, "path": "libavformat/rtsp.c"}], unread=False
        )
        self.assertEqual(step.rc, 0, step.output)
        self.assertEqual(step.output.count("waived:"), 2)

    def test_unused_waiver(self) -> None:
        """A waiver for a readable file fails rather than silently accumulating."""
        step = self.run_case(unread=False)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("unused waiver: libavformat/rtspenc.c", step.output)

    def test_unused_waiver_without_sources(self) -> None:
        """A waiver is unused even when no changed C sources trigger a scanner run."""
        self.fixture.diff_names = ""
        step = self.run_case(unread=False)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("unused waiver: libavformat/rtspenc.c", step.output)
        self.assertEqual(self.fixture.calls, [])

    def test_unused_order_with_sources(self) -> None:
        """Unused and unread statuses sort by exact path in either argument order."""
        paths = ("a.c", "z.c")
        entries = [{**self.entry, "path": paths[index]} for index in range(len(paths))]
        expected = [
            "unused waiver: a.c",
            (
                "unread: libavformat/rtspenc.c: rules could not read this file; "
                "touched lines need a check by hand"
            ),
            "no waiver: libavformat/rtspenc.c: pass --c-rule-unread-waiver",
            "unused waiver: z.c",
        ]
        for index in range(2):
            with self.subTest(reverse=index):
                step = self.run_case(entries[:: 1 if index == 0 else -1])
                self.assertEqual(step.rc, 1, step.output)
                self.assertEqual(step.output.splitlines(), expected)

    def test_unused_order_without_sources(self) -> None:
        """Unused statuses sort identically without sources in either argument order."""
        self.fixture.diff_names = ""
        paths = ("a.c", "z.c")
        entries = [{**self.entry, "path": paths[index]} for index in range(len(paths))]
        for index in range(2):
            with self.subTest(reverse=index):
                step = self.run_case(entries[:: 1 if index == 0 else -1], unread=False)
                self.assertEqual(step.rc, 1, step.output)
                self.assertEqual(
                    step.output.splitlines(), ["unused waiver: a.c", "unused waiver: z.c"]
                )
        self.assertEqual(self.fixture.calls, [])

    def test_path_is_exact(self) -> None:
        """A different spelling waives no unread path and is reported unused."""
        step = self.run_case([{**self.entry, "path": "./libavformat/rtspenc.c"}])
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("no waiver: libavformat/rtspenc.c", step.output)
        self.assertIn("unused waiver: ./libavformat/rtspenc.c", step.output)

    def test_categories_and_a_boundaries(self) -> None:
        """Fixed categories and A's one-day and ninety-day limits share date validation."""
        cases = (
            ("B", None, "2026-11-12"),
            ("C", None, "2026-11-19"),
            ("D", None, "2027-03-09"),
            ("A", "2026-11-10", "2026-11-10"),
            ("A", "2027-02-07", "2027-02-07"),
        )
        self.today = date(2026, 11, 9)
        for index in range(len(cases)):
            category, expires, expected = cases[index]
            with self.subTest(category=category, expires=expires):
                entry = {**self.entry, "category": category}
                if expires:
                    entry["expires"] = expires
                step = self.run_case([entry])
                self.assertEqual(step.rc, 0, step.output)
                self.assertIn(f"category {category}, expires {expected}", step.output)

    def test_usage_unknown_field(self) -> None:
        """Unknown fields cannot silently extend the waiver schema."""
        self.assert_usage([{**self.entry, "extra": "typo"}], "extra")

    def test_usage_long_unknown_key(self) -> None:
        """A ten-thousand-character unknown key produces a bounded cut diagnostic."""
        value = json.dumps({**self.entry, "x" * 10000: "typo"})
        message = self.assert_value_usage([value], "unknown field: " + "x" * 157 + "...")
        self.assertTrue(message.endswith("x" * 157 + "..."))

    def test_usage_long_duplicate_path(self) -> None:
        """A ten-thousand-character duplicate path is bounded before scanning."""
        value = json.dumps({**self.entry, "path": "x" * 10000})
        self.assert_value_usage([value, value], "duplicate waiver for " + "x" * 157 + "...")

    def test_usage_long_duplicate_key(self) -> None:
        """Duplicate JSON keys share the escaped 160-character diagnostic limit."""
        key = json.dumps("x" * 10000)
        value = "{" + key + ":1," + key + ":2}"
        self.assert_value_usage([value], "duplicate field: " + "x" * 157 + "...")

    def test_usage_control_values_are_escaped(self) -> None:
        """Unknown keys, duplicate keys and duplicate paths escape control characters."""
        key = "line\n\r\t\x1b\x00"
        encoded = json.dumps(key)
        values = (
            json.dumps({**self.entry, key: "typo"}),
            "{" + encoded + ":1," + encoded + ":2}",
            json.dumps({**self.entry, "path": key}),
        )
        for index in range(len(values)):
            with self.subTest(kind=index):
                arguments = [values[index]] * (2 if index == 2 else 1)
                self.assert_value_usage(arguments, r"line\n\r\t\u001b\u0000")

    def test_usage_oversize_argument_before_json(self) -> None:
        """Arguments above 65536 characters fail before JSON decoding or scanning."""
        with unittest.mock.patch.object(upstream_lint.json, "loads") as decode:
            self.assert_value_usage([" " * 65537], "waiver exceeds 65536 characters")
        decode.assert_not_called()

    def test_argument_length_boundary(self) -> None:
        """An exactly 65536-character legitimate waiver remains accepted."""
        entry = {**self.entry, "reason": ""}
        entry["reason"] = "x" * (65536 - len(json.dumps(entry)))
        value = json.dumps(entry)
        self.assertEqual(len(value), 65536)
        step = self.run_values([value])
        self.assertEqual(self.process_rc, 0, self.output)
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("expires 2026-11-19: " + entry["reason"], step.output)

    def test_argument_capacity_for_long_path_and_reason(self) -> None:
        """The input budget fits a 4096-character path and 1024-character reason."""
        entry = {
            **self.entry,
            "path": "\U00010000" * 4096,
            "reason": "\U00010000" * 1024,
            "expires": "2026-11-19",
        }
        value = json.dumps(entry)
        self.assertLessEqual(len(value), 65536)
        step = self.run_values([value])
        self.assertEqual(self.process_rc, 1, self.output)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("unused waiver: " + r"\ud800\udc00" * 4096, step.output)

    def test_reason_control_text_stays_on_one_line(self) -> None:
        """Accepted multiline reasons appear escaped on one physical waiver line."""
        step = self.run_case([{**self.entry, "reason": "checked\nnext\r\t\x1b line"}])
        self.assertEqual(self.process_rc, 0, self.output)
        self.assertEqual(step.rc, 0, step.output)
        self.assertEqual(len(step.output.splitlines()), 2)
        self.assertTrue(step.output.endswith(r"checked\nnext\r\t\u001b line"))

    def test_path_control_text_stays_on_one_line(self) -> None:
        """Exact multiline paths stay escaped for live, expired, missing and unused statuses."""
        path = "dir/line\nnext\r\t\x1b.c"
        display = r"dir/line\nnext\r\t\u001b.c"
        entries = upstream_lint._parse_unread_waivers(
            [json.dumps({**self.entry, "path": path})], self.today
        )
        live = upstream_lint._unread_report([path], entries)
        self.assertEqual(live.rc, 0, live.output)
        self.assertEqual(len(live.output.splitlines()), 2)
        self.assertIn(f"waived: {display}: category C", live.output)
        missing = upstream_lint._unread_report([path], ())
        self.assertEqual(missing.rc, 1, missing.output)
        self.assertEqual(len(missing.output.splitlines()), 2)
        self.assertIn(f"no waiver: {display}:", missing.output)
        expired_entries = upstream_lint._parse_unread_waivers(
            [json.dumps({**self.entry, "path": path})], date(2026, 11, 20)
        )
        expired = upstream_lint._unread_report([path], expired_entries)
        self.assertEqual(expired.rc, 1, expired.output)
        self.assertEqual(len(expired.output.splitlines()), 2)
        self.assertIn(f"expired: {display}: category C", expired.output)
        step = self.run_case([{**self.entry, "path": path}])
        self.assertEqual(self.process_rc, 1, self.output)
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(len(step.output.splitlines()), 3)
        self.assertIn(f"unused waiver: {display}", step.output)

    def two_source_payload(self) -> dict[str, object]:
        """Add a second changed C source beside the default unread source."""
        self.fixture.diff_names += "libavformat/rtsp.c\0"
        self.fixture.patches["libavformat/rtsp.c"] = "@@ -10,0 +11 @@\n+x\n"
        payload = self.fixture.syntax_error_payload()
        payload["paths"] = {"scanned": [self.entry["path"], "libavformat/rtsp.c"]}
        return payload

    def test_mixed_expired_and_live_waivers(self) -> None:
        """A live waiver beside an expired waiver cannot clear the run's failure."""
        self.today = date(2026, 11, 20)
        payload = self.two_source_payload()
        payload["errors"].append({"type": "Syntax error", "path": "libavformat/rtsp.c"})
        self.fixture.stub_json = json.dumps(payload)
        live = {**self.entry, "path": "libavformat/rtsp.c", "entered": "2026-11-19"}
        step = self.run_case([self.entry, live], unread=False)
        self.assertEqual(self.process_rc, 1, self.output)
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(
            step.output.splitlines(),
            [
                (
                    "unread: libavformat/rtsp.c: rules could not read this file; "
                    "touched lines need a check by hand"
                ),
                (
                    "waived: libavformat/rtsp.c: category C, expires 2026-11-29: "
                    "touched lines checked by hand"
                ),
                (
                    "unread: libavformat/rtspenc.c: rules could not read this file; "
                    "touched lines need a check by hand"
                ),
                "expired: libavformat/rtspenc.c: category C, expired 2026-11-19",
            ],
        )

    def test_readable_finding_beside_unread_waiver(self) -> None:
        """A dated unread waiver leaves readable findings needing their own free reason."""
        payload = self.two_source_payload()
        payload["results"] = [
            {
                "check_id": "ffmpeg-rtsp-connect-failure-without-network-close",
                "path": "libavformat/rtsp.c",
                "start": {"line": 11},
                "end": {"line": 11},
                "extra": {"message": "missing ff_network_close()"},
            }
        ]
        self.fixture.stub_rc = 1
        self.fixture.stub_json = json.dumps(payload)
        reasons = ("", "checked finding by hand")
        for index in range(len(reasons)):
            with self.subTest(reason=reasons[index]):
                step = self.run_case(reason=reasons[index], unread=False)
                self.assertEqual(self.process_rc, 1 - index, self.output)
                self.assertEqual(step.rc, 1 - index, step.output)
                expected = [
                    (
                        "finding: libavformat/rtsp.c:11: "
                        "ffmpeg-rtsp-connect-failure-without-network-close: "
                        "missing ff_network_close()"
                    ),
                    (
                        "unread: libavformat/rtspenc.c: rules could not read this file; "
                        "touched lines need a check by hand"
                    ),
                    (
                        "waived: libavformat/rtspenc.c: category C, expires 2026-11-19: "
                        "touched lines checked by hand"
                    ),
                ]
                if index:
                    expected.insert(0, "waived: checked finding by hand")
                else:
                    expected.append("fix the flagged path, or pass --c-rule-reason")
                self.assertEqual(step.output.splitlines(), expected)

    def test_unread_report_matches_stdout(self) -> None:
        """The report option saves exactly the unread and unused statuses on stdout."""
        values = [json.dumps(self.entry), json.dumps({**self.entry, "path": "z.c"})]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            step = self.run_values(values, report=report)
            self.assertEqual(self.process_rc, 1, self.output)
            self.assertEqual(step.rc, 1, step.output)
            self.assertEqual(report.read_text(encoding="utf-8"), self.output)
        self.assertEqual(
            step.output.splitlines(),
            [
                (
                    "unread: libavformat/rtspenc.c: rules could not read this file; "
                    "touched lines need a check by hand"
                ),
                (
                    "waived: libavformat/rtspenc.c: category C, expires 2026-11-19: "
                    "touched lines checked by hand"
                ),
                "unused waiver: z.c",
            ],
        )

    def test_usage_waiver_count_limit(self) -> None:
        """More than 2000 waivers fail usage before parsing, preparation or scanning."""
        with unittest.mock.patch.object(upstream_lint.json, "loads") as decode:
            self.assert_value_usage([json.dumps(self.entry)] * 2001, "at most 2000 waivers")
        decode.assert_not_called()

    def test_usage_missing_fields(self) -> None:
        """Every required field is named when missing from a waiver."""
        fields = sorted(self.entry)
        for index in range(len(fields)):
            entry = self.entry.copy()
            del entry[fields[index]]
            self.assert_usage([entry], fields[index])

    def test_usage_empty_reason_and_field_types(self) -> None:
        """Empty or non-string fields fail usage validation before scanning."""
        cases = (
            ("reason", ""),
            ("reason", "   "),
            ("reason", None),
            ("path", ""),
            ("path", []),
            ("entered", 20261109),
            ("expires", ""),
        )
        for index in range(len(cases)):
            field, value = cases[index]
            self.assert_usage([{**self.entry, field: value}], field)

    def test_usage_category(self) -> None:
        """Unknown categories fail instead of acquiring an arbitrary interval."""
        self.assert_usage([{**self.entry, "category": "E"}], "category")

    def test_usage_rule(self) -> None:
        """Only the unread result class accepts this waiver."""
        self.assert_usage([{**self.entry, "rule": "PartialParsing"}], "rule")

    def test_usage_invalid_dates(self) -> None:
        """Invalid calendar dates and non-ISO spellings name the date field."""
        cases = (
            ("entered", "2026-02-30"),
            ("entered", "20261109"),
            ("entered", "2026-1-09"),
            ("expires", "2026-02-30"),
            ("expires", "20261119"),
            ("expires", "2026-11-19T00:00:00"),
        )
        for index in range(len(cases)):
            field, value = cases[index]
            self.assert_usage([{**self.entry, field: value}], field)

    def test_usage_future_entered(self) -> None:
        """An exception cannot be recorded after the run's injected day."""
        self.assert_usage([{**self.entry, "entered": "2026-11-19"}], "entered")

    def test_usage_category_intervals(self) -> None:
        """Fixed interval mismatches and A's missing or out-of-range expiry fail."""
        cases = (
            ("B", "2026-11-13"),
            ("C", "2026-11-18"),
            ("D", "2027-03-08"),
            ("A", None),
            ("A", "2026-11-09"),
            ("A", "2027-02-08"),
            ("A", "2026-11-08"),
        )
        for index in range(len(cases)):
            category, expires = cases[index]
            entry = {**self.entry, "category": category}
            if expires:
                entry["expires"] = expires
            self.assert_usage([entry], "expires")

    def test_usage_duplicate_file(self) -> None:
        """Repeated paths are usage errors even when the supplied reasons differ."""
        self.assert_usage([self.entry, {**self.entry, "reason": "second review"}], "path")

    def test_usage_json_and_duplicate_fields(self) -> None:
        """Malformed JSON, non-objects and repeated fields are explicit usage errors."""
        values = ("{", "[]", "null", '{"path":"one","path":"two"}')
        for index in range(len(values)):
            output = io.StringIO()
            with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as caught:
                upstream_lint.main(
                    ["--tree", ".", "--base", "base", "--c-rule-unread-waiver", values[index]]
                )
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("JSON" if index < 3 else "path", output.getvalue())
            self.assertNotIn("unrecognized arguments", output.getvalue())

    def test_usage_deep_nesting_recursion_error(self) -> None:
        """Deeply nested waiver JSON turns RecursionError into an explicit usage error."""
        output = io.StringIO()
        with (
            unittest.mock.patch.object(upstream_lint.json, "loads", side_effect=RecursionError),
            unittest.mock.patch.object(upstream_lint, "_prepare") as prepare,
            unittest.mock.patch.object(upstream_lint, "_checks") as checks,
            contextlib.redirect_stderr(output),
            self.assertRaises(SystemExit) as caught,
        ):
            upstream_lint.main(["--tree", ".", "--base", "base", "--c-rule-unread-waiver", "{}"])
        stderr = output.getvalue()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--c-rule-unread-waiver: JSON: waiver nesting too deep", stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("RecursionError", stderr)
        prepare.assert_not_called()
        checks.assert_not_called()

    def test_unread_waiver_object_rejects_recursion_error(self) -> None:
        """Direct waiver JSON decoding translates RecursionError into ValueError."""
        with (
            unittest.mock.patch.object(upstream_lint.json, "loads", side_effect=RecursionError),
            self.assertRaises(ValueError) as caught,
        ):
            upstream_lint._unread_waiver_object("{}")
        self.assertEqual(str(caught.exception), "JSON: waiver nesting too deep")

    def test_unread_waiver_cannot_waive_tool_errors(self) -> None:
        """Valid dated waivers leave tool, warning and JSON failures at rc two."""
        cases = (
            (127, "", self.fixture.syntax_error_payload()),
            (0, "semgrep_scan: warning", self.fixture.syntax_error_payload()),
            (0, "", {"paths": {"scanned": []}, "results": [], "errors": []}),
            (0, "", {**self.fixture.syntax_error_payload(), "errors": [{"type": "Other"}]}),
        )
        for index in range(len(cases)):
            self.fixture.stub_rc, self.fixture.stub_stdout, payload = cases[index]
            self.fixture.stub_json = json.dumps(payload)
            step = self.run_case(reason="manual review", unread=False)
            self.assertEqual(step.rc, 2, step.output)
            self.assertNotIn("waived:", step.output)


class RevertProofStepTest(FixtureTest):
    """Test the revert-proof step in scripts/upstream_lint.py with temporary Git repositories."""

    def test_tree_replacement_cannot_hide_source_fix(self) -> None:
        """A documentation-only replacement tree cannot hide a stored source-only fix."""
        self.git("rm", "-rf", ".")
        self.commit("empty fixture base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("libavfilter/vf_x.c", SOURCE)
        self.commit("avfilter/vf_x: fix source value")
        fix = self.git("rev-parse", "HEAD").strip()
        stored_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        plain = self.proof_step()
        self.assertEqual(plain.rc, 1, plain.output)
        self.assertIn("no revert-proof record", plain.output)
        self.git("checkout", "--detach", self.base)
        self.write("doc/manual.txt", "replacement documentation\n")
        self.commit("doc: replacement fixture")
        replacement_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.git("checkout", "--detach", fix)
        self.git("replace", stored_tree, replacement_tree)
        self.assertEqual(
            self.git("diff-tree", "--name-only", "-r", fix).splitlines()[1:], ["doc/manual.txt"]
        )
        replaced = self.proof_step()
        self.assertEqual((replaced.rc, replaced.output), (plain.rc, plain.output))

    def test_tree_replacement_cannot_change_fix_patch(self) -> None:
        """Replacing a fix tree with its parent cannot remove stored patch function names."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix source value")
        fix = self.git("rev-parse", "HEAD").strip()
        stored_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        parent_tree = self.git("rev-parse", f"{self.base}^{{tree}}").strip()
        plain = upstream_lint._fix_commits(self.root, self.base, fix)
        self.assertIn("ff_value", plain[0][2])
        self.git("replace", stored_tree, parent_tree)
        self.assertEqual(upstream_lint._fix_commits(self.root, self.base, fix), plain)

    def test_loaded_records_retain_only_verdicts_and_pass_status(self) -> None:
        """Mixed duplicate records retain verdict strings and pass status without payloads."""
        commit, head, head_tree = self.add_fix_commit()
        failing = self.write_record(
            "failing.json", self.valid_record(commit, head, head_tree, rc_reverted=0)
        )
        passing = self.write_record("passing.json", self.valid_record(commit, head, head_tree))
        loaded = []
        real_load = upstream_lint._load_revert_proofs

        def capture_load(*args):
            """Capture the actual retained structure without depending on private arguments."""
            result = real_load(*args)
            loaded.append(result)
            return result

        with unittest.mock.patch.object(upstream_lint, "_load_revert_proofs", capture_load):
            step = self.proof_step(failing, passing)
        self.assertEqual((step.rc, step.output), (0, "1 fix commit(s), 2 revert-proof record(s)"))
        self.assertEqual(
            loaded,
            [({commit: (["rc_reverted is 0 (test passes without the fix)"], True)}, {}, [])],
        )

    def test_signature_display_keeps_fix_and_parent_records_parseable(self) -> None:
        """Signed commits yield identical proof findings with signature display enabled."""
        configure_ssh_signing(self.root, self.root.parent)
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.git("add", ".")
        run_git(
            self.root,
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-qm",
            "avfilter/vf_x: fix signed value",
            preserve_config=True,
        )
        commit = self.git("rev-parse", "HEAD").strip()
        self.assertIn("gpgsig", self.git("cat-file", "commit", commit))
        self.git("config", "log.showSignature", "false")
        unsigned_display = self.proof_step()
        plain_parents = upstream_lint._commit_history_error(self.root, commit)
        self.git("config", "log.showSignature", "true")
        signed_display = self.proof_step()
        self.assertEqual(
            (signed_display.rc, signed_display.output),
            (unsigned_display.rc, unsigned_display.output),
        )
        self.assertEqual(upstream_lint._commit_history_error(self.root, commit), plain_parents)

    def test_scan_limits_respect_only_nonblank_waivers(self) -> None:
        """Path and commit scan caps admit nonblank waivers while retaining their diagnostics."""
        self.add_fix_commit()
        for cap, diagnostic in (
            (1, "commit paths exceed MAX_PATHS=1"),
            (0, "commit scan exceeds MAX_PATHS=0"),
        ):
            with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", cap):
                for reason, expected in (("manual verification", 0), ("", 1), (" \t ", 1)):
                    with self.subTest(cap=cap, reason=reason):
                        step = upstream_lint._revert_proof(
                            self.root, self.base, "HEAD", waiver=reason
                        )
                        self.assertEqual(step.rc, expected, step.output)
                        self.assertIn(diagnostic, step.output)
                        if expected == 0:
                            self.assertTrue(step.output.startswith("waived: manual verification\n"))
                        else:
                            self.assertNotIn("waived:", step.output)

    def test_git_runtime_error_cannot_be_waived(self) -> None:
        """A plain Git failure remains a failing step even with an explicit waiver."""
        with unittest.mock.patch.object(
            upstream_lint, "_git", side_effect=RuntimeError("git failed")
        ):
            step = upstream_lint._revert_proof(self.root, self.base, "HEAD", waiver="manual")
        self.assertEqual((step.rc, step.output), (1, "git failed"))

    def test_fifo_record_is_refused_without_waiting_for_writer(self) -> None:
        """A writerless FIFO produces a regular-file diagnostic within a bounded child."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("os.mkfifo is unavailable; writerless FIFO fixture unsupported")
        record = self.root.parent / "record.fifo"
        os.mkfifo(record)
        program = (
            "import sys; from pathlib import Path; from scripts import upstream_lint; "
            "step = upstream_lint._revert_proof(Path(sys.argv[1]), sys.argv[2], 'HEAD', "
            "(Path(sys.argv[3]),)); print(step.output); sys.exit(step.rc)"
        )
        result = subprocess.run(  # nosec B603 - fixed Python and fixture paths, no shell.
            [sys.executable, "-B", "-c", program, str(self.root), self.base, str(record)],
            cwd=upstream_lint.REPO_ROOT,
            env=isolated_git_environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"{record}: not a regular file", result.stdout)

    def test_directory_record_is_refused_as_nonregular(self) -> None:
        """A directory receives the same explicit regular-file diagnostic as a FIFO."""
        step = self.proof_step(self.root)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"{self.root}: not a regular file", step.output)

    def test_record_descriptors_close_on_success_and_errors(self) -> None:
        """Regular reads, nonregular refusals and descriptor errors never leak an open file."""
        record = self.write_record("regular.json", self.valid_record(*self.add_fix_commit()))
        for path in (record, self.root):
            with (
                self.subTest(path=path),
                unittest.mock.patch.object(os, "close", wraps=os.close) as close,
            ):
                upstream_lint._read_revert_proof(path)
                close.assert_called_once()
                with self.assertRaises(OSError):
                    os.fstat(close.call_args.args[0])
        for operation in ("fstat", "fdopen"):
            with (
                self.subTest(operation=operation),
                unittest.mock.patch.object(
                    os, operation, side_effect=OSError("planted read failure")
                ),
                unittest.mock.patch.object(os, "close", wraps=os.close) as close,
            ):
                result = upstream_lint._read_revert_proof(record)
                self.assertEqual(result[2], f"{record}: not valid JSON")
                close.assert_called_once()

    def test_record_hex_width_and_case_boundaries(self) -> None:
        """Lowercase SHA-256 IDs validate while short and uppercase IDs remain type errors."""
        commit, head, head_tree = self.add_fix_commit()
        for field in ("commit", "head", "head_tree"):
            with self.subTest(field=field):
                payload = self.valid_record(commit, head, head_tree, **{field: "a" * 64})
                self.assertIsNone(upstream_lint._revert_proof_schema_error(payload))
                for invalid in ("a" * 63, "A" * 40):
                    payload[field] = invalid
                    self.assertEqual(
                        upstream_lint._revert_proof_schema_error(payload),
                        f"wrong value type for {field}",
                    )

    def test_sha256_unmatched_record_is_silent_in_sha1_range(self) -> None:
        """A valid 64-hex record outside a SHA-1 fix range produces no schema finding."""
        self.add_fix_commit()
        record = self.write_record("unmatched.json", self.valid_record(*(["a" * 64] * 3)))
        step = self.proof_step(record)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("no revert-proof record", step.output)
        self.assertNotIn(str(record), step.output)
        self.assertNotIn("wrong value type", step.output)

    def test_docs_only_range_validates_supplied_records(self) -> None:
        """Neutral ranges report malformed records while accepting absent or unrelated records."""
        self.write("doc/manual.txt", "neutral documentation\n")
        self.commit("doc: update manual")
        self.assertEqual(self.proof_step().rc, 0)
        record = self.write_record("unmatched.json", self.valid_record(*([self.base] * 3)))
        self.assertEqual(self.proof_step(record).rc, 0)
        for text, diagnostic in (("broken JSON", "not valid JSON"), ("{}", "missing key")):
            with self.subTest(text=text):
                record.write_text(text, encoding="utf-8")
                step = self.proof_step(record)
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn(f"{record}: {diagnostic}", step.output)
                self.assertEqual(len(step.output.splitlines()), 1)
                waived = upstream_lint._revert_proof(
                    self.root, self.base, "HEAD", (record,), "manual verification"
                )
                self.assertEqual(waived.rc, 0, waived.output)
                self.assertIn("waived: manual verification", waived.output)

    def test_fix_cap_respects_nonblank_waiver(self) -> None:
        """Only a nonblank waiver overrides the fix cap and skips per-fix validation."""
        self.add_fix_commit()
        self.add_fix_commit("libavfilter/vf_y.c", "avfilter/vf_y: fix second")
        cap = "fix commits exceed MAX_CLAIM_COMMITS=1: 2"
        with (
            unittest.mock.patch.object(upstream_lint, "MAX_CLAIM_COMMITS", 1),
            unittest.mock.patch.object(
                upstream_lint, "_load_revert_proofs", side_effect=AssertionError("over cap")
            ),
        ):
            for reason, expected in (("manual verification", 0), ("", 1), (" \t ", 1)):
                with self.subTest(reason=reason):
                    step = upstream_lint._revert_proof(self.root, self.base, "HEAD", waiver=reason)
                    self.assertEqual(step.rc, expected, step.output)
                    self.assertEqual(
                        step.output, f"waived: {reason}\n{cap}" if expected == 0 else cap
                    )

    def test_record_byte_limit_refuses_before_json_parse(self) -> None:
        """Exactly the limit parses, while one byte more is refused before JSON parsing."""
        commit, head, head_tree = self.add_fix_commit()
        record = self.write_record("oversized.json", self.valid_record(commit, head, head_tree))
        encoded = record.read_bytes()
        limit = len(encoded) + 16
        record.write_bytes(encoded + b" " * 16)
        with unittest.mock.patch.object(upstream_lint, "MAX_RECORD_BYTES", limit, create=True):
            step = self.proof_step(record)
        self.assertEqual(step.rc, 0, step.output)
        record.write_bytes(encoded + b" " * 17)
        with (
            unittest.mock.patch.object(upstream_lint, "MAX_RECORD_BYTES", limit, create=True),
            unittest.mock.patch.object(json, "loads", side_effect=AssertionError("parsed")),
        ):
            payload, bound_commit, error = upstream_lint._read_revert_proof(record)
        self.assertIsNone(payload)
        self.assertIsNone(bound_commit)
        self.assertEqual(error, f"{record}: record exceeds MAX_RECORD_BYTES={limit}")

    def test_noop_graft_cli_demands_source_record(self) -> None:
        """Full CLI preflight admits a no-op graft and demands the source fix record."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix value")
        commit = self.git("rev-parse", "HEAD").strip()
        self.write(".git/info/grafts", f"{self.base}\n")
        self.git("config", "advice.graftFileDeprecated", "true")
        rc, output = self.check("--no-test-reason", "fixture exercises proof demand")
        self.assertEqual(rc, 1, output)
        self.assertNotIn("step: preflight", output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix value", output)
        self.assertIn("no revert-proof record", output)
        self.assertNotIn("history is incomplete", output)

    def test_hidden_graft_cli_reports_named_history_finding(self) -> None:
        """Full CLI reaches the named history finding when a side graft hides its parent."""
        branch = self.git("symbolic-ref", "--short", "HEAD").strip()
        self.git("commit", "--allow-empty", "-qm", "main: advance base")
        base = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-qb", "side", self.base)
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: fix side value")
        commit = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", branch)
        self.git("merge", "--no-ff", "-qm", "merge side history", "side")
        self.base = base
        self.write(".git/info/grafts", f"{commit}\n")
        self.git("config", "advice.graftFileDeprecated", "true")
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertNotIn("step: preflight", output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix side value: {commit}", output)
        self.assertIn("history is incomplete", output)
        self.assertIn("git fetch --unshallow", output)
        self.assertNotIn("no revert-proof record", output)

    def test_shallow_docs_fix_reports_incomplete_history(self) -> None:
        """A docs-only side boundary produces its own history finding without a proof demand."""
        clone = self.root.parent / "shallow"
        base, commit = clone_shallow_side_fix(self.root, clone, "doc/manual.txt")
        self.root, self.base = clone, base
        step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(len(step.output.splitlines()), 1, step.output)
        self.assertIn(commit, step.output)
        self.assertIn("history is incomplete", step.output)
        self.assertIn("fetch --unshallow", step.output)
        self.assertNotIn("no revert-proof record", step.output)
        self.assertNotIn("merge commit", step.output)

    def test_shallow_source_fix_cannot_accept_record_until_history_is_complete(self) -> None:
        """A matching source proof fails at a shallow boundary and passes after local deepening."""
        clone = self.root.parent / "shallow"
        base, commit = clone_shallow_side_fix(self.root, clone, "libavfilter/vf_x.c")
        self.root, self.base = clone, base
        head = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        record = self.write_record("shallow.json", self.valid_record(commit, head, head_tree))
        step = self.proof_step(record)
        self.assertEqual(step.rc, 1, step.output)
        self.assertEqual(len(step.output.splitlines()), 1, step.output)
        self.assertIn(commit, step.output)
        self.assertIn("history is incomplete", step.output)
        self.assertNotIn("no revert-proof record", step.output)
        self.git("fetch", "-q", "--unshallow", "origin")
        complete = self.proof_step(record)
        self.assertEqual(complete.rc, 0, complete.output)
        self.assertIn("1 fix commit(s), 1 revert-proof record(s)", complete.output)

    def test_neutral_shallow_boundary_is_not_silently_skipped(self) -> None:
        """A boundary with no fix wording still reports unknown parents by commit."""
        clone = self.root.parent / "shallow"
        base, commit = clone_shallow_side_fix(
            self.root, clone, "doc/manual.txt", "doc: update wording"
        )
        self.root, self.base = clone, base
        step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(commit, step.output)
        self.assertIn("history is incomplete", step.output)

    def test_imported_true_root_remains_provable_after_history_check(self) -> None:
        """A stored zero-parent source fix keeps the round-seven required-proof result."""
        commit, _, _ = self.import_root_commit(
            "libavfilter/vf_root.c", "avfilter/vf_root: fix imported value"
        )
        step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(commit[:12], step.output)
        self.assertIn("no revert-proof record", step.output)
        self.assertNotIn("history is incomplete", step.output)

    def import_root_commit(self, path: str, subject: str) -> tuple[str, str, str]:
        """Merge an unrelated root into a range whose base remains an ancestor."""
        branch = self.git("symbolic-ref", "--short", "HEAD").strip()
        self.git("checkout", "--orphan", "imported-root")
        self.git("rm", "-rf", ".")
        self.write(path, SOURCE)
        self.commit(subject)
        commit = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", branch)
        self.git(
            "merge",
            "--allow-unrelated-histories",
            "--no-ff",
            "-qm",
            "merge imported history",
            "imported-root",
        )
        head = self.git("rev-parse", "HEAD").strip()
        self.git("merge-base", "--is-ancestor", self.base, head)
        return commit, head, self.git("rev-parse", "HEAD^{tree}").strip()

    def test_imported_root_regression_reaches_function_only_test_reference(self) -> None:
        """An imported root fix passes regression-test when a changed test names only ff_value."""
        self.import_root_commit("libavfilter/vf_root.c", "avfilter/vf_root: fix imported value")
        self.write(
            "libavutil/tests/film_grain_params.c",
            "int main(void)\n{\n    return ff_value();\n}\n",
        )
        self.commit("tests: exercise imported root function")
        rc, output = self.check(
            "--no-revert-proof-reason",
            "regression-test fixture",
            "--no-revert-proof-reason",
            "imported-root fixture",
        )
        self.assertEqual(rc, 0, output)
        self.assertIn("step: regression-test rc: 0", output)
        self.assertIn("1 fix commit(s), 1 test path(s) changed", output)

    def test_imported_root_source_fix_requires_record(self) -> None:
        """An imported root source fix cannot silently pass as a zero-fix range."""
        commit, _, _ = self.import_root_commit(
            "libavfilter/vf_root.c", "avfilter/vf_root: fix imported value"
        )
        step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_root: fix imported value", step.output)
        self.assertIn("no revert-proof record", step.output)

    def test_imported_root_source_fix_accepts_valid_record(self) -> None:
        """A complete matching record satisfies an imported root source fix."""
        commit, head, head_tree = self.import_root_commit(
            "libavfilter/vf_root.c", "avfilter/vf_root: fix imported value"
        )
        record = self.write_record(
            "root.json",
            self.valid_record(commit, head, head_tree, reverted_paths=["libavfilter/vf_root.c"]),
        )
        step = self.proof_step(record)
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("1 fix commit(s), 1 revert-proof record(s)", step.output)

    def test_imported_root_without_fix_wording_is_exempt(self) -> None:
        """An imported root source addition without fix wording remains exempt."""
        self.import_root_commit("libavfilter/vf_root.c", "avfilter/vf_root: add imported value")
        step = self.proof_step()
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("0 fix commit(s)", step.output)

    def test_imported_root_without_library_source_is_exempt(self) -> None:
        """An imported root documentation fix remains exempt from source proof."""
        self.import_root_commit("doc/imported.txt", "doc: fix imported wording")
        step = self.proof_step()
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("0 fix commit(s)", step.output)

    def test_record_keys_are_independent_of_path_bound(self) -> None:
        """A valid seven-key proof object remains readable with a one-path bound."""
        payload = self.valid_record("a" * 40, "b" * 40, "c" * 40, command=["pytest"])
        record = self.write_record("proof.json", payload)
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
            result = upstream_lint._read_revert_proof(record)
        self.assertEqual(result, (payload, "a" * 40, None))

    def test_command_arguments_are_independent_of_path_bound(self) -> None:
        """A two-argument command remains valid with a one-path bound."""
        payload = self.valid_record("a" * 40, "b" * 40, "c" * 40)
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
            error = upstream_lint._revert_proof_schema_error(payload)
        self.assertIsNone(error)

    def add_fix_commit(
        self, path: str = "libavfilter/vf_x.c", subject: str = "avfilter/vf_x: fix y"
    ) -> tuple[str, str, str]:
        """Write a source fix and test path, commit them and return commit, head and head_tree."""
        self.write(path, SOURCE.replace("return 1", "return 2"))
        self.write("tests/ref/fate/filter-x", "0\n")
        self.commit(subject)
        head = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        return head, head, head_tree

    def write_record(self, filename: str, payload: dict[str, object]) -> Path:
        """Write a JSON record dictionary to the temporary parent directory."""
        target = self.root.parent / filename
        target.write_text(json.dumps(payload), encoding="utf-8")
        return target

    def valid_record(
        self, commit: str, head: str, head_tree: str, /, **overrides: object
    ) -> dict[str, object]:
        """Build a valid revert-proof record dictionary with optional field overrides."""
        base_record: dict[str, object] = {
            "commit": commit,
            "head": head,
            "head_tree": head_tree,
            "command": ["pytest", "-q"],
            "rc_head": 0,
            "rc_reverted": 1,
            "reverted_paths": ["libavfilter/vf_x.c"],
        }
        base_record.update(overrides)
        return base_record

    def test_step_accepts_matching_record_with_nonzero_rc_reverted(self) -> None:
        """A matching record with rc_head 0 and nonzero rc_reverted passes revert-proof."""
        commit, head, head_tree = self.add_fix_commit()
        record_file = self.write_record("proof.json", self.valid_record(commit, head, head_tree))
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 0, output)
        self.assertIn("step: revert-proof rc: 0", output)

    def test_unmatched_record_error_does_not_suppress_missing_proof(self) -> None:
        """An unbound parse error stays at step scope beside the commit's missing proof."""
        commit, _, _ = self.add_fix_commit()
        record = self.root.parent / "invalid-record.json"
        record.write_text("not JSON", encoding="utf-8")
        step = self.proof_step(record)
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y: no revert-proof record", step.output)
        error = f"{record}: not valid JSON"
        self.assertEqual(step.output.splitlines().count(error), 1, step.output)
        self.assertEqual(step.output.count(error), 1, step.output)

    def test_message_only_replace_ref_cannot_hide_fix(self) -> None:
        """A replacement with identical parents cannot hide a stored fix by renaming it."""
        commit, _, _ = self.add_fix_commit()
        self.git("commit", "--amend", "-qm", "avfilter/vf_x: rename helper")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("reset", "--hard", commit)
        self.git("replace", commit, replacement)
        step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(commit, step.output)
        self.assertIn("replace refs", step.output)
        self.assertNotIn("no revert-proof record", step.output)

    def test_step_refuses_missing_record(self) -> None:
        """A fix commit with no revert-proof record fails and names the commit and subject."""
        commit, _, _ = self.add_fix_commit()
        rc, output = self.check()
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("no revert-proof record", output)

    def test_step_refuses_record_of_another_head_tree(self) -> None:
        """A record whose head_tree differs from the range head tree fails as stale."""
        commit, head, _ = self.add_fix_commit()
        stale_tree = "0" * 40
        record_file = self.write_record("stale.json", self.valid_record(commit, head, stale_tree))
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("stale", output)

    def test_step_refuses_rc_reverted_zero(self) -> None:
        """A record with rc_reverted 0 fails because the test passes without the fix."""
        commit, head, head_tree = self.add_fix_commit()
        record_file = self.write_record(
            "weak.json", self.valid_record(commit, head, head_tree, rc_reverted=0)
        )
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("test passes without the fix", output)

    def test_step_refuses_rc_reverted_timeout(self) -> None:
        """A record with rc_reverted timeout fails because a timeout gives no verdict."""
        commit, head, head_tree = self.add_fix_commit()
        record_file = self.write_record(
            "timeout.json", self.valid_record(commit, head, head_tree, rc_reverted="timeout")
        )
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("no verdict", output)

    def test_step_refuses_rc_head_nonzero(self) -> None:
        """A record whose rc_head is nonzero fails and names the commit and subject."""
        commit, head, head_tree = self.add_fix_commit()
        record_file = self.write_record(
            "bad_head.json", self.valid_record(commit, head, head_tree, rc_head=2)
        )
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("rc_head", output)

    def test_step_refuses_duplicate_key(self) -> None:
        """A record JSON file containing a duplicate key is refused by the JSON reader."""
        commit, head, head_tree = self.add_fix_commit()
        dup_path = self.root.parent / "dup.json"
        duplicate_record = (
            "{\n"
            f'  "commit": "{commit}",\n'
            f'  "head": "{head}",\n'
            f'  "head_tree": "{head_tree}",\n'
            '  "command": ["pytest"],\n'
            '  "rc_head": 0,\n'
            '  "rc_head": 0,\n'
            '  "rc_reverted": 1,\n'
            '  "reverted_paths": ["libavfilter/vf_x.c"]\n'
            "}\n"
        )
        dup_path.write_text(
            duplicate_record,
            encoding="utf-8",
        )
        rc, output = self.check("--revert-proof", str(dup_path))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("duplicate key", output)

    def test_step_refuses_missing_key(self) -> None:
        """A record JSON file missing a required key fails and names the missing key."""
        commit, head, head_tree = self.add_fix_commit()
        payload = self.valid_record(commit, head, head_tree)
        del payload["reverted_paths"]
        record_file = self.write_record("missing.json", payload)
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("missing key", output)

    def test_step_refuses_extra_key(self) -> None:
        """A record JSON file with an extra key fails and names the extra key."""
        commit, head, head_tree = self.add_fix_commit()
        payload = self.valid_record(commit, head, head_tree, unexpected="value")
        record_file = self.write_record("extra.json", payload)
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("extra key", output)

    def test_step_bounds_extra_key_text_in_schema_error(self) -> None:
        """An oversized extra key name is truncated in the revert-proof schema diagnostic."""
        commit, head, head_tree = self.add_fix_commit()
        long_key = "z" * (upstream_lint.MAX_DIAGNOSTIC_KEY + 40)
        payload = self.valid_record(commit, head, head_tree)
        payload[long_key] = 1
        record_file = self.write_record("huge_key.json", payload)
        _, commit_id, error = upstream_lint._read_revert_proof(record_file)
        self.assertEqual(commit_id, commit)
        self.assertIsNotNone(error)
        self.assertIn("extra key:", error or "")
        self.assertNotIn(long_key, error or "")
        self.assertIn("...", error or "")

    def test_schema_samples_many_extra_keys(self) -> None:
        """A large extra-key diagnostic reports a short sorted sample and the total."""
        payload = dict.fromkeys(upstream_lint.REVERT_PROOF_KEYS)
        for index in range(1999, -1, -1):
            payload[f"extra-{index:04d}-" + "x" * 248] = None
        error = upstream_lint._revert_proof_schema_error(payload) or ""
        self.assertLess(len(error), 2000)
        self.assertIn("2000 total", error)
        self.assertIn(
            ", ".join(f"extra-{index:04d}-" + "x" * 245 + "..." for index in range(5)), error
        )
        self.assertNotIn("extra-0005-", error)

    def test_step_refuses_nul_in_recorded_command_argument(self) -> None:
        """A recorded command argument containing NUL bytes is refused before measurement."""
        commit, head, head_tree = self.add_fix_commit()
        payload = self.valid_record(commit, head, head_tree, command=["pytest", "a\x00b"])
        record_file = self.write_record("nul_arg.json", payload)
        result = upstream_lint._read_revert_proof(record_file)
        self.assertEqual(result[0], None)
        self.assertIn("wrong value type for command", result[2] or "")

    def test_step_refuses_tag_object_id_as_record_head(self) -> None:
        """A record whose head field names an annotated tag is refused as inexact."""
        commit, head, head_tree = self.add_fix_commit()
        tag = f"proof-head-tag-{commit[:8]}"
        self.git("tag", "-a", tag, "-m", "proof fixture tag", head)
        tag_sha = self.git("rev-parse", tag).strip()
        self.assertNotEqual(tag_sha, head)
        record_file = self.write_record(
            "tag_head.json", self.valid_record(commit, tag_sha, head_tree)
        )
        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("head is not an exact commit id", output)

    def test_record_count_overflow_waiver_passes_with_reason(self) -> None:
        """A non-blank revert-proof waiver covers record-count overflow before loading."""
        commit, head, head_tree = self.add_fix_commit()
        first = self.write_record("first.json", self.valid_record(commit, head, head_tree))
        second = self.write_record(
            "second.json", self.valid_record(commit, head, head_tree, rc_reverted=2)
        )
        fixes = upstream_lint._fix_commits(self.root, self.base, head)
        real_result = upstream_lint._revert_proof_result

        def capped_result(tree, head_sha, history, records, waiver):
            with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
                return real_result(tree, head_sha, history, records, waiver)

        with unittest.mock.patch.object(
            upstream_lint, "_revert_proof_result", side_effect=capped_result
        ):
            step = upstream_lint._revert_proof(
                self.root,
                self.base,
                head,
                (first, second),
                "fixture duplicate records",
            )
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("waived: fixture duplicate records", step.output)
        self.assertIn("revert-proof records exceed MAX_PATHS=1: 2", step.output)
        self.assertEqual(len(fixes), 1)

    def test_record_count_overflow_blank_waiver_fails(self) -> None:
        """Record-count overflow without a waiver keeps revert-proof rc 1."""
        commit, head, head_tree = self.add_fix_commit()
        first = self.write_record("first.json", self.valid_record(commit, head, head_tree))
        second = self.write_record("second.json", self.valid_record(commit, head, head_tree))
        real_result = upstream_lint._revert_proof_result

        def capped_result(tree, head_sha, history, records, waiver):
            with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
                return real_result(tree, head_sha, history, records, waiver)

        with unittest.mock.patch.object(
            upstream_lint, "_revert_proof_result", side_effect=capped_result
        ):
            step = upstream_lint._revert_proof(self.root, self.base, head, (first, second))
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("revert-proof records exceed MAX_PATHS=1: 2", step.output)

    def test_step_refuses_wrong_type(self) -> None:
        """A record JSON file with a wrong field value type fails and names the commit."""
        commit, head, head_tree = self.add_fix_commit()
        for idx, overrides in enumerate(
            (
                {"commit": "not-40-hex"},
                {"head": 123},
                {"head_tree": "Z" * 40},
                {"command": "pytest"},
                {"rc_head": True},
                {"rc_head": False},
                {"rc_head": 0.0},
                {"rc_head": None},
                {"rc_head": []},
                {"rc_reverted": "other"},
                {"rc_reverted": True},
                {"rc_reverted": False},
                {"rc_reverted": 0.0},
                {"rc_reverted": None},
                {"rc_reverted": []},
                {"reverted_paths": ["b.c", "a.c"]},
            )
        ):
            with self.subTest(overrides=overrides):
                record_file = self.write_record(
                    f"wrong_{idx}.json", self.valid_record(commit, head, head_tree, **overrides)
                )
                rc, output = self.check("--revert-proof", str(record_file))
                self.assertEqual(rc, 1, output)
                self.assertIn("step: revert-proof rc: 1", output)
                self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
                self.assertIn("wrong value type", output)

    def test_record_accepts_return_code_values(self) -> None:
        """Integer return codes and recognized outcome strings pass record validation."""
        for rc_head in (0, 1):
            for rc_reverted in (0, 1, "timeout", "launch-error"):
                with self.subTest(rc_head=rc_head, rc_reverted=rc_reverted):
                    payload = self.valid_record(
                        "a" * 40, "b" * 40, "c" * 40, rc_head=rc_head, rc_reverted=rc_reverted
                    )
                    record = self.write_record("proof.json", payload)
                    result = upstream_lint._read_revert_proof(record)
                    self.assertEqual(result, (payload, "a" * 40, None))

    def test_step_refuses_file_that_is_not_json(self) -> None:
        """A record file that is not valid JSON fails and names the commit and subject."""
        commit, _, _ = self.add_fix_commit()
        bad_path = self.root.parent / "not_json.txt"
        bad_path.write_text("{not valid json\n", encoding="utf-8")
        rc, output = self.check("--revert-proof", str(bad_path))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("not valid JSON", output)

    def test_step_waiver_passes_and_names_commit(self) -> None:
        """A non-blank --no-revert-proof-reason passes the step and lists the waived commit."""
        commit, _, _ = self.add_fix_commit()
        rc, output = self.check("--no-revert-proof-reason", "hardware-only path")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: revert-proof rc: 0\nwaived: hardware-only path", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)

    def test_step_boundary_range_without_fix_commit_passes(self) -> None:
        """A range without a source fix commit passes revert-proof with a summary line."""
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update y")
        rc, output = self.check()
        self.assertEqual(rc, 0, output)
        self.assertIn("step: revert-proof rc: 0\n0 fix commit(s)", output)

    def test_step_boundary_two_fixes_with_one_record_names_only_unrecorded_commit(self) -> None:
        """When one of two fix commits has a valid record, only the other commit is reported."""
        first_commit, _, _ = self.add_fix_commit("libavfilter/vf_x.c", "avfilter/vf_x: fix first")
        self.write("libavfilter/vf_y.c", SOURCE.replace("return 1", "return 3"))
        self.write("tests/ref/fate/filter-y", "0\n")
        self.commit("avfilter/vf_y: fix second")
        second_commit = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        record_file = self.write_record(
            "first.json", self.valid_record(first_commit, second_commit, head_tree)
        )

        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{second_commit[:12]}: avfilter/vf_y: fix second", output)
        self.assertNotIn(f"{first_commit[:12]}: avfilter/vf_x: fix first", output)

    def test_step_refuses_merge_commit_with_fix_wording_unless_waived(self) -> None:
        """A merge commit with fix wording is refused by name unless waived by reason."""
        self.git("checkout", "-qb", "side", self.base)
        self.write("libavfilter/vf_y.c", SOURCE.replace("return 1", "return 3"))
        self.commit("avfilter/vf_y: add y")
        self.git("checkout", "-q", "-")
        self.write("libavfilter/vf_x.c", SOURCE.replace("return 1", "return 2"))
        self.commit("avfilter/vf_x: update x")
        self.git("merge", "--no-ff", "-qm", "avfilter/vf_x: merge side and fix y", "side")
        merge_sha = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        record_file = self.write_record(
            "merge.json", self.valid_record(merge_sha, merge_sha, head_tree)
        )

        rc, output = self.check("--revert-proof", str(record_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{merge_sha[:12]}: avfilter/vf_x: merge side and fix y", output)
        self.assertIn("own commit", output)

        rc, output = self.check("--no-revert-proof-reason", "merge conflict resolution")
        self.assertEqual(rc, 0, output)
        self.assertIn("step: revert-proof rc: 0\nwaived: merge conflict resolution", output)
        self.assertIn(f"{merge_sha[:12]}: avfilter/vf_x: merge side and fix y", output)

    def test_step_accepts_good_plus_stale_duplicate_records(self) -> None:
        """A valid record for a commit satisfies the step even when a stale duplicate exists."""
        commit, head, head_tree = self.add_fix_commit()
        stale_file = self.write_record("stale.json", self.valid_record(commit, head, "0" * 40))
        good_file = self.write_record("good.json", self.valid_record(commit, head, head_tree))

        rc, output = self.check("--revert-proof", str(stale_file), "--revert-proof", str(good_file))
        self.assertEqual(rc, 0, output)
        self.assertIn("step: revert-proof rc: 0", output)

    def test_step_refuses_good_plus_malformed_duplicate_records(self) -> None:
        """A malformed record remains a finding even when a valid record for the commit exists."""
        commit, head, head_tree = self.add_fix_commit()
        good_file = self.write_record("good.json", self.valid_record(commit, head, head_tree))
        bad_payload = self.valid_record(commit, head, head_tree)
        del bad_payload["reverted_paths"]
        bad_file = self.write_record("bad.json", bad_payload)

        rc, output = self.check("--revert-proof", str(good_file), "--revert-proof", str(bad_file))
        self.assertEqual(rc, 1, output)
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn(f"{commit[:12]}: avfilter/vf_x: fix y", output)
        self.assertIn("missing key", output)

    def test_step_refuses_fix_commits_above_commit_cap(self) -> None:
        """More fix commits than MAX_CLAIM_COMMITS fails revert-proof without truncating."""
        self.add_fix_commit("libavfilter/vf_x.c", "avfilter/vf_x: fix first")
        self.write("libavfilter/vf_y.c", SOURCE.replace("return 1", "return 3"))
        self.write("tests/ref/fate/filter-y", "0\n")
        self.commit("avfilter/vf_y: fix second")
        second_commit = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        record_file = self.write_record(
            "second.json", self.valid_record(second_commit, second_commit, head_tree)
        )

        with unittest.mock.patch.object(upstream_lint, "MAX_CLAIM_COMMITS", 1):
            _, output = self.check("--revert-proof", str(record_file))
        self.assertIn("step: revert-proof rc: 1", output)
        self.assertIn("fix commits exceed MAX_CLAIM_COMMITS=1: 2", output)

    def proof_step(self, *records: Path) -> upstream_lint.Step:
        """Run only the revert-proof consumer against the fixture's committed range."""
        head = self.git("rev-parse", "HEAD").strip()
        return upstream_lint._revert_proof(self.root, self.base, head, records)

    def test_step_refuses_commit_scan_overflow_before_classification(self) -> None:
        """A fix behind the commit scan bound cannot disappear as a zero-fix range."""
        self.add_fix_commit()
        self.write("doc/new.txt", "newer neutral commit\n")
        self.commit("doc: update text")
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 1):
            step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn("commit scan exceeds MAX_PATHS=1: 2", step.output)

    def test_step_accepts_exact_commit_scan_bound(self) -> None:
        """Exactly seven commits still prove the fix behind six neutral commits."""
        commit, _, _ = self.add_fix_commit()
        for number in range(6):
            self.write("doc/new.txt", f"neutral update {number}\n")
            self.commit("doc: update text")
        head = self.git("rev-parse", "HEAD").strip()
        head_tree = self.git("rev-parse", "HEAD^{tree}").strip()
        record = self.write_record("proof.json", self.valid_record(commit, head, head_tree))
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 7):
            step = self.proof_step(record)
        self.assertEqual(step.rc, 0, step.output)
        self.assertIn("1 fix commit(s), 1 revert-proof record(s)", step.output)

    def test_step_refuses_path_scan_overflow_before_source_classification(self) -> None:
        """A source behind seven doc paths cannot hide beyond the path scan bound."""
        for number in range(7):
            self.write(f"doc/{number}.txt", "documentation\n")
        commit, _, _ = self.add_fix_commit()
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 7):
            step = self.proof_step()
        self.assertEqual(step.rc, 1, step.output)
        self.assertIn(f"{commit}: commit paths exceed MAX_PATHS=7: 9", step.output)

    def test_step_accepts_exact_path_scan_bound(self) -> None:
        """Exactly seven commit paths include the complete sorted source set."""
        for number in range(5):
            self.write(f"doc/{number}.txt", "documentation\n")
        commit, head, head_tree = self.add_fix_commit()
        record = self.write_record("proof.json", self.valid_record(commit, head, head_tree))
        with unittest.mock.patch.object(upstream_lint, "MAX_PATHS", 7):
            step = self.proof_step(record)
        self.assertEqual(step.rc, 0, step.output)

    def test_step_refuses_record_head_with_wrong_tree_or_missing_commit(self) -> None:
        """A plausible head hash must resolve to a commit with the recorded tree."""
        commit, _, head_tree = self.add_fix_commit()
        for head, diagnostic in (
            (self.base, "head commit tree differs"),
            ("0" * 40, "head does not resolve to a commit"),
            (head_tree, "head does not resolve to a commit"),
        ):
            with self.subTest(head=head):
                record = self.write_record(
                    "bad-head.json", self.valid_record(commit, head, head_tree)
                )
                step = self.proof_step(record)
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn(diagnostic, step.output)

    def test_step_refuses_sorted_but_inexact_reverted_paths(self) -> None:
        """Sorted source lists still fail when paths are missing, extra or duplicated."""
        self.write("libavfilter/vf_y.c", SOURCE)
        commit, head, head_tree = self.add_fix_commit()
        for paths in (
            ["libavfilter/vf_x.c"],
            ["libavfilter/vf_x.c", "libavfilter/vf_y.c", "libavfilter/vf_z.c"],
            ["libavfilter/vf_x.c", "libavfilter/vf_x.c", "libavfilter/vf_y.c"],
        ):
            with self.subTest(paths=paths):
                record = self.write_record(
                    "bad-paths.json",
                    self.valid_record(commit, head, head_tree, reverted_paths=paths),
                )
                step = self.proof_step(record)
                self.assertEqual(step.rc, 1, step.output)
                self.assertIn("reverted_paths differ from fix source paths", step.output)

    def test_step_accepts_complete_sorted_reverted_source_paths(self) -> None:
        """The full sorted source set accepts with a resolvable matching head commit."""
        self.write("libavfilter/vf_y.c", SOURCE)
        commit, head, head_tree = self.add_fix_commit()
        record = self.write_record(
            "proof.json",
            self.valid_record(
                commit, head, head_tree, reverted_paths=["libavfilter/vf_x.c", "libavfilter/vf_y.c"]
            ),
        )
        step = self.proof_step(record)
        self.assertEqual(step.rc, 0, step.output)


if __name__ == "__main__":
    unittest.main()
