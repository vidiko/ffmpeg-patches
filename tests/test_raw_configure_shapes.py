# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Exercise complex command shapes, boundaries, and subshell forms."""

from __future__ import annotations

import ast
import graphlib
import io
import json
import math
import os
import re
import time
import unittest.mock
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts import raw_configure_body as body_mod
from scripts import raw_configure_files as files_mod
from scripts import raw_configure_lex as lex_mod
from scripts.raw_configure_body import (
    BodyBudget,
    InspectionContext,
    _probe_clean_redirect_target,
    scan_body,
)
from tests.raw_configure_support import CLIENTS, GUARD_MOD, RawConfigureGuardBase

GUARDFD_G1 = (
    "#!/bin/bash\n"
    "delay=$((1 << 2))\n"
    "if ! python3 - x 3<<< \"$d\" > y <<'PYTHON'\n"
    "import sys\n"
    "PYTHON\n"
    "then\n  echo no\n"
    "fi\n"
)

GUARDFD_G6 = (
    "#!/bin/bash\n"
    "set -eu\n"
    "retry() {\n"
    "  delay=$(((1 << (1 - 1)) + 1))\n"
    "  sleep 0\n"
    "}\n"
    "judge_paths() {\n"
    '  if ! python3 - "$tree_file" 3<<< "$dump_json" > "$paths_file" <<\'PYTHON\'\n'
    "import json\n"
    "import os\n"
    "import sys\n\n"
    "with os.fdopen(3) as handle:\n"
    "    data = json.load(handle)\n"
    "print(sys.argv[1], len(data))\n"
    "PYTHON\n"
    "  then\n"
    "    return 1\n"
    "  fi\n"
    "}\n"
    "retry true\n"
    "judge_paths . '{}' tree.txt paths.txt\n"
)

_BODY_PATH = Path(body_mod.__file__)
_LEX_PATH = Path(lex_mod.__file__)
_PARITY_CFG = "./" + "con" + "figure"
_PARITY_COMMANDS = ("bash", "sh", "python3 -", "cat", "cat - x")
_PARITY_WORDS = (
    f'"{_PARITY_CFG}"',
    f"'{_PARITY_CFG} --prefix=/x'",
    '"$d"',
    "'true'",
    "x",
)
_PARITY_TAILS = ("", " > /tmp/y")
_INLINE_FAIL_OPEN = (
    ("eval_bash_fd0_cfg", f"eval 'bash 0<<< \"{_PARITY_CFG}\"'\n"),
    ("eval_bash_fd3_cfg", f"eval 'bash 3<<< \"{_PARITY_CFG}\"'\n"),
    ("bashc_bash_fd0_cfg", f"bash -c 'bash 0<<< \"{_PARITY_CFG}\"'\n"),
    ("eval_bash_fd0_var", "eval 'bash 0<<< \"$d\"'\n"),
    (
        "top_cat_fd3_var_then_eval_bash_fd0_cfg",
        f'cat 3<<< "$d"\neval \'bash 0<<< "{_PARITY_CFG}"\'\n',
    ),
    ("bash_fd0_cfg_then_cat_redirect", f'bash 0<<< "{_PARITY_CFG}" > /tmp/y\n'),
    ("python_fd0_cfg", f'python3 - 0<<< "{_PARITY_CFG}"\n'),
    ("env_bash_fd0_cfg", f'env bash 0<<< "{_PARITY_CFG}"\n'),
)
_R9_Q = f'"{_PARITY_CFG}"'
_R9_PAD = ":\n" * 300
_R9_CASES = (
    ("md01_plain_cfg_fd33_x", f"bash <<< {_R9_Q} 33<<< x\n", "refuse"),
    ("md02_fd33_x_plain_cfg", f"bash 33<<< x <<< {_R9_Q}\n", "refuse"),
    ("md03_fd0_cfg_fd33_x", f"bash 0<<< {_R9_Q} 33<<< x\n", "refuse"),
    ("md04_fd33_x_fd0_cfg", f"bash 33<<< x 0<<< {_R9_Q}\n", "refuse"),
    ("md05_fd0_cfg_fd10_x", f"bash 0<<< {_R9_Q} 10<<< x\n", "refuse"),
    ("md06_plain_cfg_brace_x", f"bash <<< {_R9_Q} {{fd}}<<< x\n", "refuse"),
    ("md07_fd0_cfg_brace_x", f"bash 0<<< {_R9_Q} {{fd}}<<< x\n", "refuse"),
    ("md08_fd00_cfg", f"bash 00<<< {_R9_Q}\n", "refuse"),
    ("md09_fd000_cfg", f"bash 000<<< {_R9_Q}\n", "refuse"),
    ("md10_fd33_cfg_only", f"bash 33<<< {_R9_Q}\n", "any"),
    ("md11_cat_fd33_var_redirect", 'cat 33<<< "$d" > /tmp/y\n', "any"),
    ("md12_plain_cfg_fd3_x", f"bash <<< {_R9_Q} 3<<< x\n", "refuse"),
    ("md13_fd0_cfg_fd3_x", f"bash 0<<< {_R9_Q} 3<<< x\n", "refuse"),
    ("md14_fd33_cfg_dup0", f"bash 33<<< {_R9_Q} 0<&33\n", "refuse"),
    ("md15_fd3_cfg_dup0", f"bash 3<<< {_R9_Q} 0<&3\n", "refuse"),
    ("md16_exec_fd33_then_dup", f"exec 33<<< {_R9_Q}; bash 0<&33\n", "refuse"),
    ("md17_fd0_cfg_2to1", f"bash 0<<< {_R9_Q} 2>&1\n", "refuse"),
    ("md20_fd0_x_fd33_cfg", f"bash 0<<< x 33<<< {_R9_Q}\n", "any"),
    ("md21_sh_fd0_cfg_fd33_x", f"sh 0<<< {_R9_Q} 33<<< x\n", "refuse"),
    ("md22_fd0_cfg_fd99_x", f"bash 0<<< {_R9_Q} 99<<< x\n", "refuse"),
    ("pad300_cat_fd3_var_redirect", _R9_PAD + 'cat 3<<< "$d" > /tmp/y\n', "any"),
    (
        "cat_fd3_var_pad300_bash_fd3_cfg",
        'cat 3<<< "$d" > /tmp/y\n' + _R9_PAD + f'bash 3<<< "{_PARITY_CFG}"\n',
        "refuse",
    ),
    (
        "cat_fd3_var_pad300_bash_plain_cfg",
        'cat 3<<< "$d" > /tmp/y\n' + _R9_PAD + f'bash <<< "{_PARITY_CFG}"\n',
        "refuse",
    ),
    ("cat_fd3_var_pad300_cfg", 'cat 3<<< "$d" > /tmp/y\n' + _R9_PAD + f"{_PARITY_CFG}\n", "refuse"),
    ("bash_fd33_cfg", f'bash 33<<< "{_PARITY_CFG}"\n', "any"),
    ("bash_fd0_33_cfg", f'bash 0<<< "{_PARITY_CFG}" 33<<< x\n', "refuse"),
    ("bash_brace_fd_cfg", f'bash {{fd}}<<< "{_PARITY_CFG}"\n', "any"),
    ("bash_fd0_nospace_cfg", f'bash 0<<<"{_PARITY_CFG}"\n', "refuse"),
    ("bash_fd0_unquoted_cfg", f"bash 0<<<{_PARITY_CFG}\n", "refuse"),
    ("bash_fd0_ansic_cfg", f"bash 0<<<$'{_PARITY_CFG}'\n", "refuse"),
    ("bash_tab_fd0_cfg", f'bash\t0<<< "{_PARITY_CFG}"\n', "refuse"),
    ("bash_s_fd0_cfg", f'bash -s 0<<< "{_PARITY_CFG}"\n', "refuse"),
    ("cmdsub_bash_fd0_cfg", f'x=$(bash 0<<< "{_PARITY_CFG}")\n', "refuse"),
    ("two_marks_one_line", f'cat 3<<< "$d"; bash 0<<< "{_PARITY_CFG}"\n', "refuse"),
    ("cat_fd3_then_pipe_bash", f'cat 0<<< "{_PARITY_CFG}" | bash\n', "refuse"),
    ("cat_fd3_var_semicolon_true", 'cat 3<<< "$d"; true\n', "any"),
)
_GRAMMAR_CASES = (
    ("cat 3<<< x\n", 4, 4, "cat <<< x\n", 1),
    ("cat 33<<< x\n", 4, 5, "cat <<< x\n", 1),
    ("cat 00<<< x\n", 4, 5, "cat <<< x\n", 1),
    ("cat 000<<< x\n", 4, 6, "cat <<< x\n", 1),
    ("cat 99<<< x\n", 4, 5, "cat <<< x\n", 1),
    ("cat {fd}<<< x\n", 4, 7, "cat <<< x\n", 1),
    ("cat {_a1}<<< x\n", 4, 8, "cat <<< x\n", 1),
    ("cat a3<<< x\n", 5, 0, "cat a3<<< x\n", 0),
    ("cat x_33<<< x\n", 6, 0, "cat x_33<<< x\n", 0),
    ("echo '3<<<'\n", 6, 0, "echo '3<<<'\n", 0),
    ("cat {1fd}<<< x\n", 4, 0, "cat {1fd}<<< x\n", 0),
)
_R10_PROBES = (
    ("p00_control_plain_payload", "body", 'bash <<< "./helper.sh"\n'),
    ("p01_dup_stdin_fd3_payload", "body", 'bash 0<&3 3<<< "./helper.sh"\n'),
    ("p02_fd3_then_dup", "body", 'bash 3<<< "./helper.sh" 0<&3\n'),
    ("p03_exec_bind_then_dup", "body", 'exec 3<<< "./helper.sh"\nbash 0<&3\n'),
    ("p04_dup_payload_unquoted", "body", "bash 0<&3 3<<< ./helper.sh\n"),
    ("p05_dup_payload_sub_helper", "body", 'bash 0<&3 3<<< "sub/helper.sh"\n'),
    ("p06_dup_payload_source", "body", 'bash 0<&3 3<<< ". ./helper.sh"\n'),
    ("p07_cat_tail_payload_pipe", "body", 'cat 0<&3 3<<< "./helper.sh" | bash\n'),
    ("p08_sh_dup_payload", "body", 'sh 0<&3 3<<< "./helper.sh"\n'),
    ("q00_cmd_control", "cmd", 'bash <<< "./helper.sh"'),
    ("q01_cmd_dup_payload", "cmd", 'bash 0<&3 3<<< "./helper.sh"'),
    ("q02_cmd_fd3_then_dup", "cmd", 'bash 3<<< "./helper.sh" 0<&3'),
    ("q03_cmd_exec_then_dup", "cmd", 'exec 3<<< "./helper.sh"; bash 0<&3'),
    (
        "rq2_exec_copy_fd4_then_dup",
        "body",
        'exec 4<<< "./helper.sh"\nexec 3<<< x\nexec 3<&4\nbash 0<&3\n',
    ),
    ("rx1_dup_before_later_hs", "body", 'exec 3<<< "./helper.sh"\nbash 0<&3 3<<< x\n'),
    ("rx2_two_hs_later_wins", "body", 'bash 3<<< x 3<<< "./helper.sh" 0<&3\n'),
    ("rx3_dup_between_hs", "body", 'bash 3<<< "./helper.sh" 0<&3 3<<< x\n'),
    (
        "rd1_tail_then_mark_past_256",
        "body",
        'cat 3<<< "$d" > /tmp/y\n' + _R9_PAD + 'bash 0<&3 3<<< "./helper.sh"\n',
    ),
    (
        "rd2_tail_then_cfg_past_256",
        "body",
        'cat 3<<< "$d" > /tmp/y\n' + _R9_PAD + f'bash 3<<< "{_PARITY_CFG}" 0<&3\n',
    ),
    ("q61_hyphen_digit_word", "body", "./helper-3<<< x\n"),
    ("rk1_escaped_quote_then_dup", "body", "printf '%s' \\\" 3<<< x; bash 0<&3 3<<< ./helper.sh\n"),
    (
        "hk1_cmd_escaped_quote_then_dup",
        "cmd",
        "printf '%s' \\\" 3<<< x; bash 0<&3 3<<< ./helper.sh",
    ),
    ("hk2_cmd_escaped_quote_then_plain", "cmd", "printf '%s' \\\" 3<<< x; bash <<< ./helper.sh"),
    (
        "hk3_body_escaped_quote_then_plain",
        "body",
        "printf '%s' \\\" 3<<< x\nbash <<< ./helper.sh\n",
    ),
    ("hx1_cmd_dup_before_later_hs", "cmd", 'exec 3<<< "./helper.sh"; bash 0<&3 3<<< x'),
    ("hx2_cmd_two_hs_later_wins", "cmd", 'bash 3<<< x 3<<< "./helper.sh" 0<&3'),
    ("hx3_cmd_dup_between_hs", "cmd", 'bash 3<<< "./helper.sh" 0<&3 3<<< x'),
    ("hc1_cmd_exec_copy_then_dup", "cmd", 'exec 4<<< "./helper.sh"; exec 3<&4; bash 0<&3'),
    ("hc2_body_exec_copy_then_dup", "body", 'exec 4<<< "./helper.sh"\nexec 3<&4\nbash 0<&3\n'),
    ("hc3_body_exec_copy_one_line", "body", 'exec 4<<< "./helper.sh" 3<&4\nbash 0<&3\n'),
    (
        "hc4_cmd_close_copy_rebind",
        "cmd",
        'exec 3<<< x; exec 3<&-; exec 4<<< "./helper.sh"; exec 3<&4; bash 0<&3',
    ),
    ("i01_body_dash_s_glued_dup", "body", 'bash -s<&3 3<<< "./helper.sh"\n'),
    ("i02_body_dash_s_digit_glued_dup", "body", 'bash -s5<&3 3<<< "./helper.sh"\n'),
    ("i03_body_fd_then_glued_dup", "body", 'bash 3<<< "./helper.sh" -s<&3\n'),
    ("i04_body_dash_glued_dup", "body", 'sh -<&3 3<<< "./helper.sh"\n'),
    ("i05_cmd_dash_s_glued_dup", "cmd", 'bash -s<&3 3<<< "./helper.sh"'),
    ("i06_cmd_dash_s_digit_glued_dup", "cmd", 'bash -s5<&3 3<<< "./helper.sh"'),
    ("i07_body_exec_then_glued_dup", "body", 'exec 3<<< "./helper.sh"\nbash -s<&3\n'),
)
_R10_BOUNDARIES = (
    ("b01", "echo item-3<<<x", False),
    ("b02", "echo item.3<<<x", False),
    ("b03", "echo item/3<<<x", False),
    ("b04", "echo item=3<<<x", False),
    ("b05", "echo item+3<<<x", False),
    ("b06", "echo item:3<<<x", False),
    ("b07", "echo item,3<<<x", False),
    ("b08", "echo item@3<<<x", False),
    ("b09", "echo item%3<<<x", False),
    ("b10", "echo item~3<<<x", False),
    ("b11", "echo a;3<<<x; echo rc=$?", True),
    ("b12", "echo a|3<<<x; echo rc=$?", True),
    ("b13", "cat 3<<<x 0<&3", True),
    ("b14", "echo b >3<<<x; cat 3", False),
    ("b15", "exec 3>e3; echo d >&3<<<x; cat e3", False),
    ("b16", "(3<<<x cat 0<&3)", True),
    ("b17", "true &3<<<x cat 0<&3; wait", True),
    ("b18", "echo item-{fd}<<<x", False),
    ("r01", "(cat 0<&3)3<<<x; echo rc=$?", True),
    ("r02", "{ cat 0<&3; }3<<<x; echo rc=$?", False),
    ("r03", "true&&3<<<x cat 0<&3", True),
    ("r04", "false||3<<<x cat 0<&3", True),
    ("r05", "echo a|&3<<<x cat 0<&3", True),
    ("r06", 'echo "item"3<<<x', False),
    ("r07", "cat\t3<<<x 0<&3", True),
    ("r08", "true\n3<<<x cat 0<&3", True),
    ("r09", "echo $3<<<x", False),
    ("r10", "(cat 0<&3) 3<<<x", True),
    ("r11", "echo b &>3<<<x; cat 3", False),
    ("r12", "echo b >&33<<<x; echo rc=$?", False),
)
_R10_DUP_ROWS = (
    ("0<&3", True),
    ("<&3", True),
    ("-s<&3", True),
    ("-s5<&3", True),
    ("x-5<&3", True),
    ("5<&3", False),
)
_R10_DESCRIPTOR_ROWS = (
    ("c01", "exec 3<<<first; exec 3<&-; cat 0<&3; echo rc=$?", None),
    ("c02", "exec 3<<<first; exec 3>&-; cat 0<&3; echo rc=$?", None),
    ("c03", "exec 3<<<first; exec 3</dev/null; cat 0<&3; echo rc=$?", None),
    ("c04", "exec 4<<<four; exec 3<<<first; exec 3<&4; cat 0<&3", "four"),
    ("c05", "exec 3<<<first; true 3<&-; cat 0<&3", "first"),
    ("c06", "exec 3<<<first; cat 3<&- 0<&3; echo rc=$?", None),
    ("o01", "exec 3<<<first; cat 0<&3 3<<<second", "first"),
    ("o02", "exec 3<<<first; cat 3<<<second 0<&3", "second"),
    ("o03", "cat 3<<<one 3<<<two 0<&3", "two"),
    ("o04", "cat 3<<<one 0<&3 3<<<two", "one"),
)
_R11_REFUSE_PROBES = (
    ("j01_body_exec_then_move", "body", 'exec 3<<< "./helper.sh"\nbash <&3-\n'),
    ("j02_body_inline_move", "body", 'bash 3<<< "./helper.sh" 0<&3-\n'),
    ("j03_cmd_inline_move", "cmd", 'bash 3<<< "./helper.sh" 0<&3-'),
    ("j04_cmd_exec_then_move", "cmd", 'exec 3<<< "./helper.sh"; bash <&3-'),
    ("j05_body_exec_spaced_word", "body", 'exec 3<<< "./helper.sh"\nbash -s 3 </dev/null 0<&3\n'),
    ("j06_cmd_inline_spaced_word", "cmd", 'bash -s 3<<< "./helper.sh" 3 </dev/null 0<&3'),
    ("j07_body_escaped_arith_heredoc", "body", ': "\\$((" <<X\nX\nbash 0<&3 3<<< "./helper.sh"\n'),
    (
        "j08_body_escaped_arith_line",
        "body",
        ': "\\$(("; cat <<X\nX\nbash 0<&3 3<<< "./helper.sh"\n',
    ),
    ("j09_body_twin_missing_paren", "body", 'bash 0<&3 3<<< "./helper.sh"\n( echo a\n'),
    ("j10_body_move_then_word", "body", 'exec 3<<< "./helper.sh"\nbash -s <&3- x\n'),
    (
        "l01_body_escaped_arith_bash_heredoc",
        "body",
        'd=x\n: "\\$((x"; bash <<X; : "))"\n./helper.sh\nX\ncat 3<<< "$d"\n',
    ),
    (
        "l02_body_escaped_arith_bash_heredoc_tail_first",
        "body",
        'd=x\ncat 3<<< "$d"\n: "\\$((x"; bash <<X; : "))"\n./helper.sh\nX\n',
    ),
    (
        "l03_body_escaped_arith_bash_heredoc_dup",
        "body",
        ': "\\$((x"; bash <<X; : "))"\n./helper.sh\nX\nbash 0<&3 3<<< "./helper.sh"\n',
    ),
    (
        "l04_body_escaped_arith_sh_heredoc",
        "body",
        'd=x\n: "\\$((x"; sh <<X; : "))"\n./helper.sh\nX\ncat 3<<< "$d"\n',
    ),
)
_R11_ALLOW_PROBES = (
    ("k01_body_heredoc_data_two_marks", "body", "cat <<'EOF'\n3<<<x\n4<<<x\nEOF\n"),
    ("k03_body_control_cat_fd", "body", 'd=x\ncat 3<<< "$d"\n'),
    ("k04_body_escaped_arith_literal", "body", ': "\\$(("\necho ok\n'),
    ("k06_body_heredoc_data_one_mark", "body", "cat <<'EOF'\n3<<<x\nEOF\n"),
)
_R11_MOVE_ROWS = (
    ("m01", "exec 3<<<moved; cat <&3-; echo rc=$?; cat <&3 2>&1; echo rc2=$?", "moved"),
    ("m02", "exec 3<<<moved; cat 0<&3-; cat <&3 2>&1; echo rc2=$?", "moved"),
    ("m03", "cat 3<<<moved 0<&3-", "moved"),
    ("m04", "cat 0<&3- 3<<<moved 2>&1; echo rc=$?", None),
    ("m05", "exec 3<<<moved; cat <&3 -; echo rc=$?", "moved"),
    ("m06", "exec 3<<<moved; exec 4<&3-; cat <&3", None),
    ("m07", "exec 3<<<moved; exec 4<&3-; cat <&4", "moved"),
    ("m08", "exec 3<<<moved; cat 4<&3- <&4; cat <&3", "moved"),
    ("m09", "exec 3<<<moved; cat 4<&3- <&3", None),
)
_R11_SPACED_ROWS = (
    ("s01", "exec 3<<<kept; cat - 3 </dev/null 0<&3 2>&1", "kept"),
    ("s02", "exec 3<<<kept; cat - 3</dev/null 0<&3 2>&1; echo rc=$?", None),
    ("s03", "cat - 3<<<kept 3 </dev/null 0<&3 2>&1", "kept"),
    ("s04", "cat - 3<<<kept 3</dev/null 0<&3 2>&1; echo rc=$?", None),
    ("s05", "printf '[%s]' 3 </dev/null; echo", None),
)
_R11_FD0_ROWS = (
    ("z01", "cat 0<<<first", "first"),
    ("z02", "cat 00<<<first", "first"),
    ("z03", "exec 3<<<dup; cat 0<&3 0<<<last", "last"),
    ("z04", "cat 3<<<dup 0<&3 00<<<last", "last"),
    ("z05", "cat 0<<<first 3<<<dup 0<&3", "dup"),
)
_R11_TS_MISSING_SINGLE = (
    "( echo a\n",
    "{ echo a\n",
    "echo $(a\n",
    "if true; then echo a\n",
    'echo "a\n',
    "case x in a) echo;;\n",
    "[[ a\n",
    "echo ${a\n",
    "for i in a; do echo a\n",
    "f() { echo a\n",
    "while true; do echo a\n",
    "cat <(echo a\n",
    "echo $((1+2\n",
    "echo `a\n",
    "( cat\n",
    "{ cat; \n",
    "echo a | ( cat\n",
    "x=$(echo a\n",
    "if true; then cat; fi; ( echo\n",
    "(\n",
    "( (echo a)\n",
    "echo $( (a)\n",
    "[ a\n",
)

_R12_REFUSE_PROBES = (
    (
        "m01_cmd_pipeline_exec_first_stage",
        "cmd",
        'exec 3<<< "./helper.sh"; exec 3<<< x | cat >/dev/null; bash <&3',
    ),
    (
        "m02_body_pipeline_exec_first_stage",
        "body",
        'exec 3<<< "./helper.sh"\nexec 3<<< x | cat >/dev/null\nbash <&3\n',
    ),
    (
        "m03_cmd_pipeline_exec_last_stage",
        "cmd",
        'exec 3<<< "./helper.sh"; cat </dev/null | exec 3<<< x; bash <&3',
    ),
    ("m04_cmd_subshell_exec", "cmd", 'exec 3<<< "./helper.sh"; ( exec 3<<< x ); bash <&3'),
    ("m05_body_subshell_exec", "body", 'exec 3<<< "./helper.sh"\n( exec 3<<< x )\nbash <&3\n'),
    ("m06_cmd_saved_var_reassigned", "cmd", 'd=./helper.sh; exec 3<<< "$d"; d=x; bash 0<&3'),
    ("m07_body_saved_var_reassigned", "body", 'd=./helper.sh\nexec 3<<< "$d"\nd=x\nbash 0<&3\n'),
    (
        "m08_body_saved_var_read",
        "body",
        'd=./helper.sh\nexec 3<<< "$d"\nread -r d <<< x\nbash <&3\n',
    ),
    (
        "m09_cmd_saved_var_for",
        "cmd",
        'd=./helper.sh; exec 3<<< "$d"; for d in x; do :; done; bash <&3',
    ),
    ("m10_body_saved_var_export", "body", 'd=./helper.sh\nexec 3<<< "$d"\nexport d=x\nbash <&3\n'),
    ("m11_cmd_saved_var_benign", "cmd", 'd=./helper.sh; exec 3<<< "$d"; d=true; bash <&3'),
    ("m12_body_saved_var_benign", "body", 'd=./helper.sh\nexec 3<<< "$d"\nd=true\nbash <&3\n'),
    (
        "m13_cmd_inline_saved_var_benign",
        "cmd",
        'd=./helper.sh; exec 3<<< "$d"; d=true; bash 0<&3 4<<< x',
    ),
    (
        "m14_body_arith_paren_then_exec",
        "body",
        ': $(( (1 + (2)) << 1 ))\nexec 3<<< "./helper.sh"\nbash <&3\n',
    ),
    (
        "m15_cmd_arith_paren_then_exec",
        "cmd",
        ': $(( (1 + (2)) << 1 )); exec 3<<< "./helper.sh"; bash <&3',
    ),
    (
        "m16_body_arith_paren_inline_dup",
        "body",
        ': $(( (1 + (2)) << 1 ))\nbash 3<<< "./helper.sh" 0<&3\n',
    ),
    (
        "m17_body_printf_v_saved_benign",
        "body",
        'printf -v d %s ./helper.sh\nexec 3<<< "$d"\nd=true\nbash <&3\n',
    ),
    (
        "m19_body_read_saved_benign",
        "body",
        'read -r d <<< ./helper.sh\nexec 3<<< "$d"\nd=true\nbash <&3\n',
    ),
    (
        "m20_body_declare_saved_benign",
        "body",
        'declare d=./helper.sh\nexec 3<<< "$d"\nd=true\nbash <&3\n',
    ),
    (
        "m21_body_append_saved_benign",
        "body",
        'd=./helper\nd+=.sh\nexec 3<<< "$d"\nd=true\nbash <&3\n',
    ),
)
_R12_ALLOW_PROBES = (
    ("n01_body_arith_nested_paren_shift", "body", 'd=x\n: $(( (1 + (2)) << 1 ))\ncat 3<<< "$d"\n'),
    ("n02_body_arith_plain_shift", "body", 'd=x\n: $(( 1 << 1 ))\ncat 3<<< "$d"\n'),
    ("n03_body_arith_one_group_shift", "body", 'd=x\n: $(( (1) << 1 ))\ncat 3<<< "$d"\n'),
    ("n04_cmd_pipeline_exec_cat", "cmd", "exec 3<<< x; exec 3<<< y | cat >/dev/null; cat <&3"),
    ("n05_body_saved_literal_cat", "body", "exec 3<<< first\nd=x\ncat <&3\n"),
    ("n06_body_control_cat_fd", "body", 'd=x\ncat 3<<< "$d"\n'),
    (
        "n07_body_arith_nested_paren_dup",
        "body",
        'd=x\n: $(( (1 + (2)) << 1 ))\ncat 3<<< "$d" 0<&3\n',
    ),
    ("n08_body_arith_plain_dup", "body", 'd=x\n: $(( 1 << 1 ))\ncat 3<<< "$d" 0<&3\n'),
    (
        "n09_body_arith_nested_paren_exec_dup",
        "body",
        'd=x\n: $(( (1 + (2)) << 1 ))\nexec 3<<< "$d"\ncat <&3\n',
    ),
    ("n10_body_plain_dup_control", "body", 'd=x\ncat 3<<< "$d" 0<&3\n'),
)
_STALE_REASON = "saved here-string word may change before its duplication"
_UNKNOWN_REASON = "descriptor binding unknown at duplication"
_R12_CONTEXT_ROWS = (
    ("p01", "exec 3<<<parent; exec 3<<<stage | cat >/dev/null; cat <&3", "parent"),
    ("p02", "exec 3<<<parent; cat </dev/null | exec 3<<<stage; cat <&3", "parent"),
    ("p03", "exec 3<<<parent; { exec 3<<<grp; }; cat <&3", "grp"),
    ("p04", "exec 3<<<parent; ( exec 3<<<sub ); cat <&3", "parent"),
    ("p05", "exec 3<<<parent; exec 3<<<stage | cat <&3", "parent"),
    ("p06", "exec 3<<<parent; exec 3<<<stage && cat <&3", "stage"),
    (
        "l01",
        "shopt -s lastpipe; exec 3<<<parent; cat </dev/null | exec 3<<<stage; cat <&3",
        _UNKNOWN_REASON,
    ),
    (
        "l02",
        "shopt -s lastpipe; exec 3<<<parent; exec 3<<<stage | cat >/dev/null; cat <&3",
        "parent",
    ),
    ("l03", "f() { exec 3<<<fn; }; exec 3<<<parent; f; cat <&3", _UNKNOWN_REASON),
    ("l04", "exec 3<<<parent; exec 3<<<bg & wait; cat <&3", "parent"),
    ("l05", "exec 3<<<parent; x=$(exec 3<<<cs); cat <&3", "parent"),
    ("l06", "exec 3<<<parent; { exec 3<<<grp; } | cat; cat <&3", "parent"),
    ("l07", "exec 3<<<parent; if true; then exec 3<<<if; fi; cat <&3", "if"),
    ("l08", "exec 3<<<parent; for i in 1; do exec 3<<<loop; done; cat <&3", "loop"),
    ("l09", "exec 3<<<parent; true && exec 3<<<and; cat <&3", "and"),
    ("l10", "exec 3<<<parent; cat <(exec 3<<<ps) >/dev/null; cat <&3", "parent"),
    ("u01", "exec 3<<<a; }; cat <&3", _UNKNOWN_REASON),
    ("u02", "function g { exec 3<<<z; }; exec 3<<<a; cat <&3", _UNKNOWN_REASON),
    ("u03", "case x in a) exec 3<<<y ;; esac; cat <&3", "y"),
    ("u04", "echo $((1+2)); exec 3<<<a; cat <&3", "a"),
)
_R12_SAVED_ROWS = (
    ("v01", 'd=first; exec 3<<<"$d"; d=second; cat <&3', _STALE_REASON),
    ("v02", 'd=first; exec 3<<<"$d"; read -r d <<<second; cat <&3', _STALE_REASON),
    ("v03", 'd=first; exec 3<<<"$d"; cat <&3', "$d"),
    ("v04", 'd=first; cat 3<<<"$d" 0<&3', "$d"),
    ("v05", "exec 3<<<first; d=x; cat <&3", "first"),
    ("v06", 'd=first; exec 3<<<"$d"; unset d; cat <&3', _STALE_REASON),
    ("v07", 'd=first; exec 3<<<"$d" 4<<<"$d"; d=second; cat <&4', _STALE_REASON),
)
_R12_NON_ASSIGNING = (
    "cat file",
    "echo hi",
    "true",
    ":",
    "test -n x",
    "[ -n x ]",
    "printf '%s' x",
    "exec 4<<<y",
    "exec 5<&-",
)
_R12_ASSIGNING = (
    "printf -v d x",
    "echo $((d=1))",
    "echo ${d:=x}",
    'echo "$[d=1]"',
    "d=x cat file",
    "d+=x",
    "read d",
    "declare d=x",
    "export d=x",
    "local d=x",
    "typeset d=x",
    "mapfile a",
    "readarray a",
    "unset d",
    "let d=1",
    "eval d=x",
    "source ./x",
    ". ./x",
    "for d in x; do :; done",
    "select d in x; do break; done",
    "case x in x) :;; esac",
    "myfn",
)
_R12_ARITH_ROWS = (
    (b": $(( (1 + (2)) << 1 ))", [(2, 23)]),
    (b"delay=$(( (1 + (2)) << 1 ))", [(6, 27)]),
    (b": $(( 1 << 1 ))", [(2, 15)]),
    (b": $(( (1) << 1 ))", [(2, 17)]),
    (b'echo "$((1<<2))"', [(6, 15)]),
    (b": $(( (1 + (2 << 1 ))", []),
    (b": $(( x ) )", []),
)
_R12_SECOND_CAT_ROWS = (
    ("c01", "exec 3<<<moved; cat <&3-; cat <&3", ["moved", "moved"]),
    ("c02", "exec 3<<<moved; cat 0<&3-; cat <&3", ["moved", "moved"]),
    ("c03", "exec 3<<<moved; exec 0<&3-; cat <&3", [None]),
)


def _first(items: list[str | None]) -> str | None:
    """Return the first stdin word of a cat list, or None when no cat was found."""
    return items[0] if items else None


def _best_seconds(call: Callable[[], object], repeats: int = 3) -> float:
    """Return the shortest wall time of repeated calls."""
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best


def _ast_module_funcs(path: Path) -> dict[str, ast.FunctionDef]:
    """Collect top-level function definitions from one module file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            out[node.name] = node
    return out


def _body_lex_call_edges(
    body_funcs: dict[str, ast.FunctionDef], lex_funcs: dict[str, ast.FunctionDef]
) -> dict[str, set[str]]:
    """Build plain-name call edges between body and lex module-level functions."""
    body_names = set(body_funcs)
    lex_names = set(lex_funcs)
    edges: dict[str, set[str]] = {name: set() for name in body_names | lex_names}
    for home, func in {**body_funcs, **lex_funcs}.items():
        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            callee = node.func.id
            if callee in body_names or callee in lex_names:
                edges[home].add(callee)
    return edges


def _find_call_cycle(edges: dict[str, set[str]]) -> str | None:
    """Return one call cycle path when present, otherwise None."""
    graph = {node: sorted(neighbors) for node, neighbors in edges.items()}
    try:
        graphlib.TopologicalSorter(graph).prepare()
    except graphlib.CycleError as err:
        if err.args[1:]:
            return " -> ".join(err.args[1])
        return "cycle"
    return None


PROBE_GAP_SHAPES = (
    "command -p cd $R/tree; ./configure",
    "command -- cd $R/tree; ./configure",
    "builtin -- cd $R/tree; ./configure",
    "function f { cd $R/tree; }; f; ./configure",
    "time -p -- cd $R/tree; ./configure",
    "CDPATH=$R cd tree; ./configure",
    "shopt -s expand_aliases; alias c=cd\nc $R/tree; ./configure",
    "export CDPATH=$R; cd tree; ./configure",
    "CDPATH=$R; cd tree; ./configure",
    "pushd $R/tree; pushd /tmp; pushd +1; ./configure",
    "source $R/s.sh; ./configure",
    ". $R/s.sh; ./configure",
    "command -p . $R/s.sh; ./configure",
    "BASH_ENV=$R/s.sh bash -c ./configure",
    "env -C $R/tree ./configure",
    "env --chdir=$R/tree ./configure",
    "cd $R/tree; ~+/configure",
    "false && cd /tmp; ./configure",
    "if false; then cd /tmp; fi; ./configure",
    "true || cd /tmp; ./configure",
    "while false; do cd /tmp; done; ./configure",
    "pushd /tmp; pushd +1; ./configure",
    "[ -d /nope ] && cd /tmp; ./configure",
    "f() { cd /tmp; }; ./configure",
    "cd() { :; }; cd /tmp; ./configure",
    "enable -n cd; cd /tmp; ./configure",
    "shopt -s expand_aliases\nalias cd=:\ncd /tmp; ./configure",
    "for i in; do cd /tmp; done; ./configure",
)


class RawConfigureShapeTest(RawConfigureGuardBase):
    """Exercise complex command shapes, boundaries, and subshell forms."""

    def test_refuses_all_probe_gap_shapes(self) -> None:
        """Refuse all 28 probe gap shapes from non-tree directories."""
        (self.root / "s.sh").write_text(f"cd {self.tree}\n", encoding="utf-8")
        cases = tuple((cmd.replace("$R", str(self.root)), self.other) for cmd in PROBE_GAP_SHAPES)
        self._assert_refused(cases)

    def test_refuses_wrapper_and_relocation_forms(self) -> None:
        """Block direct, wrapped, and relocated FFmpeg configure calls."""
        cases = (
            ("./configure --prefix=/x", self.tree),
            ("bash configure", self.tree),
            ("sh ./configure", self.tree),
            (f"cd {self.tree} && ./configure", self.root),
            ("env FOO=1 nice -n 10 ./configure", self.tree),
            (str(self.tree / "configure"), self.root),
            ("cd BUILD && ../tree/configure", self.root),
            ("systemd-run --user --scope -p MemoryHigh=8G -- ./configure", self.tree),
            ("praetorctl admit -label x -- ./configure", self.tree),
            ('"$SRC"/configure', self.tree),
            ("./configure`unknown`", self.tree),
            ("true\n./configure", self.tree),
            ("env -u FOO ./configure", self.tree),
            ("timeout 5 ./configure", self.tree),
            ("taskset 0x1 ./configure", self.tree),
            ("chrt -f 1 ./configure", self.tree),
            ("ionice -c 2 -n 0 ./configure", self.tree),
            ("stdbuf -oL ./configure", self.tree),
            ("setsid ./configure", self.tree),
            ("nohup ./configure", self.tree),
            ("exec ./configure", self.tree),
            ("command ./configure", self.tree),
            ("builtin ./configure", self.tree),
            ("time ./configure", self.tree),
            ("systemd-run --user -p MemoryHigh=8G ./configure", self.tree),
            ('cd "$X" && ./configure', self.tree),
            ("cd - && ./configure", self.tree),
            ("popd; ./configure", self.tree),
            ("sudo ./configure", self.tree),
            ("flock /tmp/l ./configure", self.tree),
            ("f=./configure; $f", self.tree),
            ("source ./configure", self.tree),
            (". ./configure", self.tree),
            ("./conf*", self.tree),
        )
        self._assert_refused(cases)

    def test_refuses_interpreter_and_reader_abuse_forms(self) -> None:
        """Block interpreter one-liners and reader-abuse configure invocations."""
        cases = (
            ("bash -c './configure'", self.tree),
            ("bash -c 'sudo ./configure'", self.tree),
            ("xargs ./configure", self.tree),
            ("echo ./configure | bash", self.tree),
            ("find . -name configure -exec sh {} \\;", self.tree),
            ("echo $(./configure)", self.tree),
            ("echo `./configure`", self.tree),
            ("python3 -c \"import os; os.system('./configure')\"", self.tree),
            ("perl -e 'system q(./configure)'", self.tree),
            ('awk "BEGIN{system(\\"./configure\\")}"', self.tree),
            ("sed -n '1e ./configure' README", self.tree),
            ("less +'!./configure' x", self.tree),
            ("rg --pre ./configure x .", self.tree),
            ("git -c alias.x='!./configure' x", self.tree),
            ("git -c core.pager=./configure log", self.tree),
            ("git rebase -x ./configure HEAD~1", self.tree),
            ("git bisect run ./configure", self.tree),
            ("git submodule foreach ./configure", self.tree),
            ("LESSOPEN='|./configure %s' less README", self.tree),
            ("GIT_PAGER=./configure git log", self.tree),
            ("GIT_EXTERNAL_DIFF=./configure git diff", self.tree),
            ("cat configure | sh", self.tree),
        )
        self._assert_refused(cases)

    def test_refuses_subshell_and_pipeline_directory_leaks(self) -> None:
        """Refuse subshell and pipeline forms leaking directory state to configure."""
        cases = (
            ("(cd /tmp); ./configure", self.tree),
            ("(cd /tmp) && ./configure", self.tree),
            ("cd /tmp | true; ./configure", self.tree),
            ("(cd /tmp; (cd /var)); ./configure", self.tree),
        )
        self._assert_refused(cases)

    def test_refuses_subshell_and_cd_resolution_fail_opens(self) -> None:
        """Refuse background cd, pipe-and, failed cd, lexical dots, and CDPATH lookups."""
        plain_file = self.root / "plain_file"
        plain_file.write_text("x", encoding="utf-8")
        symlink = self.tree / "l"
        symlink.symlink_to(self.other)
        cases = (
            ("cd /tmp & ./configure", self.tree),
            ("cd /tmp &\n./configure", self.tree),
            ("cd /tmp |& true; ./configure", self.tree),
            ("cd /tmp && true & ./configure", self.tree),
            ("true && cd /tmp & ./configure", self.tree),
            ("cd /nonexistent-rcg9; ./configure", self.tree),
            ("cd /nonexistent-rcg9 || true; ./configure", self.tree),
            (f"cd {plain_file}; ./configure", self.tree),
            ("cd l/..; ./configure", self.tree),
        )
        self._assert_refused(cases)
        other_tree = self.other / "tree"
        other_tree.mkdir()
        cdpath_cases = (("cd tree; ./configure", self.other),)
        self._assert_refused(cdpath_cases, env={**os.environ, "CDPATH": str(self.root)})

    def test_refuses_redirect_ampersand_forms(self) -> None:
        """Refuse configure runs where cd or configure contains redirect ampersands."""
        cases = (
            (f"cd {self.tree} 2>&1; ./configure", self.other),
            (f"cd {self.tree} &>/dev/null; ./configure", self.other),
            (f"cd {self.tree} >&2; ./configure", self.other),
            (f"cd {self.tree} &>>log; ./configure", self.other),
            (f"cd {self.tree} 2>&-; ./configure", self.other),
            ("./configure 2>&1", self.tree),
            ("./configure >log 2>&1 &", self.tree),
        )
        self._assert_refused(cases)

    def test_refuses_unsearchable_directory_cd(self) -> None:
        """Refuse raw configure after cd into a directory without search permission."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores directory search permissions")
        noexec = self.root / "noexec"
        noexec.mkdir(mode=0o700, exist_ok=True)
        noexec.chmod(0o600)
        self.addCleanup(lambda: noexec.chmod(0o700) if noexec.exists() else None)
        self._assert_refused(((f"cd {noexec}; ./configure", self.tree),))

    def test_refuses_digit_directory_redirect_ambiguities(self) -> None:
        """Refuse digit directory cd redirect ambiguities while keeping valid targets allowed."""
        digit_tree = self.root / "2"
        digit_tree.mkdir()
        (digit_tree / "libavcodec").mkdir()
        script = digit_tree / "configure"
        script.write_text(f"#!/bin/sh\ntouch '{self.marker}'\n", encoding="utf-8")
        script.chmod(0o755)
        refuse_cases = (
            ("cd 2 >&1; ./configure", self.root),
            ("cd 2 2>&1; ./configure", self.root),
            ("cd 2>&1 2; ./configure", self.root),
            ("cd 2>&1; ./configure", self.root),
            ("pushd 2 >&1; ./configure", self.root),
        )
        self._assert_refused(refuse_cases)

    def test_refuses_wrapped_shell_and_option_forms(self) -> None:
        """Refuse shell invocations behind wrappers and with complex options."""
        cases = (
            (f"env bash -c 'cd {self.tree} && ./configure'", self.root),
            (f"timeout 5 sh -c 'cd {self.tree} && ./configure'", self.root),
            (f"nohup bash -c 'cd {self.tree} && ./configure'", self.root),
            (f"bash -o pipefail -c 'cd {self.tree} && ./configure'", self.root),
            (f"bash --norc -c 'cd {self.tree} && ./configure'", self.root),
            (f"bash -eo pipefail -c 'cd {self.tree} && ./configure'", self.root),
        )
        self._assert_refused(cases)

    def test_oversized_glob_refusal_and_benign_allow(self) -> None:
        """Refuse oversized glob configure invocations while allowing benign commands."""
        padding = " # " + "x" * 65536
        oversized_refusal = f"cd {self.tree} && ./c?nfigure{padding}"
        self._assert_refused(((oversized_refusal, self.root),), remedy="--body-file")
        oversized_allow = "ls"
        client = self._next_client()
        with self.subTest(client=client):
            result = self.run_guard(client, self.payload(client, oversized_allow, self.root))
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_oversized_quote_and_backslash_configure_refusal(self) -> None:
        """Refuse oversized configure invocations split by quotes and backslashes."""
        padding = " # " + "x" * 65536
        cases = (
            (f"cd {self.tree} && ./con''figure{padding}", self.root),
            (f'cd {self.tree} && ./con""figure{padding}', self.root),
            (f"cd {self.tree} && ./conf\\igure{padding}", self.root),
            (f"./con''figure{padding}", self.tree),
        )
        self._assert_refused(cases, remedy="--body-file")

    def test_midword_expansion_configure_refusal_and_benign_allow(self) -> None:
        """Refuse mid-word configure expansions while allowing benign variants."""
        refuse_cases = (
            (f"cd {self.tree} && ./conf${{e}}igure", self.root),
            (f"cd {self.tree} && ./${{e}}con${{e}}figure", self.root),
            ("./co$'n'figure", self.tree),
            ("./conf$eigure", self.tree),
        )
        self._assert_refused(refuse_cases)
        allow_cases = (("echo conf${e}igure", self.tree),)
        for command, cwd in allow_cases:
            client = self._next_client()
            with self.subTest(client=client, command=command):
                result = self.run_guard(client, self.payload(client, command, cwd))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.marker.exists())

    def test_undecidable_configure_refusal_and_benign_allow(self) -> None:
        """Refuse undecidable dynamic commands in trees while allowing benign commands."""
        (self.tree / "tools").mkdir(exist_ok=True)
        refuse_cases = (
            ("./co$'n'figure", self.tree),
            (r"./co$'\x6e'figure", self.tree),
            ("./$X", self.tree),
            (f"cd {self.tree} && ./co$'n'figure", self.root),
        )
        self._assert_refused(refuse_cases)
        allow_cases = (
            ("echo co$'n'figure", self.tree),
            ("echo $PATH", self.tree),
            ("$HOME/bin/tool", self.tree),
            ("ls $PWD", self.tree),
        )
        for client in CLIENTS:
            for command, cwd in allow_cases:
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(self.marker.exists())

    def test_decidable_allowlist_configure_refusal_and_benign_allow(self) -> None:
        """Refuse undecidable names and directory expansions while allowing safe patterns."""
        (self.tree / "tools").mkdir(exist_ok=True)
        refuse_cases = (
            ("./co`printf n`figure", self.tree),
            ("./co{n,}figure", self.tree),
            ("{.,x}/configure", self.tree),
            ("./co{n..n}figure", self.tree),
            ("./co[n]figure", self.tree),
        )
        self._assert_refused(refuse_cases)
        allow_cases = (
            ("ls ./*.c", self.tree),
            ("cp ./a.txt ./b.txt", self.tree),
            ("echo {a,b}", self.tree),
            ("ls libavcodec/{a,b}.c", self.tree),
            ("$HOME/bin/tool", self.tree),
            ("ls $PWD", self.tree),
        )
        for client in CLIENTS:
            for command, cwd in allow_cases:
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(self.marker.exists())

    def test_command_substitution_path_refusals(self) -> None:
        """Refuse command substitutions glued to configure paths targeting a tree."""
        cases = (
            ("$(pwd)/configure", self.tree),
            ("$(git rev-parse --show-toplevel 2>/dev/null || pwd)/configure", self.tree),
            ('"$(pwd)"/configure', self.tree),
            ("$(pwd)/co{n,}figure", self.tree),
        )
        self._assert_refused(cases)

    def test_shell_script_operand_without_slash_refusals(self) -> None:
        """Refuse shell script arguments without a slash that target configure."""
        cases = (
            ("sh co{n,}figure", self.tree),
            ("bash co`echo n`figure", self.tree),
            ("sh co$'n'figure", self.tree),
        )
        self._assert_refused(cases)

    def test_parsed_dynamic_path_allows(self) -> None:
        """Allow parsed commands with substitutions and dynamic paths outside trees."""
        heredoc = "cat <<'EOF' > /dev/null\nfix(hooks): it's in scripts/x.py\nEOF"
        cases = (
            ("echo $(pwd)/x", self.tree),
            ("sh ./tools/x.sh", self.tree),
            ("cat $(pwd)/README", self.tree),
            ("git commit -F - <<'EOF'\nfix: refuse scripts/a.py\nEOF", self.other),
            ("git commit -F - <<'EOF'\nfix: don't refuse scripts/a.py\nEOF", self.other),
            (heredoc, self.other),
            ("sed -n 1p configure", self.tree),
            ("git commit -F /tmp/msg.txt", self.other),
            ("gh pr create --body-file /tmp/body.md --title x", self.other),
            ("ls", self.other),
        )
        for client in CLIENTS:
            for command, cwd in cases:
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(self.marker.exists())

    def test_eval_and_prefix_command_refusals(self) -> None:
        """Refuse configure execution reached through eval or prefix-wrapped directory changes."""
        cases = (
            (f"eval 'cd {self.tree}' && ./configure", self.root),
            (f"eval cd {self.tree}; ./configure", self.root),
            (f'eval "cd {self.tree}"; sh configure', self.root),
            (f"if cd {self.tree}; then ./configure; fi", self.root),
            (f"{{ cd {self.tree}; ./configure; }}", self.root),
            (f"while cd {self.tree}; do ./configure; break; done", self.root),
            (f"! cd {self.tree} || ./configure", self.root),
            (f"time cd {self.tree}; ./configure", self.root),
            (f"time -p cd {self.tree}; ./configure", self.root),
            (f"command cd {self.tree}; ./configure", self.root),
            (f"builtin cd {self.tree}; ./configure", self.root),
            (f"X=1 cd {self.tree}; ./configure", self.root),
        )
        self._assert_refused(cases)

    def test_eval_and_prefix_command_controls_and_boundaries(self) -> None:
        """Allow benign eval and prefix commands and enforce boundary limits."""
        allow_cases = (
            (f"if cd {self.tree}; then ls; fi", self.root),
            ("eval 'echo hi'; ls", self.root),
            ("command -v ls", self.root),
            ("time ls", self.root),
            ("ls", self.tree),
            ("{ ls; }", self.tree),
            ("if then elif else do while until ! { time command builtin", self.root),
        )
        for client in CLIENTS:
            for command, cwd in allow_cases:
                with self.subTest(client=client, command=command):
                    result = self.run_guard(client, self.payload(client, command, cwd))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(self.marker.exists())
            long_if = "if " * 4000 + f"cd {self.tree}; ./configure"
            with self.subTest(client=client, boundary="long_if"):
                result = self.run_guard(client, self.payload(client, long_if, self.root))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.marker.exists())

    def test_exception_and_whitespace_quoted_word(self) -> None:
        """Fail closed on inspection exceptions and refuse whitespace-only quoted words."""
        stderr_buf = io.StringIO()
        with (
            unittest.mock.patch(
                "sys.stdin.buffer.read",
                return_value=json.dumps(self.payload("claude", "ls", self.other)).encode("utf-8"),
            ),
            unittest.mock.patch.object(
                GUARD_MOD, "_inspect", side_effect=RuntimeError("simulated error")
            ),
            unittest.mock.patch("sys.stderr", stderr_buf),
        ):
            rc = GUARD_MOD.main(["--client", "claude"])
            self.assertEqual(rc, 2)
            self.assertIn("scripts/ffmpeg_configure.py", stderr_buf.getvalue())
        for client in CLIENTS:
            for cmd in ('"  " ./configure', './configure "  "'):
                with self.subTest(client=client, command=cmd):
                    result = self.run_guard(client, self.payload(client, cmd, self.other))
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("scripts/ffmpeg_configure.py", result.stderr)

    def test_refuses_fd_descriptor_herestring_fail_open_shapes(self) -> None:
        """Refuse main-line fail-open f shapes hidden by missing heredoc ends."""
        bodies = (
            'delay=$((1 << 2))\ncat scripts/x.py 3<<< "$d"\n./configure --prefix=/x\n',
            'delay=$((1 << 2))\ncat 3<<< "$d"\n./configure --prefix=/x\n',
            'delay=$((1 << 2))\ncat - x 3<<< "$d" > y\n./configure --prefix=/x\n',
        )
        for body in bodies:
            self._check_parser_body(body, refused=True)

    def test_refuses_fd_descriptor_herestring_known_bad_shapes(self) -> None:
        """Refuse empty here-strings, semicolon tails, and configure in tail payloads."""
        bodies = (
            "cat 3<<< x\n./configure --prefix=/x\n",
            'cat - x 3<<< "$d" > y\n./configure --prefix=/x\n',
            'delay=$((1 << 2))\ncat 3<<< "$d" > /tmp/y; ./configure --prefix=/x\n',
            'delay=$((1 << 2))\n./configure 3<<< "$d" > /tmp/y\n',
            'delay=$((1 << 2))\ncat 3<<< "$(./configure)" > /tmp/y\n',
            'delay=$((1 << 2))\ncat 3<<< "$d" > /tmp/y 4<<< "$e"\n',
            'delay=$((1 << 2))\ncat 3<<< "$d" | ./configure\n',
        )
        for body in bodies:
            self._check_parser_body(body, refused=True)

    def test_refuses_fd_descriptor_herestring_review2_shapes(self) -> None:
        """Refuse the round-2 review desync shapes without lexer blanking."""
        bodies = (
            (
                "((cat <<- 3<<<'true' >y\nx; delay=$((1 << 2));\n"
                "if cat - x 3<<< \"$d\" > y <<'true'\n"
                "3\nif ./configure --prefix=/x\ntrue\nthen :; fi\n); true)\n"
            ),
            (
                "delay=$((1 << 2))\ncat <<'EOF' >y\nEOF\r\n\nif cat - x 3<<< \"$d\" > y <<'true'\n"
                "EOF\nif ./configure --prefix=/x\ntrue\nthen :; fi\n"
            ),
            (
                "delay=$((1 << 2))\ncat <<'E'\\\n'OF' >y\nE\nif cat - x 3<<< \"$d\" > y <<'true'\n"
                "EOF\nif ./configure --prefix=/x\ntrue\nthen :; fi\n"
            ),
            (
                "delay=$((1 << 2))\necho `echo \\` #\\` ; cat <<'EOF' >y`\n"
                "if cat - x 3<<< \"$d\" > y <<'true'\n"
                "EOF\nif ./configure --prefix=/x\ntrue\nthen :; fi\n"
            ),
            (
                "((cat <<'EOF' >y\nx; if cat - x 3<<< \"$d\" > y <<'true'\n"
                "EOF\nif ./configure --prefix=/x\ntrue\nthen :; fi\n); true)\n"
            ),
        )
        for body in bodies:
            self._check_parser_body(body, refused=True)

    def test_refuses_fd_descriptor_herestring_guardfd_shapes(self) -> None:
        """Refuse guardfd fixtures that combine heredocs with descriptor tails."""
        self._check_parser_body(GUARDFD_G1, refused=True)
        self._check_parser_body(GUARDFD_G6, refused=True)

    def test_refuses_fd_descriptor_herestring_boundary_mutations(self) -> None:
        """Refuse allow-list boundary violations around the p1 tail shape."""
        base = 'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n'
        bodies = (
            'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y # x\n',
            'delay=$((1 << 2))\npython3 - x 3<<< "$(x)" > /tmp/y\n',
            base + 'delay=$((1 << 2))\ncat 4<<< "$e" > /tmp/z\n',
            'delay=$((1 << 2))\r\npython3 - x 3<<< "$d" > /tmp/y\n',
            'delay=$((1 << 2))\\\npython3 - x 3<<< "$d" > /tmp/y\n',
            '# `x`\ndelay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n',
            'if true; then\npython3 - x 3<<< "$d" > /tmp/y\nfi\n',
            'delay=$((1 << 2))\npython3 - x 10<<< "$d" > /tmp/y\n',
            'delay=$((1 << 2))\ncat 3<<< "$d" > /tmp/a\ncat 4<<< "$e" > /tmp/b\n',
        )
        for body in bodies:
            self._check_parser_body(body, refused=True)

    def test_allows_fd_descriptor_herestring_pass_shapes(self) -> None:
        """Allow shift-prefixed descriptor here-string tails blocked only by ERROR spans."""
        bodies = (
            'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n',
            'delay=$((1 << 2))\ncat - 3<<< "$d" > out/y\n',
            'delay=$((1 << 2))\npython3 scripts/x.py 3<<< "$d" > /tmp/y 2>&1\n',
            'python3 - x 3<<< "$d" > /tmp/y\n',
            'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\necho done\n',
            "delay=$((1 << 2))\npython3 - x 3<<< '$d' > /tmp/y\n",
        )
        for body in bodies:
            self._check_parser_body(body, refused=False)

    def test_b5_descriptor_tail_matches_b6_clean_redirect(self) -> None:
        """Give b5 the same verdict as the clean here-string redirect in b6."""
        b5 = 'delay=$((1 << 2))\ncat 3<<< "$d" > ./configure\n'
        b6 = 'cat <<< "$d" > ./configure\n'
        for body in (b5, b6):
            self._check_parser_body(body, refused=False)

    def test_refuses_unterminated_heredoc_dangerous_tail(self) -> None:
        """Refuse configure bytes left after an unclosed heredoc opener."""
        body = "cat <<EOF\n./configure --prefix=/x\n"
        self._check_parser_body(body, refused=True)

    def test_refuses_descriptor_plain_twin_parity_fail_open_rows(self) -> None:
        """Refuse every parity-grid descriptor form that fail-opened on plain-twin parity."""
        client = self._next_client()
        for cmd in _PARITY_COMMANDS:
            for word in _PARITY_WORDS:
                for tail in _PARITY_TAILS:
                    plain = f"{cmd} <<< {word}{tail}"
                    plain_res = self.run_guard(client, self.payload(client, plain, self.tree))
                    self.assertIn(plain_res.returncode, (0, 2), plain_res.stderr)
                    if plain_res.returncode != 2:
                        continue
                    for fd in ("0", "3"):
                        desc = f"{cmd} {fd}<<< {word}{tail}"
                        with self.subTest(cmd=cmd, word=word, tail=tail, fd=fd):
                            result = self.run_guard(client, self.payload(client, desc, self.tree))
                            self.assertEqual(result.returncode, 2, result.stderr)

    def test_refuses_descriptor_plain_twin_inline_fail_open_rows(self) -> None:
        """Refuse inline descriptor shapes that fail-opened before the plain-twin guard."""
        cases = tuple((body.rstrip("\n"), self.tree) for _label, body in _INLINE_FAIL_OPEN)
        self._assert_refused(cases)

    def test_allows_descriptor_plain_twin_cat_pass_shapes(self) -> None:
        """Allow descriptor cat tails that stay allowed after plain-twin parity."""
        bodies = (
            'cat 3<<< "$d"\n',
            'cat 3<<< "$d" > /tmp/y\n',
            'cat - x 3<<< "$d"\n',
        )
        for body in bodies:
            self._check_parser_body(body, refused=False)

    def test_descriptor_plain_twin_fd_refused_when_plain_refused(self) -> None:
        """Refuse fd 0 and fd 3 whenever the plain here-string twin is refused."""
        for cmd in _PARITY_COMMANDS:
            for word in _PARITY_WORDS:
                for tail in _PARITY_TAILS:
                    plain = f"{cmd} <<< {word}{tail}\n"
                    plain_hit = scan_body(plain, self._shape_context(), BodyBudget())[0]
                    if plain_hit is None:
                        continue
                    for fd in ("0", "3"):
                        body = f"{cmd} {fd}<<< {word}{tail}\n"
                        with self.subTest(cmd=cmd, word=word, tail=tail, fd=fd):
                            hit = scan_body(body, self._shape_context(), BodyBudget())[0]
                            self.assertIsNotNone(hit)

    def test_script_blocks_fd_herestring_allowlist_shift_limit(self) -> None:
        """Fail closed when shift occurrences exceed the script-wide inspection limit."""
        shift = "delay=$((1 << 2))\n"
        heredoc = "cat <<EOF\nx\nEOF\n"
        raw_many = (shift * 4100 + heredoc).encode()
        self.assertTrue(lex_mod.script_blocks_fd_herestring_allowlist(raw_many))
        raw_n = (shift * 4096).encode()
        raw_n1 = (shift * 4097).encode()
        self.assertFalse(lex_mod.script_blocks_fd_herestring_allowlist(raw_n))
        self.assertTrue(lex_mod.script_blocks_fd_herestring_allowlist(raw_n1))
        self.assertFalse(lex_mod.script_blocks_fd_herestring_allowlist((shift * 10).encode()))

    def test_descriptor_twin_refuses_when_plain_twin_parser_unavailable(self) -> None:
        """Refuse descriptor tails when the plain-twin side scan cannot parse."""
        body = 'd=x\ncat 3<<< "$d"\n'
        self.assertIsNone(scan_body(body, self._shape_context(), BodyBudget())[0])
        calls: list[int] = []
        real_parser = body_mod.bash_parser

        def staged_parser() -> object:
            """Return the real parser once, then a refusal string on the twin lookup."""
            calls.append(1)
            if len(calls) > 1:
                return "simulated parser unavailable"
            return real_parser()

        with unittest.mock.patch.object(body_mod, "bash_parser", side_effect=staged_parser):
            hit = scan_body(body, self._shape_context(), BodyBudget())[0]
        self.assertIsNotNone(hit)
        self.assertIn("without the descriptor digit is refused", hit or "")
        self.assertIn("simulated parser unavailable", hit or "")

    def _shape_context(self) -> InspectionContext:
        """Build the inspection context shared by in-process shape probes."""
        return InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )

    def test_clean_redirect_targets_match_descriptor_tail_targets(self) -> None:
        """Pin descriptor-tail redirect targets to clean here-string redirect checks."""
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )
        budget = BodyBudget()
        for target in ("./configure", "/tmp/y", "out/y"):
            self.assertTrue(_probe_clean_redirect_target(target, context, budget))

    def test_raw_configure_body_lex_call_graph_acyclic(self) -> None:
        """Assert module-level calls between body and lex helpers form an acyclic graph."""
        body_funcs = _ast_module_funcs(_BODY_PATH)
        lex_funcs = _ast_module_funcs(_LEX_PATH)
        cycle = _find_call_cycle(_body_lex_call_edges(body_funcs, lex_funcs))
        if cycle is not None:
            self.fail(f"call cycle: {cycle}")

    def test_refuses_descriptor_tail_when_clean_redirect_probe_fails(self) -> None:
        """Refuse an otherwise valid tail when the precomputed redirect verdict is false."""
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )
        body = 'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n'
        patch = unittest.mock.patch.object(
            body_mod, "_probe_clean_redirect_target", return_value=False
        )
        with patch:
            hit = scan_body(body, context, BodyBudget())[0]
        self.assertIsNotNone(hit)
        self.assertIn("unparsable shell text naming a command", hit or "")

    def test_allows_c1g_main_tail_when_inline_eval_follows(self) -> None:
        """Allow p1 tail when an inline eval body follows and keeps its own verdict."""
        body = (
            "delay=$((1 << 2))\npython3 - x 3<<< \"$d\" > /tmp/y\neval 'cat <<< x > /tmp/z ; ( :'\n"
        )
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )
        hit = scan_body(body, context, BodyBudget())[0]
        self.assertIsNone(hit)

    def test_main_refused_tail_unchanged_with_inline_neighbor(self) -> None:
        """Keep a refused main redirect when an allow-listed inline tail neighbors it."""
        refused = 'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n'
        allowed_inline = "eval 'cat <<< x > /tmp/z ; ( :'\n"
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )
        budget = BodyBudget()
        patch = unittest.mock.patch.object(
            body_mod, "_probe_clean_redirect_target", return_value=False
        )
        after = refused + allowed_inline
        before = allowed_inline + refused
        with patch:
            for body in (after, before):
                hit = scan_body(body, context, budget)[0]
                self.assertIsNotNone(hit)
                self.assertIn("unparsable shell text naming a command", hit or "")

    def test_fd_tail_allow_verdict_scoped_to_each_script_text(self) -> None:
        """Keep allow-list answers separate for the main file and bash -c inline text."""
        bash_first = (
            "delay=$((1 << 2))\n"
            "d=3\n"
            'bash -c "python3 - x ${d}<<< \\"$d\\" > /tmp/z"\n'
            'python3 - x 3<<< "$d" > /tmp/y\n'
        )
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )

        def probe(target: str, _context: InspectionContext, _budget: BodyBudget) -> bool:
            if target == "/tmp/y":
                return True
            if target == "/tmp/z":
                return False
            return False

        patch = unittest.mock.patch.object(
            body_mod, "_probe_clean_redirect_target", side_effect=probe
        )
        with patch:
            self.assertIsNone(scan_body(bash_first, context, BodyBudget())[0])

    def test_inline_without_primed_verdicts_stays_fail_closed(self) -> None:
        """Refuse an inline descriptor tail when redirect verdicts were not primed."""
        inline = b'python3 - x 3<<< "$d" > /tmp/z\n'
        scan = body_mod._Scan(  # noqa: SLF001
            InspectionContext(
                cwd=self.root,
                directory_changed=False,
                files_read=[],
                classifier=lambda _words: None,
            ),
            BodyBudget(),
        )
        parser = body_mod.bash_parser()
        if isinstance(parser, str):
            self.skipTest(parser)
        scan.syntax_roots[inline] = parser.parse(inline).root_node
        self.assertFalse(body_mod._fd_herestring_tail_allowlisted(scan, inline))  # noqa: SLF001

    def test_quoted_arith_heredoc_blocks_allowlist_precondition(self) -> None:
        """Treat << on a line as heredoc when $(() sits in single quotes."""
        raw = (
            b": '$((' ; cat <<X ; : '))'\n"
            b"x\n"
            b"X\n"
            b"delay=$((1 << 2))\n"
            b'python3 - x 3<<< "$d" > /tmp/y\n'
        )
        self.assertTrue(lex_mod.script_blocks_fd_herestring_allowlist(raw))

    def test_collect_error_nodes_truncation_refuses_allowlist(self) -> None:
        """Refuse when ERROR collection stops before finishing the tree walk."""

        def _stub_chain(depth: int) -> object:
            """Build a flat child chain longer than collect_error_nodes may pop."""
            nodes: list[object] = []
            for _ in range(depth):
                nodes.append(
                    type(
                        "Node",
                        (),
                        {
                            "type": "program",
                            "start_byte": 0,
                            "end_byte": 1,
                            "descendant_count": 0,
                            "children": (),
                        },
                    )()
                )
            for idx in range(depth - 1):
                nodes[idx].children = (nodes[idx + 1],)  # type: ignore[attr-defined]
            return nodes[0]

        self.assertIsNone(lex_mod.collect_error_nodes(_stub_chain(5000)))
        scan = body_mod._Scan(  # noqa: SLF001
            InspectionContext(
                cwd=self.root,
                directory_changed=False,
                files_read=[],
                classifier=lambda _words: None,
            ),
            BodyBudget(),
        )
        raw = b'python3 - x 3<<< "$d" > /tmp/y\n'
        parser = body_mod.bash_parser()
        if isinstance(parser, str):
            self.skipTest(parser)
        scan.syntax_roots[raw] = parser.parse(raw).root_node
        scan.redirect_target_ok[raw] = {"/tmp/y": True}
        with unittest.mock.patch.object(body_mod, "collect_error_nodes", return_value=None):
            self.assertFalse(body_mod._fd_herestring_tail_allowlisted(scan, raw))  # noqa: SLF001

    def test_refuses_fd_descriptor_herestring_outside_toplevel_command(self) -> None:
        """Refuse descriptor tails embedded outside a top-level simple command."""
        p1 = 'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n'
        tail = p1.split("\n", 1)[1]
        bodies = (
            f"delay=$((1 << 2))\nif true; then\n  {tail}fi\n",
            f"delay=$((1 << 2))\nwhile false; do\n  {tail}done\n",
            f"delay=$((1 << 2))\nf() {{\n  {tail}}}\n",
            f"delay=$((1 << 2))\n{{\n  {tail}}}\n",
        )
        for body in bodies:
            self._check_parser_body(body, refused=True)

    def test_fd_descriptor_top_level_rule_isolates_nontop_tail(self) -> None:
        """Prove scan_body prelude refuses nested tails; subshell flips under patch."""
        p1 = 'delay=$((1 << 2))\npython3 - x 3<<< "$d" > /tmp/y\n'
        tail = p1.split("\n", 1)[1]
        outside = "descriptor here-string tail sits outside a top-level simple command"
        blocked = (
            (
                f"delay=$((1 << 2))\nif true; then\n  {tail}fi\n",
                "unparsable shell text naming a command near line 1",
            ),
            (
                f"delay=$((1 << 2))\nwhile false; do\n  {tail}done\n",
                "unparsable shell text naming a command near line 1",
            ),
            (
                f"delay=$((1 << 2))\nf() {{\n  {tail}}}\n",
                "unparsable shell text naming a command near line 2",
            ),
            (f"delay=$((1 << 2))\n{{\n  {tail}}}\n", outside),
            (f"delay=$((1 << 2))\n(\n  {tail})\n", outside),
        )
        context = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[],
            classifier=lambda _words: None,
            script_dir=self.root,
        )
        for body, want in blocked:
            self.assertEqual(scan_body(body, context, BodyBudget())[0], want)
        with unittest.mock.patch(
            "scripts.raw_configure_body.tail_line_is_toplevel", return_value=True
        ):
            for body, _want in blocked[:-1]:
                self.assertIsNotNone(scan_body(body, context, BodyBudget())[0])
            subshell = blocked[-1][0]
            self.assertIsNone(scan_body(subshell, context, BodyBudget())[0])
        self.assertIsNone(scan_body(p1, context, BodyBudget())[0])

    def test_refuses_r9_command_surface_table(self) -> None:
        """Decide every in-scope lim414b and lim414 command case in-process."""
        for label, command, want in _R9_CASES:
            with self.subTest(label=label):
                blocked = GUARD_MOD._inspect_with_deadline(command, self.tree)
                if want == "refuse":
                    self.assertIsNotNone(blocked)

    def test_refuses_r9_script_body_table(self) -> None:
        """Refuse every in-scope lim414b and lim414 refuse body when invoked via bash ./s.sh."""
        client = self._next_client()
        script = self.tree / "s.sh"
        for label, command, want in _R9_CASES:
            if want != "refuse":
                continue
            script.write_text(command, encoding="utf-8")
            with self.subTest(label=label):
                result = self.run_guard(client, self.payload(client, "bash ./s.sh", self.tree))
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_descriptor_prefix_grammar_table(self) -> None:
        """Verify shared descriptor-prefix counting, stripping, and opener length."""
        for text, pos, want_hop, want_stripped, want_count in _GRAMMAR_CASES:
            raw = text.encode("utf-8")
            with self.subTest(text=text):
                self.assertEqual(lex_mod.descriptor_tail_mark_count(raw), want_count)
                self.assertEqual(
                    lex_mod.strip_descriptor_tail_marks(raw), want_stripped.encode("utf-8")
                )
                self.assertEqual(lex_mod._herestring_op_len(text, pos), want_hop)

    def test_descriptor_twin_owns_files_read_and_directory_state(self) -> None:
        """Keep caller files_read and directory_state isolated from the twin side scan."""
        (self.root / "lib.sh").write_text(":\n", encoding="utf-8")
        sourced_body = 'source ./lib.sh\ncat 3<<< "$d"\n'
        ctx_real = InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=[0],
            classifier=lambda _words: None,
            script_dir=self.root,
            source_reader=files_mod._read_source,
        )
        ctx_patched = ctx_real._replace(files_read=[0])
        self.assertIsNone(scan_body(sourced_body, ctx_real, BodyBudget())[0])
        with unittest.mock.patch.object(
            body_mod, "_descriptor_plain_twin_refusal", return_value=(None, [], [], [])
        ):
            self.assertIsNone(scan_body(sourced_body, ctx_patched, BodyBudget())[0])
        self.assertEqual(ctx_real.files_read[0], 1)
        self.assertEqual(ctx_real.files_read[0], ctx_patched.files_read[0])
        dir_state = [False]
        limit_budget = BodyBudget(nodes=body_mod.MAX_BODY_NODES - 26)
        hit = scan_body('cd /tmp\ncat 3<<< "$d"\n', self._shape_context(), limit_budget, dir_state)[
            0
        ]
        self.assertEqual(hit, "shell syntax tree larger than inspect limit")
        self.assertEqual(dir_state, [False])

    def test_refuses_fd0_leading_zeros_and_stdin_dup_precedence(self) -> None:
        """Refuse leading-zero fd 0 precedence and 0<&N or <&N dups onto fd 0 on both surfaces."""
        cmd_cases = (
            f"bash 33<<< x 00<<< {_R9_Q}\n",
            f"bash 33<<< x 000<<< {_R9_Q}\n",
            f"bash 0<<< x 33<<< {_R9_Q} 0<&33\n",
            f"bash 0<<< x 33<<< {_R9_Q} <&33\n",
            f"exec 33<<< {_R9_Q}; python3 - 0<&33\n",
            f"exec 3<<< {_R9_Q}; python3 - <&3\n",
        )
        for command in cmd_cases:
            with self.subTest(surface="command", command=command):
                self.assertIsNotNone(GUARD_MOD._inspect_with_deadline(command, self.tree))
        part_a = "./con"
        part_b = "figure"
        body_cases = (
            f'a={part_a}; b={part_b}; bash 33<<< "$a$b" 0<&33\n',
            f'a={part_a}; b={part_b}; bash 33<<< "$a$b" <&33\n',
            f'a={part_a}; b={part_b}; exec 33<<< "$a$b"; bash 0<&33\n',
            f'a={part_a}; b={part_b}; exec 33<<< "$a$b"; bash <&33\n',
        )
        for body in body_cases:
            with self.subTest(surface="body", body=body):
                self.assertIsNotNone(scan_body(body, self._shape_context(), BodyBudget())[0])

    def test_refuses_r10_probe_table(self) -> None:
        """Refuse every in-scope r10 probe case across command and script-body surfaces."""
        (self.tree / "sub").mkdir(exist_ok=True)
        helper_text = f"{_PARITY_CFG} --help\n"
        for name in ("helper.sh", "sub/helper.sh", "helper-3"):
            target = self.tree / name
            target.write_text(helper_text, encoding="utf-8")
            target.chmod(0o755)
        script = self.tree / "s.sh"
        for label, kind, text in _R10_PROBES:
            command = text
            if kind == "body":
                script.write_text(text, encoding="utf-8")
                command = "bash ./s.sh"
            with self.subTest(label=label, kind=kind):
                self.assertIsNotNone(GUARD_MOD._inspect_with_deadline(command, self.tree))

    def test_r10_boundary_and_dup_grammar_table(self) -> None:
        """Match token-boundary descriptor marks and fd 0 dup recognition against bash."""
        for label, text, want_mark in _R10_BOUNDARIES:
            masked = lex_mod._mask_quoted_bytes(text.encode("utf-8"))
            with self.subTest(label=label):
                self.assertEqual(lex_mod._TAIL_MARK.search(masked) is not None, want_mark)
        for dup_text, want_dup in _R10_DUP_ROWS:
            with self.subTest(dup=dup_text):
                self.assertEqual(lex_mod._dup_stdin_source(dup_text) == 3, want_dup)
                bmatch = lex_mod._DUP_STDIN_BYTES.search(dup_text.encode("ascii"))
                got_bytes = (
                    bmatch is not None
                    and lex_mod._dup_stdin_fd(bmatch.group(1), bmatch.group(2)) == 3
                )
                self.assertEqual(got_bytes, want_dup)

    def _cat_stdin_from_tokens(self, command: str) -> list[str | None]:
        """Return the here-string word attached to each cat fd 0 on the lexer surface."""
        scanned, herestrings, _ = lex_mod._scan_herestrings(command)
        tokens, refusal = lex_mod._resolve_token_flow(lex_mod._split_tokens(scanned) or [])
        if refusal is not None:
            return [refusal]
        stages: list[list[str]] = [[]]
        for tok in tokens:
            if tok in lex_mod.SEPARATORS:
                stages.append([])
            else:
                stages[-1].append(tok)
        found: list[str | None] = []
        for stage in stages:
            words, attached = lex_mod._strip_redirections(stage)
            if words and words[0] == "cat":
                zero = bool(attached) and attached[0].startswith("__RCG_HS_0_")
                found.append(herestrings.get(attached[0]) if zero else None)
        return found

    def _cat_stdin_from_bytes(self, command: str) -> list[str | None]:
        """Return the plain here-string word rewritten onto each cat fd 0 on the byte surface."""
        rewritten, refusal = lex_mod.rewrite_descriptor_dups_checked(command.encode("utf-8"))
        if refusal is not None:
            return [refusal]
        found: list[str | None] = []
        for seg in re.split(rb";|\||\(|\)|&&|(?<![<>])&(?!>)", rewritten):
            if not seg.strip().startswith(b"cat "):
                continue
            masked = lex_mod._mask_quoted_bytes(seg)
            mark_ends = {
                m.end()
                for m in lex_mod._TAIL_MARK.finditer(masked)
                if not lex_mod._is_stdin_descriptor(m.group(1))
            }
            words: list[str] = []
            for idx in range(len(masked) - 2):
                if masked[idx : idx + 3] == b"<<<" and idx + 3 not in mark_ends:
                    span = lex_mod._herestring_word_end_bytes(seg, masked, idx + 3)
                    if span is not None:
                        words.append(seg[span[0] : span[1]].decode("utf-8"))
            found.append(words[-1] if words else None)
        return found

    def test_r10_descriptor_table_both_surfaces(self) -> None:
        """Match close, copy, rebind, and source-order descriptor resolution to bash."""
        for label, command, want in _R10_DESCRIPTOR_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(_first(self._cat_stdin_from_tokens(command)), want)
            with self.subTest(label=label, surface="bytes"):
                self.assertEqual(_first(self._cat_stdin_from_bytes(command)), want)

    def test_whole_body_descriptor_marks_past_256_lines(self) -> None:
        """Count marks and reject qualification across lines beyond the former 256-line cap."""
        two_marks = 'cat 3<<< "$d" > /tmp/y\n' + (":\n" * 298) + 'cat 4<<< "$e" > /tmp/z\n'
        raw_two = two_marks.encode("utf-8")
        self.assertEqual(lex_mod.descriptor_tail_mark_count(raw_two), 2)
        self.assertIsNone(lex_mod.find_descriptor_herestring_tail(raw_two))
        late_single = (":\n" * 299) + 'cat 3<<< "$d" > /tmp/y\n'
        raw_single = late_single.encode("utf-8")
        self.assertEqual(lex_mod.descriptor_tail_mark_count(raw_single), 1)
        self.assertIsNotNone(lex_mod.find_descriptor_herestring_tail(raw_single))

    def test_char_byte_offsets_and_escaped_quote_herestrings(self) -> None:
        """Match char-to-byte table entries to UTF-8 prefix lengths and extract q01."""
        surrogates = b"\x80\xff".decode("utf-8", "surrogateescape")
        text = "az\u00e9\u00df\u20ac\u2603" + surrogates + " 3<<< x"
        raw = text.encode("utf-8", "surrogatepass")
        table = lex_mod._char_byte_offsets(text, raw) or ()
        self.assertEqual(len(table), len(text) + 1)
        for idx in range(len(text) + 1):
            want = len(text[:idx].encode("utf-8", "surrogatepass"))
            self.assertEqual(table[idx], want)
        q01 = "printf '%s' \\\" 3<<< x; echo; cat 3<<<y 0<&3"
        _, herestrings, hs_to_scan = lex_mod._scan_herestrings(q01)
        self.assertEqual(hs_to_scan, ["x", "y"])
        self.assertEqual(herestrings["__RCG_HS_FD3_0__"], "x")
        self.assertEqual(herestrings["__RCG_HS_FD3_1__"], "y")

    def test_r11_probe_table(self) -> None:
        """Refuse lim414j and lim414l cases and allow non-record lim414k cases in-process."""
        (self.tree / "sub").mkdir(exist_ok=True)
        helper_text = f"{_PARITY_CFG} --help\n"
        for name in ("helper.sh", "sub/helper.sh"):
            target = self.tree / name
            target.write_text(helper_text, encoding="utf-8")
            target.chmod(0o755)
        script = self.tree / "s.sh"
        for label, kind, text in _R11_REFUSE_PROBES:
            command = text
            if kind == "body":
                script.write_text(text, encoding="utf-8")
                command = "bash ./s.sh"
            with self.subTest(label=label, kind=kind):
                self.assertIsNotNone(GUARD_MOD._inspect_with_deadline(command, self.tree))
        for label, kind, text in _R11_ALLOW_PROBES:
            command = text
            if kind == "body":
                script.write_text(text, encoding="utf-8")
                command = "bash ./s.sh"
            with self.subTest(label=label, kind=kind):
                self.assertIsNone(GUARD_MOD._inspect_with_deadline(command, self.tree))

    def test_r11_move_and_operand_boundary_table(self) -> None:
        """Model descriptor moves and shell-word dup boundaries on token and byte surfaces."""
        for label, command, want in _R11_MOVE_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(_first(self._cat_stdin_from_tokens(command)), want)
            with self.subTest(label=label, surface="bytes"):
                rewritten = lex_mod.rewrite_descriptor_dups(command.encode("utf-8"))
                self.assertNotIn(b"moved-", rewritten)
                self.assertEqual(_first(self._cat_stdin_from_bytes(command)), want)
        self.assertEqual(_first(self._cat_stdin_from_tokens("cat 3<<<moved <&3")), "moved")
        self.assertEqual(_first(self._cat_stdin_from_bytes("cat 3<<<moved <&3")), "moved")
        self.assertEqual(_first(self._cat_stdin_from_tokens("cat 3<<<moved <&3-")), "moved")
        self.assertEqual(_first(self._cat_stdin_from_bytes("cat 3<<<moved <&3-")), "moved")
        m08_bytes = lex_mod.rewrite_descriptor_dups(b"exec 3<<<moved; cat 4<&3- <&4; cat <&3")
        self.assertTrue(m08_bytes.endswith(b"cat <<< moved"))
        m08_scanned, _, _ = lex_mod._scan_herestrings("exec 3<<<moved; cat 4<&3- <&4; cat <&3")
        self.assertTrue((lex_mod._tokens(m08_scanned) or [""])[-1].startswith("__RCG_HS_0_"))
        for bad_dup in ("<&3x", "<&3."):
            with self.subTest(bad_dup=bad_dup):
                cmd = f"cat 3<<<moved {bad_dup}"
                self.assertIsNone(lex_mod._dup_stdin_source(bad_dup))
                self.assertIsNone(lex_mod._DUP_STDIN_BYTES.search(bad_dup.encode("ascii")))
                self.assertIsNone(_first(self._cat_stdin_from_tokens(cmd)))
                self.assertIsNone(_first(self._cat_stdin_from_bytes(cmd)))
                self.assertEqual(lex_mod.rewrite_descriptor_dups(cmd.encode("ascii")), cmd.encode())

    def test_r11_heredoc_data_marks_table(self) -> None:
        """Exclude closed here-document payload lines from mark counting and dup rewriting."""
        k01 = b"cat <<'EOF'\n3<<<x\n4<<<x\nEOF\n"
        k06 = b"cat <<'EOF'\n3<<<x\nEOF\n"
        one_real = b"d=x\ncat <<'EOF'\n3<<<x\n4<<<x\nEOF\ncat 3<<< \"$d\"\n"
        two_real = 'cat 3<<< "$d"\ncat 4<<< "$d"\n'
        self.assertEqual(lex_mod.descriptor_tail_mark_count(k01), 0)
        self.assertEqual(lex_mod.descriptor_tail_mark_count(k06), 0)
        self.assertFalse(lex_mod.descriptor_tail_marks_present(k01))
        self.assertEqual(lex_mod.descriptor_tail_mark_count(one_real), 1)
        self.assertIsNotNone(scan_body(two_real, self._shape_context(), BodyBudget())[0])
        unterm = b"cat <<'EOF'\n3<<<x\n4<<<x\n"
        self.assertEqual(lex_mod.descriptor_tail_mark_count(unterm), 2)
        hd_dup = "exec 3<<<real; cat <<'EOF'\nexec 3<<<fake\nEOF\ncat 0<&3"
        self.assertEqual(_first(self._cat_stdin_from_bytes(hd_dup)), "real")

    def test_r11_missing_node_twin_refusal(self) -> None:
        """Refuse plain twins recovered with MISSING syntax nodes and allow complete groups."""
        ctx = self._shape_context()
        for tail_text in _R11_TS_MISSING_SINGLE:
            body = 'd=x\ncat 3<<< "$d"\n' + tail_text
            with self.subTest(tail_text=tail_text):
                hit = scan_body(body, ctx, BodyBudget())[0]
                self.assertIsNotNone(hit)
                self.assertIn("unparsable shell syntax", hit or "")
        dup_mark_body = 'd=x\ncat 3<<< "$d"\n( cat 3<<< x\n'
        self.assertIsNotNone(scan_body(dup_mark_body, ctx, BodyBudget())[0])
        complete = 'd=x\ncat 3<<< "$d"\n( echo a )\n'
        self.assertIsNone(scan_body(complete, ctx, BodyBudget())[0])

    def test_r11_twin_rebinding_flow(self) -> None:
        """Carry rebound script and unknown flags from an accepted twin into the caller budget."""
        (self.tree / "safe.sh").write_text("echo ok\n", encoding="utf-8")
        child = self.tree / "child.sh"
        child.write_text(
            'HERE="$(dirname "$(readlink -f "$0")")"\n. "$HERE/safe.sh"\n', encoding="utf-8"
        )
        child.chmod(0o755)
        script = self.tree / "s.sh"
        script.write_text('exec 3<<< "./child.sh"\nbash 0<&3\n', encoding="utf-8")
        self.assertIsNone(GUARD_MOD._inspect_with_deadline("bash ./s.sh", self.tree))
        rebound_body = 'exec 3<<< "PATH=/tmp ./child.sh"\nbash 0<&3\n'
        script.write_text(rebound_body, encoding="utf-8")
        self.assertIsNotNone(GUARD_MOD._inspect_with_deadline("bash ./s.sh", self.tree))
        budget = BodyBudget()
        ctx = InspectionContext(
            cwd=self.tree,
            directory_changed=False,
            files_read=[0],
            classifier=lambda _w: None,
            script_dir=self.tree,
        )
        self.assertIsNone(scan_body(rebound_body, ctx, budget)[0])
        self.assertIn(child.resolve(), budget.rebound_scripts)
        unk_budget = BodyBudget()
        self.assertIsNone(
            scan_body(rebound_body, ctx._replace(directory_changed=True), unk_budget)[0]
        )
        self.assertTrue(unk_budget.rebound_unknown)

    def test_r11_escaped_arithmetic_spans(self) -> None:
        """Skip backslash-escaped arithmetic openers outside single quotes."""
        self.assertEqual(lex_mod._line_arith_spans(b': "\\$((x"; : "))"'), [])
        self.assertEqual(lex_mod._line_arith_spans(b"\\$(("), [])
        self.assertEqual(lex_mod._line_arith_spans(b'echo "$((1<<2))"'), [(6, 15)])
        blocked = b': "\\$((x" <<X; : "))"\nX\ncat 3<<< "$d"\n'
        self.assertTrue(lex_mod.script_blocks_fd_herestring_allowlist(blocked))
        allowed_shift = b'echo "$((1<<2))"\ncat 3<<< "$d"\n'
        self.assertFalse(lex_mod.script_blocks_fd_herestring_allowlist(allowed_shift))

    def test_r11_spaced_numeric_word_table(self) -> None:
        """Treat numeric words as redirect prefixes only when source-adjacent to the operator."""
        for label, command, want in _R11_SPACED_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(_first(self._cat_stdin_from_tokens(command)), want)
            with self.subTest(label=label, surface="bytes"):
                self.assertEqual(_first(self._cat_stdin_from_bytes(command)), want)
        s05_tokens = lex_mod._tokens("printf '[%s]' 3 </dev/null") or []
        self.assertEqual(lex_mod._strip_redirections(s05_tokens)[0], ["printf", "[%s]", "3"])
        attached_tokens = lex_mod._tokens("printf '[%s]' 3</dev/null") or []
        self.assertEqual(lex_mod._strip_redirections(attached_tokens)[0], ["printf", "[%s]"])

    def test_r11_explicit_fd0_table(self) -> None:
        """Select the last standard-input binding across explicit 0/00 here-strings and dups."""
        for label, command, want in _R11_FD0_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(_first(self._cat_stdin_from_tokens(command)), want)
            with self.subTest(label=label, surface="bytes"):
                self.assertEqual(_first(self._cat_stdin_from_bytes(command)), want)
        for body in ('cat 33<<< "$d"\n', 'cat {fd}<<< "$d"\n'):
            self.assertIsNone(scan_body(body, self._shape_context(), BodyBudget())[0])

    def test_r12_probe_table(self) -> None:
        """Refuse every in-scope lim414m case and allow every lim414n case in-process."""
        (self.tree / "sub").mkdir(exist_ok=True)
        helper_text = f"{_PARITY_CFG} --help\n"
        for name in ("helper.sh", "sub/helper.sh"):
            target = self.tree / name
            target.write_text(helper_text, encoding="utf-8")
            target.chmod(0o755)
        script = self.tree / "s.sh"
        for want_refused, table in ((True, _R12_REFUSE_PROBES), (False, _R12_ALLOW_PROBES)):
            for label, kind, text in table:
                command = text
                if kind == "body":
                    script.write_text(text, encoding="utf-8")
                    command = "bash ./s.sh"
                with self.subTest(label=label, kind=kind):
                    blocked = GUARD_MOD._inspect_with_deadline(command, self.tree)
                    self.assertEqual(blocked is not None, want_refused)

    def test_r12_execution_context_table_both_surfaces(self) -> None:
        """Keep exec bindings of isolated pipeline stages, groups and jobs out of the caller."""
        for label, command, want in _R12_CONTEXT_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(self._cat_stdin_from_tokens(command)[-1], want)
            with self.subTest(label=label, surface="bytes"):
                self.assertEqual(self._cat_stdin_from_bytes(command)[-1], want)

    def test_r12_isolated_exec_twin_reads_the_parent_word(self) -> None:
        """Rewrite the dup after an isolated exec to the parent word in the plain twin."""
        for body in (
            'exec 3<<< "./helper.sh"\nexec 3<<< x | cat >/dev/null\nbash <&3\n',
            'exec 3<<< "./helper.sh"\n( exec 3<<< x )\nbash <&3\n',
        ):
            with self.subTest(body=body):
                twin = lex_mod.rewrite_descriptor_dups(body.encode("utf-8"))
                self.assertTrue(twin.rstrip().endswith(b'bash <<< "./helper.sh"'))

    def _saved_word_want(self, got: list[str | None], want: str) -> None:
        """Compare the last cat stdin word or refusal reason, ignoring surrounding quotes."""
        last = got[-1]
        self.assertEqual(last.strip('"') if isinstance(last, str) else last, want)

    def test_r12_saved_word_table_both_surfaces(self) -> None:
        """Resolve a saved non-literal here-string word only when it cannot have changed."""
        for label, command, want in _R12_SAVED_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self._saved_word_want(self._cat_stdin_from_tokens(command), want)
            with self.subTest(label=label, surface="bytes"):
                self._saved_word_want(self._cat_stdin_from_bytes(command), want)

    def test_r12_saved_word_allow_list_both_surfaces(self) -> None:
        """Keep a saved word across non-assigning commands and refuse across any other command."""
        for between, want in (
            *((cmd, "$d") for cmd in _R12_NON_ASSIGNING),
            *((cmd, _STALE_REASON) for cmd in _R12_ASSIGNING),
        ):
            command = f'd=first; exec 3<<<"$d"; {between}; cat <&3'
            with self.subTest(between=between, surface="tokens"):
                self._saved_word_want(self._cat_stdin_from_tokens(command), want)
            with self.subTest(between=between, surface="bytes"):
                self._saved_word_want(self._cat_stdin_from_bytes(command), want)
        literal = "exec 3<<<first; read d; cat <&3"
        self.assertEqual(self._cat_stdin_from_tokens(literal)[-1], "first")
        self.assertEqual(self._cat_stdin_from_bytes(literal)[-1], "first")

    def test_r12_saved_word_refusal_names_reason_in_script_body(self) -> None:
        """Name the unresolved-binding reasons when a script body is decided."""
        stale = 'd=first\nexec 3<<<"$d"\nd=second\ncat <&3\n'
        unknown = "shopt -s lastpipe\ncat </dev/null | exec 3<<<b\ncat <&3\n"
        self.assertEqual(lex_mod.descriptor_dup_refusal(stale.encode("utf-8")), _STALE_REASON)
        self.assertEqual(lex_mod.descriptor_dup_refusal(unknown.encode("utf-8")), _UNKNOWN_REASON)
        self.assertIsNone(lex_mod.descriptor_dup_refusal(b'd=x\nexec 3<<<"$d"\ncat <&3\n'))
        context = self._shape_context()
        self.assertEqual(scan_body(stale, context, BodyBudget())[0], _STALE_REASON)
        self.assertEqual(scan_body(unknown, context, BodyBudget())[0], _UNKNOWN_REASON)

    def test_r12_arithmetic_span_balances_nested_parentheses(self) -> None:
        """Close an arithmetic expansion only at the pair that matches its opener."""
        for line, want in _R12_ARITH_ROWS:
            with self.subTest(line=line):
                self.assertEqual(lex_mod._line_arith_spans(line), want)
        nested = b'd=x\n: $(( (1 + (2)) << 1 ))\ncat 3<<< "$d"\n'
        keyed = b'd=x\ndelay=$(( (1 + (2)) << 1 ))\ncat 3<<< "$d"\n'
        plain = b'd=x\n: $(( 1 << 1 ))\ncat 3<<< "$d"\n'
        for raw in (nested, keyed, plain, b'd=x\ncat 3<<< "$d"\n'):
            with self.subTest(raw=raw):
                self.assertFalse(lex_mod.script_blocks_fd_herestring_allowlist(raw))
        self.assertTrue(lex_mod.script_blocks_fd_herestring_allowlist(b": $(( x ) << 1 )\n"))

    def test_r12_blank_skips_do_not_copy_the_rest_of_the_line(self) -> None:
        """Keep each blank-skip helper constant-time in the length of the remaining bytes."""
        helpers = (
            ("spaces_tabs", lambda line: lex_mod._skip_spaces_tabs(line, 0)),
            ("spaces", lambda line: lex_mod._skip_spaces(line, 0)),
            ("herestring_word", lambda line: lex_mod._herestring_word_end_bytes(line, line, 0)),
        )
        small = b"  x " + b"y" * 100_000
        large = b"  x " + b"y" * 400_000
        for name, helper in helpers:
            with self.subTest(helper=name):
                t_small = _best_seconds(lambda h=helper: [h(small) for _ in range(3000)])
                t_large = _best_seconds(lambda h=helper: [h(large) for _ in range(3000)])
                self.assertLess(t_large, 2.5 * max(t_small, 0.002))
        self.assertEqual(lex_mod._skip_spaces_tabs(b" \t x", 0), 3)
        self.assertEqual(lex_mod._skip_spaces(b" \t x", 0), 1)
        self.assertEqual(lex_mod._skip_spaces_tabs(b"  ", 1), 2)
        self.assertEqual(lex_mod._skip_spaces_tabs(b"x", 5), 5)

    def test_r12_descriptor_scans_scale_with_script_size(self) -> None:
        """Scan many heredoc openers and many short redirects with a bounded doubling ratio."""
        opener = b"cat <<X\nx\nX\n"
        tail = b'd=x\ncat 3<<< "$d" 0<&3\n'
        cases = (
            ("mark_count", lex_mod.descriptor_tail_mark_count, (8_000, 256_000), opener, tail),
            ("rewrite_scripts", lex_mod.rewrite_descriptor_dups, (2_000, 32_000), opener, tail),
            (
                "rewrite_redirects",
                lex_mod.rewrite_descriptor_dups,
                (1_000, 16_000),
                b"2>/dev/null ",
                b"0<&3",
            ),
        )
        for name, call, (small, large), unit, end in cases:
            head = b"" if unit == opener else b"cat 3<<<x "
            seconds = {
                n: _best_seconds(lambda c=call, r=head + unit * n + end: c(r), repeats=2)
                for n in (small, large)
            }
            limit = 2.5 ** math.log2(large / small) * max(seconds[small], 0.01)
            with self.subTest(scan=name):
                self.assertLess(seconds[large], limit)

    def test_r12_shared_source_statement_is_charged_once(self) -> None:
        """Charge a source statement reached by an inline body and its twin once."""
        (self.root / "lib.sh").write_text(":\n", encoding="utf-8")
        body = "eval 'cat 3<<<\"$d\"; source ./lib.sh'\n"
        limit = body_mod.MAX_SCRIPT_FILES
        context = self._source_context([limit - 1])
        self.assertIsNone(scan_body(body, context, BodyBudget())[0])
        self.assertEqual(context.files_read[0], limit)
        spent = self._source_context([limit])
        self.assertIn("script file limit", scan_body(body, spent, BodyBudget())[0] or "")
        budget = BodyBudget()
        scan_body(body, self._source_context([0]), budget)
        self.assertEqual(budget.inline_bodies, 2)

    def _source_context(self, reads: list[int]) -> InspectionContext:
        """Build a context whose source reader reads real files under the test root."""
        return InspectionContext(
            cwd=self.root,
            directory_changed=False,
            files_read=reads,
            classifier=lambda _words: None,
            script_dir=self.root,
            source_reader=files_mod._read_source,
        )

    def test_r12_twin_only_source_reference_is_still_inspected(self) -> None:
        """Read and inspect a source statement that only the plain twin contains."""
        helper = self.root / "helper.sh"
        helper.write_text(f"{_PARITY_CFG} --help\n", encoding="utf-8")
        helper.chmod(0o755)
        body = "eval 'cat 3<<<\"$d\"'\n"

        def twin_with_source(raw: bytes, scan: Any) -> tuple[Any, bytes]:
            """Build a twin that adds one source statement absent from the original."""
            twin_raw = raw + b"; source ./helper.sh\n"
            root = body_mod.bash_parser().parse(twin_raw).root_node
            scan.syntax_roots[twin_raw] = root
            return root, twin_raw

        self.assertIsNone(scan_body(body, self._source_context([0]), BodyBudget())[0])
        with unittest.mock.patch.object(body_mod, "_inline_twin_node", twin_with_source):
            hit = scan_body(body, self._source_context([0]), BodyBudget())[0]
        self.assertIsNotNone(hit)

    def test_r12_move_rows_check_the_second_cat(self) -> None:
        """Keep a temporary move from closing the descriptor for the next command."""
        for label, command, want in _R12_SECOND_CAT_ROWS:
            with self.subTest(label=label, surface="tokens"):
                self.assertEqual(self._cat_stdin_from_tokens(command), want)
            with self.subTest(label=label, surface="bytes"):
                self.assertEqual(self._cat_stdin_from_bytes(command), want)
        for label, command, want in _R11_MOVE_ROWS[:2]:
            with self.subTest(label=label, surface="second"):
                self.assertEqual(self._cat_stdin_from_tokens(command)[1:], [want])
                self.assertEqual(self._cat_stdin_from_bytes(command)[1:], [want])
