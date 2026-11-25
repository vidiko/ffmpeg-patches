# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Exercise lane brief rendering, validation, and error handling."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import os
import re
import signal
import subprocess  # nosec B404 - Fixed argv is used for the zombie regression test.
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

from scripts import lane_brief, lane_isolation
from tests.helpers import run_git
from tests.test_lane_isolation import repo

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts" / "lane_brief_template.md"
CONFIG = ROOT / ".config" / "lane-brief.yaml"
ARGS = [
    "render",
    "--branch",
    "feature",
    "--task",
    "work",
    "--finding",
    "problem",
    "--fix",
    "repair",
    "--tests",
    "unit",
    "--modules",
    "tests.test_example tests.test_other",
    "--paths",
    "scripts/a.py",
    "--issue",
    "42",
    "--round",
    "2",
]

FIX5_PROBE_CASES: tuple[tuple[str, str, bool], ...] = (
    (
        "g01 grep -e then repo file then lane file",
        "grep -E -e '.{80}' scripts/lane_brief.py .lane/tmp/draft.txt",
        True,
    ),
    (
        "g02 grep -f then repo file then lane file",
        "grep -E -f .lane/tmp/pat scripts/lane_brief.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g03 grep --regexp= joined",
        "grep -E --regexp='.{80}' scripts/a.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g04 grep --regexp spaced",
        "grep -E --regexp '.{80}' scripts/a.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g05 grep --file spaced",
        "grep -E --file .lane/tmp/pat scripts/a.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g06 grep -e joined value",
        "grep -E -e.{80} scripts/a.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g07 grep two -e options",
        "grep -E -e '.{80}' -e x scripts/a.py .lane/tmp/d.txt",
        True,
    ),
    (
        "g08 control grep -e lane file only",
        "grep -E -e '.{80}' .lane/tmp/draft.txt",
        False,
    ),
    (
        "g09 control grep plain pattern repo file",
        "grep -E '.{80}' scripts/a.py",
        True,
    ),
    (
        "g10 control grep plain pattern lane file",
        "grep -E '.{80}' .lane/tmp/d.txt",
        False,
    ),
    (
        "p01 diff then grep repo file then awk",
        "git diff -- scripts/a.py | grep '^' scripts/a.py | awk 'length > 72'",
        True,
    ),
    (
        "p02 diff then cat repo file then wc",
        "git diff -- scripts/a.py | cat scripts/a.py | wc -L",
        True,
    ),
    (
        "p03 diff then sed repo file then awk",
        "git diff -- scripts/a.py | sed -n p scripts/a.py | awk 'length > 72'",
        True,
    ),
    (
        "p04 diff then grep stdin redirect repo file",
        "git diff | grep '^' < scripts/a.py | awk 'length > 72'",
        True,
    ),
    (
        "p05 control diff then grep stdin then awk",
        "git diff -- scripts/a.py | grep '^+' | awk 'length > 72'",
        False,
    ),
    (
        "p06 control diff then wc",
        "git diff -- scripts/a.py | wc -L",
        False,
    ),
    (
        "a01 gawk -- length program repo file",
        "gawk -- 'length > 72' scripts/a.py",
        True,
    ),
    (
        "a02 awk -- length program repo file",
        "awk -- 'length > 72' scripts/a.py",
        True,
    ),
    (
        "a03 awk -F, -- length program repo file",
        "awk -F, -- 'length > 72' scripts/a.py",
        True,
    ),
    (
        "a04 control awk -- print program repo file",
        "awk -- '{print $1}' scripts/a.py",
        False,
    ),
    (
        "a05 control awk -- length program lane file",
        "awk -- 'length > 72' .lane/tmp/a.txt",
        False,
    ),
    (
        "w01 wc -L -m repo then lane",
        "wc -L -m scripts/a.py .lane/tmp/a.txt",
        True,
    ),
    (
        "w02 wc -m -L repo then lane",
        "wc -m -L scripts/a.py .lane/tmp/a.txt",
        True,
    ),
    (
        "w03 wc -L -c repo then lane",
        "wc -L -c scripts/a.py .lane/tmp/a.txt",
        True,
    ),
    (
        "w04 wc -L -l repo then lane",
        "wc -L -l scripts/a.py .lane/tmp/a.txt",
        True,
    ),
    (
        "w05 wc -L -w repo then lane",
        "wc -L -w scripts/a.py .lane/tmp/a.txt",
        True,
    ),
    (
        "w06 control wc -L -m lane only",
        "wc -L -m .lane/tmp/a.txt",
        False,
    ),
    (
        "w07 grep -m value then repo file",
        "grep -E -m 5 '.{80}' scripts/a.py",
        True,
    ),
    (
        "w08 control grep -m value lane file",
        "grep -E -m 5 '.{80}' .lane/tmp/a.txt",
        False,
    ),
    (
        "r01 diff then leading stdin redirect wc",
        "git diff -- scripts/a.py | < scripts/a.py wc -L",
        True,
    ),
    (
        "r02 leading stdin redirect wc alone",
        "< scripts/a.py wc -L",
        True,
    ),
    (
        "r03 joined leading stdin redirect wc",
        "<scripts/a.py wc -L",
        True,
    ),
    (
        "r04 fd0 leading stdin redirect wc",
        "0< scripts/a.py wc -L",
        True,
    ),
    (
        "r05 diff then leading redirect awk",
        "git diff | < scripts/a.py awk 'length > 72'",
        True,
    ),
    (
        "r06 control leading lane redirect wc",
        "< .lane/tmp/a.txt wc -L",
        False,
    ),
    (
        "r07 control trailing stdin redirect repo",
        "wc -L < scripts/a.py",
        True,
    ),
)

FIX5_G1_PARSE_CASES: tuple[tuple[str, bool], ...] = (
    ("wc -Lm file", True),
    ("wc -Lm .lane/tmp/a.txt", False),
    ("wc -L --files0-from=.lane/tmp/list", True),
    ("wc -L --files0-from=.lane/tmp/list .lane/tmp/a.txt", True),
    ("wc --max-line-length file", True),
    ("wc --max-line-length .lane/tmp/a.txt", False),
    ("grep -nA3 '.{80}' file", True),
    ("grep -nA3 '.{80}' .lane/tmp/a.txt", False),
    ("grep --regexp='.{80}' file", True),
    ("grep --regexp='.{80}' .lane/tmp/a.txt", False),
    ("grep -E -- '.{80}' .lane/tmp/a.txt", False),
    ("grep -rE '.{80}'", True),
    ("grep -rE '.{80}' .lane/tmp/a.txt", True),
    ("grep -d recurse -E '.{80}' .lane/tmp/a.txt", True),
    ("rg -g '*.py' '.{80}' scripts", True),
    ("rg -g '*.py' '.{80}' .lane/tmp/a.txt", False),
    ("awk -F, -v x=1 'length > 72' file", True),
    ("awk -F, -v x=1 'length > 72' .lane/tmp/a.txt", False),
    ("awk -f .lane/tmp/p.awk scripts/a.py", True),
    ("awk -f .lane/tmp/p.awk .lane/tmp/a.txt", True),
    ("wc -L --bogus .lane/tmp/a.txt", True),
    ("wc -L -Z .lane/tmp/a.txt", True),
)

FIX5_G3_CHAIN_CASES: tuple[tuple[str, bool], ...] = (
    ("git diff | grep '^+' | awk 'length > 72'", False),
    ("git diff | sed 's/^+//' | wc -L", False),
    ("git diff | sed 's/error/warn/g' | wc -L", False),
    ("git diff | cat | wc -L", False),
    ("git diff | cat - | wc -L", False),
    ("git diff | tr -d '\\r' | wc -L", False),
    ("git diff | tee .lane/tmp/x | wc -L", True),
    ("git diff | awk '{ getline l < \"scripts/a.py\" } 1' | wc -L", True),
    ("git diff | awk '{ getline } 1' | wc -L", True),
    ("git diff | awk '{ system(\"true\") }' | wc -L", True),
    ("git diff | awk '{ print | \"cat\" }' | wc -L", True),
    ("git diff | sed 'r scripts/a.py' | wc -L", True),
    ("git diff | sed 's/a/b/w .lane/tmp/x' | wc -L", True),
    ("git diff | sed 's/a/b/e' | wc -L", True),
    ("git diff | grep -r x | wc -L", True),
    ("git diff | grep x scripts/a.py | wc -L", True),
    ("git diff | sort --files0-from=.lane/tmp/list | wc -L", True),
)

FIX6_PROBE_CASES: tuple[tuple[str, str, bool], ...] = (
    (
        "i01 awk ARGV reassign",
        "git diff | awk 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2} 1' | wc -L",
        True,
    ),
    (
        "i02 awk ARGV append",
        "git diff | awk 'BEGIN{ARGV[ARGC++]=\"scripts/a.py\"} 1' | wc -L",
        True,
    ),
    (
        "i03 gawk ARGV reassign",
        "git diff | gawk 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2} 1' | wc -L",
        True,
    ),
    (
        "i04 awk ARGV via -v",
        "git diff | awk -v f=scripts/a.py 'BEGIN{ARGV[1]=f;ARGC=2} 1' | wc -L",
        True,
    ),
    (
        "i05 awk ARGV string concat",
        'git diff | awk \'BEGIN{ARGV[1]="scripts/" "a.py";ARGC=2} 1\' | wc -L',
        True,
    ),
    (
        "i06 gawk SYMTAB ARGV",
        'git diff | gawk \'BEGIN{SYMTAB["ARGV"][1]="scripts/a.py";ARGC=2} 1\' | wc -L',
        True,
    ),
    (
        "i07 gawk SYMTAB ARGC",
        'git diff | gawk \'BEGIN{SYMTAB["ARGC"]=2;ARGV[1]="scripts/a.py"} 1\' | wc -L',
        True,
    ),
    (
        "i08 gawk indirect builtin call",
        'git diff | gawk \'BEGIN{f="system";@f("cat scripts/a.py")} 1\' | wc -L',
        True,
    ),
    (
        "i09 gawk @include",
        "git diff | gawk '@include \"scripts/inc.awk\"\n1' | wc -L",
        True,
    ),
    (
        "i10 gawk -i include",
        "git diff | gawk -i scripts/inc.awk 1 | wc -L",
        True,
    ),
    (
        "i11 awk print to command",
        "git diff | awk '{print | \"cat scripts/a.py\"}' | wc -L",
        True,
    ),
    (
        "i12 awk command getline",
        "git diff | awk 'BEGIN{\"cat scripts/a.py\" | getline l; print l} 1' | wc -L",
        True,
    ),
    (
        "i13 awk -f lane program",
        "git diff | awk -f .lane/tmp/p.awk | wc -L",
        True,
    ),
    (
        "i14 awk getline from var",
        "git diff | awk 'BEGIN{f=\"scripts/a.py\"; while ((getline l < f) > 0) print l} 1' | wc -L",
        True,
    ),
    (
        "i15 awk print redirect to file",
        "git diff | awk '{print > \"/dev/stderr\"}' | wc -L",
        True,
    ),
    (
        "i16 gawk -e program ARGV",
        "git diff | gawk -e 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2}' -e 1 | wc -L",
        True,
    ),
    (
        "i17 awk -- program ARGV",
        "git diff | awk -- 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2} 1' | wc -L",
        True,
    ),
    ("c01 awk field print", "git diff | awk '{print $1}' | wc -L", False),
    ("c02 awk -v user var", "git diff | awk -v n=3 'NR > n' | wc -L", False),
    (
        "c03 awk user function",
        "git diff | awk 'function f(x) { return x } { print f($0) }' | wc -L",
        False,
    ),
    ("c04 awk regex filter", r"git diff | awk '/^\+/ && !/^\+\+\+/' | wc -L", False),
    ("c05 awk sub strip", "git diff | awk '{ sub(/^\\+/, \"\") } 1' | wc -L", False),
    ("c06 awk regex naming ARGV", "git diff | awk '$0 ~ /ARGV/' | wc -L", False),
    (
        "c07 awk string naming ARGV",
        "git diff | awk '{ x = \"ARGV getline\" } 1' | wc -L",
        False,
    ),
    ("c08 awk comment naming ARGV", "git diff | awk '# ARGV getline\n1' | wc -L", False),
    ("c09 awk uppercase user var", "git diff | awk 'BEGIN { N = 72 } length < N' | wc -L", False),
    ("c10 awk -F field split", "git diff | awk -F: '{print $2}' | wc -L", False),
    ("c11 awk logical or and", "git diff | awk 'NR > 1 || NF == 0 && 1' | wc -L", False),
    ("c12 awk division", "git diff | awk '{ print NF / 2 }' | wc -L", False),
    (
        "f01 awk final ARGV",
        "git diff | awk 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2} length > 80'",
        True,
    ),
    (
        "f02 awk final ARGV append",
        "git diff | awk 'BEGIN{ARGV[ARGC++]=\"scripts/a.py\"} length($0) > 80'",
        True,
    ),
    (
        "f03 gawk final -i include",
        "git diff | gawk -i scripts/inc.awk 'length > 80'",
        True,
    ),
    (
        "f04 awk final print to command",
        "git diff | awk 'length < 80 { print | \"cat scripts/a.py\" }'",
        True,
    ),
    ("f05 awk final -f lane program", "git diff | awk -f .lane/tmp/p.awk", True),
    (
        "f06 gawk final SYMTAB",
        'git diff | gawk \'BEGIN{SYMTAB["ARGV"][1]="scripts/a.py";ARGC=2} length > 80\'',
        True,
    ),
    ("f07 awk final control", "git diff | awk 'length > 80'", False),
    (
        "f08 awk final control with NR",
        "git diff | awk 'length($0) > 80 { print NR \": \" $0 }'",
        False,
    ),
    (
        "l01 awk lane ARGV reassign",
        "awk 'BEGIN{ARGV[1]=\"scripts/a.py\";ARGC=2} length > 80' .lane/tmp/a.txt",
        True,
    ),
    (
        "l02 awk lane ARGV append",
        "awk 'BEGIN{ARGV[ARGC++]=\"scripts/a.py\"} length > 80' .lane/tmp/a.txt",
        True,
    ),
    (
        "l03 awk lane print to command",
        "awk 'length < 80 { print | \"cat scripts/a.py\" }' .lane/tmp/a.txt",
        True,
    ),
    (
        "l04 gawk lane -i include",
        "gawk -i scripts/inc.awk 'length > 80' .lane/tmp/a.txt",
        True,
    ),
    ("l05 awk lane -f lane program", "awk -f .lane/tmp/p.awk .lane/tmp/a.txt", True),
    (
        "l06 gawk lane SYMTAB",
        'gawk \'BEGIN{SYMTAB["ARGV"][1]="scripts/a.py"} length > 80\' .lane/tmp/a.txt',
        True,
    ),
    ("l07 awk lane control", "awk 'length > 80' .lane/tmp/a.txt", False),
    ("l08 awk lane -v control", "awk -v n=80 'length > n' .lane/tmp/a.txt", False),
    ("l09 wc lane control", "wc -L .lane/tmp/a.txt", False),
    ("l10 grep lane control", "grep -E '.{80}' .lane/tmp/a.txt", False),
)

FIX6_AWK_SCANNER_CASES: tuple[tuple[str, bool], ...] = (
    ('ARGV[1]="x"', False),
    ("ARGC=2", False),
    ('SYMTAB["ARGV"][1]="x"', False),
    ('PROCINFO["x"]', False),
    ('ENVIRON["X"]', False),
    ("getline l", False),
    ('"c" | getline', False),
    ('system("x")', False),
    ('close("x")', False),
    ("fflush()", False),
    ("nextfile", False),
    ('@include "x"', False),
    ("BEGINFILE{}", False),
    ('print | "x"', False),
    ('print > "x"', False),
    ('print $1 >> "x"', False),
    ('printf "%s" > "x"', False),
    ("a & b", False),
    (r"x = y \ z", False),
    ("awk::NR", False),
    ("foo(1)", False),
    ('"unterminated', False),
    ("/unterminated", False),
    ("length > 72", True),
    ("$0 ~ /ARGV/", True),
    ("!/getline/", True),
    ('{ x = "ARGV getline" } 1', True),
    ("# ARGV getline\n1", True),
    ("function f(x) { return x } { print f($0) }", True),
    ("BEGIN { N = 72 } length < N", True),
    ("NR > 1 || NF == 0 && 1", True),
    ("{ print NF / 2 }", True),
    ("{ print (a > b) }", True),
    (r'printf("%s\n", $0)', True),
    (r'{ sub(/^\+/, "") } 1', True),
    ("NR > 1 \\\n&& NF == 0", True),
)

CLI_THREAD_CASES: tuple[tuple[str, bool], ...] = (
    ("gawk -- 'length > 72' scripts/a.py", True),
    ("awk -- '{print $1}' scripts/a.py", False),
    ("awk -- 'length > 72' .lane/tmp/a.txt", False),
    ("wc -L -m scripts/a.py .lane/tmp/a.txt", True),
    ("wc -L -m .lane/tmp/a.txt", False),
    ("git diff -- scripts/a.py | < scripts/a.py wc -L", True),
    ("git diff | < scripts/a.py awk 'length > 72'", True),
    ("< .lane/tmp/a.txt wc -L", False),
    ("grep -E -e '.{80}' scripts/lane_brief.py .lane/tmp/draft.txt", True),
    ("grep -E -e '.{80}' .lane/tmp/draft.txt", False),
    ("git diff -- scripts/a.py | grep '^' scripts/a.py | awk 'length > 72'", True),
    ("git diff -- scripts/a.py | cat scripts/a.py | awk 'length > 72'", True),
    ("git diff -- scripts/a.py | grep '^+' | awk 'length > 72'", False),
)

MAKE_BAN_CASES: tuple[tuple[str, bool], ...] = (
    ("Never run make.\n- `make fate-x`\n", True),
    ("limits: Never run make or pre-commit.\n- `make -j4 fate-x`\n", True),
    ("Never run make or praetorctl except praetorctl admit.\n- `make fate-x`\n", True),
    ("Never run make.\n- host ran `make fate-x` (rc 0)\n", False),
    ("Never run make.\nSee `make verify-all`.\n", False),
    ("Never run `make` or `praetorctl`.\n", False),
    ("Never run push.\n- `make fate-x`\n", False),
    ("Never run make or praetorctl.\n- `make fate-x`\n", True),
    ("Never run praetorctl.\n- `make fate-x`\n", True),
    ("Never run make verify-all.\n- `make fate-x`\n", False),
    (
        (
            "- `# Why: in a make recipe, column 1 is the recipe prefix, not a shell boundary.`\n"
            "never run `make verify-all`, `make lint-all` or any whole-repository gate.\n"
        ),
        False,
    ),
    (
        (
            '- `self.skipTest("no cc or Vulkan headers; '
            'VK_FFMPEG and VK_DEVICE make the build mandatory")`\n'
            "Never run make, pre-commit, lefthook, praetorctl, semgrep, uv or pip; no network.\n"
        ),
        False,
    ),
    ("- `the make step`\nNever run make.\n", False),
    (
        (
            "5. Planted cases: `make verify` with verify depending on test.\n"
            "- never run a make target of a real repository.\n"
        ),
        True,
    ),
    ("- `cd tests && make fate-x`\nNever run make.\n", True),
    ("- `FOO=1 make fate-x`\nNever run make.\n", True),
    ("- `timeout 600 make fate-x`\nNever run make.\n", True),
    ("Never run scripts that make network calls.\n- `make fate-x`\n", False),
    ("Never run steps that make commits.\n- `make fate-x`\n", False),
    ("Never run pre-commit, make or lefthook.\n- `make fate-x`\n", True),
    ("never run a make target of a real repository.\n- `make fate-x`\n", True),
    ("Never run make.\n- `praetorctl admit -- make fate-x`\n", True),
)


ROUND11_CASES: tuple[tuple[str, str, int, str], ...] = (
    ("c01", "f1", 0, "Never run make.\n- `printf '%s\\n' 'example; make fate-x'`\n"),
    ("c02", "f1", 1, "Never run make.\n- `cd tests && make fate-x`\n"),
    ("c03", "f1", 0, "Never run make.\n- `make verify-all`\n"),
    ("c04", "f1", 0, "Never run make.\n- host ran: `make fate-x`\n"),
    ("c05", "f1", 1, 'Never run make.\n- `echo "$(make fate-x)"`\n'),
    ("c06", "f1", 1, "Never run make.\n- `(make fate-x)`\n"),
    ("c07", "f1", 1, "Never run make.\n- `timeout 60 nice -n 10 make fate-x`\n"),
    ("c08", "f1", 0, "Never run make.\n- `echo 'a | make b'`\n"),
    ("c09", "f2", 1, "Never run `echo a; echo b` or make.\n- `make fate-x`\n"),
    ("c10", "f2", 0, "Never run `echo a`; make is fine.\n- `make fate-x`\n"),
    ("c11", "f4", 0, "- `git diff | grep -F '|' | wc -L`\n"),
    ("c12", "f4", 1, "- `cat scripts/a.py | wc -L`\n"),
    ("c13", "f4", 0, "- `git diff ';' | wc -L`\n"),
    ("c14", "f4", 0, "- `git diff | grep -F '>' | wc -L`\n"),
    ("c15", "f4", 1, "- `git diff | wc -L; cat scripts/a.py | wc -L`\n"),
    ("c16", "f5", 0, "- `grep -F '.{80}' scripts/a.py`\n"),
    ("c17", "f5", 1, "- `grep -E '.{80}' scripts/a.py`\n"),
    ("c18", "f5", 0, "- `fgrep '.{80}' scripts/a.py`\n"),
    ("c19", "f5", 1, "- `grep -F -E '.{80}' scripts/a.py`\n"),
    ("c20", "f5", 0, "- `grep -iF '.{80}' scripts/a.py`\n"),
    ("c21", "f5", 0, "- `rg -F '.{80}' scripts/a.py`\n"),
    ("c22", "f5", 1, "- `rg -F --no-fixed-strings '.{80}' scripts/a.py`\n"),
    ("c23", "f5", 1, "- `grep '.{80}' scripts/a.py`\n"),
    ("c24", "f6", 1, "- `wc -L .lane/tmp/a.txt 2 > /dev/null`\n"),
    ("c25", "f6", 0, "- `wc -L .lane/tmp/a.txt 2>/dev/null`\n"),
    ("c26", "f6", 1, "- `wc -L .lane/tmp/a.txt '2'>/dev/null`\n"),
    ("c27", "f6", 0, "- `wc -L .lane/tmp/a.txt > /dev/null`\n"),
    ("c28", "f7", 1, "- `printf '%s\\n' \"$(cat scripts/a.py)\" 'git diff' | wc -L`\n"),
    ("c29", "f7", 0, "- `git diff --cached | wc -L`\n"),
    ("c30", "f7", 1, "- `echo git diff | wc -L`\n"),
    ("c31", "f7", 0, "- `GIT_PAGER=cat git --no-pager diff | wc -L`\n"),
    ("c32", "f7", 1, '- `git diff "$(cat scripts/a.py)" | wc -L`\n'),
    ("c33", "f7", 1, "- `git log | wc -L`\n"),
    ("c34", "f7", 1, "- `git -c diff.external=x diff | wc -L`\n"),
    ("c35", "f7", 1, "- `git difftool | wc -L`\n"),
)

FIX11_LENGTH_ROWS: tuple[tuple[str, str, bool], ...] = (
    ("f4 quoted pipe is a pattern", "git diff | grep -F '|' | wc -L", False),
    ("f4 quoted semicolon is an argument", "git diff ';' | wc -L", False),
    ("f4 quoted greater-than is a pattern", "git diff | grep -F '>' | wc -L", False),
    ("f4 quoted ampersand is a pattern", "git diff | grep -F '&' | wc -L", False),
    ("f4 real pipe from a file read", "cat scripts/a.py | wc -L", True),
    ("f4 real semicolon starts a command", "git diff | wc -L; cat scripts/a.py | wc -L", True),
    ("f4 real and-list starts a command", "git diff | wc -L && cat scripts/a.py | wc -L", True),
    ("f6 joined descriptor accepted", "wc -L .lane/tmp/a.txt 2>/dev/null", False),
    ("f6 joined descriptor to descriptor accepted", "wc -L .lane/tmp/a.txt 2>&1", False),
    ("f6 spaced digit is an operand", "wc -L .lane/tmp/a.txt 2 > /dev/null", True),
    ("f6 quoted digit is an operand", "wc -L .lane/tmp/a.txt '2'>/dev/null", True),
    ("f6 spaced redirect without digit", "wc -L .lane/tmp/a.txt > /dev/null", False),
    ("f5 grep -F fixed", "grep -F '.{80}' scripts/a.py", False),
    ("f5 grep --fixed-strings fixed", "grep --fixed-strings '.{80}' scripts/a.py", False),
    ("f5 grep combined -iF fixed", "grep -iF '.{80}' scripts/a.py", False),
    ("f5 grep combined -Fi fixed", "grep -Fi '.{80}' scripts/a.py", False),
    ("f5 grep repeated -F fixed", "grep -F -F '.{80}' scripts/a.py", False),
    ("f5 fgrep fixed", "fgrep '.{80}' scripts/a.py", False),
    ("f5 rg -F fixed", "rg -F '.{80}' scripts/a.py", False),
    ("f5 rg --fixed-strings fixed", "rg --fixed-strings '.{80}' scripts/a.py", False),
    ("f5 rg last toggle fixed", "rg --no-fixed-strings -F '.{80}' scripts/a.py", False),
    ("f5 grep -F -E mixed", "grep -F -E '.{80}' scripts/a.py", True),
    ("f5 grep -E -F mixed", "grep -E -F '.{80}' scripts/a.py", True),
    ("f5 grep -F -G mixed", "grep -F -G '.{80}' scripts/a.py", True),
    ("f5 grep -F -P mixed", "grep -F -P '.{80}' scripts/a.py", True),
    ("f5 grep long mixed", "grep -F --extended-regexp '.{80}' scripts/a.py", True),
    ("f5 grep long basic mixed", "grep --fixed-strings --basic-regexp '.{80}' scripts/a.py", True),
    ("f5 grep long perl mixed", "grep --perl-regexp --fixed-strings '.{80}' scripts/a.py", True),
    ("f5 fgrep -E mixed", "fgrep -E '.{80}' scripts/a.py", True),
    ("f5 fgrep -P mixed", "fgrep -P '.{80}' scripts/a.py", True),
    ("f5 egrep stays regex", "egrep '.{80}' scripts/a.py", True),
    ("f5 grep basic regex", "grep '.{80}' scripts/a.py", True),
    ("f5 grep -E regex", "grep -E '.{80}' scripts/a.py", True),
    ("f5 rg regex", "rg '.{80}' scripts/a.py", True),
    ("f5 rg --no-fixed-strings last", "rg -F --no-fixed-strings '.{80}' scripts/a.py", True),
    ("f5 rg -F with -P", "rg -F -P '.{80}' scripts/a.py", True),
    ("f5 rg -F with --pcre2", "rg -F --pcre2 '.{80}' scripts/a.py", True),
    ("f5 rg -F with --engine", "rg -F --engine pcre2 '.{80}' scripts/a.py", True),
    ("f7 real git diff", "git diff --cached | wc -L", False),
    ("f7 allowed --no-pager", "git --no-pager diff | wc -L", False),
    ("f7 allowed -P", "git -P diff | wc -L", False),
    ("f7 allowed --no-optional-locks", "git --no-optional-locks diff --stat | wc -L", False),
    ("f7 assignment and option", "GIT_PAGER=cat git --no-pager diff | wc -L", False),
    ("f7 printf names git diff", "printf '%s\\n' \"$(cat scripts/a.py)\" 'git diff' | wc -L", True),
    ("f7 echo names git diff", "echo git diff | wc -L", True),
    ("f7 echo then diff word", "echo diff | wc -L", True),
    ("f7 printf then diff word", "printf diff | wc -L", True),
    ("f7 substitution in git stage", 'git diff "$(cat scripts/a.py)" | wc -L', True),
    ("f7 input redirect in git stage", "git diff < scripts/a.py | wc -L", True),
    ("f7 other subcommand", "git log | wc -L", True),
    ("f7 difftool subcommand", "git difftool | wc -L", True),
    ("f7 -c option", "git -c diff.external=x diff | wc -L", True),
    ("f7 joined -c option", "git -cdiff.external=x diff | wc -L", True),
    ("f7 exec-path option", "git --exec-path=x diff | wc -L", True),
    ("f7 paginate option", "git --paginate diff | wc -L", True),
    ("f7 --no-index option", "git diff --no-index a b | wc -L", True),
    ("f7 --output option", "git diff --output=x | wc -L", True),
    ("f7 spaced --output option", "git diff --output x | wc -L", True),
    ("f7 quoted git word", "'git' diff | wc -L", True),
)

JOIN_DIFFERENTIAL_BRIEFS: tuple[str, ...] = (
    "at most 80 cols.\njoin the call onto a single line.\n",
    "at most 100 cols.\n- don't join the call onto one line.\n",
    "at most 100 cols.\n- never let the call go to one line.\n",
    "no line you write longer than 100 columns.\n  - finding: round 1 joined it into one line.\n",
    "no line you write longer than 100 columns.\n- host ran: joined the call into one line.\n",
    "no line you write longer than 100 columns.\nDo not touch the header. Join it onto one line.\n",
    "Keep lines at most 72 columns.\nDo not touch the header, but join the call onto one line.\n",
    "over 100 columns.\nask it to go to one line.\n",
    "more than 120 columns.\nit must be joined into one line.\n",
    "<= 80 columns.\ncode becomes a single line.\n",
    "limit: at most 80 columns.\n" + "Do not join the call onto one line. " * 40,
    "limit: at most 80 columns.\n"
    + "- do not join the call onto one line.\n- join it onto one line.\n" * 20,
    "limit: at most 80 columns.\n" + "Do not touch it, but join the call onto one line. " * 20,
    "limit: at most 80 columns.\n"
    + "Never join it onto one line; however join that onto one line! " * 20,
    "limit: at most 80 columns.\n\n"
    + "Do not join it onto one line.\n\nJoin it onto one line.\n" * 20,
)


class CountingPattern:
    """Wrap a compiled pattern and count every scan method call."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        """Remember the wrapped pattern and start counting at zero."""
        self.pattern = pattern
        self.calls = 0

    def finditer(self, *args: object) -> object:
        """Count and forward finditer."""
        self.calls += 1
        return self.pattern.finditer(*args)

    def split(self, *args: object) -> list[str]:
        """Count and forward split."""
        self.calls += 1
        return self.pattern.split(*args)

    def search(self, *args: object) -> object:
        """Count and forward search."""
        self.calls += 1
        return self.pattern.search(*args)

    def match(self, *args: object) -> object:
        """Count and forward match."""
        self.calls += 1
        return self.pattern.match(*args)


def _signal_probe(pid: int) -> bool:
    """Return whether the signal probe finds the process."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def process_alive(pid: int) -> bool:
    """Return whether a process exists and has not exited."""
    if not _signal_probe(pid):
        return False
    stat = Path(f"/proc/{pid}/stat")
    try:
        state = stat.read_text(encoding="utf-8").rpartition(")")[2].split()[0]
    except ProcessLookupError:
        return False
    except FileNotFoundError:
        # No stat entry: procfs absent, or the process was reaped after the first probe.
        return _signal_probe(pid)
    return state not in {"Z", "X"}


def _stems_from_import(node: ast.Import) -> set[str]:
    """Collect test module stems from an ast.Import node."""
    stems: set[str] = set()
    for alias in node.names[:100]:
        parts = alias.name.split(".")
        if len(parts) >= 2 and parts[0] == "tests":
            stems.add(parts[1])
    return stems


def _stems_from_import_from(node: ast.ImportFrom) -> set[str]:
    """Collect test module stems from an ast.ImportFrom node."""
    stems: set[str] = set()
    if node.module == "tests":
        for alias in node.names[:100]:
            stems.add(alias.name)
        return stems
    if node.module and node.module.startswith("tests."):
        parts = node.module.split(".")
        if len(parts) >= 2 and parts[0] == "tests":
            stems.add(parts[1])
    return stems


def _extract_imported_stems(tree: ast.AST) -> set[str]:
    """Extract test module stems imported by recognized forms in an AST."""
    stems: set[str] = set()
    for idx, node in enumerate(ast.walk(tree)):
        if idx >= 50000:
            break
        if isinstance(node, ast.Import):
            stems.update(_stems_from_import(node))
        elif isinstance(node, ast.ImportFrom):
            stems.update(_stems_from_import_from(node))
    return stems


def _resolve_reach_set(candidate_files: list[Path]) -> set[str]:
    """Compute the set of test stems that reach the stub helper directly or via imports."""
    target = "secret" + "-tool"
    max_bytes = 1024 * 1024
    reaching: set[str] = set()
    imports_map: dict[str, set[str]] = {}

    for test_file in candidate_files[:500]:
        if not test_file.is_file():
            continue
        try:
            with test_file.open("rb") as handle:
                raw = handle.read(max_bytes)
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            reaching.add(test_file.stem)
            continue

        if target in text:
            reaching.add(test_file.stem)

        try:
            tree = ast.parse(text, filename=test_file.name)
        except Exception:
            reaching.add(test_file.stem)
            continue

        imports_map[test_file.stem] = _extract_imported_stems(tree)

    max_passes = len(candidate_files) + 1
    for _ in range(max_passes):
        added = False
        for stem, imported_stems in list(imports_map.items())[: len(candidate_files)]:
            if stem not in reaching and not imported_stems.isdisjoint(reaching):
                reaching.add(stem)
                added = True
        if not added:
            break

    return reaching


def credential_stub_gaps(tests_dir: Path, declared: list[str]) -> tuple[list[str], list[str]]:
    """Return undeclared tests reaching the secret tool and stale declared entries."""
    max_files = 500
    candidate_files = sorted(tests_dir.glob("test_*.py"))[:max_files]
    reaching = _resolve_reach_set(candidate_files)
    undeclared: list[str] = []
    for test_file in candidate_files[:max_files]:
        if test_file.stem in reaching:
            dotted = f"tests.{test_file.stem}"
            if dotted not in declared and f"tests/{test_file.name}" not in declared:
                undeclared.append(dotted)

    stale: list[str] = []
    for entry in declared[:max_files]:
        stem = entry.removesuffix(".py").rpartition("/")[2].rpartition(".")[2]
        if not (tests_dir / f"{stem}.py").is_file():
            stale.append(entry)

    return sorted(undeclared), sorted(stale)


class LaneBriefTest(unittest.TestCase):
    """Check the CLI against real declarations and temporary briefs."""

    def setUp(self) -> None:
        """Create a temporary directory for input and output files."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("LANE_BRIEF_RUNNER", None)
        patcher = patch.object(lane_brief, "check_isolation", return_value=0)
        self.isolation = patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        """Capture the command result and both output streams."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                rc = lane_brief.main(list(args))
            except SystemExit as error:
                rc = int(error.code)
        return rc, stdout.getvalue(), stderr.getvalue()

    def rendered(self) -> str:
        """Render a complete brief and return its contents."""
        rc, output, error = self.run_cli(*ARGS)
        self.assertEqual(rc, 0, error)
        return output

    def runner_fixture(self) -> tuple[Path, Path, Path]:
        """Create a brief and a configurable runner that records its arguments."""
        brief = self.root / "brief.md"
        brief.write_text(self.rendered(), encoding="utf-8")
        runner = self.root / "runner.sh"
        runner.write_text(
            "#!/bin/sh\n"
            'dir=$(dirname "$0")\n'
            'printf "%s\\n" "$@" >> "$dir/args"\n'
            'if [ -f "$dir/sleep" ]; then sleep 3; fi\n'
            'printf "runner stdout\\n"\n'
            'printf "runner stderr\\n" >&2\n'
            'exit "$(cat "$dir/rc")"\n',
            encoding="utf-8",
        )
        runner.chmod(0o755)
        (self.root / "rc").write_text("0", encoding="utf-8")
        return brief, runner, self.root / "args"

    def assert_child_gone(self, pid_file: Path) -> None:
        """Check the child disappears, cleaning it up if the check fails."""
        pid = int(pid_file.read_text(encoding="utf-8"))
        for _ in range(200):
            if not process_alive(pid):
                return
            time.sleep(0.01)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        self.fail(f"child process {pid} still exists")

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "requires procfs")
    def test_assert_child_gone_accepts_zombie(self) -> None:
        """Accept a killed child that has not yet been reaped."""
        child = subprocess.Popen(["sleep", "30"])  # nosec B603 B607 - Fixed test command.
        try:
            os.kill(child.pid, signal.SIGKILL)
            pid_file = self.root / "zombie_pid"
            pid_file.write_text(str(child.pid), encoding="utf-8")
            self.assert_child_gone(pid_file)
        finally:
            child.wait(timeout=5)

    def test_process_alive_states(self) -> None:
        """Distinguish live, exited, missing, and unavailable procfs states."""
        with patch("os.kill"), patch.object(Path, "read_text") as read_stat:
            for state, expected in (("R", True), ("Z", False), ("X", False)):
                with self.subTest(state=state):
                    read_stat.return_value = f"123 (command with ) parentheses) {state} 1"
                    self.assertEqual(process_alive(123), expected)
            read_stat.side_effect = FileNotFoundError
            self.assertTrue(process_alive(123))
        with patch("os.kill", side_effect=ProcessLookupError):
            self.assertFalse(process_alive(123))

    def test_process_alive_reaped_during_read(self) -> None:
        """Treat a process reaped during the procfs read as gone."""
        with patch("os.kill"), patch.object(Path, "read_text", side_effect=ProcessLookupError):
            self.assertFalse(process_alive(123))

    def test_process_alive_reaped_before_read(self) -> None:
        """Treat a process reaped before the procfs read as gone."""
        with (
            patch("os.kill", side_effect=[None, ProcessLookupError]) as signal_probe,
            patch.object(Path, "read_text", side_effect=FileNotFoundError),
        ):
            self.assertFalse(process_alive(123))
            self.assertEqual(signal_probe.call_count, 2)

    def test_process_alive_without_procfs(self) -> None:
        """Treat a process passing both signal probes as alive without procfs."""
        with (
            patch("os.kill") as signal_probe,
            patch.object(Path, "read_text", side_effect=FileNotFoundError),
        ):
            self.assertTrue(process_alive(123))
            self.assertEqual(signal_probe.call_count, 2)

    def constant_names(self, tree: ast.Module) -> set[str]:
        """Collect module-level constant names from assignments."""
        return {
            target.id
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name) and re.fullmatch(r"[A-Z][A-Z0-9_]*", target.id)
        }

    def excluded_strings(self, tree: ast.Module) -> set[int]:
        """Exclude formatted string components and module and function docstrings."""
        excluded = {
            id(child)
            for node in ast.walk(tree)
            if isinstance(node, ast.JoinedStr)
            for child in ast.walk(node)
        }
        excluded.update(
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
            and ast.get_docstring(node) is not None
        )
        return excluded

    def test_constant_names_not_in_plain_strings(self) -> None:
        """Reject constant names accidentally left unformatted in string literals."""
        tree = ast.parse((ROOT / "scripts" / "lane_brief.py").read_text(encoding="utf-8"))
        names = self.constant_names(tree)
        excluded = self.excluded_strings(tree)
        pattern = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\b")
        matches = [
            (node.lineno, match.group())
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in excluded
            if (match := pattern.search(node.value))
        ]
        self.assertEqual(matches, [])

    def test_runner_output_missing_stdout(self) -> None:
        """Reject a runner without a stdout pipe."""
        process = SimpleNamespace(stdout=None)
        with self.assertRaisesRegex(OSError, "runner stdout pipe unavailable"):
            lane_brief.read_runner_output(process, 0.0)

    def test_runner_success_and_arguments(self) -> None:
        """Forward the brief and worktree as exact runner arguments."""
        brief, runner, calls = self.runner_fixture()
        rc, _, error = self.run_cli(
            "check",
            str(brief),
            "--runner",
            str(runner),
            "--worktree",
            str(self.root),
            "--config",
            str(CONFIG),
        )
        self.assertEqual(rc, 0, error)
        self.assertEqual(error, "runner stdout\nrunner stderr\n")
        self.assertEqual(
            calls.read_text(encoding="utf-8").splitlines(),
            ["--check-brief", str(brief), str(self.root)],
        )

    def test_runner_output_boundary(self) -> None:
        """Forward output exactly at the byte limit."""
        brief, runner, _ = self.runner_fixture()
        runner.write_text("#!/bin/sh\nprintf 1234567890123456\n", encoding="utf-8")
        with patch.object(lane_brief, "RUNNER_OUTPUT_LIMIT", 16, create=True):
            rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 0)
        self.assertEqual(error, "1234567890123456")

    def test_runner_output_over_limit(self) -> None:
        """Reject output one byte above the limit even on runner success."""
        brief, runner, _ = self.runner_fixture()
        runner.write_text("#!/bin/sh\nprintf 12345678901234567\n", encoding="utf-8")
        with patch.object(lane_brief, "RUNNER_OUTPUT_LIMIT", 16, create=True):
            rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 2)
        self.assertEqual(error, "lane_brief: runner failed: output exceeds 16 bytes\n")

    def test_runner_output_stopped_and_reaped(self) -> None:
        """Stop and reap a runner as soon as its output exceeds the limit."""
        brief, runner, _ = self.runner_fixture()
        pid_file = self.root / "pid"
        child_file = self.root / "child_pid"
        runner.write_text(
            "#!/bin/sh\n"
            f"echo $$ > '{pid_file}'\n"
            "sleep 30 &\n"
            f"echo $! > '{child_file}'\n"
            "for i in $(seq 1 1000); do printf '%01024d' 0; done\n"
            "sleep 30\n",
            encoding="utf-8",
        )
        started = time.monotonic()
        with patch.object(lane_brief, "RUNNER_TIMEOUT", 12):
            rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(rc, 2)
        self.assert_child_gone(child_file)
        self.assertEqual(
            error,
            f"lane_brief: runner failed: output exceeds {lane_brief.RUNNER_OUTPUT_LIMIT} bytes\n",
        )
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text(encoding="utf-8")), 0)

    def test_runner_combined_output_over_limit(self) -> None:
        """Count stdout and stderr together against the output limit."""
        brief, runner, _ = self.runner_fixture()
        runner.write_text("#!/bin/sh\nprintf 123456789\nprintf 12345678 >&2\n", encoding="utf-8")
        with patch.object(lane_brief, "RUNNER_OUTPUT_LIMIT", 16, create=True):
            rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 2)
        self.assertIn("output exceeds 16 bytes", error)

    def test_worktree_config_rejects_before_runner(self) -> None:
        """Check the selected worktree requirements before invoking the runner."""
        brief, runner, calls = self.runner_fixture()
        config = self.root / ".config" / "lane-brief.yaml"
        config.parent.mkdir()
        config.write_text("required:\n  - worktree only requirement\n", encoding="utf-8")
        rc, _, error = self.run_cli(
            "check", str(brief), "--runner", str(runner), "--worktree", str(self.root)
        )
        self.assertEqual(rc, 1)
        self.assertIn("missing required line: worktree only requirement", error)
        self.assertFalse(calls.exists())

    def test_explicit_config_overrides_worktree(self) -> None:
        """Prefer an explicit config over the selected worktree config."""
        brief, runner, calls = self.runner_fixture()
        config = self.root / ".config" / "lane-brief.yaml"
        config.parent.mkdir()
        config.write_text("required:\n  - worktree only requirement\n", encoding="utf-8")
        rc, _, error = self.run_cli(
            "check",
            str(brief),
            "--runner",
            str(runner),
            "--worktree",
            str(self.root),
            "--config",
            str(CONFIG),
        )
        self.assertEqual(rc, 0, error)
        self.assertTrue(calls.exists())

    def test_runner_refusal(self) -> None:
        """Map a runner refusal to invalid brief status."""
        brief, runner, _ = self.runner_fixture()
        (self.root / "rc").write_text("2", encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 1)
        self.assertIn("lane_brief: runner refused brief (rc 2)", error)

    def test_runner_missing_and_not_executable(self) -> None:
        """Report missing and non-executable runners as input errors."""
        brief, runner, _ = self.runner_fixture()
        runner.chmod(0o644)
        for path in (self.root / "missing", runner):
            with self.subTest(path=path):
                rc, _, error = self.run_cli("check", str(brief), "--runner", str(path))
                self.assertEqual(rc, 2)
                self.assertIn("lane_brief: runner failed:", error)

    def test_runner_timeout(self) -> None:
        """Report a runner exceeding the timeout as an input error."""
        brief, runner, _ = self.runner_fixture()
        child_file = self.root / "child_pid"
        runner.write_text(
            f"#!/bin/sh\nsleep 30 &\necho $! > '{child_file}'\nwait\n",
            encoding="utf-8",
        )
        with patch.object(lane_brief, "RUNNER_TIMEOUT", 1):
            rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 2)
        self.assert_child_gone(child_file)
        self.assertEqual(error, "lane_brief: runner failed: timed out after 1 seconds\n")

    def test_runner_from_environment(self) -> None:
        """Use the environment runner and default worktree when unspecified."""
        brief, runner, calls = self.runner_fixture()
        with patch.dict(os.environ, {"LANE_BRIEF_RUNNER": str(runner)}):
            rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 0, error)
        self.assertEqual(
            calls.read_text(encoding="utf-8").splitlines(), ["--check-brief", str(brief), str(ROOT)]
        )

    def test_runner_unset(self) -> None:
        """Explain when a valid brief skips the runner check."""
        brief, _, _ = self.runner_fixture()
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 0)
        self.isolation.assert_not_called()
        self.assertEqual(
            error, "lane_brief: runner and lane isolation checks skipped: LANE_BRIEF_RUNNER unset\n"
        )

    def test_runner_empty_environment(self) -> None:
        """Treat an empty runner environment value as unset."""
        brief, _, _ = self.runner_fixture()
        with patch.dict(os.environ, {"LANE_BRIEF_RUNNER": ""}):
            rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 0)
        self.isolation.assert_not_called()
        self.assertEqual(
            error, "lane_brief: runner and lane isolation checks skipped: LANE_BRIEF_RUNNER unset\n"
        )

    def test_local_failure_does_not_call_runner(self) -> None:
        """Reject a locally invalid brief before invoking the runner."""
        brief, runner, calls = self.runner_fixture()
        content = brief.read_text(encoding="utf-8")
        brief.write_text(content.replace(lane_brief.read_required(CONFIG)[0], ""), encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 1, error)
        self.assertIn("missing required line", error)
        self.assertFalse(calls.exists())

    def check_snippet(self, snippet: str, *, worktree: Path | None = None) -> tuple[int, str]:
        """Validate a rendered brief containing snippet and return status and stderr."""
        brief = self.root / "brief.md"
        brief.write_text(f"{self.rendered()}\n{snippet}", encoding="utf-8")
        target = worktree if worktree is not None else self.root
        rc, _, error = self.run_cli(
            "check", str(brief), "--worktree", str(target), "--config", str(CONFIG)
        )
        return rc, error

    def commit_fixture(self) -> tuple[Path, str]:
        """Create a one-commit temporary Git repository and return its path and HEAD."""
        worktree = repo(self.root / "worktree")
        commit = run_git(worktree, "rev-parse", "HEAD", preserve_config=True)
        return worktree, commit

    def test_conflict_does_not_call_runner(self) -> None:
        """Reject a conflicting brief before checking isolation or invoking the runner."""
        brief, runner, calls = self.runner_fixture()
        content = brief.read_text(encoding="utf-8")
        brief.write_text(content + "\n- `wc -L tests/checkasm/vvc_mc.c`\n", encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief), "--runner", str(runner))
        self.assertEqual(rc, 1, error)
        self.assertIn(f"{brief}: conflict:", error)
        self.isolation.assert_not_called()
        self.assertFalse(calls.exists())

    def test_conflict_case_1a_refused(self) -> None:
        """Refuse case 1a naming make in backticks while forbidding praetorctl."""
        rc, error = self.check_snippet(
            "- `nice -n 10 make -j6 x > log`\n"
            "limits: Never run cherry-pick, rebase, lefthook or praetorctl; never\n"
        )
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("nice -n 10 make -j6 x > log", error)
        self.assertIn("praetorctl admit", error)

    def test_conflict_case_1b_passes(self) -> None:
        """Pass case 1b when Never run forbids both make and praetorctl."""
        rc, error = self.check_snippet(
            "host builds.\n"
            "limits: Never run make, cherry-pick, rebase, lefthook or praetorctl; never\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_case_1c_passes(self) -> None:
        """Pass case 1c when praetorctl is forbidden without any make command."""
        rc, error = self.check_snippet(
            "- `git add a`\nlimits: Never run push or praetorctl; never\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_case_1d_passes(self) -> None:
        """Pass case 1d when make is named without forbidding praetorctl."""
        rc, error = self.check_snippet("- `make fate-x`\nlimits: Never run push; never\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_case_2a_refused(self) -> None:
        """Refuse case 2a asking a declaration to become one line under 100 columns."""
        rc, error = self.check_snippet(
            "- FFmpeg style: no line you write longer than 100 columns.\n"
            "  2. `alf_gradient_tmp` (`int32_t`; the two-line declaration becomes one line).\n"
        )
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("becomes one line", error)
        self.assertIn("longer than 100 columns", error)
        self.assertIn("exact wrapped form", error)

    def test_conflict_case_2b_passes(self) -> None:
        """Pass case 2b asking for one line when no column limit is set."""
        rc, error = self.check_snippet("the two-line declaration becomes one line.\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_case_2c_passes(self) -> None:
        """Pass case 2c giving a wrapped form under a 100-column limit."""
        rc, error = self.check_snippet(
            "no line you write longer than 100 columns.\n"
            "write it as two lines:\n"
            "```c\n"
            "    a *\n"
            "        b;\n"
            "```\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_case_2d_refused(self) -> None:
        """Refuse case 2d joining a call onto a single line under 80 cols."""
        rc, error = self.check_snippet("at most 80 cols.\njoin the call onto a single line.\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("join the call onto a single line", error)
        self.assertIn("at most 80 cols", error)

    def test_conflict_case_3a_refused(self) -> None:
        """Refuse case 3a running awk length on a whole file."""
        rc, error = self.check_snippet(
            "- `awk 'length($0) > 100 {print FILENAME\":\"FNR}' "
            "libavfilter/tests/hqdn3d_vulkan.c` (must print nothing)\n"
        )
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("hqdn3d_vulkan.c", error)
        self.assertIn("added lines of a git diff", error)

    def test_conflict_case_3b_refused(self) -> None:
        """Refuse case 3b running grep with a dot-repeat width on a whole file."""
        rc, error = self.check_snippet(r"- `grep -n '.\{101\}' libavcodec/vvc/inter.c`" + "\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn(r"grep -n '.\{101\}' libavcodec/vvc/inter.c", error)
        self.assertIn("added lines of a git diff", error)

    def test_conflict_case_3c_refused(self) -> None:
        """Refuse case 3c running wc -L on a whole file."""
        rc, error = self.check_snippet("- `wc -L tests/checkasm/vvc_mc.c`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("wc -L tests/checkasm/vvc_mc.c", error)
        self.assertIn("added lines of a git diff", error)

    def test_conflict_case_3d_passes(self) -> None:
        """Pass case 3d piping git diff output into an awk length check."""
        rc, error = self.check_snippet(
            "- `git diff -U0 HEAD~1 -- a.c | grep '^+[^+]' | awk 'length($0) > 101'` "
            "(must print nothing)\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_case_3e_passes(self) -> None:
        """Pass case 3e running awk without a length check."""
        rc, error = self.check_snippet("- `awk '{print $1}' list.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_case_4a_refused(self) -> None:
        """Refuse case 4a naming a zero-padded 40-hex commit absent from the worktree."""
        worktree, commit = self.commit_fixture()
        padded = commit[:7] + ("0" * 33)
        self.assertNotEqual(padded, commit)
        rc, error = self.check_snippet(f"HEAD {padded} (origin/main)\n", worktree=worktree)
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn(padded, error)
        self.assertIn("git rev-parse", error)

    def test_conflict_case_4b_passes(self) -> None:
        """Pass case 4b naming the full 40-hex commit held by the worktree."""
        worktree, commit = self.commit_fixture()
        self.assertEqual(len(commit.strip()), 40)
        rc, error = self.check_snippet(f"HEAD {commit} (origin/main)\n", worktree=worktree)
        self.assertEqual(rc, 0, error)

    def test_conflict_case_4c_passes(self) -> None:
        """Pass case 4c containing only a short commit name and a 64-hex digest."""
        worktree, commit = self.commit_fixture()
        digest = "a" * 64
        rc, error = self.check_snippet(f"HEAD {commit[:7]}; sha256 {digest}\n", worktree=worktree)
        self.assertEqual(rc, 0, error)

    def test_conflict_case_4d_passes(self) -> None:
        """Pass case 4d containing a 41-hex run rather than a standalone 40-hex name."""
        worktree, commit = self.commit_fixture()
        self.assertEqual(len(commit.strip()), 40)
        rc, error = self.check_snippet(f"HEAD {commit}0 (origin/main)\n", worktree=worktree)
        self.assertEqual(rc, 0, error)

    def nested_commit_fixture(self) -> tuple[Path, str, str]:
        """Create a worktree repository with a distinct nested repository under sub/nested."""
        worktree, outer_commit = self.commit_fixture()
        nested = worktree / "sub" / "nested"
        nested.parent.mkdir(parents=True)
        repo(nested)
        run_git(nested, "commit", "-q", "--allow-empty", "-m", "nested-only", preserve_config=True)
        nested_commit = run_git(nested, "rev-parse", "HEAD", preserve_config=True)
        self.assertNotEqual(nested_commit, outer_commit)
        return worktree, outer_commit, nested_commit

    def test_conflict_case_4e_fail_closed(self) -> None:
        """Fail closed with exit 2 for case 4e when the worktree or Git fails."""
        worktree, commit = self.commit_fixture()
        resolved_top = f"{worktree.resolve()}\n"
        not_repo = self.root / "not_repo"
        not_repo.mkdir()
        (not_repo / ".git").write_text("gitdir: missing\n", encoding="utf-8")
        with self.subTest(case="not_repo"):
            rc, error = self.check_snippet(f"HEAD {commit} (origin/main)\n", worktree=not_repo)
            self.assertEqual(rc, 2, error)
            self.assertIn("could not resolve", error)
            self.assertIn(commit, error)
        for case, stderr, expected in (
            ("corrupt_repo", "corrupt repo", "corrupt repo"),
            ("empty_stderr", "", "git cat-file exited 128"),
        ):
            with self.subTest(case=case):

                def fake_git(
                    args: list[str], text: str = stderr
                ) -> subprocess.CompletedProcess[str]:
                    """Stub toplevel resolution and a failing cat-file probe."""
                    if "--show-toplevel" in args:
                        return subprocess.CompletedProcess(args, 0, resolved_top, "")
                    if "cat-file" in args:
                        return subprocess.CompletedProcess(args, 128, "", text)
                    return subprocess.CompletedProcess(args, 0, "", "")

                with patch.object(lane_isolation, "run_git", side_effect=fake_git):
                    rc, error = self.check_snippet(
                        f"HEAD {commit} (origin/main)\n", worktree=worktree
                    )
                self.assertEqual(rc, 2, error)
                self.assertIn(expected, error)
        with self.subTest(case="timed_out"):

            def timeout_git(args: list[str]) -> subprocess.CompletedProcess[str]:
                """Raise an isolation timeout on the repository-root query."""
                if "--show-toplevel" in args:
                    raise lane_isolation.IsolationError("timed out")
                return subprocess.CompletedProcess(args, 0, f"{worktree / '.git'}\n", "")

            with patch.object(lane_isolation, "run_git", side_effect=timeout_git):
                rc, error = self.check_snippet(f"HEAD {commit} (origin/main)\n", worktree=worktree)
            self.assertEqual(rc, 2, error)
            self.assertIn("timed out", error)

    def test_conflict_stub_c1_passes(self) -> None:
        """Pass stub c1 recording a host-ran make verify-all line under Never run."""
        rc, error = self.check_snippet(
            "limits: Never run make verify-all, lefthook or praetorctl.\n"
            "- host ran: `make verify-all` (rc 0)\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_stub_c2_passes(self) -> None:
        """Pass stub c2 recording a host-ran make target under a praetorctl ban."""
        rc, error = self.check_snippet(
            "limits: Never run lefthook or praetorctl.\n- host ran: `make fate-vvc` (rc 0)\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_stub_c3_passes(self) -> None:
        """Pass stub c3 forbidding a one-line join under a 100-column limit."""
        rc, error = self.check_snippet(
            "no line you write longer than 100 columns.\n"
            "- do not join the declaration onto one line.\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_stub_c4_passes(self) -> None:
        """Pass stub c4 checking awk field length rather than whole-line length."""
        rc, error = self.check_snippet("- check `awk 'length($1) == 40' refs.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_stub_c5_passes(self) -> None:
        """Pass stub c5 carrying an external 40-hex commit inside a URL token."""
        worktree, _ = self.commit_fixture()
        rc, error = self.check_snippet(
            "see https://example.org/commit/1111111111111111111111111111111111111111 for context\n",
            worktree=worktree,
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_stub_c7_exits_2(self) -> None:
        """Fail closed with exit 2 for stub c7 on a plain subdirectory inside a checkout."""
        worktree, commit = self.commit_fixture()
        plain = worktree / "notrepo"
        plain.mkdir()
        self.assertFalse((plain / ".git").exists())
        rc, error = self.check_snippet(f"base {commit}\n", worktree=plain)
        self.assertEqual(rc, 2, error)
        self.assertIn("could not resolve", error)
        self.assertIn(commit, error)

    def test_conflict_stub_c8_passes(self) -> None:
        """Pass stub c8 when backtick spans appear inside the Never run clause itself."""
        rc, error = self.check_snippet("Never run `make verify-all` or `praetorctl`.\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_make_branch_allowances_pass(self) -> None:
        """Pass make spans with except-admit, scoped praetorctl bans, or verify-all spans."""
        for snippet in (
            "limits: Never run lefthook or praetorctl except praetorctl admit.\n- `make fate-x`\n",
            "limits: Never run praetorctl gate.\n- `make fate-x`\n",
            "limits: Never run praetorctl admit.\n- `make fate-x`\n",
            "limits: Never run make verify-all or praetorctl.\nSee `make verify-all`.\n",
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 0, error)

    def test_conflict_make_verify_all_ban_still_refuses_make(self) -> None:
        """Refuse a make span outside Never run when the clause only bans make verify-all."""
        rc, error = self.check_snippet(
            "limits: Never run make verify-all or praetorctl.\n- `make fate-x`\n"
        )
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_conflict_join_negations_and_records_pass(self) -> None:
        """Pass negated join clauses and finding or host-ran lines under a column limit."""
        for snippet in (
            "at most 100 cols.\n- don't join the call onto one line.\n",
            "at most 100 cols.\n- never let the call go to one line.\n",
            (
                "no line you write longer than 100 columns.\n"
                "  - finding: round 1 joined the call into one line.\n"
            ),
            (
                "no line you write longer than 100 columns.\n"
                "- host ran: joined the call into one line.\n"
            ),
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 0, error)

    def test_conflict_join_after_negated_sentence_refused(self) -> None:
        """Refuse a join phrase in a later sentence after an earlier negated sentence."""
        for snippet in (
            (
                "no line you write longer than 100 columns.\n"
                "Do not touch the header. Join the call onto one line.\n"
            ),
            (
                "no line you write longer than 100 columns.\n"
                "Do not join the header onto one line. Join the call onto one line.\n"
            ),
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 1, error)
                self.assertIn("conflict:", error)

    def test_conflict_whole_file_skipped_contexts_pass(self) -> None:
        """Pass whole-file length spans inside Never run or host-ran lines and 1-digit dots."""
        for snippet in (
            "limits: Never run `wc -L tests/checkasm/vvc_mc.c`.\n",
            "- host ran: `wc -L tests/checkasm/vvc_mc.c` (rc 0)\n",
            "- `rg 'foo.{2}bar' a.c`\n",
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 0, error)

    def test_conflict_whole_file_extra_forms_refused(self) -> None:
        """Refuse bare awk length, empty-arg length, gawk, rg, and wc --max-line-length."""
        for snippet in (
            "- `awk 'length > 100' a.c`\n",
            "- `awk 'length() > 100' a.c`\n",
            "- `gawk 'length($0) > 100' a.c`\n",
            "- `rg '.{101}' a.c`\n",
            "- `wc --max-line-length a.c`\n",
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 1, error)
                self.assertIn("conflict:", error)

    def test_conflict_whole_file_lane_owned_awk_passes(self) -> None:
        """Pass awk length without parentheses over a commit message draft under .lane/."""
        rc, error = self.check_snippet("- `awk 'length > 72' .lane/evidence/x/msg-new.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_whole_file_lane_owned_grep_passes(self) -> None:
        """Pass grep with a three-digit counted dot over a lane-owned file."""
        rc, error = self.check_snippet(r"- `grep -n '.\{101\}' .lane/evidence/foo/body.txt`" + "\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_whole_file_lane_owned_wc_passes(self) -> None:
        """Pass wc max-line-length over a file under .lane/tmp/."""
        rc, error = self.check_snippet("- `wc --max-line-length .lane/tmp/wrap-check.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_conflict_whole_file_lane_owned_absolute_passes(self) -> None:
        """Pass when an absolute path operand contains a /.lane/ segment."""
        rc, error = self.check_snippet(
            "- `awk 'length > 72' "
            "/home/example/dev/worktrees/ffmpeg-patches/.lane/evidence/x/msg.txt`\n"
        )
        self.assertEqual(rc, 0, error)

    def test_conflict_whole_file_repository_awk_refused(self) -> None:
        """Refuse bare awk length over a repository file under scripts/."""
        rc, error = self.check_snippet("- `awk 'length > 72' scripts/lane_brief.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn("lane_brief.py", error)

    def test_conflict_whole_file_mixed_lane_repo_operands_refused(self) -> None:
        """Refuse when one operand is lane-owned and another is a repository file."""
        rc, error = self.check_snippet(
            "- `awk 'length > 72' .lane/tmp/a.txt scripts/lane_brief.py`\n"
        )
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_conflict_whole_file_lane_dotdot_operand_refused(self) -> None:
        """Refuse a .lane path that escapes through a parent .. segment."""
        rc, error = self.check_snippet("- `awk 'length > 72' .lane/tmp/../scripts/x.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_conflict_whole_file_bare_filename_refused(self) -> None:
        """Refuse a whole-file length check on a bare worktree-root filename."""
        rc, error = self.check_snippet("- `awk 'length > 72' Makefile`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_conflict_nested_repository_passes(self) -> None:
        """Accept a 40-hex commit held by a nested repository named with git -C."""
        worktree, _, nested_commit = self.nested_commit_fixture()
        snippet = f"- `git -C sub/nested rev-parse HEAD`\nHEAD {nested_commit}\n"
        rc, error = self.check_snippet(snippet, worktree=worktree)
        self.assertEqual(rc, 0, error)

    def test_conflict_nested_repository_without_git_c_refused(self) -> None:
        """Refuse a nested repository commit when the brief omits git -C for it."""
        worktree, _, nested_commit = self.nested_commit_fixture()
        rc, error = self.check_snippet(f"HEAD {nested_commit}\n", worktree=worktree)
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn(nested_commit, error)

    def test_conflict_nested_repository_outside_worktree_refused(self) -> None:
        """Ignore a git -C relative path that leaves the worktree via two dots."""
        worktree, _ = self.commit_fixture()
        outside = repo(self.root / "outside")
        run_git(
            outside, "commit", "-q", "--allow-empty", "-m", "outside-only", preserve_config=True
        )
        outside_commit = run_git(outside, "rev-parse", "HEAD", preserve_config=True)
        snippet = f"- `git -C ../outside rev-parse HEAD`\nHEAD {outside_commit}\n"
        rc, error = self.check_snippet(snippet, worktree=worktree)
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn(outside_commit, error)

    def test_conflict_plain_slash_object_path_refused(self) -> None:
        """Check a 40-hex name after a plain slash when no URL scheme separator is present."""
        worktree, commit = self.commit_fixture()
        missing = commit[:7] + ("0" * 33)
        rc, error = self.check_snippet(f"see refs/x/{missing} in tree\n", worktree=worktree)
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        self.assertIn(missing, error)

    def test_conflict_nested_probe_error_and_cap(self) -> None:
        """Fail closed on nested Git errors and ignore non-root or excess git -C paths."""
        worktree, _, nested_commit = self.nested_commit_fixture()
        (worktree / "plain").mkdir()
        extra = " ".join(f"`git -C plain{i} status`" for i in range(8))
        rc, error = self.check_snippet(
            f"{extra} `git -C sub/nested status`\nHEAD {nested_commit}\n", worktree=worktree
        )
        self.assertEqual(rc, 1, error)
        nested_path = str((worktree / "sub" / "nested").resolve())
        real_run_git = lane_isolation.run_git

        def fail_nested_probe(args: list[str]) -> subprocess.CompletedProcess[str]:
            """Fail cat-file on the nested repository with exit status 128."""
            if "cat-file" in args and nested_path in args:
                return subprocess.CompletedProcess(args, 128, "", "nested broken")
            return real_run_git(args)

        with patch.object(lane_isolation, "run_git", side_effect=fail_nested_probe):
            rc, error = self.check_snippet(
                f"- `git -C plain status`\n- `git -C sub/nested status`\nHEAD {nested_commit}\n",
                worktree=worktree,
            )
        self.assertEqual(rc, 2, error)
        self.assertIn("nested broken", error)

    def test_round3_k1_never_run_span_semicolon_passes(self) -> None:
        """Pass K1 when a Never run clause holds a semicolon inside its backtick span."""
        rc, error = self.check_snippet("Never run `wc -L scripts/a.py; echo done`.\n")
        self.assertEqual(rc, 0, error)
        rc, error = self.check_snippet("- run `wc -L scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_k2_awk_string_literal_passes(self) -> None:
        """Pass K2 when awk prints a literal length string on a repository file."""
        rc, error = self.check_snippet("- `awk '{print \"length\"}' scripts/a.py`\n")
        self.assertEqual(rc, 0, error)
        for snippet in (
            "- `awk 'length > 72' scripts/a.py`\n",
            "- `awk 'length($0) > 72' scripts/a.py`\n",
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 1, error)
                self.assertIn("conflict:", error)

    def test_round3_k3_wc_l_after_other_option_refused(self) -> None:
        """Refuse K3 when wc lists -L after another option on a repository file."""
        rc, error = self.check_snippet("- `wc -l -L scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet("- `wc -l scripts/a.py`\n")
        self.assertEqual(rc, 0, error)

    def test_round3_k4_uppercase_object_names_normalized(self) -> None:
        """Normalize K4 standalone 40-hex names from either hex case."""
        upper = "F" * 40
        lower = "f" * 40
        self.assertEqual(lane_brief.standalone_object_names(f"HEAD {upper}\n"), [lower])
        self.assertEqual(lane_brief.standalone_object_names(f"HEAD {lower}\n"), [lower])
        mixed = "aAbBcCdDeEfF0123456789aAbBcCdDeEfF012345"
        self.assertEqual(len(mixed), 40)
        self.assertEqual(
            lane_brief.standalone_object_names(f"HEAD {mixed}\n"),
            [mixed.lower()],
        )
        self.assertEqual(lane_brief.standalone_object_names("HEAD " + upper + "0\n"), [])
        self.assertEqual(lane_brief.standalone_object_names("HEAD " + ("F" * 64) + "\n"), [])

    def test_round3_k4_upper_lower_deduped(self) -> None:
        """Deduplicate K4 names after lowering mixed-case duplicates."""
        name = "a" * 40
        text = f"HEAD {name.upper()} then {name}\n"
        self.assertEqual(lane_brief.standalone_object_names(text), [name])

    def test_round3_k5_non_clause_spans_matches_bruteforce(self) -> None:
        """Match K5 non_clause_spans against a brute-force clause scan."""
        samples = (
            "Never run `make`;\n`outer`\n",
            "Never run `a` and `b`;\n`between`\n",
            "Never run x;\nNever run y;\n`tail`\n",
            "line one\nNever run `inner;\n` semicolon`.\n`after`\n",
        )
        for text in samples:
            with self.subTest(text=text):
                brute = [
                    match
                    for match in lane_brief.BACKTICK_SPAN.finditer(text)
                    if not any(
                        clause.start() <= match.start() and match.end() <= clause.end()
                        for clause in lane_brief.NEVER_RUN_CLAUSE.finditer(
                            lane_brief.mask_backtick_inners(text)
                        )
                    )
                ]
                self.assertEqual(
                    [match.span() for match in lane_brief.non_clause_spans(text)],
                    [match.span() for match in brute],
                )

    def test_round3_k5_non_clause_spans_large_brief_under_two_seconds(self) -> None:
        """Finish K5 non_clause_spans within two seconds on ten thousand clause pairs."""
        count = 10_000
        text = "Never run x;\n" * count + "`a`\n" * count
        started = time.monotonic()
        outside = lane_brief.non_clause_spans(text)
        elapsed = time.monotonic() - started
        self.assertEqual(len(outside), count)
        self.assertLess(elapsed, 2.0)

    def test_round3_k6_make_span_with_make_ban_refused(self) -> None:
        """Refuse K6 when a make span appears while Never run also forbids make."""
        rc, error = self.check_snippet("Never run make or praetorctl.\n- `make fate-x`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet("Never run praetorctl.\n- `make fate-x`\n")
        self.assertEqual(rc, 1, error)

    def test_round3_k7_contrast_clause_limits_join_negation(self) -> None:
        """Refuse K7 join requests after a contrast clause under a column limit."""
        snippet = (
            "Keep lines at most 72 columns.\n"
            "Do not touch the header, but join the call onto one line.\n"
        )
        rc, error = self.check_snippet(snippet)
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet(
            "Keep lines at most 72 columns.\nDo not join the call onto one line.\n"
        )
        self.assertEqual(rc, 0, error)
        rc, error = self.check_snippet(
            "Keep lines at most 72 columns.\nJoin the call onto one line.\n"
        )
        self.assertEqual(rc, 1, error)

    def test_round3_k8_quoted_operands_lane_check(self) -> None:
        """Apply K8 lane-owned checks to quoted file operands."""
        rc, error = self.check_snippet('- `wc -L ".lane/tmp/message draft.txt"`\n')
        self.assertEqual(rc, 0, error)
        rc, error = self.check_snippet('- `wc -L .lane/tmp/draft.txt "scripts/lane_brief.py"`\n')
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet("- `wc -L .lane/tmp/draft.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_round3_k9_bare_makefile_operand_refused(self) -> None:
        """Refuse K9 when wc -L reads a bare repository filename with a lane path."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/draft.txt Makefile`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_k10_relative_lane_segment_refused(self) -> None:
        """Refuse K10 repository-relative paths that only embed a /.lane/ segment."""
        rc, error = self.check_snippet("- `wc -L tests/.lane/golden.txt`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet("- `wc -L /w/x/.lane/tmp/d.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_round3_k11_diff_exemption_needs_stdin_chain(self) -> None:
        """Refuse K11 when a piped wc reads an explicit repository file operand."""
        rc, error = self.check_snippet("- `git diff -- scripts/a.py | wc -L scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)
        rc, error = self.check_snippet(
            "- `git diff -U0 -- scripts/a.py | grep '^+' | awk 'length > 72'`\n"
        )
        self.assertEqual(rc, 0, error)

    def test_round3_k12_broken_nested_git_exits_two(self) -> None:
        """Exit 2 for K12 when a nested checkout gitdir cannot be resolved."""
        worktree, commit = self.commit_fixture()
        broken = worktree / "sub"
        broken.mkdir()
        (broken / ".git").write_text("gitdir: /nonexistent/x\n", encoding="utf-8")
        missing = "1" * 40
        rc, error = self.check_snippet(f"`git -C sub log -1`\nHEAD {missing}\n", worktree=worktree)
        self.assertEqual(rc, 2, error)
        plain = worktree / "plain"
        plain.mkdir()
        self.assertFalse(lane_brief.valid_nested_root(plain, worktree.resolve()))
        self.assertFalse(lane_brief.valid_nested_root(worktree / "missing", worktree.resolve()))

    def test_round3_k13_fixture_head_stays_sha1(self) -> None:
        """Keep K13 fixture HEAD at 40 hex even when GIT_DEFAULT_HASH is sha256."""
        with patch.dict(os.environ, {"GIT_DEFAULT_HASH": "sha256"}, clear=False):
            worktree, commit = self.commit_fixture()
        self.assertEqual(len(commit.strip()), 40)
        self.assertEqual(lane_brief.standalone_object_names(f"HEAD {commit}\n"), [commit.strip()])

    def test_round3_g2_grep_context_operand_refused(self) -> None:
        """Refuse grep counted-dot patterns with a repository operand after -A."""
        rc, error = self.check_snippet(r"- `grep -A 2 '.\{101\}' scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_g2_wc_input_redirect_refused(self) -> None:
        """Refuse wc -L when input is redirected from a repository file."""
        rc, error = self.check_snippet("- `wc -L < scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_g2_semicolon_second_command_refused(self) -> None:
        """Refuse a span whose second semicolon-separated command runs wc -L."""
        rc, error = self.check_snippet("- `git diff --stat; wc -L scripts/a.py`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_g2_xargs_wc_refused(self) -> None:
        """Refuse xargs wc -L when file names would come from git diff."""
        rc, error = self.check_snippet("- `git diff --name-only | xargs wc -L`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_g2_unclosed_quote_wc_refused(self) -> None:
        """Refuse an unclosed quote span that still names wc -L."""
        rc, error = self.check_snippet('- `wc -L "scripts/a.py`\n')
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_round3_g2_wc_redirect_lane_passes(self) -> None:
        """Pass wc -L on a lane file when output is redirected after a descriptor."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt > /dev/null 2>&1`\n")
        self.assertEqual(rc, 0, error)

    def test_round3_g2_awk_f_lane_operand_passes(self) -> None:
        """Pass awk length with -F colon and a lane-owned file operand."""
        rc, error = self.check_snippet("- `awk -F: 'length > 72' .lane/evidence/x/msg.txt`\n")
        self.assertEqual(rc, 0, error)

    def test_fix4_r1_wc_joined_stdout_redirect_passes(self) -> None:
        """Pass wc -L on a lane file when stdout redirect has no space before the target."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt >/dev/null`\n")
        self.assertEqual(rc, 0, error)

    def test_fix4_r2_wc_spaced_stderr_redirect_passes(self) -> None:
        """Pass wc -L on a lane file when stderr redirect tokens are spaced."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt 2> /dev/null`\n")
        self.assertEqual(rc, 0, error)

    def test_fix4_r3_wc_joined_stderr_redirect_passes(self) -> None:
        """Pass wc -L on a lane file when stderr descriptor and operator are joined."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt 2>/dev/null`\n")
        self.assertEqual(rc, 0, error)

    def test_fix4_r4_wc_spaced_stdout_redirect_passes(self) -> None:
        """Pass wc -L on a lane file when stdout redirect tokens are spaced (control)."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt > /dev/null`\n")
        self.assertEqual(rc, 0, error)

    def test_fix4_r5_wc_spaced_descriptor_redirect_refused(self) -> None:
        """Refuse wc -L when a spaced digit is a file operand, not a descriptor."""
        rc, error = self.check_snippet("- `wc -L .lane/tmp/a.txt 2 > /dev/null`\n")
        self.assertEqual(rc, 1, error)

    def test_fix4_r6_wc_repo_file_joined_redirect_refused(self) -> None:
        """Refuse wc -L on a repository file even when stdout redirect is joined."""
        rc, error = self.check_snippet("- `wc -L scripts/a.py >/dev/null`\n")
        self.assertEqual(rc, 1, error)
        self.assertIn("conflict:", error)

    def test_fix4_strip_awk_double_quotes_table(self) -> None:
        """Pin strip_awk_double_quotes behavior for quoted and escaped awk programs."""
        cases = {
            r'print "he\"llo"': "print ",
            'print "\\"': "print ",
            'print "open': "print ",
            'print "a" b "c"': "print  b ",
            'print "a\nb" x': "print  x",
        }
        for program, expected in cases.items():
            with self.subTest(program=program):
                self.assertEqual(lane_brief.strip_awk_double_quotes(program), expected)

    def test_fix4_awk_program_token_table(self) -> None:
        """Pin awk_program_token for option shapes and end-of-argv programs."""
        cases = [
            (["awk", "-F:", "prog"], 0, ("prog", False)),
            (["awk", "-F", ":", "prog"], 0, ("prog", False)),
            (["awk", "-v", "x=1", "prog"], 0, ("prog", False)),
            (["awk", "-f", "file.awk"], 0, (None, True)),
            (["awk", "--", "prog"], 0, ("prog", False)),
        ]
        for words, tool_index, expected in cases:
            with self.subTest(words=words):
                self.assertEqual(lane_brief.awk_program_token(words, tool_index), expected)

    def test_fix4_command_file_operands_table(self) -> None:
        """Pin command_file_operands for options and lane-owned stdin redirects."""
        cases = [
            (["wc", "-L", "-c", "file"], ["file"]),
            (["wc", "-L", "file", ">"], ["file"]),
            (["wc", "-L", "lane", "<", ".lane/tmp/in.txt"], ["lane", ".lane/tmp/in.txt"]),
        ]
        for words, expected in cases:
            with self.subTest(words=words):
                self.assertEqual(lane_brief.command_file_operands(words), expected)

    def test_fix4_command_file_operands_redirect_table(self) -> None:
        """Pin command_file_operands redirect forms that differ from round-3 tokenization."""
        cases = [
            (["wc", "-L", "file", "2", ">&", "1"], ["file"]),
            (["wc", "-L", "file", "&>", "out"], ["file"]),
        ]
        for words, expected in cases:
            with self.subTest(words=words):
                self.assertEqual(lane_brief.command_file_operands(words), expected)

    def test_fix4_g3_nested_probe_status(self) -> None:
        """Use probe failure kind for nested roots without changing worktree error text."""
        worktree, _commit = self.commit_fixture()
        broken = worktree / "sub"
        broken.mkdir()
        (broken / ".git").write_text("gitdir: /nonexistent/x\n", encoding="utf-8")
        plain = worktree / "plain"
        plain.mkdir()
        probe_plain = lane_brief.probe_repository_root(plain)
        missing = worktree / "missing"
        probe_missing = lane_brief.probe_repository_root(missing)
        probe_worktree = lane_brief.probe_repository_root(worktree)
        _root, _err, kind = probe_plain
        self.assertEqual(kind, "not_root")
        _root2, _err2, kind2 = probe_missing
        self.assertEqual(kind2, "git")
        _wroot, werr, wkind = probe_worktree
        self.assertEqual(wkind, "ok")
        self.assertEqual(werr, "")
        self.assertFalse(lane_brief.valid_nested_root(plain, worktree.resolve()))
        self.assertFalse(lane_brief.valid_nested_root(missing, worktree.resolve()))
        missing_id = "1" * 40
        rc, error = self.check_snippet(
            f"`git -C sub log -1`\nHEAD {missing_id}\n", worktree=worktree
        )
        self.assertEqual(rc, 2, error)

    def conflict_rc(self, content: str, worktree: Path) -> int:
        """Run check_conflicts on content and return its status with stderr muted."""
        with contextlib.redirect_stderr(io.StringIO()):
            return lane_brief.check_conflicts(content, "brief", worktree)

    def test_round11_cases_table(self) -> None:
        """Check every round-11 brief case against its wanted conflict status."""
        worktree, _commit = self.commit_fixture()
        for case_id, finding, want, content in ROUND11_CASES:
            with self.subTest(case=case_id, finding=finding):
                self.assertEqual(self.conflict_rc(content, worktree), want)

    def test_fix11_g1_scanner_flags(self) -> None:
        """Pin quoted, operator, and joined flags of scanner tokens."""
        rows = (
            ("a 2>f", [("a", 0, 0, 0), ("2", 0, 0, 0), (">", 0, 1, 1), ("f", 0, 0, 1)]),
            ("a 2 >f", [("a", 0, 0, 0), ("2", 0, 0, 0), (">", 0, 1, 0), ("f", 0, 0, 1)]),
            ("a '2'>f", [("a", 0, 0, 0), ("2", 1, 0, 0), (">", 0, 1, 1), ("f", 0, 0, 1)]),
            ("x '|' y", [("x", 0, 0, 0), ("|", 1, 0, 0), ("y", 0, 0, 0)]),
            ("a;b", [("a", 0, 0, 0), (";", 0, 1, 1), ("b", 0, 0, 1)]),
            (
                'echo "$(make x)"',
                [("echo", 0, 0, 0), ("$(", 0, 1, 0), ("make", 0, 0, 1)]
                + [("x", 0, 0, 0), (")", 0, 1, 1)],
            ),
        )
        for span, want in rows:
            with self.subTest(span=span):
                tokens = lane_brief.span_shell_tokens(span)
                self.assertIsNotNone(tokens)
                got = [(str(t), int(t.quoted), int(t.operator), int(t.joined)) for t in tokens]
                self.assertEqual(got, want)

    def test_fix11_g1_scanner_failures(self) -> None:
        """Report None for unclosed quotes or substitutions and past the depth limit."""
        for span in ("echo 'x", 'echo "x', "echo $(x", "echo \\", 'echo "$(x"'):
            with self.subTest(span=span):
                self.assertIsNone(lane_brief.span_shell_tokens(span))
        limit = lane_brief.MAX_SHELL_DEPTH
        inside = "$(a " * (limit - 1) + ")" * (limit - 1)
        too_deep = "$(a " * limit + ")" * limit
        self.assertIsNotNone(lane_brief.span_shell_tokens(inside))
        self.assertIsNone(lane_brief.span_shell_tokens(too_deep))

    def test_fix11_f1_make_command_position(self) -> None:
        """Refuse make only in a command position; quoted make text and unparseable spans."""
        worktree, _commit = self.commit_fixture()
        rows = (
            ("quoted argument text", "printf '%s\\n' 'example; make fate-x'", 0),
            ("quoted pipe and make", "echo 'a | make b'", 0),
            ("quoted make word", "'make' fate-x", 0),
            ("verify-all exception", "make verify-all", 0),
            ("make after and", "cd tests && make fate-x", 1),
            ("make after or", "true || make fate-x", 1),
            ("make after semicolon", "echo a; make fate-x", 1),
            ("make after pipe", "echo a | make fate-x", 1),
            ("make in substitution in double quotes", 'echo "$(make fate-x)"', 1),
            ("make in text then substitution", 'echo "a $(make fate-x) b"', 1),
            ("make in subshell", "(make fate-x)", 1),
            ("make after dash dash", "cmd -- make fate-x", 1),
            ("wrapped make", "FOO=1 nice -n10 timeout 5 make fate-x", 1),
            ("unparseable keeps pipe refusal", "echo 'a | make b", 1),
            ("unparseable keeps leading refusal", "make 'x", 1),
        )
        for tag, span, want in rows:
            with self.subTest(tag=tag):
                content = f"Never run make.\n- `{span}`\n"
                self.assertEqual(self.conflict_rc(content, worktree), want)

    def test_fix11_f2_clause_with_backticked_semicolon(self) -> None:
        """Keep a Never run clause whole across a semicolon inside backticks."""
        worktree, _commit = self.commit_fixture()
        rows = (
            ("make after backticked semicolon", "Never run `echo a; echo b` or make.\n", 1),
            (
                "praetorctl after backticked semicolon",
                "Never run `echo a; echo b` or praetorctl.\n",
                1,
            ),
            (
                "semicolon outside backticks ends the clause",
                "Never run `echo a`; make is fine.\n",
                0,
            ),
        )
        for tag, head, want in rows:
            with self.subTest(tag=tag):
                content = f"{head}- `make fate-x`\n"
                self.assertEqual(self.conflict_rc(content, worktree), want)

    def boundary_scans(self, repeats: int) -> int:
        """Count join boundary scans while checking repeated join negations."""
        content = "limit: at most 80 columns.\n" + "Do not join the call onto one line. " * repeats
        counter = CountingPattern(lane_brief.JOIN_BOUNDARY)
        with patch.object(lane_brief, "JOIN_BOUNDARY", counter):
            self.assertEqual(lane_brief.conflict_join_under_column_limit(content), "")
        return counter.calls

    def test_fix11_f3_boundaries_scanned_once(self) -> None:
        """Scan join boundaries a constant number of times however many joins repeat."""
        small = self.boundary_scans(50)
        large = self.boundary_scans(200)
        self.assertEqual(small, large)
        self.assertLessEqual(large, 2)

    def test_fix11_f3_segments_match_split(self) -> None:
        """Match today's split segment on every join match of the join briefs."""
        seen = 0
        for content in JOIN_DIFFERENTIAL_BRIEFS:
            boundaries = lane_brief.scan_join_boundaries(content)
            for match in lane_brief.ONE_LINE_JOIN.finditer(content):
                seen += 1
                want = lane_brief.JOIN_BOUNDARY.split(content[: match.start()])[-1]
                got = lane_brief.earlier_join_segment(content, boundaries, match.start())
                self.assertEqual(got, want, content[:60])
        self.assertGreater(seen, 100)

    def test_fix11_f3_straddling_boundary_matches_split(self) -> None:
        """Match today's split when a boundary match runs past the join match start."""
        pattern = re.compile(r"x\s*join|x ")
        content = "x join into one line"
        with patch.object(lane_brief, "JOIN_BOUNDARY", pattern):
            boundaries = lane_brief.scan_join_boundaries(content)
            match = lane_brief.ONE_LINE_JOIN.search(content)
            self.assertIsNotNone(match)
            self.assertLess(boundaries.starts[0], match.start())
            self.assertLess(match.start(), boundaries.ends[0])
            want = pattern.split(content[: match.start()])[-1]
            got = lane_brief.earlier_join_segment(content, boundaries, match.start())
        self.assertEqual(got, want)
        self.assertEqual(got, "")

    def length_rows(self, prefix: str) -> None:
        """Check the length rows whose tag starts with prefix through the span check."""
        rows = [row for row in FIX11_LENGTH_ROWS if row[0].startswith(prefix)]
        self.assertGreater(len(rows), 3)
        for tag, span, want in rows:
            with self.subTest(tag=tag):
                self.assertEqual(lane_brief.span_whole_file_length_refused(span), want)

    def test_fix11_f4_quoted_operators_are_words(self) -> None:
        """Split stages and commands only on operator tokens, not quoted punctuation."""
        self.length_rows("f4 ")

    def test_fix11_f5_fixed_string_allow_list(self) -> None:
        """Skip the counted-dot pattern only for fixed-string searches without other matchers."""
        self.length_rows("f5 ")

    def test_fix11_f6_descriptor_must_be_joined_and_unquoted(self) -> None:
        """Treat a digit as a descriptor only when unquoted and joined to the redirect."""
        self.length_rows("f6 ")

    def test_fix11_f7_git_diff_exemption_closed_list(self) -> None:
        """Allow the git diff exemption only for the git command word and listed options."""
        self.length_rows("f7 ")

    def test_fix11_f8_chained_git_c_resolves_in_order(self) -> None:
        """Resolve successive git -C values in order before the nested repository checks."""
        worktree, _outer, nested_commit = self.nested_commit_fixture()
        absolute = worktree.resolve() / "sub" / "nested"
        rows = (
            ("chained", "git -C sub -C nested rev-parse HEAD", 0),
            ("joined path", "git -C sub/nested rev-parse HEAD", 0),
            ("absolute later", f"git -C other -C {absolute} rev-parse HEAD", 0),
            ("empty later", "git -C sub/nested -C '' rev-parse HEAD", 0),
            ("empty first", "git -C '' -C sub/nested rev-parse HEAD", 0),
            ("chain leaves worktree", "git -C sub -C ../../.. rev-parse HEAD", 1),
            ("first value only", "git -C sub rev-parse HEAD", 1),
        )
        for tag, command, want in rows:
            with self.subTest(tag=tag):
                snippet = f"- `{command}`\nHEAD {nested_commit}\n"
                rc, error = self.check_snippet(snippet, worktree=worktree)
                self.assertEqual(rc, want, error)

    def test_fix5_probe_cases_table(self) -> None:
        """Exercise all round-5 probe spans through span_whole_file_length_refused."""
        for tag, span, want in FIX5_PROBE_CASES:
            with self.subTest(tag=tag, span=span):
                self.assertEqual(lane_brief.span_whole_file_length_refused(span), want)

    def test_fix5_g1_parse_table(self) -> None:
        """Check G1 per-tool option clusters, -- terminators, and fail-closed flags."""
        for span, want in FIX5_G1_PARSE_CASES:
            with self.subTest(span=span):
                self.assertEqual(lane_brief.span_whole_file_length_refused(span), want)

    def test_fix5_g3_chain_table(self) -> None:
        """Check G3 stdin-only pipeline filter chains and refused intermediate stages."""
        for span, want in FIX5_G3_CHAIN_CASES:
            with self.subTest(span=span):
                self.assertEqual(lane_brief.span_whole_file_length_refused(span), want)

    def test_fix6_probe_cases_table(self) -> None:
        """Exercise all non-split round-6 probe spans through span_whole_file_length_refused."""
        for tag, span, want in FIX6_PROBE_CASES:
            with self.subTest(tag=tag, span=span):
                self.assertEqual(lane_brief.span_whole_file_length_refused(span), want)

    def test_fix6_awk_scanner_table(self) -> None:
        """Exercise allow-list awk program scanner cases across refused and safe constructs."""
        for program, want in FIX6_AWK_SCANNER_CASES:
            with self.subTest(program=program):
                self.assertEqual(not lane_brief.awk_program_reads_files(program), want)

    def test_cli_thread_cases_table(self) -> None:
        """Check whole-file length refusal and exemption cases through the check command."""
        for row, (span, refused) in enumerate(CLI_THREAD_CASES, start=1):
            with self.subTest(row=row, span=span):
                rc, error = self.check_snippet(f"- `{span}`\n")
                if refused:
                    self.assertEqual(rc, 1, error)
                    self.assertIn(span, error)
                else:
                    self.assertEqual(rc, 0, error)
                    self.assertNotIn("conflict:", error)

    def test_make_ban_cases_table(self) -> None:
        """Check make-ban and praetorctl-ban conflict cases through the check command."""
        for row, (snippet, refused) in enumerate(MAKE_BAN_CASES, start=1):
            with self.subTest(row=row, snippet=snippet):
                rc, error = self.check_snippet(snippet)
                if refused:
                    self.assertEqual(rc, 1, error)
                    self.assertIn("conflict:", error)
                else:
                    self.assertEqual(rc, 0, error)
                    self.assertNotIn("conflict:", error)

    def test_make_and_praetorctl_ban_uses_praetorctl_message(self) -> None:
        """Refuse row 8 banning make and praetorctl with the praetorctl admit message."""
        rc, error = self.check_snippet(MAKE_BAN_CASES[7][0])
        self.assertEqual(rc, 1, error)
        self.assertIn("allow praetorctl admit", error)

    def test_conflict_alternate_forms_refused(self) -> None:
        """Refuse alternate column-limit, one-line join, and ERE grep length forms."""
        for snippet in (
            "over 100 columns.\nask it to go to one line.\n",
            "more than 120 columns.\nit must be joined into one line.\n",
            "<= 80 columns.\ncode becomes a single line.\n",
            "- `grep -E '.{101}' a.c`\n",
        ):
            with self.subTest(snippet=snippet):
                rc, error = self.check_snippet(snippet)
                self.assertEqual(rc, 1, error)
                self.assertIn("conflict:", error)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(signal, "SIGALRM"), "FIFO alarm unavailable"
    )
    def test_brief_fifo_rejected(self) -> None:
        """Reject a FIFO brief without waiting for a writer."""
        brief = self.root / "brief.fifo"
        os.mkfifo(brief)
        previous = signal.signal(signal.SIGALRM, self._alarm_handler)
        try:
            signal.alarm(2)
            rc, _, error = self.run_cli("check", str(brief))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(rc, 2)
        self.assertIn("not a regular file", error)

    @staticmethod
    def _alarm_handler(signum: int, frame: object) -> None:
        """Interrupt a blocked FIFO read during the regression test."""
        raise TimeoutError("FIFO read blocked")

    def test_render_and_check(self) -> None:
        """Render all arguments and validate the result against repository standards."""
        brief = self.root / "brief.md"
        brief.write_text(self.rendered(), encoding="utf-8")
        self.assertEqual(self.run_cli("check", str(brief))[0], 0)
        self.assertIn("issue #42, round 2", brief.read_text(encoding="utf-8"))
        self.assertIn(
            "python -m unittest tests.test_example tests.test_other",
            brief.read_text(encoding="utf-8"),
        )
        self.assertNotIn("<modules>", brief.read_text(encoding="utf-8"))

    def test_brief_without_import_style_refused(self) -> None:
        """Accept complete briefs and reject briefs missing the import-style module."""
        content = self.rendered()
        brief = self.root / "brief.md"
        brief.write_text(content, encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 0, error)
        brief.write_text(content.replace("tests.test_import_style", ""), encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 1)
        self.assertIn("missing required line: -m unittest tests.test_import_style", error)
        self.assertIn("python -m unittest tests.test_import_style", content)

    def test_import_style_requirement_is_exact_module_name(self) -> None:
        """Reject the path form and accept the dotted module with a trailing flag."""
        content = self.rendered()
        brief = self.root / "brief.md"
        brief.write_text(
            content.replace("tests.test_import_style", "tests/test_import_style.py"),
            encoding="utf-8",
        )
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 1)
        self.assertIn("missing required line: -m unittest tests.test_import_style", error)
        brief.write_text(
            content.replace("tests.test_import_style", "tests.test_import_style -v"),
            encoding="utf-8",
        )
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 0, error)

    def test_import_style_prose_mention_refused(self) -> None:
        """Reject a brief naming the import-style module only in its task text."""
        content = self.rendered().replace("python -m unittest tests.test_import_style", "")
        content = content.replace("task: work", "task: inspect tests.test_import_style")
        self.assertIn("task: inspect tests.test_import_style", content)
        brief = self.root / "brief.md"
        brief.write_text(content, encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 1)
        self.assertIn("missing required line: -m unittest tests.test_import_style", error)

    def test_import_style_accepts_real_invocations(self) -> None:
        """Accept supported invocations and reject the import-style module after another module."""
        content = self.rendered()
        brief = self.root / "brief.md"
        import_style_first = (
            "/usr/bin/python3 -B -m unittest tests.test_import_style tests.test_sweep_classes -v"
        )
        import_style_last = (
            "/usr/bin/python3 -B -m unittest tests.test_sweep_classes tests.test_import_style -v"
        )
        for invocation, expected in (
            ("python -m unittest tests.test_import_style", 0),
            ("/usr/bin/python3 -B -m unittest tests.test_import_style -v", 0),
            (
                import_style_first,
                0,
            ),
            (
                import_style_last,
                1,
            ),
        ):
            with self.subTest(invocation=invocation):
                brief.write_text(
                    content.replace("python -m unittest tests.test_import_style", invocation),
                    encoding="utf-8",
                )
                rc, _, error = self.run_cli("check", str(brief))
                self.assertEqual(rc, expected, error)
                if expected:
                    self.assertIn(
                        "missing required line: -m unittest tests.test_import_style", error
                    )

    def test_import_style_similar_module_refused(self) -> None:
        """Reject similarly named modules instead of the required unittest module."""
        template = self.rendered()
        invocation = "-m unittest tests.test_import_style"
        required = lane_brief.read_required(CONFIG)
        for suffix in ("s", "_extra", ".py", "2"):
            with self.subTest(module=f"tests.test_import_style{suffix}"):
                content = template.replace(invocation, invocation + suffix)
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    rc = lane_brief.check(content, "brief", required)
                self.assertEqual(rc, 1)
                self.assertIn(f"missing required line: {invocation}", error.getvalue())

    def test_entry_boundary_characters(self) -> None:
        """Accept only allowed entry endings and search beyond rejected occurrences."""
        item = "required entry"
        for follower in (" ", "\n", "\t", "", "`", '"', ")", ",", ":", ";", ". ", "."):
            with self.subTest(accepted=follower):
                self.assertTrue(lane_brief.has_entry(item + follower, item))
        for follower in ("s", "_", "2", "-", "/", ".p"):
            with self.subTest(refused=follower):
                self.assertFalse(lane_brief.has_entry(item + follower, item))
        self.assertTrue(lane_brief.has_entry(f"{item}s then {item} ", item))

    def test_entry_adjacent_occurrences_use_real_suffix(self) -> None:
        """Check adjacent occurrences against their real suffixes in the original text."""
        item = "-m unittest tests.test_import_style"
        self.assertFalse(lane_brief.has_entry(item + item + "s", item))
        self.assertTrue(lane_brief.has_entry(item + item + " ", item))

    def test_entry_overlapping_occurrence_counts(self) -> None:
        """Accept an overlapping occurrence that ends at an allowed token boundary."""
        self.assertTrue(lane_brief.has_entry("aaaa", "aaa"))
        self.assertFalse(lane_brief.has_entry("aaab", "aaa"))

    def test_entry_suffix_check_reads_two_characters(self) -> None:
        """Pass at most two trailing characters to the token-boundary check."""
        content = "a" * 59_999 + "\n"
        with patch.object(lane_brief, "ends_token", wraps=lane_brief.ends_token) as spy:
            self.assertTrue(lane_brief.has_entry(content, "a"))
            spy.assert_called()
            self.assertTrue(lane_brief.has_entry("aaaa", "aaa"))
            self.assertFalse(lane_brief.has_entry("aaab", "aaa"))
        for call in spy.call_args_list:
            self.assertLessEqual(len(call.args[0]), 2)

    def test_plain_substring_mutant_killed(self) -> None:
        """Expose the similar-module false acceptance when plain matching is restored."""
        source = (ROOT / "scripts" / "lane_brief.py").read_text(encoding="utf-8")
        original = "not has_entry(content, item)"
        self.assertEqual(source.count(original), 1)
        mutant_path = self.root / "lane_brief_mutant.py"
        mutant_path.write_text(source.replace(original, "item not in content"), encoding="utf-8")
        spec = importlib.util.spec_from_file_location("lane_brief_mutant", mutant_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        mutant = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mutant
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(mutant)
        content = self.rendered().replace("tests.test_import_style", "tests.test_import_styles")
        required = lane_brief.read_required(CONFIG)
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(mutant.check(content, "mutant", required), 0)
            self.assertEqual(lane_brief.check(content, "real", required), 1)
        self.assertEqual(
            error.getvalue(), "real: missing required line: -m unittest tests.test_import_style\n"
        )

    def test_each_missing_required_line_fails(self) -> None:
        """Reject each independently removed required substring."""
        content = self.rendered()
        brief = self.root / "brief.md"
        for required in lane_brief.read_required(CONFIG):
            with self.subTest(required=required):
                brief.write_text(content.replace(required, ""), encoding="utf-8")
                rc, _, error = self.run_cli("check", str(brief))
                self.assertEqual(rc, 1)
                self.assertIn(f"missing required line: {required}", error)

    def test_template_has_unfilled_placeholders(self) -> None:
        """Reject the unrendered template and identify its placeholders."""
        rc, _, error = self.run_cli("check", str(TEMPLATE))
        self.assertEqual(rc, 1)
        for placeholder in lane_brief.NAMES:
            self.assertIn(f"unfilled placeholder <{placeholder}>", error)

    def test_missing_inputs_fail(self) -> None:
        """Return usage errors for absent files and absent or empty required lists."""
        brief = self.root / "brief.md"
        brief.write_text(self.rendered(), encoding="utf-8")
        standards = self.root / "config.yaml"
        cases = [
            ("check", str(self.root / "missing")),
            ("check", str(brief), "--config", str(self.root / "missing")),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args)[0], 2)
        for content in ("other: value\n", "required:\n"):
            with self.subTest(content=content):
                standards.write_text(content, encoding="utf-8")
                rc, _, error = self.run_cli("check", str(brief), "--config", str(standards))
                self.assertEqual(rc, 2)
                self.assertIn("required list", error)

    def test_render_requires_arguments(self) -> None:
        """Reject a render command missing required arguments."""
        self.assertEqual(self.run_cli("render", "--branch", "feature")[0], 2)
        args = ARGS.copy()
        index = args.index("--modules")
        del args[index : index + 2]
        self.assertEqual(self.run_cli(*args)[0], 2)

    def test_directory_brief_rejected(self) -> None:
        """Reject a directory as a brief."""
        rc, _, error = self.run_cli("check", str(self.root))
        self.assertEqual(rc, 2)
        self.assertIn("not a regular file", error)

    def test_brief_size_boundary(self) -> None:
        """Accept one MiB and reject a brief one byte larger."""
        brief = self.root / "brief.md"
        padding = b"x" * 59999 + b"\n"
        content = self.rendered().encode()
        remaining = 1024 * 1024 - len(content)
        content += padding * (remaining // len(padding)) + b"x" * (remaining % len(padding))
        brief.write_bytes(content)
        self.assertEqual(self.run_cli("check", str(brief))[0], 0)
        brief.write_bytes(content + b"x")
        rc, _, error = self.run_cli("check", str(brief))
        self.assertEqual(rc, 2)
        self.assertIn("size", error)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_config_fifo_rejected(self) -> None:
        """Reject a FIFO config without waiting for a writer."""
        config = self.root / "config.fifo"
        brief = self.root / "brief.md"
        os.mkfifo(config)
        brief.write_text(self.rendered(), encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
        self.assertEqual(rc, 2)
        self.assertIn("not a regular file", error)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(signal, "SIGALRM"), "FIFO alarm unavailable"
    )
    def test_config_swapped_to_fifo_rejected(self) -> None:
        """Reject a FIFO substituted after a path-based regular-file check."""
        config = self.root / "config.yaml"
        config.write_text("required:\n  - present\n", encoding="utf-8")
        brief = self.root / "brief.md"
        brief.write_text("present\n", encoding="utf-8")
        original_open = os.open

        def swap(path: object, *args: object, **kwargs: object) -> int:
            """Replace the config with a FIFO immediately before opening it."""
            if path == config:
                config.unlink()
                os.mkfifo(config)
            return original_open(path, *args, **kwargs)

        previous = signal.signal(signal.SIGALRM, self._alarm_handler)
        try:
            with patch.object(lane_brief.os, "open", side_effect=swap):
                signal.alarm(2)
                rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(rc, 2)
        self.assertIn("not a regular file", error)

    def test_invalid_yaml_required_items(self) -> None:
        """Reject comments, unindented list items, and non-string values."""
        config = self.root / "config.yaml"
        brief = self.root / "brief.md"
        brief.write_text("first\n# TODO\n3\n", encoding="utf-8")
        for document in (
            "required:\n  - # TODO\n",
            "required:\n  - first\n- second\n",
            "required:\n  - 3\n",
        ):
            with self.subTest(document=document):
                config.write_text(document, encoding="utf-8")
                self.assertEqual(self.run_cli("check", str(brief), "--config", str(config))[0], 2)

    def test_yaml_mapping_validation(self) -> None:
        """Reject duplicate keys and invalid document or required-list shapes."""
        config = self.root / "config.yaml"
        brief = self.root / "brief.md"
        brief.write_text("first\n", encoding="utf-8")
        for document, reason in (
            ("required: [first]\nother: 1\nother: 2\n", "duplicate key other"),
            ("required: [first]\nrequired: [second]\n", "duplicate required key"),
            ("- first\n", "required list"),
            ("required: first\n", "required list"),
            ('required: ["line\\nbreak"]\n', "invalid required item"),
            ("required: [{}]\n", "invalid required item"),
        ):
            with self.subTest(document=document):
                config.write_text(document, encoding="utf-8")
                rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
                self.assertEqual(rc, 2, error)
                self.assertIn(reason, error)
                self.assertIn(str(config), error)

    def test_repository_required_values(self) -> None:
        """Preserve every requirement in the repository declaration."""
        self.assertEqual(
            lane_brief.read_required(CONFIG),
            [
                "docstrings: every public function you add OR touch",
                "one-line docstring on every new test function",
                "ruff check scripts tests",
                "ruff format --check scripts tests",
                "docstring_diff.py --cached",
                "no commit, no push",
                "-m unittest tests.test_import_style",
            ],
        )

    def test_config_item_boundaries(self) -> None:
        """Accept maximum list and item lengths and reject values above them."""
        config = self.root / "config.yaml"
        brief = self.root / "brief.md"
        brief.write_text("a " + "a" * 200, encoding="utf-8")
        for count, length, expected, reason in (
            (32, 1, 0, ""),
            (33, 1, 2, "32 items"),
            (1, 200, 0, ""),
            (1, 201, 2, "200 characters"),
        ):
            with self.subTest(count=count, length=length):
                config.write_text(
                    "required:\n" + ("  - " + "a" * length + "\n") * count, encoding="utf-8"
                )
                rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
                self.assertEqual(rc, expected, error)
                self.assertIn(reason, error)

    def test_declaration_matches_template(self) -> None:
        """Keep the real declaration nonempty and present in the tracked template."""
        required = lane_brief.read_required(CONFIG)
        self.assertTrue(required)
        content = TEMPLATE.read_text(encoding="utf-8")
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, content)

    def test_reader_accepts_bare_and_quoted_items_and_stops(self) -> None:
        """Read both item forms without consuming a neighboring section."""
        standards = self.root / "config.yaml"
        standards.write_text(
            '---\n# comment\nrequired:\n  - "quoted"\n  - bare value\n'
            "other:\n  - ignored\nnext:\n  - ignored\n",
            encoding="utf-8",
        )
        self.assertEqual(lane_brief.read_required(standards), ["quoted", "bare value"])

    def test_render_refuses_invalid_result_and_does_not_write(self) -> None:
        """Do not emit a rendered brief if an argument leaves a placeholder."""
        destination = self.root / "out.md"
        args = [*ARGS, "--finding", "<task>", "-o", str(destination)]
        rc, output, error = self.run_cli(*args)
        self.assertEqual(rc, 1)
        self.assertEqual(output, "")
        self.assertFalse(destination.exists())
        self.assertIn("unfilled placeholder <task>", error)

    def test_line_count_boundaries_for_brief_and_config(self) -> None:
        """Accept 10000 lines and reject 10001 lines in both inputs."""
        brief = self.root / "brief.md"
        config = self.root / "config.yaml"
        for target in (brief, config):
            with self.subTest(target=target.name):
                for count in (10000, 10001):
                    brief.write_text("present\n", encoding="utf-8")
                    config.write_text("required:\n  - present\n", encoding="utf-8")
                    prefix = "present\n" if target == brief else "required:\n  - present\n"
                    target.write_text(
                        prefix + "\n" * (count - prefix.count("\n")), encoding="utf-8"
                    )
                    rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
                    self.assertEqual(rc, 0 if count == 10000 else 2, error)
                    if count == 10001:
                        self.assertIn("exceeds 10000 lines", error)

    def test_duplicate_required_block_rejected(self) -> None:
        """Reject a second required block even after another section."""
        brief = self.root / "brief.md"
        config = self.root / "config.yaml"
        brief.write_text("first\n", encoding="utf-8")
        config.write_text(
            "required:\n  - first\nother: value\nrequired:\n  - second\n", encoding="utf-8"
        )
        rc, output, error = self.run_cli("check", str(brief), "--config", str(config))
        self.assertEqual(rc, 2)
        self.assertEqual(output, "")
        self.assertIn("duplicate required key", error)

    def test_invalid_required_children_rejected(self) -> None:
        """Reject empty and malformed values in the required section."""
        brief = self.root / "brief.md"
        config = self.root / "config.yaml"
        brief.write_text("Task:\n", encoding="utf-8")
        for child in ("  -", "  -   ", "  -x", "  foo"):
            with self.subTest(child=child):
                config.write_text(f'required:\n  - "Task:"\n{child}\n', encoding="utf-8")
                rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
                self.assertEqual(rc, 2, error)
                self.assertIn(str(config), error)

    def test_nested_scalar_continuation(self) -> None:
        """Require text that YAML folds into a preceding scalar."""
        brief = self.root / "brief.md"
        config = self.root / "config.yaml"
        brief.write_text("Task\n", encoding="utf-8")
        config.write_text("required:\n  - Task\n    - nested\n", encoding="utf-8")
        self.assertEqual(lane_brief.read_required(config), ["Task - nested"])
        self.assertEqual(self.run_cli("check", str(brief), "--config", str(config))[0], 1)

    def test_other_section_child_ignored(self) -> None:
        """Ignore valid content under another top-level section."""
        brief = self.root / "brief.md"
        config = self.root / "config.yaml"
        brief.write_text("Task:\n", encoding="utf-8")
        config.write_text('required:\n  - "Task:"\nother:\n  - nested\n', encoding="utf-8")
        rc, _, error = self.run_cli("check", str(brief), "--config", str(config))
        self.assertEqual(rc, 0, error)

    def test_render_line_limit_refuses_file_and_stdout(self) -> None:
        """Reject combined render values exceeding the output line limit."""
        destination = self.root / "out.md"
        args = [*ARGS, "--finding", "\n" * 4000, "--fix", "\n" * 4000, "--tests", "\n" * 4000]
        for extra in ([], ["-o", str(destination)]):
            with self.subTest(extra=extra):
                rc, output, error = self.run_cli(*args, *extra)
                self.assertEqual(rc, 2)
                self.assertEqual(output, "")
                self.assertFalse(destination.exists())
                self.assertIn("exceeds 10000 lines", error)

    def test_render_argument_character_boundaries(self) -> None:
        """Accept 8192 characters and reject 8193 for every render value."""
        for name in (
            "branch",
            "task",
            "finding",
            "fix",
            "tests",
            "paths",
            "modules",
            "issue",
            "round",
        ):
            for count in (8192, 8193):
                with self.subTest(name=name, count=count):
                    rc, output, error = self.run_cli(*ARGS, f"--{name}", "x" * count)
                    self.assertEqual(rc, 0 if count == 8192 else 2, error)
                    if count == 8193:
                        self.assertEqual(output, "")
                        self.assertIn(f"--{name}", error)

    def test_render_byte_limits_refuse_output(self) -> None:
        """Reject oversized rendered lines and content before writing output."""
        template = self.root / "template.md"
        destination = self.root / "out.md"
        for content, reason in (
            ("<finding>" * 3, "line exceeds"),
            ("<finding>\n" * 33, "size exceeds"),
        ):
            with self.subTest(reason=reason):
                template.write_text(content, encoding="utf-8")
                with patch.object(lane_brief, "TEMPLATE", template):
                    rc, output, error = self.run_cli(
                        *ARGS, "--finding", "😀" * 8192, "-o", str(destination)
                    )
                self.assertEqual(rc, 2)
                self.assertEqual(output, "")
                self.assertFalse(destination.exists())
                self.assertIn(reason, error)

    def test_run_runner_pid_guards(self) -> None:
        """Prove run_runner guards against invalid and current-group PIDs in cleanup."""

        def run_with(pid: int | bool) -> tuple[Mock, Mock]:
            killpg = Mock()
            process = SimpleNamespace(
                pid=pid,
                kill=Mock(),
                wait=Mock(return_value=0),
                poll=Mock(return_value=None),
                stdout=SimpleNamespace(close=Mock()),
            )
            with (
                patch.object(lane_brief.subprocess, "Popen", return_value=process),
                patch.object(lane_brief, "read_runner_output", side_effect=RuntimeError("planted")),
                patch.object(lane_brief.os, "killpg", killpg),
                self.assertRaisesRegex(RuntimeError, "planted"),
            ):
                lane_brief.run_runner(["dummy"])
            return killpg, process.kill

        for bad_pid in (0, 1, True):
            with self.subTest(bad_pid=bad_pid):
                killpg, kill = run_with(bad_pid)
                killpg.assert_not_called()
                kill.assert_not_called()

        with self.subTest(bad_pid=os.getpgrp()):
            killpg, kill = run_with(os.getpgrp())
            killpg.assert_not_called()
            kill.assert_called_once_with()

        good_pid = 4242 if os.getpgrp() != 4242 else 4243
        killpg, kill = run_with(good_pid)
        killpg.assert_called_once_with(good_pid, signal.SIGKILL)
        kill.assert_not_called()

        killpg, kill = run_with(2)
        killpg.assert_called_once_with(2, signal.SIGKILL)
        kill.assert_not_called()


def _write_import_chain(tests_dir: Path) -> list[str]:
    """Write import-chain fixture test files and return their sorted dotted module names."""
    target = "secret" + "-tool"
    (tests_dir / "test_planted.py").write_text(f"dummy = '{target}'\n", encoding="utf-8")
    (tests_dir / "test_alias.py").write_text(
        "from tests import test_planted as p\n", encoding="utf-8"
    )
    (tests_dir / "test_dotted.py").write_text("import tests.test_planted\n", encoding="utf-8")
    (tests_dir / "test_from.py").write_text(
        "from tests.test_planted import Base\n", encoding="utf-8"
    )
    (tests_dir / "test_chain.py").write_text("from tests import test_alias\n", encoding="utf-8")
    return [
        "tests.test_alias",
        "tests.test_chain",
        "tests.test_dotted",
        "tests.test_from",
        "tests.test_planted",
    ]


class CredentialStubGapsTest(unittest.TestCase):
    """Exercise gap detection for declared credential stub tests."""

    def test_repository_credential_stub_tests(self) -> None:
        """Verify repository credential_stub_tests has no undeclared or stale entries."""
        with CONFIG.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        self.assertIsInstance(data, dict)
        self.assertIn("credential_stub_tests", data)
        stub_tests = data["credential_stub_tests"]
        self.assertIsInstance(stub_tests, list)
        self.assertEqual(credential_stub_gaps(ROOT / "tests", stub_tests), ([], []))

    def test_credential_stub_gaps_planted_secret_tool(self) -> None:
        """Report undeclared test files referencing the target stub tool."""
        target = "secret" + "-tool"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            (tests_dir / "test_planted.py").write_text(f"dummy = '{target}'\n", encoding="utf-8")
            self.assertEqual(
                credential_stub_gaps(tests_dir, []),
                (["tests.test_planted"], []),
            )

    def test_credential_stub_gaps_stale_declaration(self) -> None:
        """Report declared entries that do not exist as test files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            self.assertEqual(
                credential_stub_gaps(tests_dir, ["tests.test_gone"]),
                ([], ["tests.test_gone"]),
            )

    def test_credential_stub_gaps_boundary_cases(self) -> None:
        """Ignore non-matching variants and non-test helper files."""
        target = "secret" + "-tool"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            (tests_dir / "test_underscore.py").write_text("val = 'secret_tool'\n", encoding="utf-8")
            (tests_dir / "test_space.py").write_text('val = "secret tool"\n', encoding="utf-8")
            (tests_dir / "helper.py").write_text(f"val = '{target}'\n", encoding="utf-8")
            self.assertEqual(credential_stub_gaps(tests_dir, []), ([], []))

    def test_credential_stub_gaps_import_reach_chain(self) -> None:
        """Report all test modules reaching the secret tool via aliases and chained imports."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            expected = _write_import_chain(tests_dir)
            self.assertEqual(credential_stub_gaps(tests_dir, []), (expected, []))

    def test_credential_stub_gaps_clean_and_declared_boundary(self) -> None:
        """Exclude clean tests and return empty gaps when all reaching tests are declared."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            declared = _write_import_chain(tests_dir)
            (tests_dir / "test_clean.py").write_text(
                "import unittest\nfrom tests import helpers\n", encoding="utf-8"
            )
            self.assertEqual(credential_stub_gaps(tests_dir, declared), ([], []))

    def test_credential_stub_gaps_syntax_error_fail_closed(self) -> None:
        """Report invalid Python files as reaching the stub to fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            (tests_dir / "test_broken.py").write_text("def (:\n", encoding="utf-8")
            self.assertEqual(
                credential_stub_gaps(tests_dir, []),
                (["tests.test_broken"], []),
            )

    def test_credential_stub_gaps_unreadable_fail_closed(self) -> None:
        """Report unreadable test files as reaching the stub to fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tests_dir = Path(tmp_dir)
            (tests_dir / "test_locked.py").write_text("x = 1\n", encoding="utf-8")
            real_open = Path.open

            def fake_open(path_obj: Path, *args: object, **kwargs: object) -> object:
                """Raise PermissionError for test_locked.py or delegate to real open."""
                if path_obj.name == "test_locked.py":
                    raise PermissionError("Access denied")
                return real_open(path_obj, *args, **kwargs)

            with patch("pathlib.Path.open", side_effect=fake_open, autospec=True):
                self.assertEqual(
                    credential_stub_gaps(tests_dir, []),
                    (["tests.test_locked"], []),
                )


class LaneBriefIsolationTest(unittest.TestCase):
    """Verify isolation blocks runner execution before its precheck starts."""

    def setUp(self) -> None:
        """Render a brief and create a runner that records every argument."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.brief = self.root / "brief.md"
        self.assertEqual(lane_brief.main(ARGS[:] + ["-o", str(self.brief)]), 0)
        self.calls = self.root / "args"
        self.runner = self.root / "runner.sh"
        self.runner.write_text(
            '#!/bin/sh\ndir=$(dirname "$0")\nprintf "%s\\n" "$@" >> "$dir/args"\n',
            encoding="utf-8",
        )
        self.runner.chmod(0o755)

    def check_worktree(self, worktree: Path) -> tuple[int, str]:
        """Check a worktree with the real isolation check and a recording runner."""
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = lane_brief.main(
                [
                    "check",
                    str(self.brief),
                    "--runner",
                    str(self.runner),
                    "--worktree",
                    str(worktree),
                    "--config",
                    str(CONFIG),
                ]
            )
        return rc, stderr.getvalue()

    def test_planted_main_never_starts_runner(self) -> None:
        """Reject the planted unmarked main checkout before starting its runner."""
        ref = f"refs/heads/local/{lane_isolation.PRIVATE_WORDS[0]}-topic"
        main = repo(self.root / "main", ref)
        rc, error = self.check_worktree(main)
        self.assertEqual(rc, 1)
        self.assertIn("lane isolation refused worktree", error)
        self.assertIn(ref, error)
        self.assertFalse(self.calls.exists())

    @unittest.skipUnless(os.name == "posix", "runner fixture is a POSIX shell script")
    def test_marked_clone_starts_runner(self) -> None:
        """Forward the exact brief and worktree arguments after isolation passes."""
        origin = repo(self.root / "origin")
        lane = self.root / "lane"
        run_git(self.root, "clone", "-q", str(origin), str(lane), preserve_config=True)
        self.assertEqual(lane_isolation.mark(lane), [])
        rc, error = self.check_worktree(lane)
        self.assertEqual((rc, error), (0, ""))
        self.assertEqual(
            self.calls.read_text(encoding="utf-8").splitlines(),
            ["--check-brief", str(self.brief), str(lane)],
        )

    def test_not_git_never_starts_runner(self) -> None:
        """Report a Git input error without starting the configured runner."""
        rc, error = self.check_worktree(self.root / "missing")
        self.assertEqual(rc, 2)
        self.assertIn("lane isolation failed", error)
        self.assertFalse(self.calls.exists())

    def test_git_unavailable_never_starts_runner(self) -> None:
        """Report unavailable Git as an isolation error without starting the runner."""
        with patch.object(lane_isolation.subprocess, "Popen", side_effect=FileNotFoundError("git")):
            rc, error = self.check_worktree(self.root / "missing")
        self.assertEqual(rc, 2)
        self.assertIn("lane isolation failed", error)
        self.assertFalse(self.calls.exists())


@unittest.skipUnless(os.name == "posix", "runner fixture uses /bin/sh")
class RunnerEnvironmentTest(unittest.TestCase):
    """Check that runners inherit no caller Git repository-location overrides."""

    def test_runner_drops_git_location(self) -> None:
        """Remove caller Git directory and worktree overrides before starting a runner."""
        with patch.dict(
            os.environ,
            {"GIT_DIR": "/nonexistent/private.git", "GIT_WORK_TREE": "/nonexistent/private"},
        ):
            result = lane_brief.run_runner(
                ["/bin/sh", "-c", 'printf "%s %s" "${GIT_DIR-unset}" "${GIT_WORK_TREE-unset}"']
            )
        self.assertEqual(result, (b"unset unset", 0))


if __name__ == "__main__":
    unittest.main()
