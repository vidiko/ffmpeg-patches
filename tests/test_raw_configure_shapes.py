# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Exercise complex command shapes, boundaries, and subshell forms."""

from __future__ import annotations

import ast
import graphlib
import io
import json
import os
import unittest.mock
from pathlib import Path

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
                    plain_rc = self.run_guard(
                        client, self.payload(client, plain, self.tree)
                    ).returncode
                    if plain_rc != 2:
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
        body = f'bash 0<<< "{_PARITY_CFG}"\n'
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
            body_mod, "_descriptor_plain_twin_refusal", return_value=None
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
