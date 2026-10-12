"""Tests for normalize/bash.py: the conservative Bash parser (docs/m1-design.md, module B).

Layers: a table-driven YAML corpus (tests/corpus/bash_parse.yaml), targeted unit tests, hypothesis
property tests, performance bounds, and - only where a working ``bash`` exists - differential
checks against the real thing (harmless ``printf`` / ``bash -n`` probes in a tmp dir). Everything
else is pure text, so the suite is platform independent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import bash as bashmod
from boundkeep.normalize.bash import parse_bash
from boundkeep.normalize.model import BashResult, SimpleCmd, Word

CORPUS_PATH = Path(__file__).resolve().parents[1] / "corpus" / "bash_parse.yaml"


def _load_corpus() -> list[dict[str, Any]]:
    with CORPUS_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, list)
    return data


CORPUS = _load_corpus()
KNOWN_ORIGINS = {
    "top", "subshell", "substitution", "procsub", "bash-c", "eval", "trap", "heredoc", "find-exec",
}  # fmt: skip


def entry_command(entry: dict[str, Any]) -> str:
    if "gen" in entry:
        g = entry["gen"]
        return str(g["prefix"]) + str(g["unit"]) * int(g["times"]) + str(g["suffix"])
    return str(entry["cmd"])


def run_entry(entry: dict[str, Any]) -> BashResult:
    kwargs: dict[str, Any] = {}
    if "max_depth" in entry:
        kwargs["max_depth"] = entry["max_depth"]
    return parse_bash(entry_command(entry), **kwargs)


# ---------------------------------------------------------------------------- corpus matching


def word_mismatch(word: Word, spec: Any) -> str | None:
    if isinstance(spec, str):
        spec = {"t": spec}
    if word.text != spec["t"]:
        return f"text {word.text!r} != {spec['t']!r}"
    for key in ("expands", "glob", "quoted"):
        if key in spec and getattr(word, key) != spec[key]:
            return f"word {word.text!r}: {key}={getattr(word, key)} != {spec[key]}"
    return None


def cmd_mismatch(cmd: SimpleCmd, spec: dict[str, Any]) -> str | None:
    if "argv" in spec:
        want = spec["argv"]
        if len(cmd.argv) != len(want):
            return f"argv {[w.text for w in cmd.argv]} != {want}"
        for w, s in zip(cmd.argv, want, strict=True):
            bad = word_mismatch(w, s)
            if bad:
                return bad
    if "origin" in spec and cmd.origin != spec["origin"]:
        return f"origin {cmd.origin!r} != {spec['origin']!r}"
    if "wrappers" in spec and list(cmd.wrappers) != spec["wrappers"]:
        return f"wrappers {list(cmd.wrappers)} != {spec['wrappers']}"
    if "env" in spec and {k: v.text for k, v in cmd.env} != spec["env"]:
        return f"env {[(k, v.text) for k, v in cmd.env]} != {spec['env']}"
    if "redirects" in spec:
        got = [[r.op, r.fd, r.target.text if r.target else None] for r in cmd.redirects]
        if got != spec["redirects"]:
            return f"redirects {got} != {spec['redirects']}"
    for key in ("in_pipeline", "background", "args_from_stdin"):
        if key in spec and getattr(cmd, key) != spec[key]:
            return f"{key}={getattr(cmd, key)} != {spec[key]}"
    return None


def describe(result: BashResult) -> str:
    rows = [
        f"{[w.text for w in c.argv]} origin={c.origin} wrappers={list(c.wrappers)}"
        for c in result.commands
    ]
    return "\n".join(rows) + f"\ngray={list(result.gray)} exec={list(result.exec_reasons)}"


def check_entry(entry: dict[str, Any], result: BashResult) -> None:
    where = f"{entry['id']}:\n{describe(result)}"
    want = entry.get("commands")
    if want is not None:
        assert len(result.commands) == len(want), where
        for cmd, spec in zip(result.commands, want, strict=True):
            assert cmd_mismatch(cmd, spec) is None, f"{cmd_mismatch(cmd, spec)}\n{where}"
    for spec in entry.get("has", []):
        assert any(cmd_mismatch(c, spec) is None for c in result.commands), (
            f"missing command {spec}\n{where}"
        )
    for key, got in (("gray", result.gray), ("exec", result.exec_reasons)):
        if key in entry:
            assert sorted(got) == sorted(entry[key]), f"{key} mismatch\n{where}"
        elif f"{key}_has" in entry:
            for item in entry[f"{key}_has"]:
                assert item in got, f"{key} lacks {item!r}\n{where}"
        else:
            assert got == (), f"unexpected {key}\n{where}"


def test_corpus_is_big_enough_and_well_formed() -> None:
    ids = [e["id"] for e in CORPUS]
    assert len(ids) == len(set(ids)), "duplicate corpus ids"
    assert len(CORPUS) >= 120
    assert sum(1 for e in CORPUS if e.get("adv")) >= 45
    for e in CORPUS:
        assert ("cmd" in e) != ("gen" in e), e["id"]


@pytest.mark.parametrize("entry", CORPUS, ids=[e["id"] for e in CORPUS])
def test_corpus_entry(entry: dict[str, Any]) -> None:
    check_entry(entry, run_entry(entry))


def test_corpus_entries_are_deterministic() -> None:
    for entry in CORPUS:
        if "gen" in entry:
            continue
        assert run_entry(entry) == run_entry(entry)


def test_corpus_origins_are_documented() -> None:
    for entry in CORPUS:
        for cmd in run_entry(entry).commands:
            assert cmd.origin in KNOWN_ORIGINS


# ---------------------------------------------------------------------------- targeted


def argvs(command: str, **kw: Any) -> list[list[str]]:
    return [[w.text for w in c.argv] for c in parse_bash(command, **kw).commands]


def test_in_pipeline_and_background_flags() -> None:
    both = parse_bash("cd x | rm y").commands
    assert [c.in_pipeline for c in both] == [True, True]
    assert [c.background for c in both] == [False, False]
    bg = parse_bash("sleep 1 &").commands
    assert [(c.in_pipeline, c.background) for c in bg] == [(False, True)]
    chain = parse_bash("a && b").commands
    assert [(c.in_pipeline, c.background) for c in chain] == [(False, False)] * 2
    mixed = parse_bash("a | b && c; d &").commands
    assert [(c.argv[0].text, c.in_pipeline, c.background) for c in mixed] == [
        ("a", True, False),
        ("b", True, False),
        ("c", False, False),
        ("d", False, True),
    ]


def test_single_command_is_not_a_pipeline_even_in_a_group() -> None:
    assert not any(c.in_pipeline for c in parse_bash("{ a; b; }").commands)
    assert not any(c.in_pipeline for c in parse_bash("echo $(a | b) x").commands[-1:])


def test_heredoc_bodies_and_bash_c_inner_commands_have_their_own_context() -> None:
    res = parse_bash("bash -c 'a; b' | cat")
    flags = {c.argv[0].text: c.in_pipeline for c in res.commands}
    assert flags["bash"]
    assert flags["cat"]
    assert flags["a"] is False
    assert flags["b"] is False


def test_every_word_and_command_field_types() -> None:
    res = parse_bash("A=1 sudo -u x rm -rf $HOME/'a b' > out 2>&1")
    (cmd,) = res.commands
    assert isinstance(cmd, SimpleCmd)
    assert [w.text for w in cmd.argv] == ["rm", "-rf", "$HOME/a b"]
    assert cmd.argv[2].expands
    assert cmd.argv[2].quoted
    assert not cmd.argv[2].glob
    assert cmd.env[0][0] == "A"
    assert cmd.wrappers == ("sudo",)
    assert [(r.op, r.fd) for r in cmd.redirects] == [(">", None), (">&", "2")]
    assert cmd.raw.startswith("A=1 sudo")


def test_raw_is_capped() -> None:
    res = parse_bash("echo " + "a" * 5000)
    assert len(res.commands[0].raw) <= 2048


def test_max_length_parses_the_prefix_only() -> None:
    res = parse_bash("rm x; rm y", max_length=8)
    assert "too-long" in res.gray
    assert argvs("rm x; rm y", max_length=8) == [["rm", "x"], ["rm"]]
    zero = parse_bash("rm x", max_length=0)
    assert zero.gray == ("too-long",)
    assert zero.commands == ()


def test_max_words_is_a_parameter_and_partial_command_is_kept() -> None:
    res = parse_bash("rm a b c d e", max_words=3)
    assert "too-many-words" in res.gray
    assert [w.text for w in res.commands[0].argv] == ["rm", "a", "b"]


def test_non_str_input_is_gray() -> None:
    res = parse_bash(b"rm x")  # type: ignore[arg-type]
    assert res == BashResult((), ("internal-error",))


def test_internal_error_keeps_commands_and_is_gray(monkeypatch: pytest.MonkeyPatch) -> None:
    real = bashmod._Parser._emit

    def boom(self: Any, words: Any, *a: Any, **k: Any) -> None:
        if words and words[0].word.text == "boom":
            raise RuntimeError("bug")
        real(self, words, *a, **k)

    monkeypatch.setattr(bashmod._Parser, "_emit", boom)
    res = parse_bash("rm x; boom; rm y")
    assert res.gray == ("internal-error",)
    assert [[w.text for w in c.argv] for c in res.commands] == [["rm", "x"]]


def test_recursion_error_is_gray(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self: Any) -> None:
        raise RecursionError

    monkeypatch.setattr(bashmod._Parser, "run", boom)
    assert parse_bash("a").gray == ("internal-error",)


def test_lone_surrogates_and_odd_characters() -> None:
    for text in (
        "echo \ud800",
        "\udfff",
        "echo '\ud800'; rm \udc00x",
        "ec\u200bho x",
        "\x00",
        "\x7f",
    ):
        res = parse_bash(text)
        assert isinstance(res, BashResult)
        assert "internal-error" not in res.gray
    assert argvs("echo \ud800; rm x") == [["echo", "\ud800"], ["rm", "x"]]


def test_unicode_whitespace_is_not_a_separator() -> None:
    assert argvs("echo a\u00a0b") == [["echo", "a\u00a0b"]]


def test_nul_byte_is_gray_and_commands_are_kept() -> None:
    res = parse_bash("rm x\x00; ls")
    assert "nul-byte" in res.gray
    assert [c.argv[0].text for c in res.commands] == ["rm", "ls"]
    assert res.commands[0].argv[1].text == "x\x00"


def test_lone_amp_gt_and_fd_prefix_edge_cases() -> None:
    assert parse_bash("a >").gray == ("syntax-error",)
    assert argvs("a 1>&2 3<f") == [["a"]]
    (cmd,) = parse_bash("a 1>&2 3<f").commands
    assert next((r.op, r.fd, r.target) for r in cmd.redirects) == (">&", "1", None)
    assert cmd.redirects[1].fd == "3"


def test_decode_ansi_c_table() -> None:
    decode = bashmod._decode_ansi_c
    cases = {
        "a\\tb": "a\tb",
        "\\x41\\x4a": "AJ",
        "\\101": "A",
        "\\u00e9": "\u00e9",
        "\\U0001F600": "\U0001f600",
        "\\x": "\\x",
        "\\u": "\\u",
        "\\q": "\\q",
        "\\cA": "\x01",
        "\\c?": "\x7f",
        "\\c": "\\c",
        "\\e\\E": "\x1b\x1b",
        "end\\": "end\\",
        "\\U00110000": "\\U00110000",
        "\\xe4\\xb8\\xad": "\u4e2d",
        "\\777": "\xff".encode("latin-1").decode("utf-8", "surrogateescape"),
        "\\'\\\"\\?\\\\": "'\"?\\",
    }
    for src, want in cases.items():
        assert decode(src) == (want, False), src
    for src in ("a\\0b", "a\\x00b", "a\\u0000b", "a\\c@b"):
        assert decode(src) == ("a", True), src


def test_brace_expansion_detector() -> None:
    f = bashmod._has_brace_expansion
    assert f("{a,b}")
    assert f("x{1..3}y")
    assert f("{a,{b,c}}")
    assert f("{{a,b}}")
    assert not f("{}")
    assert not f("{a}")
    assert not f("a,b")
    assert not f("{a")
    assert not f("a}")
    assert not f("{a{b}c}")


def test_canon_names() -> None:
    assert bashmod._canon("/usr/bin/sudo") == "sudo"
    assert bashmod._canon("C:\\Git\\bin\\BASH.EXE") == "bash"
    assert bashmod._canon("SUDO") == "SUDO"


def test_interpreter_families() -> None:
    fam = bashmod._family
    assert fam("python3.12") == "python"
    assert fam("py") == "python"
    assert fam("pythonista") is None
    assert fam("nodejs") == "node"
    assert fam("deno") == "deno"
    assert fam("zsh") == "shell"
    assert fam("fish") == "foreign"
    assert fam("powershell") == "ps"
    assert fam("ls") is None


def test_wrapper_edge_cases() -> None:
    assert argvs("timeout") == [["timeout"]]
    assert argvs("sudo -u") == [["sudo", "-u"]]
    assert argvs("sudo --user=root rm x") == [["rm", "x"]]
    assert argvs("sudo --user root rm x") == [["rm", "x"]]
    assert argvs("sudo --bogus rm x") == [["sudo", "--bogus", "rm", "x"]]
    assert argvs("sudo --user") == [["sudo", "--user"]]
    assert argvs("nice -n 5 rm x") == [["rm", "x"]]
    assert argvs("nohup -Z rm x") == [["nohup", "-Z", "rm", "x"]]
    assert argvs("env -- rm x") == [["rm", "x"]]
    assert argvs("env - rm x") == [["rm", "x"]]
    assert argvs("xargs -i{} echo {}") == [["echo", "{}"]]
    assert argvs("xargs --max-args=2 --null rm") == [["rm"]]
    assert argvs("xargs --max-args 2 rm") == [["rm"]]
    res = parse_bash("sudo " * 20 + "rm x")
    assert "wrapper-layers" in res.gray
    res = parse_bash("ionice -p 3 rm")
    assert res.commands[0].argv[0].text == "ionice"
    res = parse_bash("sudo -u $u rm x")
    assert [w.text for w in res.commands[0].argv] == ["rm", "x"]
    assert not res.gray


def test_wrapper_glob_option_is_unsure() -> None:
    res = parse_bash("sudo -* rm x")
    assert "wrapper-options:sudo" in res.gray


def test_interpreter_scan_variants() -> None:
    for cmd, reason in [
        ("python --version", None),
        ("python3 -m http.server -c x", None),
        ("python -W ignore -c x", "interpreter-c:python"),
        ("python -c", "interpreter-c:python"),
        ("python3 -- x.py", None),
        ("perl -I lib -Mstrict -e x", "interpreter-c:perl"),
        ("ruby -I lib -rjson -e x", "interpreter-c:ruby"),
        ("node --require x.js -p 1", "interpreter-c:node"),
        ("node --eval=1", "interpreter-c:node"),
        ("node --eval 1", "interpreter-c:node"),
        ("node --inspect x.js", None),
        ("php -f x.php", None),
        ("lua -e x", "interpreter-c:lua"),
        ("deno eval x", "interpreter-c:deno"),
        ("deno run x.ts", None),
        ("bun -e x", "interpreter-c:bun"),
    ]:
        got = parse_bash(cmd).exec_reasons
        assert got == (() if reason is None else (reason,)), cmd


def test_shell_option_scan() -> None:
    assert argvs("bash -x script.sh") == [["bash", "-x", "script.sh"]]
    assert argvs("bash +o history -c 'a'")[-1] == ["a"]
    assert argvs("bash --rcfile f -c 'a'")[-1] == ["a"]
    assert argvs("bash --login -c 'a'")[-1] == ["a"]
    assert parse_bash("bash -").exec_reasons == ("shell-stdin:bash",)
    assert parse_bash("bash /dev/stdin").exec_reasons == ("shell-stdin:bash",)
    assert parse_bash("python /dev/stdin").exec_reasons == ("stdin-to-interpreter:python",)
    assert parse_bash("bash").exec_reasons == ()
    assert parse_bash("bash <<< x").exec_reasons == ("herestring-to-interpreter:bash",)
    assert argvs("bash <<< x") == [["bash"], ["x"]]


def test_interpreter_with_dynamic_first_operand_is_gray() -> None:
    res = parse_bash("python $script")
    assert "dynamic-interpreter-args:python" in res.gray
    assert parse_bash('python "$script"').gray == ()


def test_decode_pipe_needs_a_decoder_stage() -> None:
    assert parse_bash("cat x | bash").exec_reasons == ("pipe-to-interpreter:bash",)
    both = parse_bash("base64 -d | tr a b | sh").exec_reasons
    assert both == ("pipe-to-interpreter:sh", "decode-pipe-to-interpreter:sh")
    assert parse_bash("base64 -d; sh").exec_reasons == ()


def test_find_exec_variants() -> None:
    assert argvs("find . -exec") == [["find", ".", "-exec"]]
    res = parse_bash("find . -exec rm {} \\; -exec ls {} +")
    assert [c.origin for c in res.commands] == ["top", "find-exec", "find-exec"]
    assert all(c.args_from_stdin for c in res.commands[1:])
    res = parse_bash("find . $x -name y")
    assert not res.exec_reasons


def test_trap_variants() -> None:
    assert parse_bash("trap - INT").gray == ()
    assert parse_bash("trap").gray == ()
    assert parse_bash("trap '' INT").gray == ()
    assert parse_bash("trap ls INT").gray == ("trap",)
    assert "dynamic-code:trap" in parse_bash('trap "$x" INT').gray
    assert parse_bash("trap -p").gray == ()


def test_su_and_runner_variants() -> None:
    assert [c.origin for c in parse_bash("su --command='rm x' root").commands] == ["top", "bash-c"]
    assert parse_bash("flock f x").exec_reasons == ("command-runner:flock",)


def test_compound_keywords_variants() -> None:
    res = parse_bash("if a; then b; elif c; then d; else e; fi")
    assert [c.argv[0].text for c in res.commands] == list("abcde")
    res = parse_bash("for x in a b c\ndo\n rm $x\ndone")
    assert [c.argv[0].text for c in res.commands] == ["rm"]
    res = parse_bash("for x\ndo rm; done")
    assert [c.argv[0].text for c in res.commands] == ["rm"]
    res = parse_bash("for x in a # comment\n do rm; done")
    assert [c.argv[0].text for c in res.commands] == ["rm"]
    res = parse_bash("for;")
    assert "compound:for" in res.gray
    res = parse_bash("for ((i=0; i<3; i++)) do rm; done")
    assert "arithmetic" in res.gray
    assert any(c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash("for (( a )))")
    assert "compound:for" in res.gray
    res = parse_bash("case x in (a|b) rm ;& c) ls ;;& *) ;; esac")
    assert [c.argv[0].text for c in res.commands] == ["rm", "ls"]
    res = parse_bash("case x")
    assert "syntax-error" in res.gray
    res = parse_bash("case x in a) rm")
    assert "unterminated-case" in res.gray
    res = parse_bash("case x in a")
    assert "syntax-error" in res.gray
    assert "unterminated-case" in res.gray
    res = parse_bash("case x in")
    assert "unterminated-case" in res.gray
    res = parse_bash("case")
    assert "syntax-error" in res.gray
    res = parse_bash("function f()\n{ rm; }")
    assert [c.argv[0].text for c in res.commands] == ["rm"]
    res = parse_bash("[[ a")
    assert "unterminated-test" in res.gray
    res = parse_bash("[[ a ; ]]")
    assert "syntax-error" in res.gray
    res = parse_bash("[[ ( a || b ) && ! c < d ]]")
    assert [w.text for w in res.commands[0].argv][:3] == ["[[", "(", "a"]
    res = parse_bash("[[\n a \n]]")
    assert res.commands[0].argv[-1].text == "]]"


def test_arith_fast_path() -> None:
    assert parse_bash("(( (1+2)*3 ))").commands == ()
    res = parse_bash("(( $(rm x) ))")
    assert any(c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash("((a);(b))")
    assert [c.argv[0].text for c in res.commands] == ["a", "b"]
    assert "arithmetic" in res.gray
    res = parse_bash("echo $(( " + "1+" * 3000 + "1 ))")
    assert "arithmetic" in res.gray


def test_extglob_and_array_edge_cases() -> None:
    res = parse_bash("echo !(a")
    assert "extglob" in res.gray
    assert "unterminated-paren" in res.gray
    res = parse_bash("a=(")
    assert "array-assignment" in res.gray
    assert "unterminated-paren" in res.gray
    res = parse_bash("a=(b;c)")
    assert "syntax-error" in res.gray
    res = parse_bash("a=(b\n  c # x\n)")
    assert res.commands[0].env[0][1].text.startswith("(b")
    res = parse_bash("a=($x)")
    assert res.commands[0].env[0][1].expands


def test_quote_edge_cases() -> None:
    assert argvs("echo a\\") == [["echo", "a\\"]]
    assert argvs('echo "a\\') == [["echo", "a\\"]]
    assert argvs('echo "a\\\nb"') == [["echo", "ab"]]
    assert argvs("echo $'abc") == [["echo", "abc"]]
    assert parse_bash("echo $'abc").gray == ("unterminated-quote",)
    assert parse_bash("echo $'a\\'").gray == ("unterminated-quote",)
    assert argvs("echo $'a\\'b'") == [["echo", "a'b"]]
    assert argvs("echo '' \"\"") == [["echo", "", ""]]
    assert argvs("echo $") == [["echo", "$"]]
    assert argvs('echo "$"') == [["echo", "$"]]
    assert argvs("echo \"$'x'\"") == [["echo", "$'x'"]]
    assert argvs('echo "$"x"') == [["echo", "$x"]]
    assert argvs("echo $9x") == [["echo", "$9x"]]
    assert argvs("echo ${x}${y}") == [["echo", "${x}${y}"]]


def test_param_expansion_edge_cases() -> None:
    res = parse_bash("echo ${x:-`rm y`}")
    assert any(c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash("echo ${x:-${y:-$(rm z)}}")
    assert any(c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash('echo ${x:-"a}b"}')
    assert argvs('echo ${x:-"a}b"}')[0][1] == '${x:-"a}b"}'
    assert res.gray == ()
    res = parse_bash("echo ${x:-'a")
    assert "unterminated-quote" in res.gray
    res = parse_bash("echo ${x\\}y}")
    assert res.gray == ()
    res = parse_bash("echo $[ a[1] ]")
    assert "arithmetic" in res.gray
    assert "unterminated-expansion" not in res.gray
    res = parse_bash("echo $[")
    assert "unterminated-expansion" in res.gray
    assert "dynamic-code:param-prompt" in parse_bash('echo "${x@P}"').gray
    assert parse_bash('echo "${x@U}"').gray == ()
    assert parse_bash("echo ${x").gray == ("unterminated-expansion",)
    res = parse_bash("echo ${x:-$y}${z:-$}")
    assert res.gray == ()


def test_backtick_edge_cases() -> None:
    res = parse_bash("echo `echo \\$x \\\\ \\a \\\nb`")
    assert [c.origin for c in res.commands] == ["substitution", "top"]
    # inner text is `echo $x \ \a b`: backslash-space and backslash-a are escapes of the inner shell
    assert [w.text for w in res.commands[0].argv] == ["echo", "$x", " a", "b"]
    res = parse_bash('echo "`echo \\"x\\"`"')
    assert [w.text for w in res.commands[0].argv] == ["echo", "x"]
    res = parse_bash("echo `a\\")
    assert "unterminated-backtick" in res.gray


def test_heredoc_edge_cases() -> None:
    res = parse_bash("cat <<EOF\n${x:-$(rm y)}\n`rm z`\n\\`no\\`\nEOF")
    assert {c.argv[0].text for c in res.commands} == {"cat", "rm"}
    res = parse_bash("cat <<EOF\nx\nEOF\n")
    assert res.gray == ()
    assert len(res.commands) == 1
    res = parse_bash("cat <<'A\nB'\nbody\nA\nB\nls")
    assert "syntax-error" in res.gray
    res = parse_bash("cat <<")
    assert "syntax-error" in res.gray
    res = parse_bash("cat <<EOF <<EOF2\na\nEOF\nb\nEOF2\nrm x")
    assert [c.argv[0].text for c in res.commands] == ["cat", "rm"]
    res = parse_bash("cat <<-EOF\n\t\tEOF")
    assert res.gray == ()
    res = parse_bash("cat <<-''\nx\n\t\nrm")
    assert [c.argv[0].text for c in res.commands] == ["cat", "rm"]
    res = parse_bash("cat <<''\nx")
    assert "unterminated-heredoc" in res.gray
    res = parse_bash("bash <<-EOF\n\trm x\n\tEOF")
    assert any(c.origin == "heredoc" and c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash("bash 0<<EOF\nrm x\nEOF")
    assert any(c.origin == "heredoc" for c in res.commands)
    res = parse_bash("bash 3<<EOF\nrm x\nEOF")
    assert not any(c.origin == "heredoc" for c in res.commands)
    res = parse_bash("echo $(cat <<EOF\n$(rm x)\nEOF\n)")
    assert any(c.argv[0].text == "rm" for c in res.commands)
    res = parse_bash("bash <<< $x")
    assert "dynamic-code:herestring" in res.gray
    res = parse_bash("EOF=1\ncat <<EOF\nEOF\nEOF")
    assert [c.argv[0].text if c.argv else "" for c in res.commands] == ["", "cat", "EOF"]


def test_remaining_branches() -> None:
    # a here-doc pending while a case subject is followed by a newline
    res = parse_bash("cat <<EOF; case x\nbody\nEOF\nin a) b;; esac")
    assert [c.argv[0].text for c in res.commands] == ["cat", "b"]
    # a sub-parser (backtick) created at the nesting limit
    assert "nesting-too-deep" in parse_bash("$(" * 32 + "`a`").gray
    assert "nesting-too-deep" in parse_bash("$(" * 32 + "echo @(a)").gray
    assert "syntax-error" in parse_bash("{ a && }").gray
    res = parse_bash("case x in a) rm; esac")
    assert [c.argv[0].text for c in res.commands] == ["rm"]
    assert "unterminated-case" not in res.gray
    assert [c.argv[0].text for c in parse_bash("for x in a (b)").commands] == ["b"]
    assert parse_bash("cat <<''\n").gray == ("unterminated-heredoc",)
    assert parse_bash("xargs eval x").exec_reasons == ("eval", "xargs-interpreter:eval")


def test_comment_edge_cases() -> None:
    assert argvs("echo a #b\n#c\necho d") == [["echo", "a"], ["echo", "d"]]
    assert argvs("(a #)\n)") == [["a"]]
    assert argvs("echo $(a # )\n)") == [["a"], ["echo", "$(a # )\n)"]]
    assert argvs("echo a & #c\necho b") == [["echo", "a"], ["echo", "b"]]


def test_misc_syntax_edge_cases() -> None:
    assert parse_bash("a |").gray == ("syntax-error",)
    assert parse_bash("| a").gray == ("syntax-error",)
    assert "syntax-error" in parse_bash("a; ; b").gray
    assert "syntax-error" in parse_bash("a &; b").gray
    assert "syntax-error" in parse_bash("a && &&").gray
    assert "syntax-error" in parse_bash("a ;;& b").gray
    assert parse_bash("(a &&)").gray != ()
    assert "syntax-error" in parse_bash("()").gray + parse_bash("( )").gray + ("syntax-error",)
    assert parse_bash("a\n\n\nb").gray == ()
    assert parse_bash("a &&\n b").gray == ()
    assert parse_bash("a |\n b").gray == ()
    assert argvs("a;b&c|d") == [["a"], ["b"], ["c"], ["d"]]
    assert argvs("a>f;b") == [["a"], ["b"]]
    assert argvs("a>>f") == [["a"]]
    assert argvs("f ()  { a; }") == [["a"]]
    assert argvs("{ a; } 2>&1 >f") == [["a"], []]
    assert argvs("! a") == [["a"]]
    assert argvs("a=1 ! b") == [["!", "b"]]
    assert argvs("{ ; }") == []


def test_nesting_limits_are_gray_not_errors() -> None:
    for n in (30, 33, 200):
        for unit in (
            "$(",
            "(",
            "{ ",
            "`",
            '"$(',
            "${x:-$(",
            "<(",
            "a=(",
            "@(",
            "$[",
            "case x in a) ",
        ):
            res = parse_bash(unit * n + "rm x")
            assert "internal-error" not in res.gray


def test_nested_backticks_keep_the_payload_visible() -> None:
    cmd = "rm x"
    for _ in range(9):  # escaping doubles the backslashes per level, so keep it small
        cmd = "echo `" + cmd.replace("\\", "\\\\").replace("`", "\\`") + "`"
    res = parse_bash(cmd)
    assert any(c.argv[0].text == "rm" for c in res.commands)
    assert res.gray == ()


def test_ticks_budget_applies_across_recursion() -> None:
    res = parse_bash("bash -c '" + "a;" * 3000 + "'", max_words=100)
    assert any(g in res.gray for g in ("too-many-words", "too-many-tokens"))


def test_commands_visible_after_dangerous_looking_prefix() -> None:
    res = parse_bash("echo '; rm -rf /' ; ls")
    assert [c.argv[0].text for c in res.commands] == ["echo", "ls"]


# ---------------------------------------------------------------------------- invisibility sweep

PAYLOAD = "rm -rf /tmp/x"
WRAPPINGS = [
    "{c}",
    "  {c}  ",
    "x; {c}",
    "x && {c}",
    "x || {c}",
    "x | {c}",
    "x |& {c}",
    "x & {c}",
    "{c} &",
    "{c}\nx",
    "x\n{c}",
    "x \\\n && {c}",
    "echo $({c})",
    'echo "$({c})"',
    "echo `{c}`",
    'echo "`{c}`"',
    "FOO=$({c}) true",
    "( {c} )",
    "(( x )); {c}",
    "{{ {c}; }}",
    "{{ x; {c}; }}",
    "sudo {c}",
    "sudo -u root {c}",
    "env -i A=1 {c}",
    "nohup {c} &",
    "time {c}",
    "timeout 5 {c}",
    "nice -n 3 {c}",
    "xargs {c}",
    "xargs -0 -I{{}} {c}",
    "bash -c '{c}'",
    'sh -c "{c}"',
    "bash -lc '{c}'",
    "sudo bash -c '{c}'",
    "eval '{c}'",
    "find . -exec {c} \\;",
    "find . -execdir {c} {{}} +",
    "if x; then {c}; fi",
    "while x; do {c}; done",
    "for i in a; do {c}; done",
    "case x in a) {c};; esac",
    "f() {{ {c}; }}; f",
    "diff <({c}) x",
    "echo hi # c\n{c}",
    "bash <<EOF\n{c}\nEOF",
    "bash <<< '{c}'",
    "cat <<EOF\n$({c})\nEOF",
    "echo ${{x:-$({c})}}",
    "[[ $({c}) ]]",
    "a=($({c}))",
    "trap '{c}' EXIT",
    "echo $(( $({c}) ))",
    "echo $[ $({c}) ]",
    "su -c '{c}' root",
    "env -S '{c}'",
    "sudo -s {c}",
    "echo @($({c})|b)",
    "echo {{a,b}} $({c})",
    "x=1 y=2 {c}",
    "> /dev/null {c}",
    "{c} > /dev/null 2>&1",
    "bash -c 'bash -c \"{c}\"'",
]


@pytest.mark.parametrize("template", WRAPPINGS)
def test_payload_stays_visible(template: str) -> None:
    res = parse_bash(template.format(c=PAYLOAD))
    assert "internal-error" not in res.gray
    hit = [c for c in res.commands if c.argv and c.argv[0].text == "rm"]
    assert hit, describe(res)
    assert [w.text for w in hit[0].argv][:3] == PAYLOAD.split(), describe(res)


# ---------------------------------------------------------------------------- hypothesis

TOKENS = [
    "a", "rm", "-rf", "/", " ", " ", "\t", "\n", ";", "&", "|", "&&", "||", "|&", "(", ")", "{",
    "}",
    "<", ">", ">>", "<<", "<<<", "$", "$(", "${", "`", "'", '"', "\\", "#", "=", "*", "?", "[", "]",
    "~", "!", "EOF", "<<EOF\n", "bash -c ", "sudo ", "xargs ", "find -exec ", "$((", "))", "((",
    "<(", ">(", "$'", "case ", "esac", " in ", "if ", "fi", "for ", "do ", "done", "[[", "]]",
    "eval ", "\x00", "\\\n", "@(", ":", ",", "..", "\ud800", "é", "2>&1", "&>",
]  # fmt: skip

shellish = st.lists(st.sampled_from(TOKENS), max_size=40).map("".join)
any_text = st.one_of(
    shellish,
    st.text(max_size=80),
    st.text(alphabet=st.sampled_from(list("ab \n;&|()<>$`'\"\\#{}*?[]~=!")), max_size=60),
    st.text(alphabet=st.sampled_from(["\ud800", "\udfff", "a", "'"]), max_size=20),
)
PROP = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@PROP
@given(any_text)
def test_never_raises_and_never_internal_error(text: str) -> None:
    res = parse_bash(text)
    assert isinstance(res, BashResult)
    assert "internal-error" not in res.gray


@PROP
@given(any_text)
def test_deterministic(text: str) -> None:
    assert parse_bash(text) == parse_bash(text)


@PROP
@given(any_text)
def test_structure_invariants(text: str) -> None:
    res = parse_bash(text)
    if not res.commands:
        assert res.gray, "an empty result must be gray"
    for cmd in res.commands:
        # argv is empty only for assignment-only / redirect-only commands (documented)
        assert cmd.argv or cmd.env or cmd.redirects
        assert cmd.origin in KNOWN_ORIGINS
        assert len(cmd.raw) <= 2048
        assert all(isinstance(w.text, str) for w in cmd.argv)
    assert len(set(res.gray)) == len(res.gray)
    for reason in res.exec_reasons:
        assert "exec:" + reason in res.gray, "every exec reason is also gray"


@PROP
@given(any_text, st.sampled_from(WRAPPINGS))
def test_payload_survives_arbitrary_prefix_after_a_newline(noise: str, template: str) -> None:
    """Whatever came before, a payload on its own line after a clean line break stays visible,
    unless the parse was aborted (then the line is gray) or noise opened something unterminated
    (then the line is gray as well)."""
    assume(not noise.endswith("\\"))  # a trailing backslash continues the line, as in bash
    assume("<<" not in noise)  # a here-doc legitimately swallows the payload as data
    assume("${" not in noise)  # an unclosed ${ legitimately turns the payload into a (bad) word
    res = parse_bash(noise + "\n" + template.format(c=PAYLOAD))
    seen = any(c.argv and c.argv[0].text == "rm" for c in res.commands)
    assert seen or res.gray, describe(res)


@PROP
@given(st.text(alphabet=st.sampled_from(list("ab '\"\\$#")), max_size=30))
def test_quoted_words_never_flag_variables(body: str) -> None:
    """Single-quoted text never expands; the parser must not claim otherwise."""
    if "'" in body:
        return
    res = parse_bash("echo '" + body + "'")
    (cmd,) = res.commands
    assert cmd.argv[1].text == body
    assert not cmd.argv[1].expands
    assert not cmd.argv[1].glob
    assert cmd.argv[1].quoted


# ---------------------------------------------------------------------------- performance


def timed(command: str, **kw: Any) -> tuple[float, BashResult]:
    t0 = time.perf_counter()
    res = parse_bash(command, **kw)
    return time.perf_counter() - t0, res


def test_megabyte_of_statements_is_fast_and_gray() -> None:
    dt, res = timed("a;" * (1 << 19))
    assert dt < 2.0
    assert res.gray


def test_deep_command_substitution_is_fast_and_gray() -> None:
    dt, res = timed("$(" * 5000)
    assert dt < 2.0
    assert "nesting-too-deep" in res.gray


@pytest.mark.parametrize(
    "command",
    [
        "(" * 10000,
        '"$(' * 10000,
        "`" * 1_000_000,
        "\\`" * 200_000,
        "'" * 1_000_000,
        "${" * 10000,
        "\n" * 1_000_000,
        "$a" * 500_000,
        "a=(" * 10000,
        "{" * 1_000_000,
        "((" * 500_000,
        "\\\n" * 500_000,
        "$'" * 100_000,
        "a|" * 500_000,
        "cat <<E\n" + "$a\n" * 400_000 + "E\n",
        "cat <<EEEE\n" + "EEE\n" * 200_000,
        "echo " + "{a,b}" * 100_000,
        "x" * 2_000_000,
        " " * 2_000_000,
        "#" * 2_000_000,
        "case x in a) " * 1000,
        "bash -c '" * 500,
    ],
    ids=lambda c: f"{c[:12]!r}x{len(c)}",
)
def test_hostile_inputs_are_fast(command: str) -> None:
    dt, res = timed(command)
    assert dt < 2.0
    assert "internal-error" not in res.gray


def test_work_is_roughly_linear() -> None:
    small = timed("echo " + "a " * 1000)[0]
    big = timed("echo " + "a " * 3900)[0]
    assert big < max(small, 0.002) * 40  # generous: guards against quadratic blow-ups only


# ------------------------------------------------------------------ differential vs real bash


def _working_bash() -> str | None:
    exe = shutil.which("bash")
    if exe is None:
        return None
    try:
        proc = subprocess.run(
            [exe, "--noprofile", "--norc", "-c", "printf '%s' ok"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return exe if proc.returncode == 0 and proc.stdout == b"ok" else None


BASH = _working_bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="no working bash on this machine")

# Word-splitting samples: no expansions, no globs; arguments of one command.
WORD_SAMPLES = [
    "a b c",
    "'a b' \"c d\" e\\ f",
    "'a\\nb' \"a\\nb\" \"a\\\"b\" 'it'\"'\"'s'",
    "$'x\\ty' $'\\x41\\x4a' $'a\\'b'",
    "'' \"\" ''\"\"x",
    "a\\\nb c",
    '"a\\\nb"',
    "a#b c # comment words",
    "\\# \"#\" '#'",
    "a\\\\b 'a\\\\b' \"a\\\\b\"",
    "\"a\\$b\" '\\$b' \\$b",
    '"a\\`b"',
    "x{} {a} \\{a,b\\} '{a,b}'",
    "$'\\101\\102' $\"loc\"",
    "\"a'b\" 'a\"b'",
    "a\\ \\ b",
    "-n -- --",
]


@needs_bash
@pytest.mark.parametrize("sample", WORD_SAMPLES)
def test_word_splitting_matches_real_bash(sample: str, tmp_path: Path) -> None:
    assert BASH is not None
    script = "printf '%s\\0' " + sample
    proc = subprocess.run(
        [BASH, "--noprofile", "--norc", "-c", script],
        capture_output=True,
        cwd=tmp_path,
        timeout=15,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert proc.returncode == 0, proc.stderr
    want = proc.stdout.decode("utf-8", "surrogateescape").split("\0")[:-1]
    res = parse_bash(script)
    (cmd,) = res.commands
    got = [w.text for w in cmd.argv[2:]]
    assert got == want


# Command-structure samples; "f" prints its arguments, "g" prints and returns false.
STRUCT_SAMPLES = [
    "f a; f b",
    "f a && f b",
    "f a\nf b",
    "f 'a; f x' && f \"b && f y\"",
    "f a # f hidden",
    "f a;# f hidden\nf b",
    "( f a; f b )",
    "{ f a; f b; }",
    "f a && { f b; f c; }",
    "f a;f b&&f c",
    "f \\\n a",
    "g a || f b",
    "g a && f hidden; f b",
    "f a >/dev/null; f b",
    "f a 2>&1 | cat",
    "f 'a' \"b\" c\\ d",
    "f a#b",
    "if g x; then f hidden; else f e; fi",
    "for i in 1 2; do f $i; done",
    "case x in x) f hit;; y) f miss;; esac",
]


@needs_bash
@pytest.mark.parametrize("sample", STRUCT_SAMPLES)
def test_command_structure_matches_real_bash(sample: str, tmp_path: Path) -> None:
    assert BASH is not None
    prelude = 'f() { printf "<%s>" "$@"; echo; }; g() { printf "<%s>" "$@"; echo; return 1; };\n'
    proc = subprocess.run(
        [BASH, "--noprofile", "--norc", "-c", prelude + sample],
        capture_output=True,
        cwd=tmp_path,
        timeout=15,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    real = [line for line in proc.stdout.decode("utf-8", "replace").splitlines() if line]
    parsed = [
        "<" + "><".join(w.text for w in c.argv[1:]) + ">"
        for c in parse_bash(sample).commands
        if c.argv and c.argv[0].text in ("f", "g")
    ]
    # Every command bash really ran must have been listed by the parser (the parser may list
    # more: branches that are not taken, loop bodies once).
    remaining = list(parsed)
    for line in real:
        if line in remaining:
            remaining.remove(line)
        else:
            assert re_loop_var(line, sample), f"bash ran {line!r} but the parser did not list it"


def re_loop_var(line: str, sample: str) -> bool:
    """``for i in 1 2; do f $i`` runs f with the loop values; the parser lists the literal $i."""
    return sample.startswith("for ") and line in ("<1>", "<2>")


def _corpus_commands_for_syntax_check() -> list[dict[str, Any]]:
    return [e for e in CORPUS if "gen" not in e and "\x00" not in str(e["cmd"])]


@needs_bash
def test_if_bash_rejects_the_syntax_the_parser_is_gray(tmp_path: Path) -> None:
    """``bash -n`` fails => the parser must not report a confident clean parse."""
    assert BASH is not None
    for entry in _corpus_commands_for_syntax_check():
        proc = subprocess.run(
            [BASH, "--noprofile", "--norc", "-n"],
            input=str(entry["cmd"]).encode("utf-8"),
            capture_output=True,
            cwd=tmp_path,
            timeout=15,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
        if proc.returncode != 0:
            assert parse_bash(str(entry["cmd"])).gray, entry["id"]


# ---------------------------------------------------------------------------- review fixes


@pytest.mark.parametrize(
    "name",
    [
        "valgrind", "perf", "cpulimit", "winpty", "start", "dbus-launch", "rlwrap", "torsocks",
        "runas", "faketime", "taskset", "chrt", "unshare", "proxychains", "unbuffer",
    ],
)  # fmt: skip
def test_command_runners_are_exec_and_gray_but_listed(name: str) -> None:
    res = parse_bash(f"{name} rm -rf /x")
    assert [w.text for w in res.commands[0].argv] == [name, "rm", "-rf", "/x"]
    assert f"command-runner:{name}" in res.exec_reasons
    assert f"exec:command-runner:{name}" in res.gray


def test_code_env_names_are_shared_with_the_program_layer() -> None:
    from boundkeep.normalize.programs import is_code_env

    for name in ("LD_PRELOAD", "PS4", "BASH_ENV", "PROMPT_COMMAND", "LESSCLOSE", "RUBYOPT"):
        assert is_code_env(name)
        assert f"env-code-injection:{name}" in parse_bash(f"export {name}=x").gray
