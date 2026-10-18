"""normalize_event: the assembler (hook event -> Actions). Review fixes of milestone M1.

Fake machines (``WORLDS``) are purely lexical, so they behave the same on every host; tests that
need the disk (globs, junctions, the work budget) use ``real_world`` under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from boundkeep.normalize import event as ev
from boundkeep.normalize import paths
from boundkeep.normalize.event import normalize_event
from boundkeep.normalize.model import Action

IS_WIN = sys.platform == "win32"

WORLDS: dict[str, dict[str, Any]] = {
    "windows": {
        "platform": "windows",
        "home": "C:\\Users\\bob",
        "cwd": "C:\\Users\\bob\\proj",
        "env": {"USERPROFILE": "C:\\Users\\bob"},
        "hk": "c:/users/bob",
        "pk": "c:/users/bob/proj",
    },
    "posix": {
        "platform": "posix",
        "home": "/home/bob",
        "cwd": "/home/bob/proj",
        "env": {"HOME": "/home/bob"},
        "hk": "/home/bob",
        "pk": "/home/bob/proj",
    },
}


# The ids must not be "windows" / "posix": conftest skips tests whose keywords name those markers.
@pytest.fixture(params=[pytest.param("windows", id="win"), pytest.param("posix", id="nix")])
def world(request: pytest.FixtureRequest) -> dict[str, Any]:
    return WORLDS[request.param]


def key_of(path: Path | str) -> str:
    return paths.normalize_path(str(path), cwd=None, home=None, dialect="tool", literal=True).key


def real_world(tmp_path: Path) -> dict[str, Any]:
    """A world whose home and project exist on this machine's disk."""
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    env = {"USERPROFILE": str(home)} if IS_WIN else {"HOME": str(home)}
    return {
        "platform": "windows" if IS_WIN else "posix",
        "home": str(home),
        "cwd": str(proj),
        "env": env,
        "hk": key_of(home),
        "pk": key_of(proj),
    }


def payload(
    world: dict[str, Any],
    tool: str,
    tool_input: dict[str, Any],
    *,
    cwd: str | None = None,
    project: str | None = None,
) -> dict[str, Any]:
    return {
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd or world["cwd"],
        "project_dir": project or world["cwd"],
    }


def norm_event(world: dict[str, Any], event: dict[str, Any], **kwargs: Any) -> list[Action]:
    return normalize_event(
        event, platform=world["platform"], env=world["env"], home=world["home"], **kwargs
    )


def run(world: dict[str, Any], command: str, *, tool: str = "Bash", **kwargs: Any) -> list[Action]:
    return norm_event(world, payload(world, tool, {"command": command}), **kwargs)


def tool(
    world: dict[str, Any], name: str, tool_input: dict[str, Any], **kwargs: Any
) -> list[Action]:
    return norm_event(world, payload(world, name, tool_input), **kwargs)


def keys(actions: list[Action]) -> set[str]:
    return {ref.key for action in actions for ref in action.paths}


def reasons(actions: list[Action]) -> set[str]:
    return {r for action in actions for r in action.gray_reasons}


def by_program(actions: list[Action], program: str) -> Action:
    return next(a for a in actions if a.program == program)


# --- item 1: cd tracking ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "tail"),
    [
        pytest.param("cd ~ && cat .aws/credentials", "/.aws/credentials", id="tilde"),
        pytest.param("cd $HOME && cat .aws/credentials", "/.aws/credentials", id="home-var"),
        pytest.param("cd ${HOME} && cat .aws/credentials", "/.aws/credentials", id="home-braces"),
        pytest.param("cd && cat .aws/credentials", "/.aws/credentials", id="bare-cd"),
        pytest.param("cd ~/Documents && cat ../.aws/credentials", "/.aws/credentials", id="dotdot"),
        pytest.param(
            "pushd ~/.claude && echo x > settings.json", "/.claude/settings.json", id="pushd"
        ),
        pytest.param(
            "(cd ~/.claude && echo x > settings.json)", "/.claude/settings.json", id="subshell"
        ),
        pytest.param(
            "cd ~/.claude | echo x > settings.json", "/.claude/settings.json", id="pipeline"
        ),
        pytest.param(
            "cd ~/.claude & echo x > settings.json", "/.claude/settings.json", id="background"
        ),
        pytest.param(
            'bash -c "cd ~/.claude && echo x > settings.json"',
            "/.claude/settings.json",
            id="bash-c",
        ),
        pytest.param(
            "cd ~/.claude; cd ..; cat .claude/settings.json", "/.claude/settings.json", id="chain"
        ),
        pytest.param("cd ~/.ssh || true; cat id_rsa", "/.ssh/id_rsa", id="or-true"),
    ],
)
def test_cd_targets_are_tracked_for_the_commands_that_follow(
    world: dict[str, Any], command: str, tail: str
) -> None:
    assert world["hk"] + tail in keys(run(world, command))


def test_cd_keeps_the_old_directory_as_a_possibility_because_cd_can_fail(
    world: dict[str, Any],
) -> None:
    got = run(world, "cd sub && cat x")
    cat = by_program(got, "cat")
    assert {r.key for r in cat.paths} == {world["pk"] + "/x", world["pk"] + "/sub/x"}
    assert cat.inside_project is True  # inside in every possibility
    out = run(world, "cd .. && cat x")
    assert {r.key for r in by_program(out, "cat").paths} == {
        world["pk"] + "/x",
        world["hk"] + "/x",
    }
    assert by_program(out, "cat").inside_project is False


def test_absolute_paths_get_one_ref_not_one_per_possible_directory(world: dict[str, Any]) -> None:
    got = run(world, "cd a; cd b; cat ~/x")
    cat = by_program(got, "cat")
    assert [r.key for r in cat.paths] == [world["hk"] + "/x"]


@pytest.mark.parametrize(
    "command", ["cd - && cat .env", "popd; cat .env", "pushd; cat .env", "pushd +1; cat .env"]
)
def test_unknowable_directory_changes_make_relative_paths_uncertain_but_keep_every_guess(
    world: dict[str, Any], command: str
) -> None:
    cat = by_program(run(world, command), "cat")
    assert world["pk"] + "/.env" in {r.key for r in cat.paths}
    unknown = [r for r in cat.paths if r.key == ".env"]
    assert unknown
    assert unknown[0].uncertain
    assert unknown[0].inside_project is None
    assert cat.gray
    assert "cwd-unknown" in cat.gray_reasons
    assert cat.inside_project is None


@pytest.mark.parametrize(
    "command",
    [
        "cd $(pwd) && cat .env",
        "cd `pwd` && cat .env",
        "cd $FOO && cat .env",
        "cd ~bob && cat .env",
        "cd d* && cat .env",
        "cd a b && cat .env",
        "cd '' && cat .env",
    ],
)
def test_cd_to_something_unknowable_keeps_the_old_directory_and_adds_an_unknown_one(
    world: dict[str, Any], command: str
) -> None:
    cat = by_program(run(world, command), "cat")
    assert world["pk"] + "/.env" in {r.key for r in cat.paths}
    assert any(r.uncertain and r.key == ".env" for r in cat.paths)
    assert "cwd-unknown" in cat.gray_reasons


def test_the_set_of_possible_directories_is_bounded(world: dict[str, Any]) -> None:
    command = "; ".join(f"cd d{i}" for i in range(6)) + "; cat x"
    cat = by_program(run(world, command), "cat")
    assert len(cat.paths) <= ev.MAX_CWDS
    assert any(r.uncertain for r in cat.paths)
    assert "cwd-unknown" in cat.gray_reasons
    assert world["pk"] + "/x" in {r.key for r in cat.paths}


def test_a_very_deep_directory_is_treated_as_unknown(world: dict[str, Any]) -> None:
    deep = "/".join(["a"] * 70)
    cat = by_program(run(world, f"cd {deep} && cat x"), "cat")
    assert all(len(r.key) < 200 for r in cat.paths)
    assert "cwd-unknown" in cat.gray_reasons


def test_env_dash_c_cannot_be_followed_so_the_line_is_gray(world: dict[str, Any]) -> None:
    got = run(world, 'env -C ~/.claude sh -c "echo x > settings.json"')
    assert any(a.gray for a in got)


def test_cd_without_a_known_cwd_is_unknown(world: dict[str, Any]) -> None:
    event = {"tool_name": "Bash", "tool_input": {"command": "cat x"}}
    got = norm_event(world, event)
    assert got[0].gray
    assert "cwd-unknown" in got[0].gray_reasons


# --- item 2: dynamic words --------------------------------------------------------------------


def test_a_bare_tilde_or_home_variable_is_not_dynamic(world: dict[str, Any]) -> None:
    for text in ("~/x", "$HOME/x", "${HOME}/x", '"$HOME"/x'):
        ref = by_program(run(world, f"cat {text}"), "cat").paths[0]
        assert ref.key == world["hk"] + "/x", text
        assert not ref.uncertain, text
        assert "dynamic-word" not in ref.reasons, text


@pytest.mark.parametrize(
    "text",
    ["$FOO/x", "${HOME:-/etc}/x", "$(echo x)/y", "`echo x`/y", "~/*.txt", "$HOME$X/y", "~bob/x"],
)
def test_other_expansions_and_globs_are_dynamic(world: dict[str, Any], text: str) -> None:
    refs = by_program(run(world, f"cat {text}"), "cat").paths
    assert refs
    assert all(r.uncertain for r in refs[:1])


def test_a_junction_or_symlink_under_a_tilde_path_is_followed(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    ssh = Path(w["home"]) / ".ssh"
    ssh.mkdir()
    (ssh / "config").write_text("x", encoding="utf-8")
    link = Path(w["home"]) / "innocent"
    if IS_WIN:
        import _winapi  # type: ignore[import-not-found,unused-ignore]

        try:
            _winapi.CreateJunction(str(ssh), str(link))
        except OSError as exc:
            pytest.skip(f"cannot create a junction here: {exc}")
    else:
        os.symlink(ssh, link, target_is_directory=True)
    got = run(w, "cat ~/innocent/config")
    assert key_of(ssh / "config") in keys(got)
    resolved = [r for r in by_program(got, "cat").paths if r.key == key_of(ssh / "config")]
    assert "resolved-on-disk" in resolved[0].reasons
    read = tool(w, "Read", {"file_path": "~/innocent/config"})
    assert key_of(ssh / "config") in keys(read)


# --- item 3: short names ----------------------------------------------------------------------


@pytest.mark.windows
def test_short_names_are_resolved_even_though_the_lexical_path_stays_uncertain(
    tmp_path: Path,
) -> None:
    import ctypes

    w = real_world(tmp_path)
    long_dir = Path(w["cwd"]) / "a_rather_long_directory_name"
    long_dir.mkdir()
    target = long_dir / "some_long_file_name.txt"
    target.write_text("x", encoding="utf-8")
    buf = ctypes.create_unicode_buffer(1024)
    get_short = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined,unused-ignore]
    if not get_short(str(target), buf, 1024) or buf.value.lower() == str(target).lower():
        pytest.skip("8.3 short names are disabled on this volume")
    for got in (
        run(w, f'cat "{buf.value}"'),
        tool(w, "Read", {"file_path": buf.value}),
        tool(w, "Write", {"file_path": buf.value, "content": "x"}),
    ):
        action = got[0]
        primary = action.paths[0]
        assert primary.uncertain
        assert "short-name-unresolved" in primary.reasons
        resolved = [r for r in action.paths if r.key == key_of(target)]
        assert resolved
        assert "resolved-on-disk" in resolved[0].reasons
        assert not resolved[0].uncertain
        assert resolved[0].inside_project is True


def test_unc_and_device_paths_are_never_resolved_on_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(os.path, "realpath", lambda p: calls.append(str(p)) or str(p))
    w = WORLDS["windows"]
    run(w, "cat //srv/share/x")
    run(w, "cat '\\\\srv\\share\\x'")
    tool(w, "Read", {"file_path": "\\\\srv\\share\\x"})
    tool(w, "Read", {"file_path": "\\\\.\\pipe\\x"})
    tool(w, "Read", {"file_path": "NUL"})
    # (the project root itself is looked up once; nothing else may be)
    assert [c for c in calls if "srv" in c or "pipe" in c or c.lower().endswith("nul")] == []


# --- item 4: the program name -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "program"),
    [
        ("rm -rf x", "rm"),
        ("/bin/rm -rf x", "rm"),
        ("/usr/bin/rm -rf x", "rm"),
        ("/usr/bin/git status", "git"),
        ("rm.exe -rf x", "rm"),
        ("git.EXE status", "git"),
        ('"C:\\Program Files\\Git\\usr\\bin\\rm.exe" -rf x', "rm"),
        ("C:/Program\\ Files/Git/usr/bin/rm.exe -rf x", "rm"),
        ("/usr/local/bin/python3 x.py", "python3"),
    ],
)
def test_the_program_is_the_canonical_name(
    world: dict[str, Any], command: str, program: str
) -> None:
    got = run(world, command)
    action = got[0]
    if world["platform"] == "posix" and "Program" in command:
        # a Windows path on a POSIX host is not a system directory: still the same name, but gray
        assert action.program == program
        assert "program-path-qualified" in action.gray_reasons
        return
    assert action.program == program
    assert "program-path-qualified" not in action.gray_reasons


def test_a_case_variant_is_the_same_program_on_windows_and_flagged_on_posix() -> None:
    win = run(WORLDS["windows"], "RM -rf x")[0]
    assert win.program == "rm"
    posix = run(WORLDS["posix"], "RM -rf x")[0]
    assert posix.program == "rm"
    assert posix.gray
    assert any(r.startswith("program-case-variant") for r in posix.gray_reasons)


@pytest.mark.parametrize(
    "command", ["./rm -rf x", "/tmp/evil/rm -rf x", "~/bin/git status", "../git status"]
)
def test_a_path_qualified_program_outside_the_system_directories_is_gray(
    world: dict[str, Any], command: str
) -> None:
    action = run(world, command)[0]
    assert action.program in ("rm", "git")
    assert action.gray
    assert "program-path-qualified" in action.gray_reasons
    assert action.paths  # the program file itself is listed, so rules can see where it lives


@pytest.mark.parametrize("command", ["/usr/bin/../../tmp/rm -rf x", "/usr/bin/./x/rm -rf x"])
def test_dot_segments_do_not_make_a_directory_a_system_directory(
    world: dict[str, Any], command: str
) -> None:
    assert "program-path-qualified" in run(world, command)[0].gray_reasons


def test_dynamic_program_names_keep_their_text(world: dict[str, Any]) -> None:
    action = run(world, "$X -rf y")[0]
    assert action.program == "$X"
    assert "dynamic-program" in action.gray_reasons
    assert run(world, "")[0].gray


def test_wrappers_are_recorded(world: dict[str, Any]) -> None:
    sudo = by_program(run(world, "sudo -u root /bin/rm -rf x"), "rm")
    assert sudo.wrappers == ("sudo",)
    multi = by_program(run(world, "nohup env FOO=1 rm -rf x"), "rm")
    assert multi.wrappers == ("nohup", "env")
    assert by_program(run(world, "rm -rf x"), "rm").wrappers == ()
    busy = by_program(run(world, "busybox rm -rf x"), "rm")
    assert busy.wrappers == ("busybox",)


def test_windows_program_names_fold_case_and_extensions() -> None:
    win = WORLDS["windows"]
    assert run(win, "GIT.exe push --force")[0].program == "git"
    assert run(win, "C:/Windows/System32/SCHTASKS.EXE /query")[0].program == "schtasks"


# --- item 5: braces and globs -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", ["plain"]),
        ("a{b,c}d", ["abd", "acd"]),
        ("~/.a{w,w}s/credentials", ["~/.aws/credentials", "~/.aws/credentials"]),
        (".{env,x}", [".env", ".x"]),
        ("{a,b}{1,2}", ["a1", "a2", "b1", "b2"]),
        ("x{a,{b,c}}y", ["xay", "xby", "xcy"]),
        ("{1..4}", ["1", "2", "3", "4"]),
        ("{4..1}", ["4", "3", "2", "1"]),
        ("{1..10..3}", ["1", "4", "7", "10"]),
        ("{01..03}", ["01", "02", "03"]),
        ("{a..d}", ["a", "b", "c", "d"]),
        ("{d..a..2}", ["d", "b"]),
        ("{a,}", ["a", ""]),
        ("${HOME}/x", ["${HOME}/x"]),
        ("{}", ["{}"]),
        ("{a}", ["{a}"]),
        ("{a,b", ["{a,b"]),
        ("a}b{", ["a}b{"]),
        ("{1..a}", ["{1..a}"]),
        ("{1..2..0}", ["{1..2..0}"]),
        ("{,}", ["", ""]),
        ("{a,{b}", ["{a,{b}"]),
    ],
)
def test_expand_braces_is_exact(text: str, expected: list[str]) -> None:
    assert ev.expand_braces(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "{1..1000}",
        "{a,b}" * 7,
        "{" * 5000,
        "x" * 3000 + "{a,b}",
        "{1..99999999999999}",
        "{a..z..-0}x",
        "{" + ",".join("x" * 3 for _ in range(70)) + "}",
    ],
)
def test_expand_braces_refuses_to_blow_up(text: str) -> None:
    started = time.perf_counter()
    got = ev.expand_braces(text)
    assert time.perf_counter() - started < 1.0
    assert got is None or len(got) <= ev.MAX_BRACE_RESULTS


def test_brace_words_get_one_ref_per_result(world: dict[str, Any]) -> None:
    got = run(world, "cat ~/.a{w,w}s/credentials")
    cat = by_program(got, "cat")
    assert [r.key for r in cat.paths] == [world["hk"] + "/.aws/credentials"]
    assert not cat.paths[0].uncertain
    assert any(a.gray for a in got)  # the parser still reports the brace expansion
    got = run(world, "cat .{env,x}")
    assert {r.key for r in by_program(got, "cat").paths} == {
        world["pk"] + "/.env",
        world["pk"] + "/.x",
    }
    got = run(world, "echo x >> ~/.bash{rc,_profile}")
    assert {world["hk"] + "/.bashrc", world["hk"] + "/.bash_profile"} <= keys(got)


def test_a_huge_brace_expansion_stays_unexpanded_and_gray(world: dict[str, Any]) -> None:
    cat = by_program(run(world, "cat {1..500}"), "cat")
    assert "brace-expansion-too-large" in cat.gray_reasons
    assert cat.paths
    assert all(r.uncertain for r in cat.paths)


def test_glob_words_are_enumerated_on_disk(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    proj = Path(w["cwd"])
    (proj / ".env").write_text("x", encoding="utf-8")
    (proj / ".env.local").write_text("x", encoding="utf-8")
    (proj / "a.txt").write_text("x", encoding="utf-8")
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    ssh = Path(w["home"]) / ".ssh"
    ssh.mkdir()
    (ssh / "id_rsa").write_text("x", encoding="utf-8")

    star = by_program(run(w, "cat .env*"), "cat")
    assert {key_of(proj / ".env"), key_of(proj / ".env.local")} <= {r.key for r in star.paths}
    unexpanded = [r for r in star.paths if "glob" in r.reasons]
    assert unexpanded
    assert unexpanded[0].uncertain  # the text itself stays uncertain
    assert all(not r.uncertain for r in star.paths if r not in unexpanded)

    plain = by_program(run(w, "cat *"), "cat")
    assert key_of(proj / "a.txt") in {r.key for r in plain.paths}
    assert key_of(proj / ".env") not in {r.key for r in plain.paths}  # "*" skips dotfiles

    home = by_program(run(w, "cat ~/.ss*/*"), "cat")
    assert key_of(ssh / "id_rsa") in {r.key for r in home.paths}

    tee = run(w, "echo x | tee .claude/set*.json")
    assert key_of(proj / ".claude" / "settings.json") in keys(tee)
    assert any(
        r.access == "write" and r.key.endswith("settings.json") for a in tee for r in a.paths
    )

    redirect = run(w, "echo x >> ~/.ss*/id_*")
    assert key_of(ssh / "id_rsa") in keys(redirect)

    braced = by_program(run(w, "cat .{env,nothing}*"), "cat")
    assert key_of(proj / ".env") in {r.key for r in braced.paths}


def test_a_glob_that_matches_nothing_keeps_its_text_and_is_gray(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    for command in ("cat nothing*", "cat nodir/*.pem", "cat ~/.nothing*/*"):
        cat = by_program(run(w, command), "cat")
        assert len(cat.paths) == 1
        assert cat.paths[0].uncertain
        assert "glob" in cat.paths[0].reasons
        assert "glob-not-expanded" in cat.gray_reasons
        assert cat.inside_project is None


def test_a_glob_with_too_many_matches_is_gray_and_bounded(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    proj = Path(w["cwd"])
    for i in range(80):
        (proj / f"f{i}.log").write_text("x", encoding="utf-8")
    cat = by_program(run(w, "cat f*.log"), "cat")
    assert "glob-too-many-matches" in cat.gray_reasons
    assert len(cat.paths) <= ev.MAX_GLOB_MATCHES + 1
    assert cat.paths[0].uncertain


def test_glob_matches_are_resolved_through_links(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    proj = Path(w["cwd"])
    ssh = Path(w["home"]) / ".ssh"
    ssh.mkdir()
    (ssh / "config").write_text("x", encoding="utf-8")
    if IS_WIN:
        import _winapi  # type: ignore[import-not-found,unused-ignore]

        try:
            _winapi.CreateJunction(str(ssh), str(proj / "link"))
        except OSError as exc:
            pytest.skip(f"cannot create a junction here: {exc}")
    else:
        os.symlink(ssh, proj / "link", target_is_directory=True)
    got = by_program(run(w, "cat li*/config"), "cat")
    assert key_of(ssh / "config") in {r.key for r in got.paths}


def test_glob_enumeration_is_skipped_for_unc_and_foreign_flavors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("disk touched")

    monkeypatch.setattr(os, "scandir", boom)
    monkeypatch.setattr(os.path, "lexists", boom)
    monkeypatch.setattr(os.path, "realpath", boom)
    for w in WORLDS.values():
        got = run(w, "cat ~/.ss*/* //srv/share/*")
        assert got[0].paths
    unc = tool(WORLDS["windows"], "Read", {"file_path": "\\\\srv\\share\\*.pem"})
    assert unc[0].paths


# --- item 6: arguments that arrive at run time ------------------------------------------------


def test_find_exec_substitutes_the_start_paths_for_the_placeholder(world: dict[str, Any]) -> None:
    got = run(world, "find ~ -exec rm -rf {} +")
    rm = by_program(got, "rm")
    assert any(r.key == world["hk"] and r.access == "write" for r in rm.paths)
    synthetic = [r for r in rm.paths if "args-from-stdin" in r.reasons]
    assert len(synthetic) == 1
    assert synthetic[0].uncertain
    assert synthetic[0].access == "write"
    assert synthetic[0].inside_project is None
    assert rm.inside_project is False
    assert rm.gray
    assert "arguments-from-stdin" in rm.gray_reasons
    again = run(world, "find /tmp -type f -exec rm -rf {} \\;")
    rm2 = by_program(again, "rm")
    assert rm2.inside_project is not True
    assert any("args-from-stdin" in r.reasons for r in rm2.paths)


def test_find_exec_without_start_paths_searches_the_cwd(world: dict[str, Any]) -> None:
    rm = by_program(run(world, "find -name x -exec rm {} \\;"), "rm")
    assert world["pk"] in {r.key for r in rm.paths}
    assert rm.inside_project is None  # the synthetic ref cannot be shown inside


def test_xargs_gets_an_uncertain_ref_with_the_programs_default_access(
    world: dict[str, Any],
) -> None:
    rm = by_program(run(world, "ls ~ | xargs rm -rf"), "rm")
    assert len(rm.paths) == 1
    assert rm.paths[0].uncertain
    assert rm.paths[0].access == "write"
    assert rm.inside_project is None
    assert rm.gray
    cat = by_program(run(world, "ls | xargs cat"), "cat")
    assert cat.paths[0].access == "read"
    assert cat.paths[0].uncertain
    replaced = by_program(run(world, "ls | xargs -I{} cp {} /tmp/x"), "cp")
    assert any("args-from-stdin" in r.reasons for r in replaced.paths)
    assert "/tmp/x" in {r.key for r in replaced.paths}


def test_xargs_of_a_program_without_file_arguments_adds_no_ref(world: dict[str, Any]) -> None:
    echo = by_program(run(world, "ls | xargs echo"), "echo")
    assert echo.paths == ()
    assert echo.gray  # still gray: its arguments are unknown


# --- item 7: file tools -----------------------------------------------------------------------


@pytest.mark.parametrize("name", ["Read", "Write", "Edit", "MultiEdit"])
def test_brackets_in_file_tool_paths_are_literal(world: dict[str, Any], name: str) -> None:
    got = tool(world, name, {"file_path": "app/[id]/page.tsx", "content": "x"})
    ref = got[0].paths[0]
    assert ref.key == world["pk"] + "/app/[id]/page.tsx"
    assert not ref.uncertain
    assert ref.inside_project is True
    assert not got[0].gray


def test_notebook_edit_uses_notebook_path(world: dict[str, Any]) -> None:
    got = tool(world, "NotebookEdit", {"notebook_path": "nb/[x].ipynb", "new_source": "x"})
    assert got[0].paths[0].key == world["pk"] + "/nb/[x].ipynb"
    assert got[0].paths[0].access == "write"
    assert "file_write" in got[0].risk_tags


def test_stars_and_question_marks_are_literal_on_posix_but_not_on_windows() -> None:
    posix = tool(WORLDS["posix"], "Read", {"file_path": "src/*.ts"})[0].paths[0]
    assert posix.key == "/home/bob/proj/src/*.ts"
    assert not posix.uncertain
    win = tool(WORLDS["windows"], "Read", {"file_path": "src\\*.ts"})[0].paths[0]
    assert win.uncertain  # a Windows file name cannot hold "*": it can only be a pattern
    brackets = tool(WORLDS["windows"], "Read", {"file_path": "app\\[id]\\page.tsx"})[0].paths[0]
    assert not brackets.uncertain


@pytest.mark.parametrize(
    "pattern",
    [
        "../../**/*.pem",
        "src/../../x/*",
        "**/../x",
        "[.][.]/x",
        ".[.]/x",
        "{..,x}/y",
        ".{.,x}/y",
        "src\\..\\x",
        "~/.ssh/*",
        "/etc/*",
        "\\\\srv\\share\\*",
        "C:/Users/*",
        "$HOME/*",
    ],
)
def test_a_glob_pattern_that_carries_a_location_is_a_path(
    world: dict[str, Any], pattern: str
) -> None:
    got = tool(world, "Glob", {"pattern": pattern})[0]
    assert got.gray
    assert "glob-pattern-path" in got.gray_reasons
    assert len(got.paths) == 2
    assert got.paths[1].uncertain
    assert got.inside_project is None


@pytest.mark.parametrize(
    "pattern", ["**/*.py", "src/**/*.ts", "*.md", "a..b/*", "[ab]/x", "{a,b}/x"]
)
def test_a_plain_glob_pattern_is_not_a_path(world: dict[str, Any], pattern: str) -> None:
    got = tool(world, "Glob", {"pattern": pattern, "path": "src"})[0]
    assert not got.gray
    assert [r.key for r in got.paths] == [world["pk"] + "/src"]
    assert got.inside_project is True


def test_a_glob_pattern_is_relative_to_the_path_parameter(world: dict[str, Any]) -> None:
    got = tool(world, "Glob", {"pattern": "../x/*", "path": "src"})[0]
    assert got.paths[1].key in (
        world["pk"] + "/x/*",
        world["pk"] + "/src/../x/*",
        world["pk"] + "/x/*",
    )
    unknown = tool(world, "Glob", {"pattern": "../x/*", "path": "$NOPE/src"})[0]
    assert unknown.gray


def test_grep_glob_parameter_and_path_are_handled_like_glob(world: dict[str, Any]) -> None:
    got = tool(world, "Grep", {"pattern": "secret", "glob": "../../*.pem"})[0]
    assert got.gray
    assert "glob-pattern-path" in got.gray_reasons
    plain = tool(world, "Grep", {"pattern": "x", "glob": "*.py", "path": "app/[id]"})[0]
    assert not plain.gray
    assert plain.paths[0].key == world["pk"] + "/app/[id]"
    assert plain.paths[0].access == "read"
    omitted = tool(world, "Grep", {"pattern": "x"})[0]
    assert [r.key for r in omitted.paths] == [world["pk"]]
    outside = tool(world, "Grep", {"pattern": "x", "path": "../.."})[0]
    assert outside.inside_project is False
    assert tool(world, "Glob", {"pattern": "*.py"})[0].paths[0].key == world["pk"]


def test_search_without_any_directory_is_gray() -> None:
    event = {"tool_name": "Glob", "tool_input": {"pattern": "*"}}
    got = norm_event(WORLDS["posix"], event)
    assert got[0].gray
    assert got[0].gray_reasons == ("no-search-directory",)


# --- item 8: project root sanity --------------------------------------------------------------


@pytest.mark.parametrize(
    "root",
    [
        pytest.param("home", id="home"),
        pytest.param("parent-of-home", id="parent-of-home"),
        pytest.param("root", id="filesystem-root"),
    ],
)
def test_a_too_broad_project_root_never_says_inside(world: dict[str, Any], root: str) -> None:
    posix = world["platform"] == "posix"
    project = {
        "home": world["home"],
        "parent-of-home": "/home" if posix else "C:\\Users",
        "root": "/" if posix else "C:\\",
    }[root]
    got = norm_event(
        world,
        payload(
            world,
            "Read",
            {"file_path": world["home"] + ("/x" if posix else "\\x")},
            project=project,
        ),
    )
    assert got[0].inside_project is None
    assert got[0].paths[0].inside_project is None


def test_a_normal_project_root_is_still_inside(world: dict[str, Any]) -> None:
    got = tool(world, "Read", {"file_path": "src/app.py"})
    assert got[0].inside_project is True


def test_a_unc_share_root_is_too_broad() -> None:
    w = WORLDS["windows"]
    event = payload(w, "Read", {"file_path": "\\\\srv\\share\\x"}, project="\\\\srv\\share")
    assert norm_event(w, event)[0].inside_project is None


def test_a_git_root_that_is_the_home_directory_is_ignored(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    (Path(w["home"]) / ".git").mkdir()
    event = {"tool_name": "Read", "tool_input": {"file_path": "x.py"}, "cwd": w["cwd"]}
    got = norm_event(w, event)
    assert got[0].inside_project is None
    (Path(w["cwd"]) / ".git").mkdir()
    got = norm_event(w, event)
    assert got[0].inside_project is True


def test_home_defaults_to_the_environment_when_not_given(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    event = payload(w, "Read", {"file_path": "x.py"}, project=w["home"])
    got = normalize_event(event, platform=w["platform"], env=w["env"])
    assert got[0].inside_project is None


# --- item 9: ".." after a symlink -------------------------------------------------------------


def test_dotdot_paths_also_get_the_ref_the_kernel_would_follow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w = WORLDS["posix"]
    seen: list[str] = []

    def fake_realpath(p: str) -> str:
        seen.append(p)
        return "/etc/x" if p.endswith("link/../x") else p

    monkeypatch.setattr(ev, "_posix_host", lambda: True)
    monkeypatch.setattr(ev, "_realpath", fake_realpath)
    got = run(w, "cat link/../x")
    cat = by_program(got, "cat")
    assert {r.key for r in cat.paths} == {"/home/bob/proj/x", "/etc/x"}
    escape = next(r for r in cat.paths if r.key == "/etc/x")
    assert escape.inside_project is False
    assert "dotdot-after-symlink" in escape.reasons
    assert cat.inside_project is False
    assert "/home/bob/proj/link/../x" in seen
    read = tool(w, "Read", {"file_path": "~/a/link/../x"})
    assert read[0].paths[0].key == "/home/bob/a/x"
    assert any(p == "/home/bob/a/link/../x" for p in seen)


def test_the_dotdot_ref_is_skipped_without_dotdot_or_off_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(ev, "_realpath", lambda p: calls.append(p) or p)
    monkeypatch.setattr(ev, "_posix_host", lambda: True)
    run(WORLDS["posix"], "cat a/b x..y ./z")
    assert calls == [] or all(".." not in c.split("/") for c in calls)
    monkeypatch.setattr(ev, "_posix_host", lambda: False)
    calls.clear()
    run(WORLDS["posix"], "cat a/../b")
    assert calls == []
    monkeypatch.setattr(ev, "_posix_host", lambda: True)
    run(WORLDS["windows"], "cat a/../b")  # a Windows flavor path: Win32 collapses ".." itself
    assert calls == []
    run(WORLDS["posix"], "cat $NOPE/../b")  # uncertain: nothing to follow
    assert calls == []


@pytest.mark.posix
def test_a_real_symlink_followed_by_dotdot_escapes_the_project(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "secret").write_text("s", encoding="utf-8")
    os.symlink(outside / "deep", Path(w["cwd"]) / "link", target_is_directory=True)
    got = run(w, "cat link/../secret")
    cat = by_program(got, "cat")
    assert key_of(outside / "secret") in {r.key for r in cat.paths}
    assert cat.inside_project is False


@pytest.mark.windows
def test_a_junction_followed_by_dotdot_is_collapsed_by_win32_itself(tmp_path: Path) -> None:
    import _winapi  # type: ignore[import-not-found,unused-ignore]

    w = real_world(tmp_path)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    try:
        _winapi.CreateJunction(str(outside / "deep"), str(Path(w["cwd"]) / "junc"))
    except OSError as exc:
        pytest.skip(f"cannot create a junction here: {exc}")
    got = run(w, "cat junc/x")
    assert key_of(outside / "deep" / "x") in keys(got)


# --- item 10: unknown hosts -------------------------------------------------------------------


def test_an_unparseable_host_makes_the_command_gray(world: dict[str, Any]) -> None:
    got = run(world, "curl http://[bad")
    curl = by_program(got, "curl")
    assert curl.network
    assert curl.gray
    assert "unparseable-url" in curl.gray_reasons
    ok = by_program(run(world, "curl https://github.com/x"), "curl")
    assert "unparseable-url" not in ok.gray_reasons
    assert ok.domains == ("github.com",)


# --- item 11: HOME and friends reassigned -----------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "HOME=/tmp cat ~/.ssh/id_rsa",
        "HOME=/tmp; cat ~/.ssh/id_rsa",
        "export HOME=/tmp; cat ~/x",
        "export -n HOME=/tmp",
        "declare -x HOME=/tmp",
        "env HOME=/tmp cat ~/x",
        "PWD=/x ls",
        "OLDPWD=/x; cd -",
        "unset HOME; cat ~/x",
        "read HOME",
        "printf -v HOME x",
        "home=/x ls",
        "local PWD=/x",
    ],
)
def test_reassigning_home_pwd_or_oldpwd_makes_the_line_gray(
    world: dict[str, Any], command: str
) -> None:
    got = run(world, command)
    assert "home-reassigned" in reasons(got), command


@pytest.mark.parametrize(
    "command",
    ["FOO=1 ls", "echo HOME=/x", "export FOO=/x", "HOMEDIR=/x ls", "cd ~ && ls"],
)
def test_other_assignments_do_not_trigger_the_home_check(
    world: dict[str, Any], command: str
) -> None:
    assert "home-reassigned" not in reasons(run(world, command))


def test_the_real_home_is_still_checked_when_home_is_reassigned(world: dict[str, Any]) -> None:
    got = run(world, "HOME=/tmp cat ~/.ssh/id_rsa")
    assert world["hk"] + "/.ssh/id_rsa" in keys(got)


def test_cdpath_assignment_makes_cd_unknown(world: dict[str, Any]) -> None:
    got = run(world, "export CDPATH=/etc; cd x; cat .env")
    assert "cdpath-assigned" in reasons(got)
    assert "cwd-unknown" in by_program(got, "cat").gray_reasons


# --- item 12: write then execute --------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "echo 'cat ~/.ssh/id_rsa' > x.sh; bash x.sh",
        "echo x > x.sh && chmod +x x.sh && ./x.sh",
        "echo x > Makefile && make",
        "echo x > Makefile; make all",
        "echo x > x.sh; source x.sh",
        "echo x > x.sh; . ./x.sh",
        "echo x | tee x.py; python3 x.py",
        "cp a b.sh; sh b.sh",
        "echo x > x.sh; bash *.sh",
        "echo x > x.sh; (cd . && bash x.sh)",
        "echo x > x.sh; bash -c 'bash x.sh'",
        "echo x > run.js; node run.js",
        "echo x > package.json && npm run build",
        "echo x > x.sh; sudo bash x.sh",
        "echo x > ../x.sh; bash ../x.sh",
        "echo x > ~/x.sh; bash ~/x.sh",
        "echo x > x.sh; exec ./x.sh",
    ],
)
def test_executing_a_file_written_earlier_on_the_line_is_gray(
    world: dict[str, Any], command: str
) -> None:
    got = run(world, command)
    assert "exec-of-written-file" in reasons(got), command


@pytest.mark.parametrize(
    "command",
    [
        "echo x > notes.txt; cat notes.txt",
        "echo x > x.sh; ls x.sh",
        "bash x.sh",
        "bash x.sh; echo x > x.sh",
        "echo x > a.sh; bash b.sh",
        "echo x > Makefile.bak; make",
        "make",
    ],
)
def test_reads_and_unrelated_executions_are_not_flagged(
    world: dict[str, Any], command: str
) -> None:
    assert "exec-of-written-file" not in reasons(run(world, command)), command


# --- item 13: budgets -------------------------------------------------------------------------


def test_a_long_cd_chain_is_cut_off_quickly_and_is_gray(world: dict[str, Any]) -> None:
    command = "cd src && " * 700 + "ls"
    started = time.perf_counter()
    got = run(world, command)
    assert time.perf_counter() - started < 2.0
    assert len(got) <= ev.MAX_ACTIONS + ev.MAX_LEXICAL_ACTIONS + 1
    assert got[-1].gray
    assert "normalize-budget-exceeded" in got[-1].gray_reasons


def test_a_very_long_cd_chain_on_the_real_disk_is_bounded(tmp_path: Path) -> None:
    w = real_world(tmp_path)
    started = time.perf_counter()
    got = run(w, "cd src && " * 1500 + "ls")
    assert time.perf_counter() - started < 2.0
    assert "normalize-budget-exceeded" in got[-1].gray_reasons


def test_an_expired_time_budget_returns_one_gray_action(world: dict[str, Any]) -> None:
    for got in (
        tool(world, "Read", {"file_path": "x"}, budget_s=0.0),
        tool(world, "Glob", {"pattern": "*"}, budget_s=0.0),
    ):
        assert len(got) == 1
        assert got[0].gray
        assert "normalize-budget-exceeded" in got[0].gray_reasons
    # A shell line keeps being classified (lexically) after the budget: one action per command
    # plus the gray marker, which comes last (review M-1).
    got = run(world, "echo a; echo b", budget_s=0.0)
    assert [a.program for a in got[:-1]] == ["echo", "echo"]
    assert got[-1].gray
    assert "normalize-budget-exceeded" in got[-1].gray_reasons


def test_actions_so_far_are_kept_when_the_budget_runs_out(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([0.0, 0.0, 0.0, 99.0] + [99.0] * 100)
    real = time.monotonic
    monkeypatch.setattr(ev.time, "monotonic", lambda: next(clock, 99.0))
    got = run(world, "echo a; echo b; echo c; echo d")
    monkeypatch.setattr(ev.time, "monotonic", real)
    assert 1 <= len(got) <= 5  # (the commands after the cut-off are classified lexically)
    assert got[-1].gray_reasons[0] == "normalize-budget-exceeded"
    assert got[0].program == "echo"


def test_more_than_256_commands_are_cut_off(world: dict[str, Any]) -> None:
    got = run(world, "echo a; " * 300)
    assert len(got) == ev.MAX_ACTIONS + 1  # (the same action again adds nothing)
    assert got[-1].gray_reasons[0] == "normalize-budget-exceeded"
    assert all(a.program == "echo" for a in got[:-1])


def test_the_number_of_disk_lookups_per_request_is_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = real_world(tmp_path)
    calls: list[str] = []
    real = paths.resolve_on_disk

    def counting(p: paths.NormPath) -> paths.NormPath:
        calls.append(p.key)
        return real(p)

    monkeypatch.setattr(paths, "resolve_on_disk", counting)
    words = " ".join(f"f{i}" for i in range(100))
    got = run(w, f"cat {words}")
    looked_up = [c for c in calls if c != w["pk"]]  # (the project root is looked up on its own)
    assert len(looked_up) <= ev.MAX_DISK_KEYS
    assert got[-1].gray
    assert got[-1].gray_reasons == ("normalize-budget-exceeded", "budget:disk-lookups")
    calls.clear()
    got = run(w, "cat x " + " ".join(["x"] * 50) + "; cat x")
    assert [c for c in calls if c != w["pk"]] == [w["pk"] + "/x"]  # looked up once per request
    assert "normalize-budget-exceeded" not in reasons(got)


def test_deep_keys_are_not_resolved_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = real_world(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(paths, "resolve_on_disk", lambda p: calls.append(p.key) or p)
    deep = "/".join(["a"] * 70)
    got = run(w, f"cat {deep}")
    assert [c for c in calls if c != w["pk"]] == []
    ref = by_program(got, "cat").paths[0]
    assert ref.uncertain
    assert "path-too-deep" in ref.reasons
    assert ref.inside_project is None


def test_too_many_refs_are_cut_off(world: dict[str, Any]) -> None:
    got = run(world, "; ".join(["cat /a/{a,b,c,d,e,f,g,h}"] * 200))
    assert got[-1].gray_reasons == ("normalize-budget-exceeded", "budget:paths")
    assert len(got) < 200


def test_find_git_root_does_not_touch_the_disk_for_network_and_device_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("disk touched")

    monkeypatch.setattr(os.path, "exists", boom)
    monkeypatch.setattr(os.path, "lexists", boom)
    monkeypatch.setattr(os.path, "realpath", boom)
    for cwd in (
        "\\\\10.255.255.1\\share\\proj",
        "//10.255.255.1/share/proj",
        "\\\\?\\UNC\\10.255.255.1\\share\\proj",
        "\\\\?\\C:\\proj",
        "\\\\.\\C:\\proj",
        "\\\\.\\pipe\\x",
        "relative/dir",
        "",
        "C:\\x\x00y",
    ):
        assert ev.find_git_root(cwd) is None, cwd
    foreign = "/home/x" if IS_WIN else "C:\\Users\\bob"
    assert ev.find_git_root(foreign) is None
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": "x"},
        "cwd": "\\\\10.255.255.1\\share\\p",
    }
    started = time.perf_counter()
    got = norm_event(WORLDS["windows"], event)
    assert time.perf_counter() - started < 2.0
    assert got[0].inside_project is None


def test_find_git_root_ignores_network_drives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert ev.find_git_root(str(sub)) == str(tmp_path)
    monkeypatch.setattr(paths, "_drive_type", lambda letter: 4)
    if IS_WIN:
        assert ev.find_git_root(str(sub)) is None


def test_find_git_root_walks_at_most_16_levels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deep = tmp_path.joinpath(*["d"] * 30)
    deep.mkdir(parents=True)
    probed: list[str] = []
    real = os.path.exists
    monkeypatch.setattr(os.path, "exists", lambda p: probed.append(str(p)) or real(p))
    assert ev.find_git_root(str(deep)) is None
    assert len(probed) <= ev.MAX_GIT_WALK == 16


def test_find_git_root_never_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise OSError("boom")

    monkeypatch.setattr(os.path, "exists", boom)
    assert ev.find_git_root(str(tmp_path)) is None
    monkeypatch.setattr(os.path, "abspath", boom)
    assert ev.find_git_root(str(tmp_path)) is None


# --- the rest of the assembler (previously covered through the pipeline only) -----------------


def test_powershell_commands_go_through_the_parser_helper(world: dict[str, Any]) -> None:
    got = run(world, "Get-ChildItem", tool="PowerShell")
    assert got
    assert all(action.shell == "powershell" for action in got)
    if sys.platform == "win32":
        assert got[0].program is not None
        assert got[0].program.lower() == "get-childitem"
    else:  # no PowerShell here: the helper is unavailable and the command is gray, never allowed
        assert all(action.gray for action in got)
        assert any(r.startswith("ps-helper") for a in got for r in a.gray_reasons)


@pytest.mark.parametrize(
    ("event", "reason"),
    [
        ({}, "no-tool-name"),
        ({"tool_name": 7}, "no-tool-name"),
        ({"tool_name": ""}, "no-tool-name"),
        ({"tool_name": "Bash"}, "no-tool-input"),
        ({"tool_name": "Bash", "tool_input": "x"}, "no-tool-input"),
        ({"tool_name": "Bash", "tool_input": {}}, "no-command"),
        ({"tool_name": "Bash", "tool_input": {"command": 3}}, "no-command"),
        ({"tool_name": "Read", "tool_input": {}}, "no-file-path"),
        ({"tool_name": "Read", "tool_input": {"file_path": "  "}}, "no-file-path"),
        ({"tool_name": "Write", "tool_input": {"file_path": 3}}, "no-file-path"),
        ({"tool_name": "WebFetch", "tool_input": {}}, "no-url"),
        ({"tool_name": "Mystery", "tool_input": {}}, "unknown-tool"),
        ({"tool_name": "mcp__srv__tool", "tool_input": {}}, "mcp-tool-not-reviewed"),
        ({"tool_name": "Bash", "tool_input": {"command": ""}}, "no-command"),
    ],
)
def test_malformed_and_unknown_events_are_gray(
    world: dict[str, Any], event: dict[str, Any], reason: str
) -> None:
    got = norm_event(world, event)
    assert got
    assert got[0].gray
    assert reason in got[0].gray_reasons


def test_mcp_tool_names_are_split(world: dict[str, Any]) -> None:
    got = norm_event(world, {"tool_name": "mcp__srv__do_it", "tool_input": {}})[0]
    assert (got.mcp_server, got.mcp_tool) == ("srv", "do_it")
    short = norm_event(world, {"tool_name": "mcp__", "tool_input": {}})[0]
    assert short.mcp_server is None


def test_web_and_harmless_tools(world: dict[str, Any]) -> None:
    fetch = tool(world, "WebFetch", {"url": "https://github.com/x", "prompt": "p"})[0]
    assert fetch.domains == ("github.com",)
    assert fetch.network
    assert not fetch.gray
    bad = tool(world, "WebFetch", {"url": "http://[bad", "prompt": "p"})[0]
    assert bad.gray
    assert "unparseable-url" in bad.gray_reasons
    assert tool(world, "WebSearch", {"query": "x"})[0].gray is False
    assert tool(world, "ToolSearch", {"query": "x"})[0].gray is False


def test_oversized_and_non_string_fields_are_ignored(world: dict[str, Any]) -> None:
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": "x"},
        "cwd": "x" * (ev._MAX_TEXT + 1),
        "session_id": 5,
        "permission_mode": "plan",
        "agent_id": "a1",
    }
    got = norm_event(world, event)[0]
    assert got.cwd is None
    assert got.session_id is None
    assert (got.permission_mode, got.agent_id) == ("plan", "a1")


def test_shell_line_tail_reasons(world: dict[str, Any]) -> None:
    got = run(world, "echo $(cat ~/x")
    assert got[-1].gray
    got = run(world, "eval 'ls'")
    assert any("exec" in r for a in got for r in a.gray_reasons)
    assert any("exec" in a.risk_tags for a in got)
    got = run(world, "curl https://github.com/x.sh | sh")
    assert any(a.gray for a in got)
    assert any("network_egress" in a.risk_tags for a in got)


def test_assignment_only_commands_and_redirect_only_commands(world: dict[str, Any]) -> None:
    got = run(world, "X=1")
    assert got[0].program is None
    got = run(world, "> ~/.bashrc")
    assert got[0].program is None
    assert got[0].paths[0].access == "write"
    assert "file_write" in got[0].risk_tags


def test_normalize_event_never_raises(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("bug")

    monkeypatch.setattr(ev, "_dispatch", boom)
    got = run(world, "ls")
    assert len(got) == 1
    assert got[0].gray
    assert got[0].gray_reasons == ("internal-error:RuntimeError",)


def test_actions_of_an_event_share_the_base_fields(world: dict[str, Any]) -> None:
    event = payload(world, "Bash", {"command": "ls; cat x"})
    event["session_id"] = "s1"
    got = norm_event(world, event)
    assert {a.session_id for a in got} == {"s1"}
    assert {a.cwd for a in got} == {world["cwd"]}
    assert {a.command_text for a in got} == {"ls; cat x"}
    assert {a.platform for a in got} == {world["platform"]}


def test_dedupe_of_identical_path_refs(world: dict[str, Any]) -> None:
    cat = by_program(run(world, "cat x x ./x"), "cat")
    assert [r.key for r in cat.paths].count(world["pk"] + "/x") <= 2


def test_helper_dynamic_word_rules() -> None:
    from boundkeep.normalize.model import Word

    assert not ev._dynamic(Word("~/x", expands=True))
    assert not ev._dynamic(Word("$HOME/x", expands=True))
    assert not ev._dynamic(Word("${HOME}/x", expands=True))
    assert not ev._dynamic(Word("$PWD/x", expands=True))
    assert ev._dynamic(Word("$HOMEX/x", expands=True))
    assert ev._dynamic(Word("$HOME_/x", expands=True))
    assert ev._dynamic(Word("${HOME:-x}", expands=True))
    assert ev._dynamic(Word("$(x)", expands=True))
    assert ev._dynamic(Word("`x`", expands=True))
    assert ev._dynamic(Word("*.c", glob=True))
    assert not ev._dynamic(Word("plain"))
    assert ev._dynamic(Word("$", expands=True))


def test_the_extra_kwarg_default_budget_is_generous_for_normal_use(
    world: dict[str, Any],
) -> None:
    started = time.perf_counter()
    for _ in range(20):
        run(world, "cd src && cat a.py b.py | grep x > out.txt; git status")
    assert (time.perf_counter() - started) / 20 < ev.TIME_BUDGET_S
