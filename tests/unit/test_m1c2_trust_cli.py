"""M1c-2: ``boundkeep trust add|remove|list`` and the doctor ``trusted-projects`` check.

Everything runs against a temporary boundkeep home and a temporary user home (USERPROFILE / HOME),
never the real ``~/.boundkeep`` or ``~/.claude``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from boundkeep import cli, doctor, fsperm, paths, trust
from boundkeep.policy import PolicyError, default_policy_text, load_policy

Run = Callable[..., tuple[int, str, str]]


@dataclass
class Env:
    boundkeep_home: Path
    user_home: Path
    projects: Path
    policy: Path
    run: Run


def _write_policy(path: Path, text: str, *, bom: bool = False, newline: str = "\n") -> None:
    data = text.replace("\n", newline).encode("utf-8")
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + data)


@pytest.fixture
def env(
    boundkeep_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> Env:
    user = tmp_path / "user"
    projects = user / "work"
    projects.mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(user))
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    # these tests are a person at a terminal: when the suite itself runs inside Claude Code the
    # variables that mark an agent's process are inherited, and `trust add` rightly refuses them
    for name in trust.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    boundkeep_home.mkdir()
    policy = boundkeep_home / "policy.yaml"
    _write_policy(policy, default_policy_text())
    monkeypatch.setattr(trust, "_stdin_is_tty", lambda: True)

    def run(*argv: str) -> tuple[int, str, str]:
        capsys.readouterr()
        code = cli.main(["--home", str(boundkeep_home), *argv])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return Env(boundkeep_home, user, projects, policy, run)


def _make_link(target: Path, link: Path) -> None:
    """A directory symlink, or a junction on Windows when symlinks need a privilege."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if sys.platform != "win32":
            pytest.skip("cannot create symlinks here")
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    if result.returncode != 0:
        pytest.skip("cannot create symlinks or junctions here")


def _project(env: Env, name: str = "proj") -> Path:
    path = env.projects / name
    path.mkdir(exist_ok=True)
    return path


def _entries(env: Env) -> list[str]:
    return trust.read_entries(str(env.policy))


# ---------------------------------------------------------------------------- pure text editing


SAMPLE = (
    "# header comment\n"
    "version: 1\n"
    "\n"
    "# the mode\n"
    "mode: enforce   # trailing\n"
    "\n"
    "defaults:\n"
    "  emit_allow: false\n"
)


def test_add_creates_the_key_right_after_version_and_changes_nothing_else() -> None:
    new = trust.add_entry_text(SAMPLE, r"C:\Users\x\proj")
    block = f'\n{trust.KEY_COMMENT}\ntrusted_projects:\n  - "C:\\\\Users\\\\x\\\\proj"\n'
    assert new == SAMPLE.replace("version: 1\n", "version: 1\n" + block, 1)
    assert yaml.safe_load(new)["trusted_projects"] == [r"C:\Users\x\proj"]


def test_add_keeps_comments_inside_an_existing_block_and_appends_after_the_last_item() -> None:
    text = (
        "version: 1\n"
        "trusted_projects:   # mine\n"
        "  # first one\n"
        '  - "/a/one"   # note\n'
        "  # between\n"
        "  - '/a/two'\n"
        "\n"
        "mode: enforce\n"
    )
    new = trust.add_entry_text(text, "/a/three")
    assert new == text.replace("  - '/a/two'\n", "  - '/a/two'\n  - \"/a/three\"\n")
    assert trust.entries_of(new) == ["/a/one", "/a/two", "/a/three"]


def test_items_at_the_indent_of_the_key_are_understood() -> None:
    text = 'version: 1\ntrusted_projects:\n- "/a/one"\nmode: enforce\n'
    new = trust.add_entry_text(text, "/a/two")
    assert new == 'version: 1\ntrusted_projects:\n- "/a/one"\n- "/a/two"\nmode: enforce\n'


def test_an_empty_flow_list_becomes_a_block_and_back() -> None:
    text = "version: 1\ntrusted_projects: []  # none yet\nmode: enforce\n"
    added = trust.add_entry_text(text, "/a/one")
    assert added == 'version: 1\ntrusted_projects: # none yet\n  - "/a/one"\nmode: enforce\n'
    (index,) = [i for i, _v in trust._layout(added).items]
    assert trust.remove_entries_text(added, {index}) == text.replace("[]  #", "[] #")


def test_unusual_forms_are_refused_not_guessed() -> None:
    for text in (
        "version: 1\ntrusted_projects: [/a/one]\n",
        "version: 1\ntrusted_projects: null\n",
        "version: 1\ntrusted_projects:\n  - {a: b}\n",
        "version: 1\ntrusted_projects:\n  - a\n  b: c\n",
        "mode: enforce\n",  # no version line
        "version: 1\ntrusted_projects:\n  - /a\ntrusted_projects:\n  - /b\n",
    ):
        with pytest.raises(trust.TrustEditError):
            trust.add_entry_text(text, "/x")


def test_a_file_without_a_final_newline_and_with_mixed_endings_is_kept() -> None:
    text = "version: 1\r\nmode: enforce\nlast: 1"
    new = trust.add_entry_text(text, "/a/one")
    assert new.endswith("\nlast: 1")
    assert new.startswith("version: 1\r\n\r\n#")  # the new lines follow their neighbour's ending
    only_version = trust.add_entry_text("version: 1", "/a/one")
    assert only_version.endswith('- "/a/one"')
    assert only_version.startswith("version: 1\n")


def test_quoting_escapes_backslashes_and_quotes_and_refuses_control_characters() -> None:
    new = trust.add_entry_text(SAMPLE, 'C:\\Users\\a "b"\\p')
    assert trust.entries_of(new) == ['C:\\Users\\a "b"\\p']
    with pytest.raises(trust.TrustEditError):
        trust.add_entry_text(SAMPLE, "/a\nb")


# ---------------------------------------------------------------------------- CLI round trips


def test_add_list_remove_round_trip_with_a_realistic_policy(env: Env) -> None:
    before = env.policy.read_bytes()
    proj = _project(env)
    code, out, err = env.run("trust", "add", "--project-dir", str(proj))
    assert code == 0, err
    canonical = trust.canonical_dir(str(proj))
    assert f"trusted: {canonical}" in out
    assert trust.WARNING in out
    assert _entries(env) == [canonical]
    assert load_policy(str(env.policy), home=str(env.user_home)).mode == "enforce"

    code, out, _ = env.run("trust", "list")
    assert code == 0
    assert "exists" in out
    assert canonical in out

    code, out, err = env.run("trust", "remove", "--project-dir", str(proj))
    assert code == 0, err
    assert "no longer trusted" in out
    assert _entries(env) == []
    # Only the trusted_projects block differs from the original (an empty "[]" key is left).
    expected = before.replace(
        b"version: 1\n", f"version: 1\n\n{trust.KEY_COMMENT}\ntrusted_projects: []\n".encode(), 1
    )
    assert env.policy.read_bytes() == expected


def test_two_projects_and_removing_one_keeps_the_other(env: Env) -> None:
    a, b = _project(env, "a"), _project(env, "b")
    assert env.run("trust", "add", "--project-dir", str(a))[0] == 0
    assert env.run("trust", "add", "--project-dir", str(b))[0] == 0
    assert _entries(env) == [trust.canonical_dir(str(a)), trust.canonical_dir(str(b))]
    assert env.run("trust", "remove", "--project-dir", str(a))[0] == 0
    assert _entries(env) == [trust.canonical_dir(str(b))]


def test_default_project_dir_is_the_current_directory(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(env)
    monkeypatch.chdir(proj)
    assert env.run("trust", "add")[0] == 0
    assert _entries(env) == [trust.canonical_dir(str(proj))]
    assert env.run("trust", "remove")[0] == 0
    assert _entries(env) == []


def test_list_without_the_key_says_so_and_exits_zero(env: Env) -> None:
    code, out, _ = env.run("trust", "list")
    assert code == 0
    assert "no trusted projects" in out


def test_list_marks_missing_directories(env: Env) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    proj.rmdir()
    code, out, _ = env.run("trust", "list")
    assert code == 0
    assert "missing" in out


def test_a_vanished_directory_can_still_be_removed(env: Env) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    proj.rmdir()
    code, _out, err = env.run("trust", "remove", "--project-dir", str(proj))
    assert code == 0, err
    assert _entries(env) == []


def test_re_adding_is_idempotent_and_leaves_the_file_alone(env: Env) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    before = env.policy.read_bytes()
    code, out, _ = env.run("trust", "add", "--project-dir", str(proj))
    assert code == 0
    assert "already trusted" in out
    assert env.policy.read_bytes() == before


def test_removing_an_absent_entry_is_a_note_not_an_error(env: Env) -> None:
    proj = _project(env)
    before = env.policy.read_bytes()
    code, out, _ = env.run("trust", "remove", "--project-dir", str(proj))
    assert code == 0
    assert "not in the trusted list" in out
    assert env.policy.read_bytes() == before


def test_a_home_relative_entry_written_by_hand_is_recognised(env: Env) -> None:
    proj = _project(env)
    text = env.policy.read_text(encoding="utf-8")
    env.policy.write_text(
        text.replace("version: 1\n", 'version: 1\ntrusted_projects:\n  - "~/work/proj"\n', 1),
        encoding="utf-8",
        newline="",
    )
    code, out, _ = env.run("trust", "add", "--project-dir", str(proj))
    assert code == 0
    assert "already trusted" in out
    assert env.run("trust", "remove", "--project-dir", str(proj))[0] == 0
    assert _entries(env) == []


# ---------------------------------------------------------------------------- refusals


def test_a_nonexistent_directory_is_refused(env: Env) -> None:
    before = env.policy.read_bytes()
    code, _out, err = env.run("trust", "add", "--project-dir", str(env.projects / "nope"))
    assert code == 1
    assert "not an existing directory" in err
    assert env.policy.read_bytes() == before


def test_a_file_is_not_a_project_directory(env: Env) -> None:
    f = env.projects / "f.txt"
    f.write_text("x", encoding="utf-8")
    code, _out, err = env.run("trust", "add", "--project-dir", str(f))
    assert code == 1
    assert "not an existing directory" in err


@pytest.mark.parametrize("where", ["home", "ancestor", "root"])
def test_too_broad_directories_are_refused_and_the_file_is_untouched(env: Env, where: str) -> None:
    target = {
        "home": env.user_home,
        "ancestor": env.user_home.parent,
        "root": Path(env.user_home.anchor),
    }[where]
    before = env.policy.read_bytes()
    code, _out, err = env.run("trust", "add", "--project-dir", str(target))
    assert code == 1
    assert err.strip()
    assert env.policy.read_bytes() == before
    assert not list(env.boundkeep_home.glob(".policy-*.tmp"))


def test_an_unloadable_policy_is_reported_and_left_alone(env: Env) -> None:
    _write_policy(env.policy, "version: 1\nrules:\n  - id: Bad Id\n")
    before = env.policy.read_bytes()
    proj = _project(env)
    for args in (
        ("add", "--project-dir", str(proj)),
        ("remove", "--project-dir", str(proj)),
        ("list",),
    ):
        code, _out, err = env.run("trust", *args)
        assert code == 1
        assert "policy" in err
        assert env.policy.read_bytes() == before


def test_a_missing_policy_file_is_an_error(env: Env) -> None:
    env.policy.unlink()
    code, _out, err = env.run("trust", "add", "--project-dir", str(_project(env)))
    assert code == 1
    assert "policy" in err


def test_a_loader_rejection_leaves_the_file_byte_identical(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject(text: str, *, home: str | None = None) -> object:
        raise PolicyError("trusted_projects[0]: refused by the loader (test)")

    monkeypatch.setattr(trust, "parse_policy_text", reject)
    before = env.policy.read_bytes()
    code, _out, err = env.run("trust", "add", "--project-dir", str(_project(env)))
    assert code == 1
    assert "refused by the loader" in err
    assert env.policy.read_bytes() == before


def test_an_unusual_trusted_projects_form_is_refused_without_touching_the_file(env: Env) -> None:
    text = default_policy_text().replace(
        "version: 1\n", "version: 1\ntrusted_projects: [/a/one]\n", 1
    )
    _write_policy(env.policy, text)
    before = env.policy.read_bytes()
    code, _out, err = env.run("trust", "add", "--project-dir", str(_project(env)))
    assert code == 1
    assert err.strip()
    assert env.policy.read_bytes() == before


def test_add_refuses_without_a_terminal_but_remove_and_list_work(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    monkeypatch.setattr(trust, "_stdin_is_tty", lambda: False)
    before = env.policy.read_bytes()
    other = _project(env, "other")
    code, _out, err = env.run("trust", "add", "--project-dir", str(other))
    assert code == 1
    assert "interactive terminal" in err
    assert env.policy.read_bytes() == before
    assert env.run("trust", "list")[0] == 0
    assert env.run("trust", "remove", "--project-dir", str(proj))[0] == 0


# ---------------------------------------------------------------------------- an agent's process
# X1 review of M1c-2 (H-5): a child the agent starts with Start-Process / `cmd /c start` or
# `< CON` has a REAL console, so the terminal check cannot tell it from a person. The variables
# Claude Code sets in every shell it starts (and that a child inherits) can.


@pytest.mark.parametrize("name", trust.AGENT_ENV)
def test_add_refuses_in_a_process_started_by_claude_code_even_at_a_terminal(
    env: Env, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    proj = _project(env)
    before = env.policy.read_bytes()
    monkeypatch.setenv(name, "1")
    code, out, err = env.run("trust", "add", "--project-dir", str(proj))  # (_stdin_is_tty: True)
    assert code == 1
    assert name in err
    assert "trusted:" not in out
    assert env.policy.read_bytes() == before  # not a byte changed
    assert _entries(env) == []


def test_add_works_again_when_the_variables_are_gone(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(env)
    monkeypatch.setenv("CLAUDECODE", "1")
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 1
    monkeypatch.delenv("CLAUDECODE")
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    assert len(_entries(env)) == 1


@pytest.mark.parametrize("value", ["", "0"])
def test_an_empty_marker_does_not_count_but_zero_does_not_matter(
    env: Env, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    # (the variable is "set" by Claude Code to 1; an empty one is the user's way to clear it)
    proj = _project(env)
    monkeypatch.setenv("CLAUDECODE", value)
    code = env.run("trust", "add", "--project-dir", str(proj))[0]
    assert code == (0 if value == "" else 1)


def test_remove_and_list_are_not_blocked_inside_claude_code(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    monkeypatch.setenv("CLAUDECODE", "1")
    assert env.run("trust", "list")[0] == 0
    assert env.run("trust", "remove", "--project-dir", str(proj))[0] == 0  # (narrowing is safe)


def test_the_agent_marker_names_are_the_ones_claude_code_sets() -> None:
    assert trust.AGENT_ENV == ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")


# ---------------------------------------------------------------------------- file fidelity


@pytest.mark.parametrize(
    ("newline", "bom"), [("\n", False), ("\r\n", False), ("\n", True), ("\r\n", True)]
)
def test_line_endings_and_a_bom_are_kept(env: Env, newline: str, bom: bool) -> None:
    _write_policy(env.policy, default_policy_text(), bom=bom, newline=newline)
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    raw = env.policy.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") == bom
    assert raw.count(b"\r\n") == (raw.count(b"\n") if newline == "\r\n" else 0)
    assert b"\r" not in raw.replace(b"\r\n", b"") if newline == "\r\n" else b"\r" not in raw
    assert _entries(env) == [trust.canonical_dir(str(proj))]
    assert env.run("trust", "remove", "--project-dir", str(proj))[0] == 0
    raw = env.policy.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") == bom
    assert raw.count(b"\r\n") == (raw.count(b"\n") if newline == "\r\n" else 0)


def test_everything_except_the_block_is_byte_identical(env: Env) -> None:
    before = env.policy.read_text(encoding="utf-8")
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    after = env.policy.read_text(encoding="utf-8")
    entry = trust.canonical_dir(str(proj)).replace("\\", "\\\\")
    block = f'\n{trust.KEY_COMMENT}\ntrusted_projects:\n  - "{entry}"\n'
    assert after == before.replace("version: 1\n", "version: 1\n" + block, 1)
    assert after.index("trusted_projects:") < after.index("mode: enforce")


def test_the_policy_keeps_its_own_comments_in_the_default_header(env: Env) -> None:
    proj = _project(env)
    assert env.run("trust", "add", "--project-dir", str(proj))[0] == 0
    after = env.policy.read_text(encoding="utf-8")
    assert after.startswith("# boundkeep default policy")


def test_the_edited_file_is_private(env: Env) -> None:
    assert env.run("trust", "add", "--project-dir", str(_project(env)))[0] == 0
    errors = [p for p in fsperm.check_private(str(env.policy)) if p.severity == "error"]
    assert errors == []
    assert not list(env.boundkeep_home.glob(".policy-*.tmp"))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path spellings")
def test_windows_spellings_of_one_directory_give_one_entry(env: Env) -> None:
    proj = _project(env)
    backslashes = str(proj)
    forward = str(proj).replace("\\", "/")
    shouted = backslashes.upper()
    assert env.run("trust", "add", "--project-dir", backslashes)[0] == 0
    for spelling in (forward, shouted, backslashes + "\\"):
        code, out, _ = env.run("trust", "add", "--project-dir", spelling)
        assert code == 0, spelling
        assert "already trusted" in out, spelling
    assert len(_entries(env)) == 1
    raw = env.policy.read_text(encoding="utf-8")
    assert "\\\\" in raw  # backslashes are escaped in the double-quoted scalar
    assert _entries(env) == [trust.canonical_dir(str(proj))]
    assert env.run("trust", "remove", "--project-dir", forward)[0] == 0
    assert _entries(env) == []


def test_canonical_dir_resolves_a_link_and_dot_segments(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    messy = str(tmp_path / "x" / ".." / "real")
    assert trust.canonical_dir(messy) == trust.canonical_dir(str(real))
    link = tmp_path / "link"
    _make_link(real, link)
    assert trust.canonical_dir(str(link)) == trust.canonical_dir(str(real))


# ---------------------------------------------------------------------------- help


def test_help_lists_trust() -> None:
    parser = cli.build_parser()
    assert "trust" in parser.format_help()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["trust"])  # an action is required
    assert exc.value.code == 2


# ---------------------------------------------------------------------------- doctor


def _doctor(env: Env) -> list[doctor.Check]:
    return doctor.check_trusted_projects(str(env.boundkeep_home))


def _set_entries(env: Env, entries: list[Path]) -> None:
    for entry in entries:
        assert env.run("trust", "add", "--project-dir", str(entry))[0] == 0


def test_doctor_with_no_trusted_projects_is_a_plain_info(env: Env) -> None:
    (check,) = _doctor(env)
    assert check.name == "trusted-projects"
    assert check.status == doctor.INFO
    assert "no trusted projects" in check.detail


def test_doctor_lists_the_count_and_states_the_risk(env: Env) -> None:
    a, b = _project(env, "a"), _project(env, "b")
    _set_entries(env, [a, b])
    checks = _doctor(env)
    assert [c.status for c in checks] == [doctor.INFO, doctor.INFO]
    assert "2 trusted project(s)" in checks[0].detail
    assert "RISK" in checks[1].detail
    assert "unreviewed" in checks[1].detail


def test_doctor_warns_about_a_missing_directory(env: Env) -> None:
    a = _project(env, "a")
    _set_entries(env, [a])
    a.rmdir()
    warns = [c for c in _doctor(env) if c.status == doctor.WARN]
    assert len(warns) == 1
    assert "no longer exists" in warns[0].detail
    assert warns[0].fix


def test_doctor_warns_about_a_redundant_nested_entry(env: Env) -> None:
    outer = _project(env, "outer")
    inner = outer / "inner"
    inner.mkdir()
    _set_entries(env, [outer, inner])
    warns = [c for c in _doctor(env) if c.status == doctor.WARN]
    assert len(warns) == 1
    assert "redundant" in warns[0].detail
    assert warns[0].detail.startswith(trust.canonical_dir(str(inner)))


def test_doctor_warns_about_a_symlink_to_somewhere_else(env: Env) -> None:
    real = _project(env, "real")
    link = env.projects / "link"
    _make_link(real, link)
    text = env.policy.read_text(encoding="utf-8")
    entry = str(link).replace("\\", "\\\\")
    env.policy.write_text(
        text.replace("version: 1\n", f'version: 1\ntrusted_projects:\n  - "{entry}"\n', 1),
        encoding="utf-8",
        newline="",
    )
    warns = [c for c in _doctor(env) if c.status == doctor.WARN]
    assert len(warns) == 1
    assert "symlink or junction" in warns[0].detail


def test_doctor_skips_the_check_when_the_policy_does_not_load(env: Env) -> None:
    _write_policy(env.policy, "version: 1\nrules:\n  - id: Bad Id\n")
    assert _doctor(env) == []


def test_run_checks_includes_the_trusted_projects_check(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor, "check_daemon", lambda _e: [])
    monkeypatch.setattr(doctor, "check_hook_command_self_test", lambda _l: [])
    monkeypatch.setattr(doctor, "check_claude_code", lambda: [])
    names = {
        c.name
        for c in doctor.run_checks(str(env.projects), str(env.boundkeep_home), dir_given=True)
    }
    assert "trusted-projects" in names
    assert paths.policy_file(str(env.boundkeep_home)) == str(env.policy)
