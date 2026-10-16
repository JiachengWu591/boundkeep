"""Review fixes of milestone M1b for the assembler (normalize/event.py) and the path layer.

PowerShell command lines go through the real parser helper, so those tests run on a Windows host
only (the helper is warmed up by ``conftest``). Nothing here executes the parsed text.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from boundkeep.normalize import event as ev
from boundkeep.normalize import paths
from boundkeep.normalize.model import Word

from .test_norm_event import WORLDS, keys, real_world, run

needs_ps = pytest.mark.skipif(sys.platform != "win32", reason="needs the PowerShell parser helper")

WIN = WORLDS["windows"]
NIX = WORLDS["posix"]


@pytest.fixture(params=[pytest.param("windows", id="win"), pytest.param("posix", id="nix")])
def world(request: pytest.FixtureRequest) -> dict[str, Any]:
    return WORLDS[request.param]


def ps(world: dict[str, Any], command: str, **kwargs: Any) -> Any:
    return run(world, command, tool="PowerShell", **kwargs)


def by_prog(actions: Any, program: str) -> Any:
    return next(a for a in actions if a.program == program)


def refs_of(actions: Any, program: str | None = None) -> list[Any]:
    return [r for a in actions if program is None or a.program == program for r in a.paths]


# --- 1. $PWD follows cd --------------------------------------------------------------------------


@needs_ps
@pytest.mark.parametrize("var", ["$PWD", "${PWD}", '"$PWD', "$pwd", "${pwd}", '"${PWD}'], ids=str)
def test_ps_pwd_after_set_location_is_the_new_directory(var: str) -> None:
    tail = '\\gh\\hosts.yml"' if var.startswith('"') else "\\gh\\hosts.yml"
    actions = ps(WIN, f"Set-Location C:\\Windows; Get-Content {var}{tail}")
    assert "c:/windows/gh/hosts.yml" in keys(actions)
    assert "c:/users/bob/proj/gh/hosts.yml" in keys(actions)  # cd can fail: the old one stays


@needs_ps
def test_ps_pwd_after_cd_is_not_judged_inside_the_project() -> None:
    actions = ps(WIN, "Set-Location C:\\Windows; Remove-Item -Recurse -Force $PWD\\System32")
    assert "c:/windows/system32" in keys(actions)
    remove = by_prog(actions, "remove-item")
    assert remove.inside_project is False


def test_bash_pwd_after_cd_is_the_new_directory(world: dict[str, Any]) -> None:
    want = world["hk"] + "/.config/gh/hosts.yml"
    for var in ("$PWD", "${PWD}", '"$PWD"'):
        actions = run(world, f"cd ~/.config; cat {var}/gh/hosts.yml")
        assert want in keys(actions), var
        assert world["pk"] + "/gh/hosts.yml" in keys(actions)  # cd can fail


def test_bash_pwd_is_case_sensitive(world: dict[str, Any]) -> None:
    # $pwd is an ordinary unset variable in bash: dynamic, never the working directory
    assert ev._dynamic(Word("$pwd/x", expands=True))


def test_uses_pwd_helper() -> None:
    assert ev._uses_pwd("$PWD/x", "bash")
    assert ev._uses_pwd("${PWD}/x", "bash")
    assert not ev._uses_pwd("$pwd/x", "bash")
    assert ev._uses_pwd("$Pwd\\x", "powershell")
    assert ev._uses_pwd("${pWd}\\x", "powershell")
    assert not ev._uses_pwd("$PWD/x", "tool")
    assert not ev._uses_pwd("plain", "powershell")


# --- 2. known PowerShell variables are not dynamic -----------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "$env:USERPROFILE\\x",
        "$ENV:userprofile\\x",
        "${env:USERPROFILE}\\x",
        "$Home\\x",
        "$HOME\\x",
        "${home}\\x",
        "$PWD\\x",
        "$Pwd",
        "$env:NOSUCHVAR\\x",  # accepted here: the path layer marks the unresolved name uncertain
        "$PROFILE",
    ],
)
def test_known_ps_variables_are_not_dynamic(text: str) -> None:
    assert not ev._dynamic(Word(text, expands=True), shell="powershell")  # noqa: S604 - a parameter name, not a subprocess


@pytest.mark.parametrize(
    "text",
    [
        "$HOMEX\\x",
        "$HOME:x",  # a drive-qualified variable name
        "$env:",
        "$env\\x",
        "${env:}",
        "${env:$x}",
        "$x\\y",
        "$(x)",
        "$env:A$x",
        "$HOMEé",
        "$env:Aé",
        "$_",
        "$",
        "${HOME:-x}",
    ],
)
def test_other_ps_dollars_stay_dynamic(text: str) -> None:
    assert ev._dynamic(Word(text, expands=True), shell="powershell")  # noqa: S604 - a parameter name, not a subprocess


def test_bash_variables_are_still_case_sensitive_and_env_colon_is_not_bash() -> None:
    assert ev._dynamic(Word("$Home/x", expands=True))
    assert ev._dynamic(Word("$env:USERPROFILE/x", expands=True))
    assert not ev._dynamic(Word("$HOME/x", expands=True))


@needs_ps
@pytest.mark.parametrize(
    "command",
    [
        "Remove-Item -Recurse $env:USERPROFILE\\proj\\build",
        "Remove-Item -Recurse $Home\\proj\\build",
        "Remove-Item -Recurse ${env:USERPROFILE}\\proj\\build",
        'Remove-Item -Recurse "$env:USERPROFILE\\proj\\build"',
        "Remove-Item -Recurse $HOME\\proj\\build",
    ],
)
def test_project_files_named_through_the_home_variable_are_inside(command: str) -> None:
    actions = ps(WIN, command)
    remove = by_prog(actions, "remove-item")
    assert remove.inside_project is True
    assert not any("dynamic-word" in r.reasons for r in remove.paths)


@needs_ps
def test_an_unknown_env_variable_stays_uncertain_and_keeps_its_name_in_the_key() -> None:
    actions = ps(WIN, "Get-Content $env:NOSUCHVAR\\x")
    ref = refs_of(actions, "get-content")[0]
    assert ref.uncertain
    assert ref.key == "$env:nosuchvar/x"
    assert ref.inside_project is None


@needs_ps
def test_a_junction_under_a_home_variable_path_is_followed(tmp_path: Path) -> None:
    world = real_world(tmp_path)
    outside = tmp_path / "home" / ".ssh"
    outside.mkdir()
    (outside / "config").write_text("x", encoding="utf-8")
    import subprocess

    link = tmp_path / "home" / "proj" / "keys"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
        capture_output=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    via_var = ps(world, "Get-Content $env:USERPROFILE\\proj\\keys\\config")
    via_tilde = ps(world, "Get-Content ~\\proj\\keys\\config")
    wanted = f"{world['hk']}/.ssh/config"
    assert wanted in keys(via_tilde)
    assert wanted in keys(via_var)


# --- 3. cd tracking on a POSIX platform (pwsh on Linux / macOS) ----------------------------------


@needs_ps
@pytest.mark.parametrize("cmdlet", ["Set-Location", "Push-Location", "set-location", "cd", "sl"])
def test_ps_cd_is_tracked_when_the_platform_is_posix(cmdlet: str) -> None:
    actions = ps(NIX, f"{cmdlet} /opt/x; Get-Content ./f")
    assert "/opt/x/f" in keys(actions)


@needs_ps
def test_ps_pop_location_makes_the_directory_unknown_on_a_posix_platform() -> None:
    actions = ps(NIX, "Pop-Location; Get-Content ./f")
    assert "cwd-unknown" in {r for a in actions for r in a.gray_reasons}


# --- 5. -LiteralPath with brackets ---------------------------------------------------------------


@needs_ps
def test_literalpath_brackets_are_a_file_name_not_a_pattern(tmp_path: Path) -> None:
    world = real_world(tmp_path)
    page = tmp_path / "home" / "proj" / "app" / "[id]"
    page.mkdir(parents=True)
    (page / "page.tsx").write_text("x", encoding="utf-8")
    actions = ps(world, "Get-Content -LiteralPath .\\app\\[id]\\page.tsx")
    read = by_prog(actions, "get-content")
    assert "glob-not-expanded" not in read.gray_reasons
    assert f"{world['pk']}/app/[id]/page.tsx" in keys(actions)
    assert read.inside_project is True
    # the same text for -Path is a wildcard: it is still expanded, never assumed literal
    wild = ps(world, "Get-Content -Path .\\app\\[id]\\page.tsx")
    assert by_prog(wild, "get-content").inside_project is None


@needs_ps
def test_literalpath_with_star_stays_a_pattern_on_a_windows_platform(tmp_path: Path) -> None:
    world = real_world(tmp_path)
    actions = ps(world, "Get-Content -LiteralPath .\\*.env")
    read = by_prog(actions, "get-content")
    assert read.inside_project is None  # a Windows name cannot hold "*": stays uncertain


def test_ps_literal_glob_helper() -> None:
    ctx = ev._Ctx("windows", {}, None, None, None, None, {}, ev._Budget(0.0))
    assert ev._ps_literal_glob(ctx, Word("a[1]/b"))
    assert not ev._ps_literal_glob(ctx, Word("a[1]/b", glob=True))
    assert not ev._ps_literal_glob(ctx, Word("a*b"))
    assert not ev._ps_literal_glob(ctx, Word("plain"))
    nix = ev._Ctx("posix", {}, None, None, None, None, {}, ev._Budget(0.0))
    assert ev._ps_literal_glob(nix, Word("a*b"))


# --- 6. PowerShell wildcards match dotfiles ------------------------------------------------------


def _dot_tree(tmp_path: Path) -> dict[str, Any]:
    world = real_world(tmp_path)
    proj = tmp_path / "home" / "proj"
    (proj / ".env").write_text("K=v", encoding="utf-8")
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    (proj / "readme.md").write_text("x", encoding="utf-8")
    return world


@pytest.mark.parametrize(
    ("pattern", "plain", "dotted"),
    [
        ("*env", set(), {".env"}),
        ("*", {"readme.md"}, {".env", ".claude", "readme.md"}),
        (".e*", {".env"}, {".env"}),  # a pattern that names the dot itself always matched
    ],
)
def test_expand_glob_dotfiles_switch(
    tmp_path: Path, pattern: str, plain: set[str], dotted: set[str]
) -> None:
    world = _dot_tree(tmp_path)
    norm = paths.normalize_path(f"{world['cwd']}/{pattern}", cwd=None, home=None, dialect="tool")
    assert {Path(m).name for m in paths.expand_glob(norm).matches} == plain
    assert {Path(m).name for m in paths.expand_glob(norm, dotfiles=True).matches} == dotted


@needs_ps
@pytest.mark.parametrize(
    ("command", "needle"),
    [
        ("Get-Content *env", "/.env"),
        ("Get-Content *.env", "/.env"),
        ("Get-Content *.*", "/.env"),
        ("Get-Content [.]e*", "/.env"),
        ("Select-String X .\\*.*", "/.env"),
        ("Set-Content *\\settings.json x", "/.claude/settings.json"),
        ("Set-Content .\\*\\settings.json x", "/.claude/settings.json"),
        ("Set-Content [.]claude\\settings.json x", "/.claude/settings.json"),
    ],
)
def test_ps_wildcards_reach_dotfiles(tmp_path: Path, command: str, needle: str) -> None:
    world = _dot_tree(tmp_path)
    actions = ps(world, command)
    assert any(k.endswith(needle) for k in keys(actions)), keys(actions)


@needs_ps
def test_bash_globs_still_skip_dotfiles(tmp_path: Path) -> None:
    world = _dot_tree(tmp_path)
    actions = run(world, "cat *env")
    assert not any(k.endswith("/.env") for k in keys(actions))


@needs_ps
def test_a_ps_wildcard_that_matches_nothing_stays_gray(tmp_path: Path) -> None:
    world = _dot_tree(tmp_path)
    actions = ps(world, "Get-Content *nosuchthing")
    assert "glob-not-expanded" in {r for a in actions for r in a.gray_reasons}


# --- 7. $PROFILE and startup folders -------------------------------------------------------------


@needs_ps
@pytest.mark.parametrize("form", ["$PROFILE", "$profile", "${PROFILE}", '"$PROFILE"'])
def test_profile_resolves_to_the_profile_files_on_a_windows_platform(form: str) -> None:
    actions = ps(WIN, f'Add-Content {form} "x"')
    got = keys(actions)
    assert "c:/users/bob/documents/windowspowershell/microsoft.powershell_profile.ps1" in got
    assert "c:/users/bob/documents/powershell/microsoft.powershell_profile.ps1" in got
    assert all(r.access == "write" and not r.uncertain for r in refs_of(actions, "add-content"))


@needs_ps
def test_profile_on_a_posix_platform() -> None:
    actions = ps(NIX, 'Add-Content $PROFILE "x"')
    assert "/home/bob/.config/powershell/Microsoft.PowerShell_profile.ps1" in keys(actions)


@needs_ps
def test_profile_as_an_outfile_target() -> None:
    actions = ps(WIN, "Invoke-WebRequest https://example.com/x -OutFile $PROFILE")
    assert any("microsoft.powershell_profile.ps1" in k for k in keys(actions))


@needs_ps
def test_profile_members_stay_gray() -> None:
    actions = ps(WIN, "Add-Content $PROFILE.CurrentUserAllHosts x")
    assert any(a.gray for a in actions)  # a member of $PROFILE is a dynamic construct


@needs_ps
def test_programdata_defaults_to_the_standard_folder_when_the_env_lacks_it() -> None:
    cmd = 'Copy-Item a.bat "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"'
    actions = ps(WIN, cmd)
    assert any(
        k.startswith("c:/programdata/microsoft/windows/start menu/programs/startup")
        for k in keys(actions)
    )


def test_programdata_default_does_not_override_the_environment() -> None:
    norm = paths.normalize_path(
        "$env:ProgramData\\x",
        cwd=None,
        home=None,
        env={"ProgramData": "D:\\PD"},
        dialect="powershell",
    )
    assert norm.key == "d:/pd/x"
    norm = paths.normalize_path("$env:ProgramData\\x", cwd=None, home=None, dialect="powershell")
    assert norm.key == "c:/programdata/x"
    assert not norm.uncertain
    # no Windows context (a POSIX cwd): nothing is invented
    norm = paths.normalize_path(
        "$env:ProgramData/x", cwd="/home/a", home=None, dialect="powershell"
    )
    assert norm.uncertain


def test_unresolved_env_variable_keeps_its_name_but_streams_are_still_stripped() -> None:
    norm = paths.normalize_path("$env:Nope\\x", cwd=None, home=None, dialect="powershell")
    assert norm.key == "$env:nope/x"
    assert norm.uncertain
    norm = paths.normalize_path("${env:Nope}\\x", cwd=None, home=None, dialect="powershell")
    assert norm.key == "${env:nope}/x"
    assert norm.uncertain
    norm = paths.normalize_path("C:\\a\\f.txt:stream", cwd=None, home=None, dialect="powershell")
    assert norm.key == "c:/a/f.txt"
    assert "ads-stripped" in norm.reasons
    norm = paths.normalize_path("$env:Nope:s\\x", cwd=None, home=None, dialect="powershell")
    assert norm.key == "$env:nope/x"
    assert "ads-stripped" in norm.reasons
