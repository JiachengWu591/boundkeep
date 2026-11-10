"""Spec revision 20: in PowerShell ``/dev/null``, ``/dev/zero`` and the like are ordinary paths.

Found by ``test_a_dynamic_word_in_path_position_is_never_dropped`` in the full run of revision 19:
``Remove-Item /dev/zero`` listed no path. The six names Bash treats as harmless devices were
dropped on the PowerShell side too.

Measured on PowerShell 5.1 (a temporary directory mounted as a session drive, made-up files):
``/dev/zero`` is ``\\dev\\zero`` on the current drive. ``Remove-Item /dev/zero`` removed the file,
``Remove-Item -Recurse /dev/null`` the directory, ``Set-Content`` and ``>`` wrote the files, and
``'x' > /dev/tcp/example.com/80`` wrote a file too. Programs started from PowerShell get the text
as written: python, ``curl.exe`` and cmd read it as a path on the current drive; only git treats
``/dev/null`` itself as an empty file.

So the PowerShell dialect lists them: cmdlet path parameters, PowerShell's redirections and the
arguments of external programs. ``/dev/tcp/H/P`` and ``/dev/udp/H/P`` are listed as paths and
keep their network target, so that no verdict gets looser. The Bash dialect is unchanged.

The tree tests use made-up files under ``tmp_path``; nothing is run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from boundkeep.daemon import pipeline
from boundkeep.normalize.model import Redirect, Word
from boundkeep.normalize.programs import CmdInfo, classify
from boundkeep.normalize.psprograms import classify_ps

from .test_m3a_rev17_review_fixes import CLEAN, _result

DEVICES = ["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"]
SOCKETS = [("/dev/tcp/example.com/80", "tcp://example.com"), ("/dev/udp/h.test/53", "udp://h.test")]


def _paths(info: CmdInfo) -> set[tuple[str, str]]:
    return {(w.text, access) for w, access in info.paths}


def _ps(program: str, *args: str, redirects: tuple[Redirect, ...] = ()) -> CmdInfo:
    return classify(program, [Word(a) for a in args], shell="powershell", redirects=redirects)  # noqa: S604 - a dialect


def _bash(program: str, *args: str, redirects: tuple[Redirect, ...] = ()) -> CmdInfo:
    return classify(program, [Word(a) for a in args], shell="bash", redirects=redirects)  # noqa: S604 - a dialect


# --- cmdlets --------------------------------------------------------------------------------------


@pytest.mark.parametrize("device", DEVICES)
@pytest.mark.parametrize(
    ("program", "access"),
    [
        ("Remove-Item", "write"),
        ("Get-Content", "read"),
        ("Set-Content", "write"),
        ("Out-File", "write"),
    ],
)
def test_a_cmdlet_lists_the_device_name_as_a_path(program: str, access: str, device: str) -> None:
    assert (device, access) in _paths(classify_ps(program, [Word(device)]))


@pytest.mark.parametrize("device", DEVICES)
def test_a_quoted_device_name_is_listed_too(device: str) -> None:
    info = classify_ps("Remove-Item", [Word("-Recurse"), Word(device, quoted=True)])
    assert (device, "write") in _paths(info)
    assert "-Recurse" in info.flags


@pytest.mark.parametrize("device", DEVICES)
def test_both_ends_of_a_copy_are_listed(device: str) -> None:
    assert (device, "write") in _paths(classify_ps("Copy-Item", [Word(".env"), Word(device)]))
    assert (device, "read") in _paths(classify_ps("Copy-Item", [Word(device), Word("out.txt")]))


# --- PowerShell's own redirections ----------------------------------------------------------------


@pytest.mark.parametrize("device", DEVICES)
@pytest.mark.parametrize(("op", "access"), [(">", "write"), (">>", "write"), ("2>", "write")])
def test_a_redirection_to_a_device_name_is_a_path(op: str, access: str, device: str) -> None:
    for program in ("Write-Output", "git"):  # a cmdlet and an external program
        info = _ps(program, "status", redirects=(Redirect(op, Word(device)),))
        assert (device, access) in _paths(info), program


def test_a_redirection_to_null_is_still_nothing() -> None:
    for target in ("$null", "$NULL", "${null}"):
        info = _ps("git", "status", redirects=(Redirect("2>", Word(target, expands=True)),))
        assert _paths(info) == set(), target


# --- external programs started from PowerShell ----------------------------------------------------


@pytest.mark.parametrize("device", DEVICES)
def test_an_external_program_lists_the_device_name(device: str) -> None:
    assert (device, "write") in _paths(_ps("curl", "-s", "-o", device, "https://example.com/a"))
    assert (device, "write") in _paths(_ps("curl.exe", "-o", device, "https://example.com/a"))
    assert device in {text for text, _ in _paths(_ps("python", device))}
    assert device in {text for text, _ in _paths(_ps("tar", "-xf", device))}
    assert device in {text for text, _ in _paths(_ps("git", "diff", "--no-index", device, "a.txt"))}


def test_pip_through_python_lists_it_too() -> None:
    """``python -m pip`` is classified through a second accumulator: it reads the same way."""
    ps = _ps("python", "-m", "pip", "install", "-r", "/dev/stdin")
    assert "/dev/stdin" in {text for text, _ in _paths(ps)}
    bash = _bash("python", "-m", "pip", "install", "-r", "/dev/stdin")
    assert "/dev/stdin" not in {text for text, _ in _paths(bash)}


# --- /dev/tcp and /dev/udp ------------------------------------------------------------------------


@pytest.mark.parametrize(("word", "url"), SOCKETS)
def test_a_socket_name_is_a_path_and_keeps_its_network_target(word: str, url: str) -> None:
    for info, access in (
        (classify_ps("Remove-Item", [Word("-Recurse"), Word(word)]), "write"),
        (classify_ps("Get-Content", [Word(word)]), "read"),
        (_ps("Write-Output", "x", redirects=(Redirect(">", Word(word)),)), "write"),
        (_ps("curl", "-o", word, "https://example.com/a"), "write"),
    ):
        assert (word, access) in _paths(info)
        assert url in info.urls
        assert info.network


def test_a_socket_name_with_a_variable_host_is_listed() -> None:
    info = classify_ps("Set-Content", [Word("/dev/tcp/$h/80", expands=True), Word("x")])
    assert ("/dev/tcp/$h/80", "write") in _paths(info)
    assert info.network


# --- the Bash dialect is unchanged ----------------------------------------------------------------


@pytest.mark.parametrize("device", DEVICES)
def test_bash_still_lists_no_path_for_a_device(device: str) -> None:
    assert _paths(_bash("rm", device)) == set()
    assert _paths(_bash("cat", device)) == set()
    assert _paths(_bash("curl", "-s", "-o", device, "https://example.com/a")) == set()
    assert _paths(_bash("git", "status", redirects=(Redirect("2>", Word(device)),))) == set()


@pytest.mark.parametrize(("word", "url"), SOCKETS)
def test_bash_still_reads_a_socket_name_as_network_only(word: str, url: str) -> None:
    for info in (_bash("cat", word), _bash("echo", "x", redirects=(Redirect(">", Word(word)),))):
        assert _paths(info) == set()
        assert url in info.urls
        assert info.network


def test_a_lone_dash_is_still_not_a_path_in_either_dialect() -> None:
    assert _paths(_bash("cat", "-")) == set()
    assert _paths(_ps("python", "-")) == set()


def test_a_device_name_the_shell_expands_is_listed_in_both() -> None:
    """Only the literal names were ever skipped."""
    word = Word("/dev/null", expands=True)
    assert _paths(classify("cat", [word], shell="bash"))  # noqa: S604 - a dialect
    assert _paths(classify_ps("Get-Content", [word]))


# --- verdicts on a real tree ----------------------------------------------------------------------


def _review(tmp_path: Path, command: str, tool: str) -> tuple[str, list[str], pipeline.Review]:
    result = _result(tmp_path, CLEAN, command, tool=tool)
    return str(result.verdict.decision), list(result.verdict.rule_ids), result


def _keys(result: pipeline.Review) -> set[str]:
    return {p.key for a in result.actions for p in a.paths}


@pytest.mark.windows
@pytest.mark.parametrize("device", DEVICES)
def test_powershell_judges_a_device_name_like_the_name_beside_it(
    tmp_path: Path, device: str
) -> None:
    """``/dev/null`` gets what ``/dev/nullx`` gets: before, the first was gray or allowed."""
    for n, shape in enumerate(
        (
            "Remove-Item {}",
            "Remove-Item -Recurse -Force {}",
            "Get-ChildItem {}",
            "git status 2> {}",
            "git diff --no-index {} README.md",
            "Get-Content .env | Out-File {}",
        )
    ):
        got, got_rules, result = _review(tmp_path / f"a{n}", shape.format(device), "PowerShell")
        want, want_rules, _ = _review(tmp_path / f"b{n}", shape.format(device + "x"), "PowerShell")
        assert (got, got_rules) == (want, want_rules), shape
        assert any(key.endswith(":" + device) for key in _keys(result)), (shape, _keys(result))


@pytest.mark.windows
def test_powershell_verdicts_for_the_measured_commands(tmp_path: Path) -> None:
    for n, (command, verdict, rule) in enumerate(
        (
            ("Remove-Item -Recurse /dev/null", "deny", "rm-outside-project"),
            ("Remove-Item /dev/zero", "ask", "ask-delete-outside-project"),
            ("Remove-Item -Recurse -Force /dev/tcp/example.com/80", "deny", "rm-outside-project"),
            ("Get-Content /dev/tcp/example.com/80", "ask", "net-allowlist"),
        )
    ):
        got, rules, _ = _review(tmp_path / str(n), command, "PowerShell")
        assert got == verdict, command
        assert rule in rules, (command, rules)


@pytest.mark.windows
def test_the_cost_git_status_with_a_dev_null_redirection_is_asked_about(tmp_path: Path) -> None:
    """PowerShell 5.1 refuses to run it when the drive has no ``\\dev`` directory (measured)."""
    got, _rules, _ = _review(tmp_path / "ps", "git status 2>/dev/null", "PowerShell")
    assert got == "ask"
    got, rules, _ = _review(tmp_path / "ps2", "git status 2>$null", "PowerShell")
    assert (got, rules) == ("allow", ["allow-git-read-only"])


def test_bash_verdicts_are_what_they_were(tmp_path: Path) -> None:
    got, rules, result = _review(tmp_path / "a", "git status 2>/dev/null", "Bash")
    assert (got, rules) == ("allow", ["allow-git-read-only"])
    assert _keys(result) <= {k for k in _keys(result) if "/dev/" not in k}
    got, rules, result = _review(tmp_path / "b", "rm /dev/zero", "Bash")
    assert (got, rules) == ("gray", [])
    assert _keys(result) == set()
    got, rules, _ = _review(tmp_path / "c", "cat README.md > /dev/tcp/example.com/80", "Bash")
    assert got == "ask"
    assert "net-allowlist" in rules
