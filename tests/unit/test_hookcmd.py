from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from boundkeep import hookcmd, ownhook

BASE_PYTHON = getattr(sys, "_base_executable", sys.executable)


def make_file(tmp_path: Path, *parts: str, content: bytes = b"MZ") -> str:
    path = tmp_path.joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


def test_a_real_interpreter_has_no_problems() -> None:
    assert hookcmd.executable_problems(BASE_PYTHON) == []
    assert hookcmd.interpreter_problems(BASE_PYTHON) == []


@pytest.mark.parametrize("path", ["python.exe", "python", "./python.exe", "..\\python.exe"])
def test_a_relative_path_is_refused(path: str) -> None:
    assert any("absolute" in p for p in hookcmd.executable_problems(path))


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    problems = hookcmd.executable_problems(str(tmp_path / "nope" / "python.exe"))
    assert any("does not exist" in p for p in problems)


def test_a_directory_is_not_an_executable(tmp_path: Path) -> None:
    assert any(
        "not a file" in p or "does not exist" in p
        for p in hookcmd.executable_problems(str(tmp_path))
    )


@pytest.mark.parametrize("folder", ["shims", "SHIMS"])
def test_version_manager_shims_are_refused(tmp_path: Path, folder: str) -> None:
    shim = make_file(tmp_path, "mise", folder, "python.exe")
    assert any("shim" in p for p in hookcmd.executable_problems(shim))


def test_the_microsoft_store_alias_is_refused(tmp_path: Path) -> None:
    alias = make_file(tmp_path, "Microsoft", "WindowsApps", "python.exe")
    assert any("Store" in p for p in hookcmd.executable_problems(alias))


@pytest.mark.windows
@pytest.mark.parametrize("name", ["python.cmd", "python.bat", "python.ps1", "python"])
def test_only_a_real_exe_is_accepted_on_windows(tmp_path: Path, name: str) -> None:
    problems = hookcmd.executable_problems(make_file(tmp_path, "bin", name))
    assert any(".exe" in p for p in problems)


@pytest.mark.posix
def test_a_file_without_the_execute_bit_is_refused_on_posix(tmp_path: Path) -> None:
    path = make_file(tmp_path, "bin", "python")
    os.chmod(path, 0o644)
    assert any("not executable" in p for p in hookcmd.executable_problems(path))


@pytest.mark.parametrize(("output", "expected"), [(b"3 8\n", "3.8"), (b"2 7\n", "2.7")])
def test_an_old_python_is_refused(
    monkeypatch: pytest.MonkeyPatch, output: bytes, expected: str
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr=b"")

    monkeypatch.setattr(hookcmd.subprocess, "run", fake_run)
    problems = hookcmd.interpreter_problems(BASE_PYTHON)
    assert any(expected in p and "3.11" in p for p in problems)


@pytest.mark.parametrize("output", [b"", b"hello\n", b"3\n", b"a b\n"])
def test_something_that_is_not_python_is_refused(
    monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout=output, stderr=b"")

    monkeypatch.setattr(hookcmd.subprocess, "run", fake_run)
    assert any("did not behave like Python" in p for p in hookcmd.interpreter_problems(BASE_PYTHON))


def test_an_interpreter_that_cannot_start_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise OSError("EFTYPE")

    monkeypatch.setattr(hookcmd.subprocess, "run", fake_run)
    assert any("cannot be started" in p for p in hookcmd.interpreter_problems(BASE_PYTHON))


def test_the_default_prefers_the_base_interpreter_over_the_venv_launcher() -> None:
    chosen = hookcmd.default_hook_python()
    assert os.path.isabs(chosen)
    assert hookcmd.interpreter_problems(chosen) == []
    if os.path.normcase(os.path.abspath(sys.executable)) != os.path.normcase(
        os.path.abspath(BASE_PYTHON)
    ):
        # running inside a virtualenv: the base interpreter saves a process hop on every tool call
        assert os.path.normcase(chosen) == os.path.normcase(os.path.abspath(BASE_PYTHON))


def test_the_default_falls_back_to_this_interpreter_when_the_base_is_a_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim = make_file(tmp_path, "mise", "shims", "python.exe")
    monkeypatch.setattr(sys, "_base_executable", shim, raising=False)
    assert os.path.normcase(hookcmd.default_hook_python()) == os.path.normcase(
        os.path.abspath(sys.executable)
    )


def test_resolve_python_style_builds_a_command_the_installer_recognizes() -> None:
    command = hookcmd.resolve_hook_command(hookcmd.STYLE_PYTHON)
    assert command.base_args[:2] == ("-I", "-S")
    assert command.base_args[2] == hookcmd.hook_script_path()
    assert os.path.isfile(command.base_args[2])
    for sub in ownhook.SUBCOMMANDS.values():
        hook = {"type": "command", "command": command.command, "args": command.args_for(sub)}
        assert ownhook.is_own_hook(hook)


def test_resolve_with_a_bad_override_lists_every_reason(tmp_path: Path) -> None:
    shim = make_file(tmp_path, "shims", "python.exe")
    with pytest.raises(hookcmd.HookCommandError) as info:
        hookcmd.resolve_hook_command(hookcmd.STYLE_PYTHON, shim)
    assert any("shim" in p for p in info.value.problems)
    assert shim in str(info.value)


def test_resolve_with_an_unknown_style_is_refused() -> None:
    with pytest.raises(hookcmd.HookCommandError):
        hookcmd.resolve_hook_command("telepathy")


def test_resolve_launcher_style_needs_the_console_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hookcmd, "launcher_path", lambda: str(tmp_path / "boundkeep-hook.exe"))
    with pytest.raises(hookcmd.HookCommandError):
        hookcmd.resolve_hook_command(hookcmd.STYLE_LAUNCHER)
    launcher = make_file(tmp_path, "boundkeep-hook.exe")
    monkeypatch.setattr(hookcmd, "launcher_path", lambda: launcher)
    if sys.platform != "win32":
        os.chmod(launcher, 0o755)  # noqa: S103 - a launcher has to be executable
    command = hookcmd.resolve_hook_command(hookcmd.STYLE_LAUNCHER)
    assert (command.command, command.base_args) == (launcher, ())


def test_command_problems_checks_the_script_too(tmp_path: Path) -> None:
    missing = str(tmp_path / "boundkeep" / "hook_client.py")
    problems = hookcmd.command_problems(BASE_PYTHON, ["-I", "-S", missing, "pre"])
    assert any("hook script" in p and "does not exist" in p for p in problems)
    script = make_file(tmp_path, "boundkeep2", "hook_client.py", content=b"pass\n")
    assert hookcmd.command_problems(BASE_PYTHON, ["-I", "-S", script, "pre"]) == []
