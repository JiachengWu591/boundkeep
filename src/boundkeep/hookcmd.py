"""Choosing and checking the command Claude Code launches for every hook.

A hook command that cannot start is the quietest way to lose the gate: Claude Code treats it as a
non-blocking error, and in the VS Code UI the user is not told at all (M0a E6, E22). So ``init``
writes a resolved, verified, absolute path, and ``doctor`` re-checks it later:

* no shims (mise, pyenv, scoop, asdf: an extra hop that fails with "cannot find binary path");
* no Microsoft Store ``python.exe`` alias (exit code 49, silently allowed);
* no ``.cmd`` / ``.bat`` / ``.ps1`` (exec form spawns a real executable; EINVAL / EFTYPE);
* Python 3.11 or newer.

Default: ``python.exe -I -S <hook_client.py>`` with the BASE interpreter. A virtualenv's
``python.exe`` is a launcher that starts the base interpreter as a child process: an empty
``-I -S`` run took 21 ms with the base interpreter and 39 ms with the virtualenv one (28 ms vs
18 ms in an earlier run), so the base interpreter is preferred (scripts/bench_hook.py).
``-I -S`` ignores PYTHON* variables and site-packages; the hook client needs only the standard
library and puts the package directory on ``sys.path`` itself.
"""

from __future__ import annotations

import os
import subprocess
import sys

import boundkeep
from boundkeep.install import HookCommand

MIN_PYTHON = (3, 11)
STYLE_PYTHON = "python"
STYLE_LAUNCHER = "launcher"
_PROBE = "import sys; print(sys.version_info[0], sys.version_info[1])"
_PROBE_TIMEOUT_S = 15.0


class HookCommandError(Exception):
    """The hook command cannot be used; ``problems`` says why, one reason per item."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def hook_script_path() -> str:
    """The hook_client.py of this installation."""
    return os.path.join(os.path.dirname(os.path.abspath(boundkeep.__file__)), "hook_client.py")


def launcher_path() -> str:
    """Where the ``boundkeep-hook`` console script of this environment lives."""
    name = "boundkeep-hook.exe" if sys.platform == "win32" else "boundkeep-hook"
    return os.path.join(os.path.dirname(os.path.abspath(sys.executable)), name)


def _lowered(path: str) -> str:
    return path.replace("\\", "/").lower()


def executable_problems(path: str) -> list[str]:
    """Why ``path`` is not something Claude Code can spawn directly; [] when it looks fine."""
    problems: list[str] = []
    if not os.path.isabs(path):
        return [f"{path!r} is not an absolute path"]
    if not os.path.isfile(path):
        return [f"{path} does not exist or is not a file"]
    lowered = _lowered(path)
    if "/shims/" in lowered:
        problems.append("it is a version-manager shim (mise, pyenv, scoop, asdf...)")
    if "/windowsapps/" in lowered:
        problems.append("it is a Microsoft Store alias (exits with 49 and the gate stays open)")
    if sys.platform == "win32":
        if os.path.splitext(path)[1].lower() != ".exe":
            problems.append("on Windows the hook command must be a real .exe (no .cmd/.bat/.ps1)")
    elif not os.access(path, os.X_OK):
        problems.append("it is not executable")
    return problems


def interpreter_problems(path: str, *, probe: bool = True) -> list[str]:
    """``executable_problems`` plus: it runs, and it is Python 3.11 or newer."""
    problems = executable_problems(path)
    if problems or not probe:
        return problems
    try:
        result = subprocess.run(  # noqa: S603 - the path was validated above, no shell
            [path, "-I", "-S", "-c", _PROBE],
            capture_output=True,
            timeout=_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"it cannot be started ({type(exc).__name__})"]
    try:
        major, minor = (int(x) for x in result.stdout.decode("ascii").split())
    except (ValueError, UnicodeDecodeError):
        return [f"it did not behave like Python (exit code {result.returncode})"]
    if (major, minor) < MIN_PYTHON:
        return [f"it is Python {major}.{minor}; boundkeep needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+"]
    return []


def default_hook_python() -> str:
    """The interpreter to write by default: the base interpreter when usable, else this one."""
    candidates: list[str] = []
    base = getattr(sys, "_base_executable", None)
    if isinstance(base, str) and base:
        candidates.append(os.path.abspath(base))
    candidates.append(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not interpreter_problems(candidate):
            return candidate
    return candidates[-1]  # let resolve_hook_command report what is wrong with it


def resolve_hook_command(style: str = STYLE_PYTHON, python: str | None = None) -> HookCommand:
    """The verified ``HookCommand`` for ``style``; raises ``HookCommandError`` with the reasons."""
    if style == STYLE_LAUNCHER:
        launcher = launcher_path()
        problems = executable_problems(launcher)
        if problems:
            raise HookCommandError([f"{launcher}: {p}" for p in problems])
        return HookCommand(launcher, ())
    if style != STYLE_PYTHON:
        raise HookCommandError([f"unknown hook style {style!r}"])
    interpreter = os.path.abspath(python) if python else default_hook_python()
    problems = interpreter_problems(interpreter)
    script = hook_script_path()
    if not os.path.isfile(script):
        problems.append(f"the hook script {script} does not exist")
    if problems:
        raise HookCommandError([f"{interpreter}: {p}" for p in problems])
    return HookCommand(interpreter, ("-I", "-S", script))


def command_problems(command: str, args: list[str]) -> list[str]:
    """Problems of an installed hook entry (``doctor``): the command, and the script it runs."""
    problems = executable_problems(command)
    for arg in args[:-1]:
        if arg.lower().endswith("hook_client.py") and not os.path.isfile(arg):
            problems.append(f"the hook script {arg} does not exist")
    return problems
