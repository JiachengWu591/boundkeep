"""Review M-3: ``hook_client._fail_safe`` must find the sub-command behind ``--home <path>``.

``boundkeep init`` always writes ``--home <path>`` (and, when ``defaults.emit_allow`` is on,
``--emit-allow``) in front of the sub-command. When ``hook_main`` cannot be imported, the fallback
used to read ``sys.argv[1]`` (``--home``): ConfigChange exited 0 and post/prompt printed a
PreToolUse-shaped answer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.e2e

SRC = REPO_ROOT / "src"


def _broken_copy(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    shutil.copytree(
        SRC / "boundkeep", root / "boundkeep", ignore=shutil.ignore_patterns("__pycache__")
    )
    with (root / "boundkeep" / "hook_main.py").open("a", encoding="utf-8") as f:
        f.write("\nraise ImportError('simulated half-finished upgrade')\n")
    return root / "boundkeep" / "hook_client.py"


def _run(
    script: Path, args: list[str], stdin: bytes, env: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-I", "-S", str(script), *args],
        input=stdin,
        capture_output=True,
        env=env,
        check=False,
        timeout=30,
    )


_EVENT = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}).encode()


@pytest.mark.parametrize(
    "prefix",
    [
        pytest.param([], id="no-flags"),
        pytest.param(["--home", "HOME"], id="home"),
        pytest.param(["--home", "HOME", "--emit-allow"], id="home-then-emit-allow"),
        pytest.param(["--emit-allow", "--home", "HOME"], id="emit-allow-then-home"),
        pytest.param(["--emit-allow"], id="emit-allow-only"),
    ],
)
def test_an_unimportable_hook_main_still_blocks_config_and_asks_for_pre(
    tmp_path: Path, hook_env: dict[str, str], prefix: list[str]
) -> None:
    script = _broken_copy(tmp_path)
    home = str(tmp_path / "home")
    flags = [home if part == "HOME" else part for part in prefix]

    pre = _run(script, [*flags, "pre"], _EVENT, hook_env)
    assert pre.returncode == 0
    assert json.loads(pre.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"

    config = _run(script, [*flags, "config"], b"{}", hook_env)
    assert config.returncode == 2, (config.stdout, config.stderr)
    assert config.stdout == b""
    assert b"blocked" in config.stderr

    for sub in ("post", "prompt"):
        quiet = _run(script, [*flags, sub], b"{}", hook_env)
        assert (quiet.returncode, quiet.stdout) == (0, b""), sub


def test_an_unimportable_hook_main_with_an_unknown_flag_does_not_allow_anything(
    tmp_path: Path, hook_env: dict[str, str]
) -> None:
    script = _broken_copy(tmp_path)
    pre = _run(script, ["--bogus", "pre"], _EVENT, hook_env)
    assert pre.returncode == 0
    assert json.loads(pre.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    config = _run(script, ["--bogus", "config"], b"{}", hook_env)
    assert config.returncode == 2


def test_the_package_root_goes_after_the_standard_library_on_sys_path(
    tmp_path: Path, hook_env: dict[str, str]
) -> None:
    """With ``-I -S`` a ``json.py`` inside the package root must not shadow the stdlib."""
    root = tmp_path / "src"
    shutil.copytree(
        SRC / "boundkeep", root / "boundkeep", ignore=shutil.ignore_patterns("__pycache__")
    )
    (root / "json.py").write_text("import os\nos._exit(1)\n", encoding="utf-8")
    script = root / "boundkeep" / "hook_client.py"
    proc = _run(script, ["pre"], _EVENT, hook_env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_the_package_still_imports_from_the_appended_root(
    tmp_path: Path, hook_env: dict[str, str]
) -> None:
    """Appending (not inserting) must not break ``from boundkeep import hook_main``."""
    script = REPO_ROOT / "src" / "boundkeep" / "hook_client.py"
    proc = _run(script, ["--version"], b"", hook_env)
    assert proc.returncode == 0
    assert proc.stdout.startswith(b"boundkeep-hook ")
