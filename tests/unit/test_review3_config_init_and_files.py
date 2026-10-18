"""Security review round 3 (docs/reviews/M1-M1b-fixes-rereview.md): the ``init`` ordering note (the
manifest is written before the settings file, with a rollback) and the integrity hashes of the
modules the hook client imports (section 4, last bullet).

Everything runs in temp directories: USERPROFILE, HOME and the boundkeep home point at ``tmp_path``
and CLAUDE_CONFIG_DIR is removed, so neither the real ``~/.boundkeep`` nor the real ``~/.claude``
(nor this repository's settings) is read or written.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import boundkeep
from boundkeep import claude_settings, cli, doctor, install, settings_io
from boundkeep import paths as bk_paths
from tests.conftest import scrubbed_env

PACKAGE_DIR = Path(boundkeep.__file__).resolve().parent
SRC_ROOT = PACKAGE_DIR.parent

EXPECTED_MODULES = {
    "hook_client.py",
    "hook_main.py",
    "protocol.py",
    "paths.py",
    "ownhook.py",
    "claude_settings.py",
    "__init__.py",
    "ipc/__init__.py",
    "ipc/client.py",
    "ipc/endpoint.py",
}


def _rel(path: str) -> str:
    return Path(path).resolve().relative_to(PACKAGE_DIR).as_posix()


# ---- init ordering --------------------------------------------------------------------------


@pytest.fixture
def sandbox(
    tmp_path: Path, boundkeep_home: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    """(project dir, settings file) with the user profile redirected into tmp_path."""
    user = tmp_path / "user"
    user.mkdir()
    for name in ("USERPROFILE", "HOME", "APPDATA"):
        monkeypatch.setenv(name, str(user))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    return project, project / ".claude" / "settings.json"


def _init(project: Path) -> int:
    return cli.main(["init", "--project-dir", str(project)])


def test_the_manifest_is_written_before_the_settings_file(
    sandbox: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    project, settings = sandbox
    settings.write_text(json.dumps({"model": "m"}), encoding="utf-8")
    seen: list[dict[str, Any]] = []
    real = settings_io.write_atomic

    def spy(path: str, data: bytes, **kwargs: Any) -> None:
        if Path(path) == settings:
            # what a running session's ConfigChange would compare the new file with
            manifest = json.loads(Path(bk_paths.manifest_file()).read_text(encoding="utf-8"))
            seen.append(manifest["installs"][0])
        real(path, data, **kwargs)

    monkeypatch.setattr(settings_io, "write_atomic", spy)
    assert _init(project) == 0
    [record] = seen
    assert record["settings_path"] == str(settings)
    assert record["watched"][claude_settings.BASELINE_MARK] == claude_settings.BASELINE_VERSION
    assert record["hook_files"]
    # and the ConfigChange check accepts what init wrote, against the manifest that was in place
    from boundkeep import hook_main

    assert hook_main.config_violation(str(settings)) is None


def test_init_wrote_nothing_to_the_manifest_that_the_settings_write_did_not_back(
    sandbox: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project, settings = sandbox
    settings.write_text(json.dumps({"model": "m"}), encoding="utf-8")
    other = install.InstallRecord(
        settings_path=str(project / "elsewhere" / "settings.json"),
        scope="project",
        created_file=False,
        hook_command="C:\\py\\python.exe",
        hook_args=("-I", "-S", "C:\\x\\boundkeep\\hook_client.py"),
        post_matcher="*",
        installed_at="2026-10-18T00:00:00Z",
    )
    manifest_path = bk_paths.manifest_file()
    Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
    install.save_manifest(manifest_path, [other])
    before = Path(manifest_path).read_bytes()
    settings_before = settings.read_bytes()
    real = settings_io.write_atomic

    def failing(path: str, data: bytes, **kwargs: Any) -> None:
        if Path(path) == settings:
            raise OSError("disk full (injected)")
        real(path, data, **kwargs)

    monkeypatch.setattr(settings_io, "write_atomic", failing)
    assert _init(project) == 1
    assert "injected" in capsys.readouterr().err
    assert Path(manifest_path).read_bytes() == before  # rolled back, byte for byte
    assert settings.read_bytes() == settings_before


def test_a_failed_first_init_leaves_no_manifest_at_all(
    sandbox: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    project, settings = sandbox
    real = settings_io.write_atomic

    def failing(path: str, data: bytes, **kwargs: Any) -> None:
        if Path(path) == settings:
            raise OSError("injected")
        real(path, data, **kwargs)

    monkeypatch.setattr(settings_io, "write_atomic", failing)
    assert _init(project) == 1
    assert not os.path.exists(bk_paths.manifest_file())
    assert not settings.exists()


def test_init_again_with_a_changed_pin_that_fails_restores_the_previous_record(
    sandbox: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    project, settings = sandbox
    assert _init(project) == 0
    manifest_path = Path(bk_paths.manifest_file())
    first = manifest_path.read_bytes()
    first_settings = settings.read_bytes()
    policy = Path(bk_paths.policy_file())
    policy.write_text(
        policy.read_text(encoding="utf-8").replace("emit_allow: false", "emit_allow: true"),
        encoding="utf-8",
    )
    real = settings_io.write_atomic

    def failing(path: str, data: bytes, **kwargs: Any) -> None:
        if Path(path) == settings:
            raise OSError("injected")
        real(path, data, **kwargs)

    monkeypatch.setattr(settings_io, "write_atomic", failing)
    assert _init(project) == 1
    assert manifest_path.read_bytes() == first
    assert settings.read_bytes() == first_settings


def test_an_unchanged_init_still_refreshes_the_record(sandbox: tuple[Path, Path]) -> None:
    project, settings = sandbox
    assert _init(project) == 0
    manifest_path = Path(bk_paths.manifest_file())
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    doc["installs"][0]["watched"] = {}
    manifest_path.write_text(json.dumps(doc), encoding="utf-8")
    before = settings.read_bytes()
    assert _init(project) == 0
    assert settings.read_bytes() == before
    again = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert claude_settings.BASELINE_MARK in again["installs"][0]["watched"]


def test_init_records_the_modules_the_hook_client_imports(sandbox: tuple[Path, Path]) -> None:
    project, _settings = sandbox
    assert _init(project) == 0
    doc = json.loads(Path(bk_paths.manifest_file()).read_text(encoding="utf-8"))
    names = {_rel(f["path"]) for f in doc["installs"][0]["hook_files"] if f["path"].endswith(".py")}
    assert names >= EXPECTED_MODULES


def test_init_warns_about_a_look_alike_it_cannot_replace(
    sandbox: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    project, settings = sandbox
    imitation = {
        "type": "command",
        "command": "C:\\evil\\boundkeep-hook.exe",
        "args": ["pre"],
    }
    settings.write_text(json.dumps({"hooks": {"Stop": [{"hooks": [imitation]}]}}), encoding="utf-8")
    assert _init(project) == 0
    out = capsys.readouterr().out
    assert "looks like boundkeep's" in out


def test_init_words_present_command_running_entries_as_the_recorded_baseline(
    sandbox: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    project, settings = sandbox
    settings.write_text(
        json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "x"}]}]}}),
        encoding="utf-8",
    )
    assert _init(project) == 0
    out = capsys.readouterr().out
    assert "SessionStart hook that is not boundkeep's" in out
    assert "records it as the baseline" in out


def test_init_warns_about_a_blanket_allow_with_the_measured_wording(
    sandbox: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    project, settings = sandbox
    settings.write_text(json.dumps({"permissions": {"allow": ["PowerShell(*)"]}}), encoding="utf-8")
    assert _init(project) == 0
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "observed on 2026-10-18 (Claude Code CLI engine, -p mode)" in out
    assert "behaviour in other modes/hosts is untested" in out


# ---- hook_files: the modules the client imports ----------------------------------------------


def _real_command() -> install.HookCommand:
    return install.HookCommand(sys.executable, ("-I", "-S", str(PACKAGE_DIR / "hook_client.py")))


def test_hook_files_cover_the_modules_hook_main_imports() -> None:
    files = install.hook_files_for(_real_command())
    names = {_rel(f.path) for f in files if f.path.endswith(".py")}
    assert names >= EXPECTED_MODULES
    assert len({os.path.normcase(f.path) for f in files}) == len(files)  # no file twice
    assert all(len(f.sha256) == 64 for f in files)
    assert files[0].path == sys.executable  # the interpreter first, as before


def test_every_boundkeep_module_the_client_really_loads_is_in_the_list(tmp_path: Path) -> None:
    """Measured, not guessed: start the client's own import chain under ``python -I -S``, take what
    ends up in ``sys.modules``, and compare it with the computed list. ConfigChange imports
    ``claude_settings`` lazily, so that path is exercised as well."""
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    code = (
        "import sys, os\n"
        f"sys.path.append({str(SRC_ROOT)!r})\n"
        "from boundkeep import hook_main\n"
        "hook_main.config_violation(sys.argv[1])\n"
        "for name, mod in sorted(sys.modules.items()):\n"
        "    f = getattr(mod, '__file__', None)\n"
        "    if f and (name == 'boundkeep' or name.startswith('boundkeep.')):\n"
        "        print(os.path.abspath(f))\n"
    )
    env = scrubbed_env({"BOUNDKEEP_HOME": str(tmp_path / "bk-home")})
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code, str(settings)],
        capture_output=True,
        env=env,
        check=False,
        timeout=60,
        encoding="utf-8",
    )
    assert result.returncode == 0, result.stderr
    loaded = {os.path.normcase(os.path.abspath(p)) for p in result.stdout.splitlines() if p}
    assert loaded, result.stdout
    listed = {
        os.path.normcase(os.path.abspath(f.path)) for f in install.hook_files_for(_real_command())
    }
    assert loaded <= listed, sorted(loaded - listed)
    assert any(p.endswith("claude_settings.py") for p in loaded)  # the lazy import was exercised


def _fake_package(tmp_path: Path) -> Path:
    package = tmp_path / "boundkeep"
    (package / "ipc").mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "0"\n', encoding="utf-8")
    (package / "hook_client.py").write_text("# client\n", encoding="utf-8")
    (package / "hook_main.py").write_text(
        "from boundkeep import __version__, ownhook\n"
        "from boundkeep.ipc import client as c\n"
        "import json\n"
        "def f():\n"
        "    from boundkeep import lazy_one\n"
        "    import boundkeep.lazy_two\n",
        encoding="utf-8",
    )
    (package / "ownhook.py").write_text("X = 1\n", encoding="utf-8")
    (package / "lazy_one.py").write_text("from boundkeep.ipc.deep import D\n", encoding="utf-8")
    (package / "lazy_two.py").write_text("import not_ours\n", encoding="utf-8")
    (package / "ipc" / "__init__.py").write_text("", encoding="utf-8")
    (package / "ipc" / "client.py").write_text(
        "from boundkeep.ipc import endpoint\n", encoding="utf-8"
    )
    (package / "ipc" / "endpoint.py").write_text("Y = 2\n", encoding="utf-8")
    (package / "ipc" / "deep.py").write_text("Z = 3\n", encoding="utf-8")
    (package / "unrelated.py").write_text("W = 4\n", encoding="utf-8")  # imported by nobody
    return package


def test_the_module_list_follows_imports_transitively_including_lazy_ones(tmp_path: Path) -> None:
    package = _fake_package(tmp_path)
    found = {
        Path(p).relative_to(package).as_posix() for p in install.runtime_module_files(str(package))
    }
    assert found == {
        "__init__.py",
        "hook_main.py",
        "ownhook.py",
        "lazy_one.py",
        "lazy_two.py",
        "ipc/__init__.py",
        "ipc/client.py",
        "ipc/endpoint.py",
        "ipc/deep.py",
    }  # not unrelated.py, and no file for the names that are not modules (__version__)


def test_hook_files_for_hashes_the_fake_packages_modules(tmp_path: Path) -> None:
    package = _fake_package(tmp_path)
    exe = tmp_path / "python.exe"
    exe.write_bytes(b"MZ")
    command = install.HookCommand(str(exe), ("-I", "-S", str(package / "hook_client.py")))
    files = install.hook_files_for(command)
    names = [Path(f.path).name for f in files]
    assert names[:3] == ["python.exe", "hook_client.py", "hook_main.py"]
    assert "endpoint.py" in names
    assert not install.hook_file_problems(files)
    (package / "ipc" / "endpoint.py").write_text("Y = 666\n", encoding="utf-8")
    [problem] = install.hook_file_problems(files)
    assert "endpoint.py" in problem
    assert "no longer matches" in problem


def test_an_unparsable_module_is_still_hashed_and_does_not_break_the_list(tmp_path: Path) -> None:
    package = _fake_package(tmp_path)
    (package / "ownhook.py").write_text("def (:\n", encoding="utf-8")
    found = {Path(p).name for p in install.runtime_module_files(str(package))}
    assert "ownhook.py" in found


def test_hook_files_for_refuses_when_an_imported_module_cannot_be_hashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _fake_package(tmp_path)
    exe = tmp_path / "python.exe"
    exe.write_bytes(b"MZ")
    command = install.HookCommand(str(exe), ("-I", "-S", str(package / "hook_client.py")))
    real = install.file_sha256

    def sha(path: str) -> str:
        if path.endswith("endpoint.py"):
            raise PermissionError("locked (injected)")
        return real(path)

    monkeypatch.setattr(install, "file_sha256", sha)
    with pytest.raises(OSError, match="injected"):
        install.hook_files_for(command)


# ---- old records ------------------------------------------------------------------------------


def _record(files: tuple[install.HookFile, ...]) -> install.InstallRecord:
    return install.InstallRecord(
        settings_path="C:\\p\\.claude\\settings.json",
        scope="project",
        created_file=False,
        hook_command=sys.executable,
        hook_args=("-I", "-S", str(PACKAGE_DIR / "hook_client.py")),
        post_matcher="*",
        installed_at="2026-10-18T00:00:00Z",
        hook_files=files,
    )


def test_a_record_with_the_full_list_is_ok_in_doctor_and_quiet_in_the_daemon() -> None:
    record = _record(install.hook_files_for(_real_command()))
    assert install.unrecorded_runtime_files(record) == []
    assert [c.status for c in doctor.check_record_integrity("n", "p", record)] == [doctor.OK]
    assert install.integrity_report([record]) == []


def test_an_old_three_file_record_warns_to_run_init_again() -> None:
    old = _record(install.hook_files_for(_real_command())[:3])  # interpreter, client, hook_main
    uncovered = {_rel(p) for p in install.unrecorded_runtime_files(old)}
    assert {"protocol.py", "paths.py", "ownhook.py", "ipc/client.py"} <= uncovered
    [check] = doctor.check_record_integrity("n", "p", old)
    assert check.status == doctor.WARN
    assert "run 'boundkeep init' again" in check.fix
    assert "protocol.py" in check.detail
    [problem] = install.integrity_report([old])
    assert "older boundkeep" in problem
    assert "boundkeep init" in problem


def test_a_swapped_extra_module_is_a_fail_not_a_warning() -> None:
    files = list(install.hook_files_for(_real_command()))
    index = next(i for i, f in enumerate(files) if f.path.endswith("protocol.py"))
    files[index] = install.HookFile(files[index].path, "0" * 64)
    [check] = doctor.check_record_integrity("n", "p", _record(tuple(files)))
    assert check.status == doctor.FAIL
    assert "protocol.py" in check.detail


def test_a_record_without_any_hashes_keeps_its_own_message() -> None:
    assert install.unrecorded_runtime_files(_record(())) == []
    [check] = doctor.check_record_integrity("n", "p", _record(()))
    assert "no file hashes" in check.detail
