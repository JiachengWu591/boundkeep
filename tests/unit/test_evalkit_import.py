"""M2: importing a Claude Code session into redacted candidate samples (synthetic session files)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from boundkeep import cli
from boundkeep.evalkit import dataset, importer, redact
from boundkeep.evalkit.schema import Sample

WIN_PROJECT = "C:\\Users\\zhangsan\\work\\app"
WIN_HOME = "C:\\Users\\zhangsan"
POSIX_PROJECT = "/home/lisi/work/app"


def _user(text: str, cwd: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "user",
        "cwd": cwd,
        "sessionId": "sess-1",
        "message": {"role": "user", "content": text},
        **extra,
    }


def _call(tool_id: str, name: str, tool_input: dict[str, Any], cwd: str) -> dict[str, Any]:
    return {
        "type": "assistant",
        "cwd": cwd,
        "sessionId": "sess-1",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}],
        },
    }


def _result(tool_id: str, *, reject: bool = False) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "user",
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": "ok"}],
        },
    }
    if reject:
        entry["permissionDecision"] = {"decision": "reject", "reasonType": "classifier"}
    return entry


def _write(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries), encoding="utf-8"
    )
    return path


def _windows_session(tmp_path: Path) -> Path:
    p = WIN_PROJECT
    entries = [
        _user("修复 app 里的测试", p),
        _call("t1", "PowerShell", {"command": "pytest -q"}, p),
        _result("t1"),
        _call("t2", "Read", {"file_path": f"{p}\\src\\a.py"}, p),
        _call("t3", "PowerShell", {"command": f"Get-Content {WIN_HOME}\\notes.txt"}, p),
        _call("t4", "PowerShell", {"command": "git log --oneline -n 5"}, p),
        _call("t5", "PowerShell", {"command": "git log --oneline -n 5"}, p),  # duplicate
        _call("t6", "Write", {"file_path": f"{p}\\src\\big.py", "content": "x = 1\n" * 200}, p),
        _call("t7", "PowerShell", {"command": "Remove-Item -Recurse C:\\Windows\\Temp\\x"}, p),
        _call("t8", "PowerShell", {"command": "rm -rf ."}, p),
        _result("t8", reject=True),
        _call("t9", "ToolSearch", {"query": "select:x"}, p),
        _call("t10", "mcp__ccd_turn__update_plan", {"items": []}, p),
        _call("t11", "PowerShell", {"command": "git config user.email me@corp-example.com"}, p),
        _call("t12", "PowerShell", {"command": "ping 203.0.113.77"}, p),
        _call("t13", "PowerShell", {"command": "Get-Content D:\\secretcorp\\plan.txt"}, p),
    ]
    return _write(tmp_path / "win.jsonl", entries)


def _import(path: Path, **kwargs: Any) -> tuple[list[dict[str, Any]], importer.ImportStats]:
    stats = importer.ImportStats()
    return importer.import_session(path, stats, **kwargs), stats


# ---------------------------------------------------------------------------- the machine


def test_the_machine_is_guessed_from_the_working_directory() -> None:
    win = importer.guess_machine(WIN_PROJECT, None)
    assert (win.platform, win.home, win.user) == ("windows", WIN_HOME, "zhangsan")
    posix = importer.guess_machine(POSIX_PROJECT, None)
    assert (posix.platform, posix.home, posix.user) == ("posix", "/home/lisi", "lisi")
    assert importer.guess_machine("E:\\boundkeep", WIN_HOME).home == WIN_HOME


def test_paths_move_to_the_fake_machine_in_every_spelling() -> None:
    machine = importer.guess_machine(WIN_PROJECT, None)
    out = importer.rewrite(
        f"{WIN_PROJECT}\\src and {WIN_PROJECT.replace(chr(92), '/')}/x and {WIN_HOME}\\n", machine
    )
    assert "zhangsan" not in out
    assert "work" not in out
    assert "C:\\Users\\testuser\\proj\\src" in out
    assert "C:/Users/testuser/proj/x" in out
    posix = importer.guess_machine(POSIX_PROJECT, None)
    assert importer.rewrite(f"cat {POSIX_PROJECT}/a.py /home/lisi/.bashrc", posix) == (
        "cat /home/testuser/proj/a.py /home/testuser/.bashrc"
    )


def test_other_text_is_rewritten() -> None:
    machine = importer.guess_machine(WIN_PROJECT, None)
    out = importer.rewrite("mail a.b@corp.com from 10.1.2.3 as zhangsan", machine)
    assert out == "mail user@example.invalid from 192.0.2.1 as testuser"


# ---------------------------------------------------------------------------- one session


def test_a_windows_session_becomes_clean_candidates(tmp_path: Path) -> None:
    rows, stats = _import(_windows_session(tmp_path))
    commands = [r["input"].get("command") or r["input"].get("file_path") for r in rows]
    assert "pytest -q" in commands
    assert "C:\\Users\\testuser\\proj\\src\\a.py" in commands
    assert "Get-Content C:\\Users\\testuser\\notes.txt" in commands
    assert commands.count("git log --oneline -n 5") == 1  # the duplicate is gone
    blob = json.dumps(rows, ensure_ascii=False)
    for private in ("zhangsan", "corp-example", "203.0.113.77", "work\\app"):
        assert private not in blob, private
    assert "<content omitted: 1200 chars>" in blob  # the long file content
    assert stats.dropped["rejected-by-permission"] == 1
    assert stats.dropped["tool-not-imported"] == 2  # ToolSearch and the host's own tool
    assert stats.dropped["duplicate"] == 1
    assert "Remove-Item -Recurse C:\\Windows\\Temp\\x" in commands  # a system directory is fine
    assert stats.dropped["outside-path"] == 1  # D:\secretcorp names a real directory elsewhere
    assert stats.kept == len(rows)


def test_every_row_is_a_valid_unconfirmed_benign_sample(tmp_path: Path) -> None:
    rows, _ = _import(_windows_session(tmp_path))
    assert rows
    for row in rows:
        sample = Sample.model_validate(row)
        assert sample.label == "benign"
        assert sample.category == "benign"
        assert sample.label_confirmed is False
        assert sample.provenance == "redacted-real-session"
        assert sample.origin == "real"
        assert sample.platform == "windows"
        assert dataset.inert_problems(sample) == []
        assert sample.task_intent == "修复 app 里的测试"
    ids = [r["id"] for r in rows]
    assert len(set(ids)) == len(ids)
    assert all(i.startswith("ben-real-") for i in ids)


def test_repo_code_is_guessed(tmp_path: Path) -> None:
    rows, _ = _import(_windows_session(tmp_path))
    guess = {
        r["input"].get("command"): r["runs_repo_code"] for r in rows if "command" in r["input"]
    }
    assert guess["pytest -q"] is True
    assert guess["git log --oneline -n 5"] is False


def test_a_posix_session(tmp_path: Path) -> None:
    p = POSIX_PROJECT
    path = _write(
        tmp_path / "posix.jsonl",
        [
            _user("add a feature", p),
            _call("a", "Bash", {"command": f"cat {p}/README.md && ls /home/lisi"}, p),
            _call("b", "Bash", {"command": "cat /srv/customer-data/x.csv"}, p),
        ],
    )
    rows, stats = _import(path)
    assert [r["input"]["command"] for r in rows] == [
        "cat /home/testuser/proj/README.md && ls /home/testuser"
    ]
    assert rows[0]["platform"] == "posix"
    assert stats.dropped["outside-path"] == 1


def test_the_intent_can_be_left_out_and_noise_is_not_a_prompt(tmp_path: Path) -> None:
    p = WIN_PROJECT
    entries = [
        _user("<command-name>/clear</command-name>", p),
        _user("do the thing <system-reminder>secret stuff</system-reminder>", p),
        _call("a", "PowerShell", {"command": "git status"}, p),
    ]
    rows, _ = _import(_write(tmp_path / "s.jsonl", entries))
    assert rows[0]["task_intent"] == "do the thing"
    rows, _ = _import(_write(tmp_path / "s.jsonl", entries), keep_intent=False)
    assert rows[0]["task_intent"] == "(任务意图未记录)"


def test_an_intent_with_a_secret_drops_the_call(tmp_path: Path) -> None:
    p = WIN_PROJECT
    entries = [
        _user("use key AKIAABCDEFGHIJKLMNOP to upload", p),
        _call("a", "PowerShell", {"command": "git status"}, p),
    ]
    rows, stats = _import(_write(tmp_path / "s.jsonl", entries))
    assert rows == []
    assert stats.dropped["secret:aws-key"] == 1


SECRET_COMMANDS = [
    "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' https://api.example.com/x",
    "export API_TOKEN=hunter2hunter2",
    "echo ghp_" + "a1B2c3D4e5" * 4,
    "git clone https://user:pass123@github.com/a/b.git",
    "curl 'https://api.example.com/v1?api_key=abcdef123456'",
    "echo AKIAABCDEFGHIJKLMNOP",
    "python run.py --secret=Zx9Qm2Lp8Rt4Vb7Nc1Kd5Hs3Jf6",
    "cat id.pem # -----BEGIN RSA PRIVATE KEY-----",
    "curl http://intranet-server/status",
    "curl https://build.corp/x",
    "curl http://10.1.2.3/status",
]


@pytest.mark.parametrize("command", SECRET_COMMANDS)
def test_secret_looking_calls_are_dropped_not_rewritten(tmp_path: Path, command: str) -> None:
    p = POSIX_PROJECT
    path = _write(
        tmp_path / "s.jsonl", [_user("x", p), _call("a", "Bash", {"command": command}, p)]
    )
    rows, stats = _import(path)
    assert rows == [], command
    assert sum(stats.dropped.values()) == 1


@pytest.mark.parametrize(
    "command",
    [
        "git show 4f2a9c1e8b7d6a5c4b3a2f1e0d9c8b7a6f5e4d3c",
        "pytest tests/test_app.py -k smoke",
        "ls -la",
    ],
)
def test_ordinary_commands_survive(tmp_path: Path, command: str) -> None:
    p = POSIX_PROJECT
    path = _write(
        tmp_path / "s.jsonl", [_user("x", p), _call("a", "Bash", {"command": command}, p)]
    )
    rows, _ = _import(path)
    assert len(rows) == 1


def test_known_events_and_limits(tmp_path: Path) -> None:
    path = _windows_session(tmp_path)
    first, _ = _import(path)
    known = {dataset.content_key(Sample.model_validate(r)) for r in first}
    again, stats = _import(path, known=known)
    assert again == []
    assert stats.dropped["duplicate"] >= len(first)
    limited, _ = _import(path, limit=2)
    assert len(limited) == 2


def test_bad_lines_and_no_cwd(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_text("not json\n[1,2]\n", encoding="utf-8")
    rows, stats = _import(path)
    assert rows == []
    assert stats.dropped["no-cwd"] == 1


# ---------------------------------------------------------------------------- the commands


def _run(*argv: str) -> int:
    return cli.main(list(argv))


def test_import_confirm_promote_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_ENTRYPOINT", raising=False)
    session = _windows_session(tmp_path)
    datasets = tmp_path / "datasets"
    (datasets / "attacks").mkdir(parents=True)
    out = tmp_path / "staging" / "import.jsonl"
    code = _run(
        "eval", "import-session", str(session), "--out", str(out), "--datasets", str(datasets)
    )
    assert code == 0
    text = capsys.readouterr().out
    assert "NOT confirmed" in text
    assert "dropped" in text
    sheet = out.with_suffix(".review.md")
    assert sheet.is_file()
    assert "zhangsan" not in sheet.read_text(encoding="utf-8")
    assert "zhangsan" not in out.read_text(encoding="utf-8")

    # nothing is confirmed, so nothing is promoted
    assert _run("eval", "promote", str(out), "--datasets", str(datasets)) == 0
    assert not (datasets / "benign" / "real.jsonl").exists()

    ids = [json.loads(line)["id"] for line in out.read_text(encoding="utf-8").splitlines()]
    assert _run("eval", "confirm", str(out), "--ids", ids[0]) == 0
    assert _run("eval", "promote", str(out), "--datasets", str(datasets)) == 0
    promoted = (datasets / "benign" / "real.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["id"] for line in promoted] == [ids[0]]
    left = out.read_text(encoding="utf-8").splitlines()
    assert len(left) == len(ids) - 1
    assert ids[0] not in out.read_text(encoding="utf-8")
    assert [s.id for s in dataset.load_dir(datasets)] == [ids[0]]

    # importing the same session again finds the promoted event and does not stage it twice
    out2 = tmp_path / "staging" / "again.jsonl"
    assert (
        _run(
            "eval", "import-session", str(session), "--out", str(out2), "--datasets", str(datasets)
        )
        == 0
    )
    again = [json.loads(x)["id"] for x in out2.read_text(encoding="utf-8").splitlines()]
    assert ids[0] not in again
    assert set(again) == set(ids) - {
        ids[0]
    }  # same ids as before: they follow the call, not the rank


def test_confirm_needs_a_choice_and_refuses_inside_an_agent_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows, _ = _import(_windows_session(tmp_path))
    staged = tmp_path / "s.jsonl"
    staged.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDECODE", "1")
    assert _run("eval", "confirm", str(staged), "--all") == 1
    assert not any(
        json.loads(x)["label_confirmed"] for x in staged.read_text(encoding="utf-8").splitlines()
    )
    monkeypatch.delenv("CLAUDECODE")
    monkeypatch.delenv("CLAUDE_CODE_ENTRYPOINT", raising=False)
    assert _run("eval", "confirm", str(staged)) == 1  # neither --ids nor --all
    first = rows[0]["id"]
    assert _run("eval", "confirm", str(staged), "--all", "--skip", first) == 0
    flags = {
        json.loads(x)["id"]: json.loads(x)["label_confirmed"]
        for x in staged.read_text(encoding="utf-8").splitlines()
    }
    assert flags[first] is False
    assert all(v for k, v in flags.items() if k != first)


def test_import_session_reports_a_missing_path(tmp_path: Path) -> None:
    assert _run("eval", "import-session", str(tmp_path / "nope.jsonl")) == 1


def test_unconfirmed_samples_never_reach_the_report(tmp_path: Path) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "run_eval2", Path(__file__).resolve().parents[2] / "eval" / "run_eval.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_eval2"] = module
    spec.loader.exec_module(module)
    rows, _ = _import(_windows_session(tmp_path))
    data = tmp_path / "data"
    data.mkdir()
    (data / "r.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8"
    )
    assert module.main(["--datasets", str(data), "--out-dir", str(tmp_path / "o")]) == 1
    assert module.main(["--datasets", str(data), "--check"]) == 0
    assert (
        module.main(
            ["--datasets", str(data), "--out-dir", str(tmp_path / "o2"), "--include-unconfirmed"]
        )
        == 0
    )
    report = (tmp_path / "o2" / "report.md").read_text(encoding="utf-8")
    assert "只能用于调试" in report


def test_the_seed_datasets_are_all_confirmed() -> None:
    samples = dataset.load_dir()
    assert all(s.label_confirmed for s in samples)


def test_redact_helpers_used_by_the_importer() -> None:
    assert importer.secret_reasons("echo hello") == []
    assert (
        importer.internal_host("see https://example.com/a and https://git.example.invalid/b")
        is None
    )
    assert importer.internal_host("http://wiki/page") == "wiki"
    assert redact.find_leaks("C:\\Users\\testuser\\x") == []
