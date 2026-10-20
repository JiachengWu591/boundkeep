"""scripts/session_command_stats.py prints counts only: nothing of the transcripts leaks into it."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "session_command_stats.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("session_command_stats", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _line(name: str, tool_input: dict[str, object], cwd: str) -> str:
    block = {"type": "tool_use", "name": name, "input": tool_input}
    return json.dumps({"type": "assistant", "cwd": cwd, "message": {"content": [block]}})


@pytest.fixture
def transcripts(tmp_path: Path) -> Path:
    root = tmp_path / "projects" / "some-project-name"
    root.mkdir(parents=True)
    secret_word = "".join(["pass", "word", "=", "hunter2xyz"])  # built at run time on purpose
    project = "/home/jane-doe-privatename/client-acme-secret-project"
    lines = [
        _line("Bash", {"command": "git status"}, project),
        _line("Bash", {"command": f"echo {secret_word} > notes.txt"}, project),
        _line("Bash", {"command": "my-private-deploy-script.sh --prod"}, project),
        _line("Bash", {"command": "my-private-deploy-script.sh --prod"}, project),
        _line("Read", {"file_path": f"{project}/src/app.py"}, project),
        _line("Read", {"file_path": "/home/jane-doe-privatename/.ssh/id_rsa"}, project),
        _line("mcp__weird__tool", {"x": 1}, project),
        "this line is not json",
    ]
    for _ in range(6):
        lines.append(_line("Bash", {"command": "make build"}, project))
    (root / "session.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path / "projects"


def test_the_output_has_counts_and_none_of_the_transcript_text(transcripts: Path) -> None:
    module = _load()
    out = io.StringIO()
    assert (
        module.main(["--root", str(transcripts), "--min-count", "5", "--since-days", "1"], out) == 0
    )
    text = out.getvalue()
    assert "Bash" in text
    assert "Read" in text
    assert "(other tools)" in text
    assert "verdict distribution" in text
    for leaked in (
        "jane-doe-privatename",
        "client-acme-secret-project",
        "some-project-name",
        "hunter2xyz",
        "notes.txt",
        "app.py",
        "id_rsa",
        "my-private-deploy-script",  # occurs twice, below --min-count
        "mcp__weird__tool",
        "--prod",
    ):
        assert leaked not in text, leaked


def test_a_program_name_is_shown_only_from_min_count_on(transcripts: Path) -> None:
    module = _load()
    shown = io.StringIO()
    module.main(["--root", str(transcripts), "--min-count", "5", "--since-days", "1"], shown)
    assert "make" in shown.getvalue()  # six occurrences
    hidden = io.StringIO()
    module.main(["--root", str(transcripts), "--min-count", "7", "--since-days", "1"], hidden)
    assert "make " not in hidden.getvalue().split("shell programs whose verdict was not allow")[1]


def test_reasons_are_cut_at_the_first_colon() -> None:
    module = _load()
    assert module._reason_kind("ps-exec:Invoke-Expression") == "ps-exec"
    assert module._reason_kind("git-unknown-subcommand:my secret thing") == "git-unknown-subcommand"
    assert module._reason_kind("WEIRD CAPS: x") == "other"


def test_only_plain_program_names_are_kept() -> None:
    module = _load()
    assert module._plain_program("git") == "git"
    assert module._plain_program("C:\\Users\\jane\\bin\\tool.exe") == "tool.exe"
    assert module._plain_program("name with spaces") is None
    assert module._plain_program("$(evil)") is None
    assert module._plain_program(None) is None


def test_a_missing_root_is_reported_and_nothing_else(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load()
    assert module.main(["--root", str(tmp_path / "nope")], io.StringIO()) == 1
    assert "no transcripts" in capsys.readouterr().err


def test_rule_ids_and_blocker_sets_are_printed_without_any_transcript_text(
    transcripts: Path,
) -> None:
    module = _load()
    out = io.StringIO()
    assert (
        module.main(["--root", str(transcripts), "--min-count", "5", "--since-days", "1"], out) == 0
    )
    text = out.getvalue()
    assert "rules behind the non-allow verdicts" in text
    assert "what blocks an allow, per call" in text
    # the ssh private key Read is denied by a rule: its id (a policy name) is shown, its path is not
    assert "no-secret-read" in text or "no-credential-store-read" in text
    assert "id_rsa" not in text
    assert ".ssh" not in text


def test_only_ast_class_names_follow_the_three_detail_kinds() -> None:
    module = _load()
    assert (
        module._reason_detail("ps-compound:AssignmentStatementAst")
        == "ps-compound:AssignmentStatementAst"
    )
    assert (
        module._reason_detail("ps-dynamic:MemberExpressionAst") == "ps-dynamic:MemberExpressionAst"
    )
    assert module._reason_detail("ps-compound:AssignmentStatementAst,IfStatementAst") == (
        "ps-compound:AssignmentStatementAst"
    )
    # anything else after the colon (a name, a path, free text) is never shown
    assert module._reason_detail("ps-dynamic:C:\\Users\\jane\\secret.txt") is None
    assert module._reason_detail("ps-compound:my-private-thing") is None
    assert (
        module._reason_detail("program-path-qualified:E:\\proj\\.venv\\Scripts\\python.exe") is None
    )
    assert module._reason_detail("ps-exec:Invoke-Expression") is None
    assert module._reason_detail("ps-dynamic") is None
