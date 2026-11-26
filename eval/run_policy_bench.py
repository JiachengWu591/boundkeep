"""The policy-compilation benchmark (M4, PROJECT_SPEC.md §8.1).

Run it with ``uv run python eval/run_policy_bench.py``.

Each sentence of eval/policy-compile/cases.yaml goes the way of ``boundkeep policy add``: the send
gate, a backend, the proposal reader and the checks against the shipped default policy (no replay:
the dev-split replay is the same for every case and needs the source checkout). The report goes to
eval/policy-compile-report.md.

    python eval/run_policy_bench.py                    # fake backend: the hand-written answers
    python eval/run_policy_bench.py --only pc-01 pc-09 # some cases
    python eval/run_policy_bench.py --backend configured --confirm --out %TEMP%\\pc-real.md

``--backend configured`` sends every sentence (50 requests) to the LLM backend of YOUR boundkeep
policy, with YOUR key (BOUNDKEEP_LLM_API_KEY) and at YOUR cost; it refuses to start without
``--confirm``. Run it in your own terminal. Its answers are not the hand-written ones, so it has no
expected outcomes: the report lists what came back and leaves the "semantic match" column for a
person to fill in.

Exit code: 0 when every case of a fake-backend run ends as expected, 1 otherwise.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from boundkeep import __version__
from boundkeep.audit import send_gate
from boundkeep.audit.backends import build_proposer
from boundkeep.audit.backends.base import BackendError, ProposerBackend
from boundkeep.audit.backends.fake import FakeBackend
from boundkeep.compiler import checks, proposal
from boundkeep.compiler.prompt import system_prompt
from boundkeep.evalkit.runner import ps_helper_ready
from boundkeep.policy import default_policy_text, load_policy, parse_policy_text

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "policy-compile" / "cases.yaml"
REPORT = ROOT / "policy-compile-report.md"
HOME = "/home/testuser"
OUTCOMES = ("accepted", "refused", "not-usable", "invalid-output", "not-sent", "failed")


@dataclass
class Result:
    case: dict[str, Any]
    outcome: str = "failed"
    codes: list[str] = field(default_factory=list)  # refusal codes / reader code
    warnings: list[str] = field(default_factory=list)
    detail: str = ""
    runs_pass: int = 0
    runs_corrected: int = 0
    runs_fail: int = 0
    rules: list[dict[str, Any]] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def expected(self) -> str:
        return str(self.case.get("expect", ""))

    def matches(self) -> bool:
        want = self.expected
        if want.startswith("refused:"):
            need = set(want.split(":", 1)[1].split(","))
            return self.outcome == "refused" and need <= set(self.codes)
        if self.outcome != want:
            return False
        if want == "accepted":
            return set(self.case.get("warnings", [])) <= set(self.warnings)
        return True


def _clean(text: str, limit: int = 120) -> str:
    out = "".join(ch if ch.isprintable() else "?" for ch in text).replace("|", "\\|")
    return out if len(out) <= limit else out[: limit - 3] + "..."


def _fake_for(case: dict[str, Any]) -> FakeBackend:
    if "answer_text" in case:
        return FakeBackend([str(case["answer_text"])])
    return FakeBackend([json.dumps(case["answer"], ensure_ascii=False)])


def run_case(
    case: dict[str, Any],
    policy_text: str,
    rule_ids: list[str],
    backend: ProposerBackend,
    ps_ready: bool,
    timeout_s: float,
) -> Result:
    result = Result(case)
    started = time.perf_counter()
    try:
        gated = send_gate.gate_policy_request(case["request"], rule_ids, home=HOME)
        if gated.request is None:
            result.outcome, result.detail = "not-sent", gated.refused or ""
            return result
        try:
            answer = backend.propose(gated.request, deadline=time.monotonic() + timeout_s)
        except BackendError as exc:
            result.outcome = "invalid-output" if exc.kind == "invalid_output" else "failed"
            result.codes, result.detail = [exc.kind], exc.detail
            return result
        try:
            prop = proposal.parse_proposal_text(proposal.text_from_json(answer.data))
        except proposal.ProposalError as exc:
            result.outcome, result.codes, result.detail = "not-usable", [exc.code], str(exc)
            return result
        result.rules = [dict(r) for r in prop.rules]
        report = checks.check(
            policy_text, prop, source="bench", ps_ready=ps_ready, note="benchmark", real_home=HOME
        )
        new_runs = [r for r in report.runs if r.new]
        result.runs_pass = sum(1 for r in new_runs if r.outcome == "pass")
        result.runs_corrected = sum(1 for r in new_runs if r.outcome == "corrected")
        result.runs_fail = sum(1 for r in new_runs if r.outcome == "fail")
        result.warnings = sorted({f.code for f in report.findings if f.level == "warn"})
        refusals = [f for f in report.findings if f.level == "refuse"]
        if refusals:
            result.outcome = "refused"
            result.codes = sorted({f.code for f in refusals})
            result.detail = refusals[0].message
        else:
            result.outcome = "accepted"
        return result
    finally:
        result.seconds = time.perf_counter() - started


def _rate(part: int, whole: int) -> str:
    return f"{part}/{whole} ({100 * part / whole:.1f}%)" if whole else "-"


def _rules_text(rules: list[dict[str, Any]]) -> str:
    parts = []
    for rule in rules:
        match = json.dumps(rule.get("match", {}), ensure_ascii=False, separators=(",", ":"))
        parts.append(f"{rule.get('action')} {rule.get('id')} {match}")
    return _clean("; ".join(parts), 220) or "-"


def write_report(
    results: list[Result], out: Path, *, backend_label: str, fake: bool, ps_ready: bool, policy: str
) -> None:
    sent = [r for r in results if r.outcome != "not-sent"]
    valid = [r for r in sent if r.outcome in ("accepted", "refused")]
    dangerous = [r for r in results if r.case.get("dangerous")]
    stopped = [r for r in dangerous if r.outcome != "accepted"]
    runs_total = sum(r.runs_pass + r.runs_corrected + r.runs_fail for r in valid)
    runs_pass = sum(r.runs_pass for r in valid)
    runs_corrected = sum(r.runs_corrected for r in valid)
    accepted = sum(1 for r in valid if r.outcome == "accepted")
    agree = [r for r in results if r.matches()]
    prompt = system_prompt()
    lines = [
        "# Policy-compilation benchmark (M4)",
        "",
        "Generated by `eval/run_policy_bench.py`; the method is in PROJECT_SPEC.md §8.1 and the "
        "cases are `eval/policy-compile/cases.yaml`.",
        "",
        f"- date: {datetime.datetime.now(datetime.UTC).date().isoformat()}",
        f"- boundkeep {__version__}; policy checked against: {policy}",
        f"- backend: {backend_label}",
        f"- system prompt: version {prompt.version}, sha256 {prompt.sha256[:16]}",
        "- PowerShell parser helper: "
        + ("ready" if ps_ready else "not available (PowerShell tests and canaries skipped)"),
        "",
    ]
    if fake:
        lines += [
            "**The answers are hand-written** (`answer` in the cases file). These numbers say how "
            "the checks treat those answers; they say nothing about the quality of any model's "
            "compilation. A run with a real backend is the user's to start (`--backend "
            "configured`, their key and cost).",
            "",
        ]
    lines += [
        "## Metrics",
        "",
        "| metric | value |",
        "|---|---|",
        f"| cases | {len(results)} |",
        f"| sentences refused by the send gate (nothing sent) | {len(results) - len(sent)} |",
        f"| schema-valid answers (reached the checks) / sent | {_rate(len(valid), len(sent))} |",
        f"| accepted (no refusal) / schema-valid | {_rate(accepted, len(valid))} |",
        f"| proposed test runs that pass as written | {_rate(runs_pass, runs_total)} |",
        "| proposed test runs written with the real verdict (the existing policy decides them) | "
        f"{_rate(runs_corrected, runs_total)} |",
    ]
    if fake:
        lines += [
            "| dangerous proposals stopped (`dangerous: true`) | "
            f"{_rate(len(stopped), len(dangerous))} |",
            f"| outcome as expected | {_rate(len(agree), len(results))} |",
        ]
    lines += ["| semantic match (person's review) | not measured: see the review sheet |", ""]
    lines += [
        "## Cases",
        "",
        "| id | category | request | expected | outcome | codes / warnings | as expected | s |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        codes = ", ".join(r.codes)
        if r.warnings:
            codes += (" / " if codes else "") + "warn: " + ", ".join(r.warnings)
        ok = ("yes" if r.matches() else "**NO**") if fake else "-"
        lines.append(
            f"| {r.case['id']} | {r.case.get('category', '')} | {_clean(r.case['request'], 70)} | "
            f"{r.expected if fake else '-'} | {r.outcome} | {_clean(codes, 80) or '-'} | {ok} | "
            f"{r.seconds:.1f} |"
        )
    misses = [r for r in results if fake and not r.matches()]
    lines += ["", "## Cases that did not end as expected", ""]
    if not fake:
        lines.append("Not applicable: a real backend's answers have no expected outcome.")
    elif not misses:
        lines.append("None.")
    for r in misses:
        lines.append(
            f"- {r.case['id']}: expected {r.expected}, got {r.outcome} "
            f"({', '.join(r.codes) or '-'}): {_clean(r.detail, 300)}"
        )
    lines += [
        "",
        "## Review sheet (semantic match, filled in by a person)",
        "",
        "| id | request | rules proposed | matches the request? |",
        "|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.case['id']} | {_clean(r.case['request'], 80)} | {_rules_text(r.rules)} |  |"
        )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--cases", type=Path, default=CASES)
    p.add_argument("--out", type=Path, default=REPORT)
    p.add_argument("--only", nargs="+", metavar="ID")
    p.add_argument("--backend", choices=("fake", "configured"), default="fake")
    p.add_argument(
        "--confirm", action="store_true", help="you accept the cost of --backend configured"
    )
    p.add_argument(
        "--policy-of-backend",
        help="the policy whose llm_audit names the backend (default: boundkeep's own)",
    )
    p.add_argument("--timeout", type=float, default=60.0)
    args = p.parse_args(argv)
    cases = yaml.safe_load(args.cases.read_text(encoding="utf-8"))
    if args.only:
        cases = [c for c in cases if c["id"] in set(args.only)]
    policy_text = default_policy_text()
    rule_ids = [r.id for r in parse_policy_text(policy_text, home=HOME).rules]
    configured: ProposerBackend | None = None
    label = "fake (the hand-written answers of the cases file)"
    if args.backend == "configured":
        if not args.confirm:
            print(  # noqa: T201
                f"--backend configured sends {len(cases)} requests at your cost; add --confirm"
            )
            return 1
        from boundkeep import paths

        policy = load_policy(args.policy_of_backend or paths.policy_file())
        configured, why = build_proposer(policy.llm_audit)
        if configured is None:
            print(  # noqa: T201
                f"no backend: {why}"
            )
            return 1
        label = f"{configured.name}, model {configured.model}, transport {configured.transport}"
    ps_ready = ps_helper_ready()
    results = []
    for case in cases:
        backend = configured if configured is not None else _fake_for(case)
        result = run_case(case, policy_text, rule_ids, backend, ps_ready, args.timeout)
        mark = "" if configured is not None else ("ok" if result.matches() else "MISMATCH")
        print(  # noqa: T201
            f"{case['id']}: {result.outcome} {','.join(result.codes)} {mark}", flush=True
        )
        results.append(result)
    write_report(
        results,
        args.out,
        backend_label=label,
        fake=configured is None,
        ps_ready=ps_ready,
        policy="policies/default.yaml (shipped)",
    )
    print(  # noqa: T201
        f"report: {args.out}"
    )
    if configured is None and any(not r.matches() for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
