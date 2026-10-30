"""Run samples through the real pipeline, in process, on the fake machines of ``boundkeep test``.

No Claude Code, no daemon, no network and no real disk: the same ``policycli._run_one`` the policy's
own tests use. A sample with platform ``any`` runs on both machines and counts once for each, so
every number is per platform and nothing is merged.

Configurations without an LLM (``OFFLINE_CONFIGS``):

* ``rules-only``: every sample is judged as in a fresh session (the session layer is off).
* ``rules+taint``: every sample gets a session of its own in a real ``SessionStore`` (in memory).
  A sample marked ``tainted`` first gets one PostToolUse of a taint source (the tool its
  ``taint_sources`` label stands for, ``TAINT_SOURCE_TOOLS``), as a hook event would deliver it;
  then its own call is counted and judged in the state the store reports. Its task intent is not
  used: without an LLM nothing reads it.

A gray verdict (the rules cannot say) is what a user would be asked about when no LLM is
configured, so its effective verdict is ``ask`` in both. A PowerShell sample on a host without the
parser helper is skipped and listed, never counted.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from boundkeep import policycli
from boundkeep.evalkit.schema import FAKE_SESSION, Sample
from boundkeep.policy import Policy, default_policy_text, parse_policy_text
from boundkeep.session.facts import FRESH, SessionFacts
from boundkeep.session.store import SessionStore

Machine = Literal["posix", "windows"]
MACHINES: tuple[Machine, ...] = ("windows", "posix")

#: configuration -> whether it can run today (the four ablation rows of PROJECT_SPEC.md section 12)
CONFIGS: dict[str, bool] = {
    "rules-only": True,
    "rules+taint": True,  # M3a: the session layer, no LLM
    "rules+LLM": False,  # M3b
    "rules+LLM+taint": False,  # M3b
}
#: the configurations that need no network and no key: every run measures all of them
OFFLINE_CONFIGS: tuple[str, ...] = ("rules-only", "rules+taint")
#: the tool call a sample's taint source label stands for in its simulated session
TAINT_SOURCE_TOOLS: dict[str, str] = {
    "web-content": "WebFetch",
    "web-search": "WebSearch",
    "mcp": "mcp__eval__tool",
}


@dataclass(frozen=True)
class Outcome:
    sample_id: str
    machine: Machine
    category: str
    label: str
    split: str
    origin: str
    expected: str | None
    raw: str  # the policy's own verdict: allow | gray | ask | deny | error
    effective: str  # what the user meets with no LLM: allow | ask | deny
    rule_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    latency_ms: float
    runs_repo_code: bool = False
    tainted: bool = False  # the session the sample was judged in had read untrusted content


@dataclass
class RunResult:
    config: str
    policy_label: str
    policy_sha256: str
    trusted: bool = False  # the fake machine's project is listed in trusted_projects
    taint_all: bool = False  # every sample was judged in a tainted session (a reference run)
    outcomes: list[Outcome] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (sample id, why)


def effective_verdict(raw: str, config: str) -> str:
    """What a verdict means to the user under ``config``. Gray and error end in a question."""
    if config not in OFFLINE_CONFIGS:
        raise ValueError(f"configuration {config!r} cannot run yet")
    return raw if raw in ("allow", "deny") else "ask"


def _session_for(
    store: SessionStore | None, sample: Sample, machine: Machine, policy: Policy, taint_all: bool
) -> SessionFacts:
    """The session state ``sample`` is judged in (``rules+taint``); fresh without a store."""
    if store is None:
        return FRESH
    sid = f"eval-{sample.id}-{machine}"
    sources = policy.taint.sources
    if sample.tainted or taint_all:
        for label in sample.taint_sources or ("web-content",):
            store.tool_result(sid, TAINT_SOURCE_TOOLS.get(label, "WebFetch"), sources=sources)
    return store.tool_call(sid, sample.tool, sources=sources, window=policy.taint.window)


def machines_for(sample: Sample) -> tuple[Machine, ...]:
    return MACHINES if sample.platform == "any" else (sample.platform,)


def ps_helper_ready() -> bool:
    """Start the PowerShell parser helper and wait a little; True only when it can parse."""
    from boundkeep.normalize import psparse

    psparse.warm_up(wait_s=15)
    return bool(psparse.status().get("state") == "ready")


def _policy_for(policy_file: str | None, machine: Machine, trusted: bool = False) -> Policy:
    if not trusted:
        return policycli._load(policy_file, machine)
    if policy_file is None:
        text = default_policy_text()
    else:
        text = Path(policy_file).read_text(encoding="utf-8")
    block = f"trusted_projects:\n  - '{policycli._FAKE[machine]['project']}'\n"
    if "\nrules:\n" not in text:
        raise ValueError("the policy has no top-level rules: key to put trusted_projects before")
    text = text.replace("\nrules:\n", "\n" + block + "rules:\n", 1)
    return parse_policy_text(text, home=policycli._FAKE[machine]["home"])


def policy_fingerprint(policy_file: str | None) -> tuple[str, str]:
    """(label, sha256 of the policy text) so a report says exactly which rules it measured."""
    if policy_file is None:
        text = default_policy_text()
        label = "policies/default.yaml (shipped)"
    else:
        text = Path(policy_file).read_text(encoding="utf-8")
        label = policy_file
    return label, hashlib.sha256(text.encode("utf-8")).hexdigest()


def run(
    samples: Iterable[Sample],
    *,
    config: str = "rules-only",
    policy_file: str | None = None,
    ps_ready: bool | None = None,
    trusted: bool = False,
    taint_all: bool = False,
) -> RunResult:
    """Every sample on every machine it applies to. Never raises: a pipeline failure is ``error``
    (fail-closed, counts as an ask). ``taint_all`` (``rules+taint`` only) judges every sample, the
    benign ones too, in a session that has just read untrusted content: a reference for what the
    taint layer costs, not an ablation row."""
    if not CONFIGS.get(config, False):
        raise ValueError(f"configuration {config!r} is not available")
    if taint_all and config != "rules+taint":
        raise ValueError("taint_all needs the rules+taint configuration")
    label, digest = policy_fingerprint(policy_file)
    result = RunResult(
        config=config,
        policy_label=label,
        policy_sha256=digest,
        trusted=trusted,
        taint_all=taint_all,
    )
    items = list(samples)
    powershell = any(s.tool == "PowerShell" for s in items)
    if ps_ready is None:
        ps_ready = ps_helper_ready() if powershell else False
    policies = {m: _policy_for(policy_file, m, trusted) for m in MACHINES}
    store = SessionStore(":memory:") if config == "rules+taint" else None
    for machine in MACHINES:  # warm-up: imports, compiled patterns, the first policy lookup
        policycli._run_one(policies[machine], machine, "Bash", {"command": "true"}, None, None)
    for sample in items:
        for machine in machines_for(sample):
            if sample.tool == "PowerShell" and not ps_ready:
                result.skipped.append((sample.id, "PowerShell parser helper not available"))
                continue
            started = time.perf_counter()
            tainted = False
            try:
                session = _session_for(store, sample, machine, policies[machine], taint_all)
                tainted = session.read_untrusted
                review = policycli._run_one(
                    policies[machine],
                    machine,
                    sample.tool,
                    sample.input,
                    None,
                    None,
                    FAKE_SESSION,
                    session,
                )
                raw = str(review.verdict.decision)
                rule_ids = tuple(review.verdict.rule_ids)
                reasons = tuple(review.verdict.reasons)
            except Exception:  # noqa: BLE001 - the pipeline never raises; if it does, fail closed
                raw, rule_ids, reasons = "error", (), ("pipeline error",)
            elapsed = (time.perf_counter() - started) * 1000.0
            result.outcomes.append(
                Outcome(
                    sample_id=sample.id,
                    machine=machine,
                    category=sample.category,
                    label=sample.label,
                    split=sample.split,
                    origin=sample.origin,
                    expected=sample.expected_min_verdict,
                    raw=raw,
                    effective=effective_verdict(raw, config),
                    rule_ids=rule_ids,
                    reasons=reasons,
                    latency_ms=elapsed,
                    runs_repo_code=sample.runs_repo_code,
                    tainted=tainted,
                )
            )
    if store is not None:
        store.close()
    return result
