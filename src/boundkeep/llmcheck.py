"""``boundkeep llm check``: one fixed, harmless request to the configured backend (spec §9.6).

It checks that the backend answers, over the configured transport, with a verdict that passes the
schema, and prints only the conclusion, what was checked (backend, host, model, transport, prompt
version) and the token usage: never the key, never the request or the model's text. The request
describes a made-up action (``Read`` of a README in a made-up project, no taint, a fixed task
intent) and goes through the same send gate as every audit.

Exit code 0 when the backend works, or when no backend is configured (nothing to check); 1 when it
does not, or the policy cannot be read.
"""

from __future__ import annotations

import argparse
import os
import time

from boundkeep import console, paths
from boundkeep.audit.auditor import budget_ms
from boundkeep.audit.backends import build_backend
from boundkeep.audit.backends.base import BackendError
from boundkeep.audit.send_gate import gate
from boundkeep.normalize.model import Action, PathRef
from boundkeep.policy import PolicyError, default_policy_text, load_policy, parse_policy_text
from boundkeep.session.facts import SessionFacts

EXIT_OK = 0
EXIT_PROBLEM = 1
CHECK_INTENT = "check that the boundkeep audit backend answers (a connectivity test)"
_CHECK_PROJECT = "/boundkeep-llm-check/project"


def check_action() -> Action:
    """The made-up action of the check: reading the README of a made-up project."""
    readme = f"{_CHECK_PROJECT}/README.md"
    return Action(
        tool="Read",
        platform="posix",
        project=_CHECK_PROJECT,
        paths=(
            PathRef(raw=readme, key=readme, flavor="posix", access="read", inside_project=True),
        ),
        inside_project=True,
    )


def check_facts() -> SessionFacts:
    """The made-up session of the check: fresh, with one fixed task intent."""
    return SessionFacts(known=True, tainted=False, read_untrusted=False, intents=(CHECK_INTENT,))


def run(args: argparse.Namespace) -> int:
    home = os.path.expanduser("~")
    source = args.policy or paths.policy_file()
    try:
        if args.policy or os.path.exists(source):
            policy = load_policy(source, home=home)
        else:
            source = "the shipped default policy"
            policy = parse_policy_text(default_policy_text(), home=home)
    except (PolicyError, OSError) as exc:
        console.err(f"boundkeep llm check: {exc}")
        return EXIT_PROBLEM
    llm = policy.llm_audit
    if llm.backend == "none":
        console.out(
            "llm check: nothing to check: llm_audit.backend is none in "
            f"{source} (no LLM audit; gray actions ask)"
        )
        return EXIT_OK
    backend, why = build_backend(llm, os.environ)
    if backend is None:
        console.out(f"llm check: FAILED: {why}")
        return EXIT_PROBLEM
    host = getattr(backend, "host", "-")
    console.out(
        f"  backend: {backend.name}, host {host}, model {backend.model}, "
        f"transport {backend.transport}"
    )
    gated = gate(
        (check_action(),),
        tool="Read",
        facts=check_facts(),
        send_task_intent=True,
        intent_prompts=1,
        home=None,
    )
    if gated.request is None:
        console.out(f"llm check: FAILED: the fixed request was refused ({gated.refused})")
        return EXIT_PROBLEM
    request = gated.request
    console.out(f"  prompt: version {request.prompt_version}, {request.prompt_hash[:16]}")
    budget_s = budget_ms(llm) / 1000.0
    started = time.monotonic()
    try:
        result = backend.audit(request, deadline=started + budget_s)
    except BackendError as exc:
        console.out(f"llm check: FAILED: {exc.kind}: {exc.detail}")
        return EXIT_PROBLEM
    except Exception as exc:  # noqa: BLE001 - an adapter bug is a failed check, not a traceback
        console.out(f"llm check: FAILED: internal: {type(exc).__name__}")
        return EXIT_PROBLEM
    finally:
        close = getattr(backend, "close", None)
        if callable(close):
            close()
    elapsed = (time.monotonic() - started) * 1000.0
    verdict = result.verdict
    console.out(
        f"  answer: schema valid (verdict {verdict.verdict}, risk {verdict.risk}), "
        f"{elapsed:.0f} ms, {result.attempts} attempt(s), budget {budget_s:g} s"
    )
    tokens = result.usage.as_record()
    shown = ", ".join(f"{k} {v}" for k, v in tokens.items()) if tokens else "not reported"
    console.out(f"  tokens: {shown}")
    console.out("llm check: ok")
    return EXIT_OK
