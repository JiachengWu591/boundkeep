"""The live half of the contract: the configured real backend answers the fixed request.

Skipped unless ``--live`` is given. It never runs in CI and never in a development agent's session
(the agent holds no key): the user runs it in their own shell, with the key in
``BOUNDKEEP_LLM_API_KEY`` and ``BOUNDKEEP_LIVE_POLICY`` naming a policy whose ``llm_audit`` block
configures the backend. Results are reported per backend, model, version and settings (M3b).
"""

from __future__ import annotations

import os
import time

import pytest

from boundkeep.audit.auditor import budget_ms
from boundkeep.audit.backends import build_backend
from boundkeep.audit.send_gate import gate
from boundkeep.llmcheck import CHECK_INTENT, check_action
from boundkeep.policy import load_policy
from boundkeep.session.facts import SessionFacts


@pytest.mark.live
def test_the_configured_backend_answers_the_fixed_request_with_a_valid_verdict() -> None:
    policy_path = os.environ.get("BOUNDKEEP_LIVE_POLICY")
    if not policy_path:
        pytest.skip("set BOUNDKEEP_LIVE_POLICY to a policy with an llm_audit backend")
    policy = load_policy(policy_path)
    backend, why = build_backend(policy.llm_audit, os.environ)
    assert backend is not None, why
    facts = SessionFacts(known=True, tainted=False, read_untrusted=False, intents=(CHECK_INTENT,))
    gated = gate(
        (check_action(),),
        tool="Read",
        facts=facts,
        send_task_intent=True,
        intent_prompts=1,
        home=None,
    )
    assert gated.request is not None
    result = backend.audit(
        gated.request, deadline=time.monotonic() + budget_ms(policy.llm_audit) / 1000.0
    )
    assert result.verdict.verdict in ("allow", "ask", "deny")
