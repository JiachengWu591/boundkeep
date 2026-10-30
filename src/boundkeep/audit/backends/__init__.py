"""LLM audit backends: the contract (``base``), the scripted test double (``fake``) and the
OpenAI-compatible adapter (``openai_compatible``). ``anthropic`` is not implemented yet: a policy
that names it gets an auditor that always fails (``on_failure``), never a silent pass.
"""

from __future__ import annotations

from collections.abc import Mapping

from boundkeep.audit.backends.base import AuditBackend
from boundkeep.policy.schema import LlmAudit


def build_backend(
    llm: LlmAudit, env: Mapping[str, str] | None = None
) -> tuple[AuditBackend | None, str | None]:
    """(the backend the policy names, or None; why there is none although one is named)."""
    if llm.backend == "none":
        return None, None
    if llm.backend == "openai_compatible" and llm.openai_compatible is not None:
        from boundkeep.audit.backends.openai_compatible import OpenAICompatibleBackend

        try:
            return OpenAICompatibleBackend(llm.openai_compatible, env=env), None
        except ValueError as exc:
            return None, f"the openai_compatible backend cannot be used ({str(exc)[:120]})"
    if llm.backend == "anthropic":
        return None, "the anthropic backend is not implemented in this boundkeep version"
    return None, f"the {llm.backend} backend has no configuration block"
