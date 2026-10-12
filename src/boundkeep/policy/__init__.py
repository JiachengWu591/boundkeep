"""Policy file schema, loader, glob matcher and rule engine (M1)."""

from __future__ import annotations

from boundkeep.policy.glob import Glob, GlobError, compile_glob
from boundkeep.policy.loader import (
    MAX_POLICY_BYTES,
    PolicyError,
    default_policy_text,
    load_policy,
    parse_policy_text,
    set_mode,
    taint_sources_to_matcher,
    write_default_policy,
)
from boundkeep.policy.matcher import (
    ActionVerdict,
    RuleHit,
    Verdict,
    evaluate,
    explain_rule,
    match_rule,
)
from boundkeep.policy.schema import (
    Defaults,
    FrozenMap,
    LlmAudit,
    Match,
    Mode,
    Policy,
    PolicyTest,
    Rule,
    Taint,
)

__all__ = [
    "MAX_POLICY_BYTES",
    "ActionVerdict",
    "Defaults",
    "FrozenMap",
    "Glob",
    "GlobError",
    "LlmAudit",
    "Match",
    "Mode",
    "Policy",
    "PolicyError",
    "PolicyTest",
    "Rule",
    "RuleHit",
    "Taint",
    "Verdict",
    "compile_glob",
    "default_policy_text",
    "evaluate",
    "explain_rule",
    "load_policy",
    "match_rule",
    "parse_policy_text",
    "set_mode",
    "taint_sources_to_matcher",
    "write_default_policy",
]
