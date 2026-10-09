"""Policy file schema and loader (M0 minimal version; M1 adds rules and tests)."""

from __future__ import annotations

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
from boundkeep.policy.schema import Defaults, Mode, Policy, Taint

__all__ = [
    "MAX_POLICY_BYTES",
    "Defaults",
    "Mode",
    "Policy",
    "PolicyError",
    "Taint",
    "default_policy_text",
    "load_policy",
    "parse_policy_text",
    "set_mode",
    "taint_sources_to_matcher",
    "write_default_policy",
]
