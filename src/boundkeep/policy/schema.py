"""The M0 policy schema: four keys, strict, immutable.

A policy file is security configuration, so a typo that is silently ignored (``modee:
audit-only``) would be a silent failure of the gate. Every model therefore forbids unknown keys,
and every field is validated in strict mode (no ``"yes"`` -> ``True`` or ``1.0`` -> ``1``
coercion). M1 extends this schema with rules and tests; M0 only needs what ``init``, ``mode``,
``serve`` and ``doctor`` share:

* ``version``: always ``1``.
* ``mode``: ``enforce`` (decisions go back to Claude Code) or ``audit-only`` (decisions are only
  recorded).
* ``defaults.emit_allow``: whether an ALLOW verdict is emitted as an explicit hook "allow"
  (which skips Claude Code's own confirmation) instead of "no decision".
* ``taint.sources``: tool names (or ``prefix*`` patterns) whose results taint the session. They
  decide the PostToolUse matcher.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

Mode = Literal["enforce", "audit-only"]

MAX_TAINT_SOURCES = 64
MAX_TAINT_SOURCE_LENGTH = 128
DEFAULT_TAINT_SOURCES: tuple[str, ...] = ("WebFetch", "WebSearch", "mcp__*")

# Letters, digits, underscore, hyphen and dot, then at most one trailing "*". An explicit ASCII
# class and ``fullmatch`` (not ``$``, which tolerates a trailing newline, and not ``\w``, which
# matches non-ASCII letters) keep this exact. A bare "*" is rejected: it would taint on every tool
# and is almost certainly a mistake; say "mcp__*" or list the tools instead.
_SOURCE_RE = re.compile(r"[A-Za-z0-9_.\-]+\*?")

_STRICT = ConfigDict(frozen=True, extra="forbid", strict=True)


def _shorten(value: str, limit: int = 40) -> str:
    """A bounded, printable, pure-ASCII rendering of an untrusted string for error messages.

    ``ascii()`` escapes every non-ASCII character, so a look-alike (a Cyrillic "o" in a tool name)
    cannot be mistaken for the real letter in the message.
    """
    body = ascii(value[:limit])[1:-1]  # drop the quotes ascii() adds; we add our own
    return f"'{body}{'...' if len(value) > limit else ''}'"


def check_taint_source(source: object) -> str:
    """Return ``source`` if it is a valid taint source, else raise ``ValueError``.

    Shared by the schema and by ``taint_sources_to_matcher`` so a value that parses can always be
    turned into a matcher, and a value that would not make a safe matcher never parses.
    """
    if not isinstance(source, str):
        raise ValueError("taint source must be a string")
    if not source:
        raise ValueError("taint source must not be empty")
    if len(source) > MAX_TAINT_SOURCE_LENGTH:
        raise ValueError(f"taint source is longer than {MAX_TAINT_SOURCE_LENGTH} characters")
    if _SOURCE_RE.fullmatch(source) is None:
        raise ValueError(
            f"taint source {_shorten(source)} is not allowed: use letters, digits, '_', '-', '.' "
            "and at most one trailing '*' (with at least one character before it)"
        )
    return source


class Defaults(BaseModel):
    model_config = _STRICT

    emit_allow: bool = False


class Taint(BaseModel):
    """Taint sources.

    ``sources`` is a tuple, not a list: a frozen model with a mutable list inside is not frozen
    (any holder of a shared ``Policy`` could append an unvalidated entry, and the model would not
    be hashable). The YAML list is converted before validation.

    Duplicates are silently removed (first occurrence wins, order kept): a repeated name is
    harmless and rejecting it would only annoy, whereas the 64-entry limit is checked on the raw
    list so an absurdly long file is still refused. An empty list is valid (no taint source), but
    it has no PostToolUse matcher: ``taint_sources_to_matcher`` refuses it and callers must
    handle that case themselves (for example by not registering the PostToolUse hook).
    """

    model_config = _STRICT

    # The per-item validator gives errors the index (``sources[1]``); the validator below adds
    # the count limit and the de-duplication.
    sources: tuple[Annotated[str, AfterValidator(check_taint_source)], ...] = DEFAULT_TAINT_SOURCES

    @field_validator("sources", mode="before")
    @classmethod
    def _list_to_tuple(cls, value: Any) -> Any:
        # Strict mode refuses a list for a tuple field, but YAML only produces lists. Convert
        # exactly that type: anything else (a string, a mapping, a tuple smuggled in through
        # model_validate) keeps failing as before.
        return tuple(value) if type(value) is list else value

    @field_validator("sources", mode="after")
    @classmethod
    def _check_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_TAINT_SOURCES:
            raise ValueError(f"at most {MAX_TAINT_SOURCES} taint sources are allowed")
        seen: dict[str, None] = {}
        for entry in value:
            seen.setdefault(entry, None)
        return tuple(seen)


class Policy(BaseModel):
    model_config = _STRICT

    version: Literal[1]
    mode: Mode = "enforce"
    defaults: Defaults = Field(default_factory=Defaults)
    taint: Taint = Field(default_factory=Taint)

    @field_validator("version", mode="before")
    @classmethod
    def _version_is_a_plain_int(cls, value: Any) -> Any:
        # Pydantic's Literal[1] accepts True and 1.0 even in strict mode.
        if type(value) is not int:
            raise ValueError("version must be the integer 1")
        return value
