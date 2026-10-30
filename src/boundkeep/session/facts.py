"""What the session layer knows about one tool call's session (pure data, no I/O).

Kept apart from ``store`` so that the policy matcher can take it without importing SQLite code, and
so that nothing here imports the policy package (which imports the matcher).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SessionFacts:
    """The taint state a tool call is judged in, and the task intents when they were asked for.

    ``known`` False means there is no usable state (no session id, the store failed); ``tainted``
    and ``read_untrusted`` are then True (fail closed).
    """

    known: bool
    tainted: bool  # one of the taint.window calls after a call of a taint source
    read_untrusted: bool  # a taint source was called at some point in this session (sticky)
    sources: tuple[str, ...] = ()
    calls_since_taint: int | None = None
    intents: tuple[str, ...] = ()


# A session that read nothing untrusted: what ``boundkeep test`` and the rules-only evaluation use.
FRESH = SessionFacts(known=True, tainted=False, read_untrusted=False)
UNKNOWN = SessionFacts(known=False, tainted=True, read_untrusted=True)


def tainted_facts(sources: tuple[str, ...] = ("WebFetch",)) -> SessionFacts:
    """A session whose previous tool call was a taint source (policy tests with ``tainted``)."""
    return SessionFacts(
        known=True, tainted=True, read_untrusted=True, sources=sources, calls_since_taint=1
    )


def is_taint_source(tool: str, sources: tuple[str, ...]) -> bool:
    """``tool`` is one of ``sources`` (a name or a ``prefix*`` pattern; the matcher's reading)."""
    if not tool:
        return False
    return any(tool.startswith(s[:-1]) if s.endswith("*") else tool == s for s in sources)
