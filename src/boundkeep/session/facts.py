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
    and ``read_untrusted`` are then True and the project marks unknown (fail closed).
    """

    known: bool
    # a taint source was called and the taint step has turned fewer than taint.window calls into
    # an ask since (PROJECT_SPEC.md §7, revision 7, P-F6)
    tainted: bool
    read_untrusted: bool  # a taint source was called at some point in this session (sticky)
    sources: tuple[str, ...] = ()
    taint_asks: int | None = None  # the asks of the taint step since the latest source call
    intents: tuple[str, ...] = ()
    # places written by sessions that read untrusted content, from ANY session (``session.marks``;
    # revision 7, P-F1); ``marks_known`` False: they could not be read (every project counts)
    marks: tuple[str, ...] = ()
    marks_known: bool = True


# A session that read nothing untrusted: what ``boundkeep test`` and the rules-only evaluation use.
FRESH = SessionFacts(known=True, tainted=False, read_untrusted=False)
UNKNOWN = SessionFacts(known=False, tainted=True, read_untrusted=True, marks_known=False)


def tainted_facts(sources: tuple[str, ...] = ("WebFetch",)) -> SessionFacts:
    """A session whose previous tool call was a taint source (policy tests with ``tainted``)."""
    return SessionFacts(
        known=True, tainted=True, read_untrusted=True, sources=sources, taint_asks=0
    )


def is_taint_source(tool: str, sources: tuple[str, ...]) -> bool:
    """``tool`` is one of ``sources`` (a name or a ``prefix*`` pattern; the matcher's reading)."""
    if not tool:
        return False
    return any(tool.startswith(s[:-1]) if s.endswith("*") else tool == s for s in sources)
