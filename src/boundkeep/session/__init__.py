"""Session state: the task intent and taint marks (PROJECT_SPEC.md §7 and §9.2).

``facts`` is what a tool call is judged in (pure data); ``intent`` turns a UserPromptSubmit prompt
into a task intent (host blocks removed, pasted text left out, redacted, cut); ``store`` keeps the
per-session taint marks and intents in SQLite, and the project marks (``marks``: where sessions
that read untrusted content wrote) that every session sees.
"""

from __future__ import annotations

from boundkeep.session.facts import (
    FRESH,
    UNKNOWN,
    SessionFacts,
    is_taint_source,
    tainted_facts,
)
from boundkeep.session.intent import extract_intent
from boundkeep.session.store import (
    Mark,
    SessionStore,
    SessionStoreError,
    UnavailableStore,
    open_store,
)

__all__ = [
    "FRESH",
    "UNKNOWN",
    "Mark",
    "SessionFacts",
    "SessionStore",
    "SessionStoreError",
    "UnavailableStore",
    "extract_intent",
    "is_taint_source",
    "open_store",
    "tainted_facts",
]
