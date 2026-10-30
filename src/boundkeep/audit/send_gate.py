"""The single way content reaches an LLM backend (PROJECT_SPEC.md §9.2, §9.6, §11).

A field whitelist first, redaction second. Only structured fields of the normalized actions leave:
the tool name, per action the program, subcommand, flags, words, paths (shown relative to
``<project>`` or ``~``, with their access and whether they are inside the project), hosts, risk
tags, wrappers and the short reasons the rules could not decide; whether the working directory is
inside the project; the taint bits and the names of the source tools; the task intent (already
stripped of IDE blocks and pasted text, redacted and cut when it was stored). Never a file's
content, a tool's output, the raw command line, the working directory or a hook field the list
does not name. A path whose key came from expanding an environment variable is shown in its
unexpanded form (the daemon's environment holds secrets, the API key among them). ``redact_obj``
runs over the whole payload.

Refused (nothing is sent; the audit fails to ``on_failure``):

* too much to show whole: more than ``MAX_ACTIONS`` actions, an action with more than
  ``MAX_WORDS`` words, ``MAX_PATHS`` paths or ``MAX_DOMAINS`` hosts, a word longer than
  ``MAX_WORD_CHARS``, a payload above ``MAX_CONTENT_CHARS``. A cut view could hide the part that
  matters behind padding, and a model can only allow what it was shown;
* a word or path with a control or format character other than tab, CR and LF (bidi overrides,
  zero-width characters, terminal escapes): such text reads differently from what runs;
* a secret that only shows across words (``--password X``, ``-Password 'X'``, ``curl -u u:pw``):
  redacting the command's words one by one would miss it, so the words are redacted as one line
  as well, and a difference means the command carries a secret (the user decides about that);
* a serialized request that the redactor would still change (a secret formed across fields):
  the redactor works on shell text, so its edits on JSON are not trusted to keep the structure;
* a request that contains the value of a secret-looking environment variable (``secrets``).

The system prompt comes from ``audit.prompt`` and holds no user data.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from boundkeep.audit.backends.base import _SEAL, GatedRequest
from boundkeep.audit.prompt import system_prompt
from boundkeep.normalize.model import Action, PathRef
from boundkeep.normalize.paths import key_of_home
from boundkeep.redact import redact_obj, redact_text
from boundkeep.session.facts import SessionFacts

SCHEMA_TAG: Final = "boundkeep.audit-request/1"
MAX_ACTIONS: Final = 8
MAX_WORDS: Final = 32
MAX_WORD_CHARS: Final = 400
MAX_PATHS: Final = 16
MAX_DOMAINS: Final = 16
MAX_FLAGS: Final = 32
MAX_UNCLEAR: Final = 6
MAX_UNCLEAR_CHARS: Final = 120
MAX_NAME_CHARS: Final = 128
MAX_INTENT_CHARS: Final = 2000
MAX_CONTENT_CHARS: Final = 16_000
MIN_SECRET_CHARS: Final = 8  # shorter values of secret-looking variables are not looked for
_ALLOWED_CONTROLS: Final = frozenset("\t\r\n")
_EXPANDED: Final = "variable-expanded"  # normalize.paths: a variable in the word was expanded


@dataclass(frozen=True, slots=True)
class GateResult:
    """``request`` to send, or ``refused`` (why nothing may be sent); ``payload`` is what the
    request carries (redacted), for the audit log and for tests."""

    request: GatedRequest | None
    refused: str | None
    payload: dict[str, Any] | None


class _Refused(Exception):
    pass


def _clean_name(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return "".join(ch if ch.isprintable() else "?" for ch in value[:MAX_NAME_CHARS])


def _checked_text(value: str, what: str) -> str:
    if len(value) > MAX_WORD_CHARS:
        raise _Refused(f"{what} is longer than {MAX_WORD_CHARS} characters")
    if any(not ch.isprintable() and ch not in _ALLOWED_CONTROLS for ch in value):
        raise _Refused(f"{what} holds a control or format character")
    return value


class _Places:
    """Shows paths and words relative to the project and the home directory."""

    def __init__(self, home: str | None, project: str | None) -> None:
        self._home_key = key_of_home(home) if home else ""
        self._project_key = project or ""
        raw_homes: list[str] = []
        if home:
            raw_homes = [home.rstrip("\\/"), home.rstrip("\\/").replace("\\", "/")]
        self._raw_homes = [h for h in dict.fromkeys(raw_homes) if len(h) > 3]

    def key(self, key: str) -> str:
        project = self._project_key.rstrip("/")
        if project and (key == project or key.startswith(project + "/")):
            return "<project>" + key[len(project) :]
        home = self._home_key.rstrip("/")
        if home and (key == home or key.startswith(home + "/")):
            return "~" + key[len(home) :]
        return key

    def word(self, word: str) -> str:
        """A command word with the home directory written as ``~`` (best effort, any case)."""
        for raw in self._raw_homes:
            lowered = word.lower()
            needle = raw.lower()
            start = lowered.find(needle)
            while start >= 0:
                word = word[:start] + "~" + word[start + len(raw) :]
                lowered = word.lower()
                start = lowered.find(needle, start + 1)
        return word


def _path(ref: PathRef, places: _Places) -> dict[str, Any]:
    raw = _checked_text(ref.raw, "a path")
    key = _checked_text(ref.key, "a path")
    # ``$TOKEN/x`` was expanded with the daemon's environment: its key carries the value
    shown = places.word(raw) if _EXPANDED in ref.reasons else places.key(key)
    return {"path": shown, "access": ref.access, "inside_project": ref.inside_project}


def _secret_across_words(words: Sequence[str]) -> bool:
    """The words, redacted as one command line, hide more than redacted one by one.

    Each word is shell-quoted on both sides, so a pattern that runs to the end of a line (an
    ``Authorization:`` header value) ends at its word's closing quote, as in a real command."""
    if len(words) < 2:
        return False
    quoted = [shlex.quote(w) for w in words]
    return redact_text(" ".join(quoted)) != " ".join(redact_text(q) for q in quoted)


def _action(action: Action, places: _Places) -> dict[str, Any]:
    if len(action.args) > MAX_WORDS:
        raise _Refused(f"a command has more than {MAX_WORDS} words")
    if _secret_across_words((*((action.program,) if action.program else ()), *action.args)):
        raise _Refused("a command carries a secret across its words (a password or token flag)")
    if len(action.paths) > MAX_PATHS:
        raise _Refused(f"a command touches more than {MAX_PATHS} paths")
    if len(action.domains) > MAX_DOMAINS:
        raise _Refused(f"a command names more than {MAX_DOMAINS} hosts")
    if len(action.flags) > MAX_FLAGS:
        raise _Refused(f"a command has more than {MAX_FLAGS} flags")
    out: dict[str, Any] = {}
    program = _clean_name(action.program)
    if program:
        out["program"] = program
    subcommand = _clean_name(action.subcommand)
    if subcommand:
        out["subcommand"] = subcommand
    if action.flags:
        out["flags"] = [_checked_text(f, "a flag") for f in action.flags]
    if action.args:
        out["args"] = [places.word(_checked_text(a, "a command word")) for a in action.args]
    if action.paths:
        out["paths"] = [_path(ref, places) for ref in action.paths]
    if action.domains:
        out["domains"] = [_checked_text(d, "a host") for d in action.domains]
    out["network"] = action.network
    out["risk_tags"] = list(action.risk_tags)
    if action.wrappers:
        out["wrappers"] = [w for w in (_clean_name(x) for x in action.wrappers) if w]
    unclear = [
        "".join(ch if ch.isprintable() else "?" for ch in reason[:MAX_UNCLEAR_CHARS])
        for reason in action.gray_reasons[:MAX_UNCLEAR]
    ]
    if unclear:
        out["unclear"] = unclear
    if action.dynamic_args:
        out["dynamic_args"] = True
    mcp_server = _clean_name(action.mcp_server)
    if mcp_server:
        out["mcp_server"] = mcp_server
    mcp_tool = _clean_name(action.mcp_tool)
    if mcp_tool:
        out["mcp_tool"] = mcp_tool
    return out


def gate(
    actions: Sequence[Action],
    *,
    tool: object,
    facts: SessionFacts,
    send_task_intent: bool,
    intent_prompts: int,
    home: str | None,
    secrets: Sequence[str] = (),
) -> GateResult:
    """The request for one gray tool call, or why it must not be sent. Never raises.

    ``secrets``: values that must never be sent (the auditor passes the values of the daemon's
    secret-looking environment variables, the API key's among them); compared without case, since
    Windows path keys are casefolded."""
    try:
        return _gate(
            actions,
            tool=tool,
            facts=facts,
            send_task_intent=send_task_intent,
            intent_prompts=intent_prompts,
            home=home,
            secrets=secrets,
        )
    except _Refused as exc:
        return GateResult(None, str(exc), None)
    except Exception as exc:  # noqa: BLE001 - nothing leaves when the gate itself fails
        return GateResult(None, f"the send gate failed ({type(exc).__name__})", None)


def _gate(
    actions: Sequence[Action],
    *,
    tool: object,
    facts: SessionFacts,
    send_task_intent: bool,
    intent_prompts: int,
    home: str | None,
    secrets: Sequence[str],
) -> GateResult:
    if not actions:
        raise _Refused("there is no action to show")
    if len(actions) > MAX_ACTIONS:
        raise _Refused(f"the call has more than {MAX_ACTIONS} commands")
    project = next((a.project for a in actions if a.project), None)
    places = _Places(home, project)
    intent: list[str] | None = None
    if send_task_intent:
        intent = [
            text[:MAX_INTENT_CHARS]
            for text in facts.intents[-max(1, intent_prompts) :]
            if isinstance(text, str) and text
        ]
    payload: dict[str, Any] = {
        "schema": SCHEMA_TAG,
        "task_intent": intent,
        "tool": _clean_name(tool) or "?",
        "actions": [_action(action, places) for action in actions],
        "cwd_inside_project": True if project else None,
        "tainted": facts.tainted,
        "taint_sources": [s for s in (_clean_name(x) for x in facts.sources) if s],
        "read_untrusted": facts.read_untrusted,
    }
    redacted = redact_obj(payload)
    if not isinstance(redacted, dict):
        raise _Refused("the payload could not be redacted")
    # spaced separators: the redactor's patterns stop at whitespace, so a URL in one field and an
    # ``@`` in the next do not read as ``://user:pw@`` (and refuse the request) for lack of one
    content = json.dumps(redacted, ensure_ascii=False, separators=(", ", ": "))
    if len(content) > MAX_CONTENT_CHARS:
        raise _Refused(f"the request would be longer than {MAX_CONTENT_CHARS} characters")
    if redact_text(content) != content:
        # Something still looks like a secret once the fields are put together. The redactor's
        # patterns are for shell text: on JSON an edit can run across fields and drop whole
        # actions while the result still parses (self-review of M3a), so nothing is sent.
        raise _Refused("the request would carry text that looks like a secret across its fields")
    folded = content.casefold()
    if any(len(s) >= MIN_SECRET_CHARS and s.casefold() in folded for s in secrets):
        raise _Refused("the request would carry the value of a secret environment variable")
    prompt = system_prompt()
    request = GatedRequest(
        content=content,
        system_prompt=prompt.text,
        prompt_hash=prompt.sha256,
        prompt_version=prompt.version,
        seal=_SEAL,
    )
    return GateResult(request, None, redacted)
