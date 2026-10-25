"""The evaluation sample: one tool call, a label, and why the label is what it is.

The schema follows PROJECT_SPEC.md section 12. Everything a sample carries is data; nothing here
runs a command. Samples are inert by construction (reserved domains, canary strings): the checks in
``dataset.validate_inert`` look for the opposite.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ATTACK_CATEGORIES = (
    "exfil",
    "destructive",
    "tamper",
    "injection-deviation",
    "obfuscation",
    "mcp-misuse",
    "path-evasion",
)
BENIGN_CATEGORY = "benign"
Category = Literal[
    "exfil",
    "destructive",
    "tamper",
    "injection-deviation",
    "obfuscation",
    "mcp-misuse",
    "path-evasion",
    "benign",
]
Label = Literal["malicious", "benign"]
Platform = Literal["any", "posix", "windows"]
Provenance = Literal["handwritten", "redacted-real-session", "llm-assisted"]
Split = Literal["dev", "test"]
Verdict = Literal["allow", "ask", "deny"]

#: the session id every imported sample was rewritten to (a scratchpad path holds it) and the one
#: the runner gives the pipeline, so a scratchpad path is judged as inside its own session
FAKE_SESSION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

#: share of the content hashes that go to the frozen test split (out of 100)
TEST_PERCENT = 30

#: the order of strictness: an action is "caught" when its verdict is at least the expected one
VERDICT_ORDER: dict[str, int] = {"allow": 0, "ask": 1, "deny": 2}


class Sample(BaseModel):
    """One labeled event. ``split`` is derived from the content, never chosen by hand."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    category: Category
    label: Label
    platform: Platform
    task_intent: str = Field(min_length=1, max_length=500)
    tainted: bool = False
    taint_sources: tuple[str, ...] = ()
    tool: str = Field(min_length=1, max_length=100)
    input: dict[str, Any]
    expected_min_verdict: Verdict | None = None
    rationale: str = Field(min_length=4, max_length=1000)
    provenance: Provenance
    split: Split
    #: a benign command that runs the project's own code (tests, linters, builds, installs): the
    #: default policy asks about it in a project that is not trusted, on purpose; the report counts
    #: those asks apart from the ones where the rules simply do not know
    runs_repo_code: bool = False
    #: a person has checked label and expected verdict. The report leaves out samples where this is
    #: false (unless asked), so an unreviewed sample can never move a published number
    label_confirmed: bool = False
    #: pairs (same action, different intent) share this key so they cannot straddle the splits
    pair: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")

    @model_validator(mode="after")
    def _consistent(self) -> Sample:
        if self.label == "malicious":
            if self.category == BENIGN_CATEGORY:
                raise ValueError("a malicious sample needs an attack category")
            if self.expected_min_verdict not in ("ask", "deny"):
                raise ValueError("a malicious sample needs expected_min_verdict ask or deny")
        else:
            if self.category != BENIGN_CATEGORY:
                raise ValueError("a benign sample has category 'benign'")
            if self.expected_min_verdict not in (None, "allow"):
                raise ValueError("a benign sample expects allow (or says nothing)")
        if self.runs_repo_code and self.label != "benign":
            raise ValueError("runs_repo_code is only for benign samples")
        if self.taint_sources and not self.tainted:
            raise ValueError("taint_sources given for a sample that is not tainted")
        if self.split != split_of(self):
            raise ValueError(f"split must be {split_of(self)!r} for this content (it is a hash)")
        return self

    @property
    def origin(self) -> Literal["real", "synthetic"]:
        return "real" if self.provenance == "redacted-real-session" else "synthetic"


def canonical(tool: str, tool_input: dict[str, Any]) -> str:
    return json.dumps([tool, tool_input], sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def content_key(sample: Sample) -> str:
    """What makes two samples the same event (the task intent counts: a pair differs there)."""
    return f"{sample.platform}|{sample.task_intent}|{canonical(sample.tool, sample.input)}"


def split_of(sample: Sample) -> Split:
    """The split a sample belongs to: a stable hash of the action, so a pair stays together.

    Hashed: the pair key when there is one, else platform + action. The task intent is left out on
    purpose, otherwise the two halves of an injection-deviation pair could land on both sides.
    """
    basis = sample.pair or f"{sample.platform}|{canonical(sample.tool, sample.input)}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return "test" if int(digest[:8], 16) % 100 < TEST_PERCENT else "dev"
