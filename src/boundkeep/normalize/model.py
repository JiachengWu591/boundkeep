"""The data model shared by the M1 normalizer, the policy matcher and the pipeline.

``Word`` / ``Redirect`` / ``SimpleCmd`` / ``BashResult`` are what the Bash parser hands over (plain
frozen dataclasses, no validation cost). ``Action`` and ``PathRef`` are what rules match on
(pydantic, strict, frozen: they are built from untrusted hook input, so every field is validated).
See docs/m1-design.md for how the pieces fit and PROJECT_SPEC.md section 7 for the semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Shell = Literal["bash", "powershell"]
Platform = Literal["posix", "windows"]
Flavor = Literal["windows", "posix"]
Access = Literal["read", "write", "unknown"]  # unknown: may read, may write
RiskTag = Literal["network_egress", "file_write", "exec", "secret_access", "config_tamper"]


@dataclass(frozen=True, slots=True)
class Word:
    """One shell word after quote removal.

    ``text`` keeps expansions verbatim (``$HOME/.ssh``, ``$(cat x)``): resolving what is known
    (``$HOME``) is the path layer's job, deciding that something is unknowable is the parser's.
    """

    text: str
    expands: bool = False  # a variable, command, arithmetic or tilde expansion (not in '...')
    glob: bool = False  # unquoted * ? [..]: the word may stand for many words
    quoted: bool = False  # any quoting was used (informational)


@dataclass(frozen=True, slots=True)
class Redirect:
    op: str  # ">", ">>", "<", "<<", "<<<", ">&", "&>", ...
    target: Word | None  # None for here-doc bodies and fd duplication such as 2>&1
    fd: str | None = None


@dataclass(frozen=True, slots=True)
class SimpleCmd:
    argv: tuple[Word, ...]  # program first; wrappers (sudo, env, nohup, ...) already removed
    env: tuple[tuple[str, Word], ...] = ()  # NAME=value prefixes
    redirects: tuple[Redirect, ...] = ()
    wrappers: tuple[str, ...] = ()  # e.g. ("sudo", "env"), outermost first
    origin: str = "top"  # top | subshell | substitution | bash-c | ...
    args_from_stdin: bool = False  # xargs: more arguments arrive at run time
    raw: str = ""
    in_pipeline: bool = False  # one stage of a `|` / `|&` pipeline (stages run in subshells)
    background: bool = False  # followed by `&`: runs in the background, in a subshell


@dataclass(frozen=True, slots=True)
class BashResult:
    commands: tuple[SimpleCmd, ...]
    gray: tuple[str, ...] = ()  # reasons the line as a whole is not fully understood
    exec_reasons: tuple[str, ...] = ()  # why the line gets the "exec" tag (eval, python -c, ...)


class PathRef(BaseModel):
    """A file path an action touches, in the canonical form of ``normalize.paths``."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    raw: str
    key: str  # canonical comparison key (see normalize/paths.py)
    flavor: Flavor
    access: Access = "unknown"
    inside_project: bool | None = None  # True only when definitely inside; None when unsure
    uncertain: bool = False  # unresolved variable, glob, drive-relative, device name, ...
    reasons: tuple[str, ...] = ()


class Action(BaseModel):
    """One normalized action: a non-command tool call, or ONE simple command of a command line."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    tool: str
    shell: Shell | None = None
    platform: Platform
    session_id: str | None = None
    cwd: str | None = None
    permission_mode: str | None = None
    agent_id: str | None = None
    program: str | None = None
    subcommand: str | None = None
    wrappers: tuple[str, ...] = ()  # sudo, env, ... that were peeled off; allow rules never match
    args: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()  # long and short; combined short flags both ways (-rf, -r, -f)
    paths: tuple[PathRef, ...] = ()
    domains: tuple[str, ...] = ()
    network: bool = False
    inside_project: bool | None = None  # True only when every path is definitely inside
    risk_tags: tuple[RiskTag, ...] = ()
    gray: bool = False  # this action (or part of it) could not be understood
    gray_reasons: tuple[str, ...] = Field(default=())
    mcp_server: str | None = None
    mcp_tool: str | None = None
    command_text: str | None = None  # the original command line (shell tools only), for audit
