"""Shell calls that read remote text into the agent's context are taint sources (PROJECT_SPEC.md
§7, revision 8, P-R5; X1 re-review of the M3a fixes, R-5).

What ``gh issue view``, ``curl``, ``Invoke-RestMethod``, ``npm view`` or ``ssh host cmd`` print is
written by someone else, and "read the issue, then fix it" is the most common way an injection
reaches a coding agent. So a shell call with a network action (``network`` set or ``domains`` not
empty) is a source, unless every such action only moves code: git's sync subcommands, and the
install, sync, build and run subcommands of package managers, whose network use is fetching
packages (what they print is progress, build and test output). Anything not in the tables counts:
a missing entry only makes the session ask more. Accepted residue: install scripts and git print
text a remote wrote too.

Pure functions, no I/O; nothing here imports the policy package.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from boundkeep.normalize.model import Action

SHELL_SOURCE_TOOLS: Final = frozenset({"Bash", "PowerShell"})
NETWORK_SOURCE_PREFIX: Final = "shell-network:"

_GIT_SYNC: Final = frozenset({"clone", "fetch", "pull", "push"})


def _subs(text: str, *, bare: bool = False) -> frozenset[str | None]:
    words: set[str | None] = set(text.split())
    if bare:
        words.add(None)  # the command with no subcommand (``yarn``, ``npx tool``)
    return frozenset(words)


_PIP_MOVES: Final = _subs("install download wheel lock")
# package manager -> the subcommands whose network use is fetching packages (the subcommand sets
# with network in ``normalize.programs._PKG``, minus the ones that print what a registry holds:
# view, info, search, audit, outdated, publish and the account commands still count)
_MOVES_CODE: Final[dict[str, frozenset[str | None]]] = {
    "pip": _PIP_MOVES,
    "python": _PIP_MOVES,  # python -m pip install ...
    "py": _PIP_MOVES,
    "npm": _subs(
        "install i add ci update up upgrade dedupe ddp prune install-test it install-ci-test cit "
        "link ln exec x dlx create init",
        bare=True,
    ),
    "npx": _subs("", bare=True),
    "cargo": _subs(
        "install build b run r check c test t fetch update add vendor generate-lockfile doc clippy"
    ),
    "go": _subs("get install mod build run test generate"),
    "uv": _subs("add sync pip run tool lock install"),
    "poetry": _subs("install add update lock"),
    "composer": _subs("install update require create-project"),
    "conda": _subs("install create update upgrade"),
    "gem": _subs("install update fetch"),
    "brew": _subs("install update upgrade reinstall fetch tap cask"),
    "apt": _subs(
        "install update upgrade dist-upgrade full-upgrade download source build-dep reinstall"
    ),
    "dnf": _subs(
        "install update upgrade reinstall downgrade check-update makecache download distro-sync "
        "groupinstall"
    ),
    "apk": _subs("add update upgrade fetch"),
    "pipx": _subs("install run upgrade upgrade-all inject reinstall-all"),
}
_ALIASES: Final = {
    "pipenv": "pip",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    "bunx": "npx",
    "pnpx": "npx",
    "apt-get": "apt",
    "aptitude": "apt",
    "yum": "dnf",
    "microdnf": "dnf",
    "mamba": "conda",
    "micromamba": "conda",
}
_VERSION_SUFFIX: Final = re.compile(r"[0-9.]+$")


def _family(program: str | None) -> str:
    """``pip3.12.exe`` -> ``pip``, ``python3`` -> ``python``, ``pnpm`` -> ``npm``."""
    name = (program or "").casefold()
    name = name.removesuffix(".exe")
    name = _VERSION_SUFFIX.sub("", name) or name
    return _ALIASES.get(name, name)


def moves_code(action: Action) -> bool:
    """The action's network use is fetching or pushing code, not reading remote text."""
    family = _family(action.program)
    if family == "git":
        return action.subcommand in _GIT_SYNC
    subs = _MOVES_CODE.get(family)
    return subs is not None and action.subcommand in subs


def network_source(actions: Sequence[Action]) -> str | None:
    """The program of the first shell action that may read remote text (a taint source), or
    None when no action of a shell call reaches the network except to move code."""
    for action in actions:
        if action.tool not in SHELL_SOURCE_TOOLS or not (action.network or action.domains):
            continue
        if not moves_code(action):
            return action.program or "?"
    return None
