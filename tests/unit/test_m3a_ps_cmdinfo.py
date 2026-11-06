"""PowerShell's CmdInfo for an external program is the Bash side's, field by field (review IR-1).

``psprograms._external`` classifies a program that is not a cmdlet (git, curl, rg ...) with the
Bash tables and builds its own CmdInfo from the result. It copied the fields one by one and missed
``pathspec_magic``, which revision 13 added: in PowerShell, ``git add :/`` run from a sub directory
no longer had the project root scanned for protected files and was allowed by a rule
(docs/reviews/M3a-rev13-16-independent-review.md, IR-1). This compares every field of CmdInfo, so a
field added later is compared too. PowerShell may add gray reasons and risk tags of its own; it may
not drop any.
"""

from __future__ import annotations

import dataclasses

import pytest

from boundkeep.normalize import programs, psprograms
from boundkeep.normalize.model import Word

ADDED_BY_POWERSHELL = frozenset({"gray", "tags"})  # PowerShell may add to these, never drop

COMMANDS = [
    ["git", "add", ":/"],
    ["git", "add", ":!x"],
    ["git", "add", ":(top)"],
    ["git", "add", "--", ":/"],
    ["git", "add", ":(exclude,top)x"],
    ["git", "add", "-A"],
    ["git", "add", "src"],
    ["git", "log", "-p", "--", ":(top).env"],
    ["git", "diff", "--", ":(icase).ENV"],
    ["git", "diff", "--cached"],
    ["git", "status"],
    ["git", "stash", "push", "--", ":(top).claude/settings.json"],
    ["git", "archive", "-o", "x.zip", "HEAD", "::.env"],
    ["git", "show", "HEAD:.env"],
    ["git", "grep", "-e", "TOKEN"],
    ["curl", "-o", "out.html", "https://example.com/"],
    ["rg", "-n", "TODO", "src"],
    ["tar", "-czf", "a.tgz", "src"],
    ["npm", "test"],
    ["ssh", "host", "ls"],
    ["C:/Windows/System32/git.exe", "status"],
]


def _words(argv: list[str]) -> list[Word]:
    return [Word(w, quoted=w.startswith(":")) for w in argv[1:]]


def _bash_name(program: str) -> str:
    """The name ``_external`` hands to the Bash tables."""
    has_sep = "/" in program or "\\" in program
    return program if has_sep else psprograms._base(program)


@pytest.mark.parametrize("argv", COMMANDS, ids=" ".join)
def test_every_field_is_the_bash_sides(argv: list[str]) -> None:
    words = _words(argv)
    bash = programs.classify(_bash_name(argv[0]), words, shell="bash")  # noqa: S604 - a dialect
    ps = psprograms._external(argv[0], words, (), ())
    for field in dataclasses.fields(programs.CmdInfo):
        theirs, mine = getattr(bash, field.name), getattr(ps, field.name)
        if field.name in ADDED_BY_POWERSHELL:
            assert set(theirs) <= set(mine), (field.name, theirs, mine)
        else:
            assert mine == theirs, (field.name, theirs, mine)


def test_the_comparison_covers_the_magic() -> None:
    # the field this file exists for: true on the Bash side, so the comparison above means something
    bash = programs.classify("git", _words(["git", "add", ":/"]), shell="bash")  # noqa: S604
    assert bash.pathspec_magic


@pytest.mark.parametrize("magic", [":/", ":!x", ":(top)", ":(exclude)x"])
def test_the_magic_reaches_the_caller(magic: str) -> None:
    info = psprograms.classify_ps("git", [Word("add"), Word(magic, quoted=True)])
    assert info.pathspec_magic, magic
    assert not psprograms.classify_ps("git", [Word("add"), Word("src")]).pathspec_magic
