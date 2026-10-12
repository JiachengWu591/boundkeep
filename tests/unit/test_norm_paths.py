"""Tests for ``boundkeep.normalize.paths``: path keys, ``inside_project`` and ``resolve_on_disk``.

The lexical layer is platform independent (Windows semantics are tested on Linux too): the tables
below only use strings. Only the file system tests at the end need a particular platform, and the
symlink ones skip themselves where symlinks cannot be created. Nothing here touches the real home
directory: every path under test is either a string or lives in ``tmp_path``.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Literal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from boundkeep.normalize import paths as paths_module
from boundkeep.normalize.paths import (
    NormPath,
    inside_project,
    key_of_home,
    normalize_path,
    resolve_on_disk,
)

Dialect = Literal["bash", "powershell", "tool"]

# --- three worlds a path can be normalized in -------------------------------------------------

WIN_ENV = {
    "USERPROFILE": "C:\\Users\\bob",
    "APPDATA": "C:\\Users\\bob\\AppData\\Roaming",
    "LOCALAPPDATA": "C:\\Users\\bob\\AppData\\Local",
    "TEMP": "C:\\Users\\bob\\AppData\\Local\\Temp",
    "COMPUTERNAME": "DESKTOP-1",
}
POSIX_ENV = {"HOME": "/home/dev"}
CONTEXTS: dict[str, tuple[str | None, str | None, Mapping[str, str] | None]] = {
    "W": ("C:\\proj", "C:\\Users\\bob", WIN_ENV),
    "P": ("/home/dev/proj", "/home/dev", POSIX_ENV),
    "N": (None, None, None),
}


def norm(raw: str, ctx: str = "W", dialect: Dialect = "tool") -> NormPath:
    cwd, home, env = CONTEXTS[ctx]
    return normalize_path(raw, cwd=cwd, home=home, env=env, dialect=dialect)


def root_of(raw: str, ctx: str = "W", dialect: Dialect = "tool") -> NormPath:
    return norm(raw, ctx, dialect)


# --- lexical table ----------------------------------------------------------------------------


def c(
    name: str,
    raw: str,
    ctx: str,
    key: str,
    fl: Literal["w", "p"],
    *,
    d: Dialect = "tool",
    unc: bool = False,
    r: tuple[str, ...] = (),
    ab: bool = True,
    dev: bool = False,
) -> Any:
    return pytest.param(raw, ctx, d, key, fl, unc, r, ab, dev, id=name)


LEXICAL = [
    # --- plain Windows paths
    c("win-basic", "C:\\Users\\Bob\\.ssh\\id_rsa", "W", "c:/users/bob/.ssh/id_rsa", "w"),
    c("win-lower-drive", "c:\\Users\\bob", "W", "c:/users/bob", "w"),
    c("win-forward-slashes", "C:/Users/Bob/.ssh", "W", "c:/users/bob/.ssh", "w"),
    c("win-mixed-slashes", "C:\\Users/Bob\\.ssh", "W", "c:/users/bob/.ssh", "w"),
    c("win-repeated-and-trailing", "C:\\\\Users\\\\\\bob\\", "W", "c:/users/bob", "w"),
    c("win-root", "C:\\", "W", "c:/", "w"),
    c("win-dot-components", "C:\\a\\.\\b\\.", "W", "c:/a/b", "w"),
    c("win-dotdot", "C:\\proj\\sub\\..\\x", "W", "c:/proj/x", "w"),
    c("win-dotdot-cannot-escape-root", "C:\\..\\..\\x", "W", "c:/x", "w"),
    c(
        "win-dotdot-out-of-project",
        "C:\\proj\\..\\..\\Users\\bob\\.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
    ),
    c(
        "win-bash-dialect-keeps-windows-meaning",
        "C:\\Users\\bob",
        "W",
        "c:/users/bob",
        "w",
        d="bash",
    ),
    # --- prefixes
    c("prefix-extended", "\\\\?\\C:\\Users\\bob", "W", "c:/users/bob", "w", r=("extended-prefix",)),
    c(
        "prefix-device-drive",
        "\\\\.\\C:\\Users\\bob",
        "W",
        "c:/users/bob",
        "w",
        r=("device-prefix",),
    ),
    c(
        "prefix-extended-dotdot-is-literal-so-uncertain",
        "\\\\?\\C:\\proj\\..\\secret",
        "W",
        "c:/secret",
        "w",
        unc=True,
        r=("extended-path-dots",),
    ),
    c("prefix-forward-extended", "//?/C:/Users/bob", "W", "c:/users/bob", "w"),
    c("prefix-nt", "\\??\\C:\\x", "W", "c:/x", "w", r=("nt-prefix",)),
    c("prefix-extended-unc", "\\\\?\\UNC\\srv\\share\\x", "W", "//srv/share/x", "w", r=("unc",)),
    c(
        "prefix-extended-volume",
        "\\\\?\\Volume{1234}\\x",
        "W",
        "//./volume{1234}/x",
        "w",
        unc=True,
        dev=True,
        r=("device:VOLUME{1234}",),
    ),
    # --- UNC
    c("unc-basic", "\\\\SRV\\Share\\a\\..\\..\\b", "W", "//srv/share/b", "w", r=("unc",)),
    c("unc-forward-slashes-windows-ctx", "//srv/share/x", "W", "//srv/share/x", "w", r=("unc",)),
    c("unc-server-only", "\\\\srv", "W", "//srv", "w", unc=True, r=("unc-incomplete",)),
    c("unc-bare", "\\\\", "W", "//", "w", unc=True, r=("unc-incomplete",), ab=False),
    c(
        "unc-admin-share-of-localhost-is-a-drive",
        "\\\\localhost\\C$\\Users\\bob",
        "W",
        "c:/users/bob",
        "w",
        r=("admin-share-local",),
    ),
    c(
        "unc-admin-share-of-this-computer",
        "\\\\desktop-1\\D$\\x",
        "W",
        "d:/x",
        "w",
        r=("admin-share-local",),
    ),
    c(
        "unc-admin-share-of-unknown-host",
        "\\\\other\\C$\\x",
        "W",
        "//other/c$/x",
        "w",
        unc=True,
        r=("admin-share",),
    ),
    c(
        "unc-three-leading-backslashes",
        "\\\\\\srv\\share\\x",
        "W",
        "//srv/share/x",
        "w",
        unc=True,
        r=("odd-leading-separators",),
    ),
    # --- alternate data streams
    c("ads-stream-name", "C:\\proj\\a.txt:hidden", "W", "c:/proj/a.txt", "w", r=("ads-stripped",)),
    c("ads-data-stream", "C:\\proj\\a.txt::$DATA", "W", "c:/proj/a.txt", "w", r=("ads-stripped",)),
    c("ads-on-directory", "C:\\proj::$DATA", "W", "c:/proj", "w", r=("ads-stripped",)),
    c("ads-index-allocation", "C:\\proj\\dir::$INDEX_ALLOCATION\\x", "W", "c:/proj/dir/x", "w"),
    c("ads-only-stream-component", "C:\\proj\\::$DATA\\x", "W", "c:/proj/x", "w"),
    c("ads-not-stripped-on-posix", "/home/dev/a.txt:s", "P", "/home/dev/a.txt:s", "p"),
    # --- trailing dots and spaces
    c("dots-trailing-space", "C:\\proj\\x. ", "W", "c:/proj/x", "w", r=("trailing-dots-spaces",)),
    c("dots-trailing-dot-on-project", "c:\\PROJ.\\x", "W", "c:/proj/x", "w"),
    # Win32 strips every trailing dot/space only from the LAST component, one dot from the others.
    # The key strips more (so deny rules over-match) but the path is then ambiguous.
    c("dots-mid-single-dot-is-exact", "C:\\proj\\a.\\b", "W", "c:/proj/a/b", "w"),
    c(
        "dots-mid-dot-space-dot-is-ambiguous",
        "C:\\proj\\a. .\\b",
        "W",
        "c:/proj/a/b",
        "w",
        unc=True,
        r=("trailing-dots-spaces-ambiguous",),
    ),
    c("dots-mid-trailing-space-is-ambiguous", "C:\\proj \\x", "W", "c:/proj/x", "w", unc=True),
    c("dots-mid-two-dots-is-ambiguous", "C:\\proj..\\x", "W", "c:/proj/x", "w", unc=True),
    c("dots-before-trailing-sep-is-ambiguous", "C:\\proj\\x. \\", "W", "c:/proj/x", "w", unc=True),
    c("dots-three-dots-component-read-as-parent", "C:\\proj\\...\\x", "W", "c:/x", "w", unc=True),
    c("dots-dotdot-space-read-as-parent", "C:\\proj\\.. \\x", "W", "c:/x", "w", unc=True),
    c("dots-space-only-component", "C:\\proj\\ \\x", "W", "c:/proj/x", "w", unc=True),
    c("dots-last-component-all-stripped", "C:\\proj\\x. . ", "W", "c:/proj/x", "w"),
    c("dots-kept-on-posix", "/home/dev/proj/x.", "P", "/home/dev/proj/x.", "p"),
    # --- drive-relative and rooted
    c(
        "drive-relative-same-drive",
        "C:foo",
        "W",
        "c:/proj/foo",
        "w",
        unc=True,
        r=("drive-relative",),
        ab=False,
    ),
    c(
        "drive-relative-other-drive",
        "D:foo",
        "W",
        "d:/foo",
        "w",
        unc=True,
        r=("drive-relative",),
        ab=False,
    ),
    c(
        "drive-relative-bare-drive",
        "C:",
        "W",
        "c:/proj",
        "w",
        unc=True,
        r=("drive-relative",),
        ab=False,
    ),
    c("rooted-uses-cwd-drive", "\\foo", "W", "c:/foo", "w", unc=True, r=("rooted-current-drive",)),
    c(
        "rooted-without-cwd",
        "\\foo",
        "N",
        "\\foo",
        "w",
        d="powershell",
        unc=True,
        r=("rooted-no-drive",),
        ab=False,
    ),
    c(
        "rooted-forward-in-tool-windows-ctx",
        "/foo",
        "W",
        "c:/foo",
        "w",
        unc=True,
        r=("rooted-current-drive",),
    ),
    # --- device names
    c("device-nul", "NUL", "W", "//./nul", "w", unc=True, r=("device:NUL",), dev=True),
    c(
        "device-nul-with-extension",
        "NUL.txt",
        "W",
        "//./nul",
        "w",
        unc=True,
        r=("device:NUL",),
        dev=True,
    ),
    c(
        "device-lowercase-in-dir",
        "C:\\proj\\com1.log",
        "W",
        "//./com1",
        "w",
        unc=True,
        r=("device:COM1",),
        dev=True,
    ),
    c("device-with-colon", "LPT9:", "W", "//./lpt9", "w", unc=True, dev=True),
    c("device-superscript-com", "COM\u00b9", "W", "//./com\u00b9", "w", unc=True, dev=True),
    c("device-conin", "CONIN$", "W", "//./conin$", "w", unc=True, dev=True),
    c("device-trailing-space-ext", "C:\\proj\\prn .txt", "W", "//./prn", "w", unc=True, dev=True),
    c(
        "device-pipe",
        "\\\\.\\pipe\\x",
        "W",
        "//./pipe/x",
        "w",
        unc=True,
        dev=True,
        r=("device-prefix", "device:PIPE"),
    ),
    c(
        "device-component-in-the-middle",
        "C:\\proj\\nul\\x",
        "W",
        "c:/proj/nul/x",
        "w",
        unc=True,
        r=("device-component:NUL",),
    ),
    c("device-not-on-posix", "nul", "P", "/home/dev/proj/nul", "p"),
    c("device-lookalike-is-a-file", "C:\\proj\\nullable.txt", "W", "c:/proj/nullable.txt", "w"),
    # --- MSYS / Cygwin / WSL
    c(
        "msys-drive",
        "/c/Users/bob/.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
        d="bash",
        r=("msys-translated",),
    ),
    c("msys-drive-root", "/c", "W", "c:/", "w", d="bash"),
    c("msys-uppercase-drive", "/D/Work", "W", "d:/work", "w", d="bash"),
    c(
        "msys-cygdrive",
        "/cygdrive/c/Users",
        "W",
        "c:/users",
        "w",
        d="bash",
        r=("cygdrive-translated",),
    ),
    c(
        "msys-wsl-mount-from-posix-cwd",
        "/mnt/c/proj/../x",
        "P",
        "c:/x",
        "w",
        d="bash",
        r=("wsl-translated",),
    ),
    c(
        "msys-dotdot-above-drive-is-git-bash-root",
        "/c/../proj/x",
        "W",
        "/proj/x",
        "p",
        d="bash",
        unc=True,
        r=("git-bash-root",),
    ),
    c("msys-wsl-dotdot-above-drive-is-plain-posix", "/mnt/c/../xy", "P", "/mnt/xy", "p", d="bash"),
    c(
        "msys-dotdot-then-drive-letter",
        "/tmp/../c/Users/bob/.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
        d="bash",
        r=("msys-translated",),
    ),
    c("msys-dot-component-before-drive", "/./c/x", "W", "c:/x", "w", d="bash"),
    c("msys-backslashes-after-prefix", "/c/Users\\bob", "W", "c:/users/bob", "w", d="bash"),
    c("msys-not-a-mount", "/mnt/wsl/x", "P", "/mnt/wsl/x", "p", d="bash"),
    # --- Git Bash roots (no reliable mapping)
    c("gitbash-tmp", "/tmp/x", "W", "/tmp/x", "p", d="bash", unc=True, r=("git-bash-root",)),
    c("gitbash-root", "/", "W", "/", "p", d="bash", unc=True, r=("git-bash-root",)),
    c(
        "gitbash-home",
        "/home/bob/.ssh",
        "W",
        "/home/bob/.ssh",
        "p",
        d="bash",
        unc=True,
        r=("git-bash-root",),
    ),
    c("gitbash-uppercase-kept", "/Usr/Bin", "W", "/Usr/Bin", "p", d="bash", unc=True),
    # --- POSIX
    c("posix-basic", "/home/dev/proj/a.py", "P", "/home/dev/proj/a.py", "p"),
    c("posix-case-kept", "/Home/Dev", "P", "/Home/Dev", "p"),
    c("posix-dotdot", "/home/dev/../x", "P", "/home/x", "p"),
    c("posix-dotdot-above-root", "/../../etc/passwd", "P", "/etc/passwd", "p"),
    c(
        "posix-double-slash-root",
        "//etc/passwd",
        "P",
        "/etc/passwd",
        "p",
        unc=True,
        r=("double-slash-root",),
    ),
    c("posix-triple-slash-root", "///etc/passwd", "P", "/etc/passwd", "p"),
    c("posix-backslash-is-a-character", "/home/dev/a\\b", "P", "/home/dev/a\\b", "p"),
    c("posix-repeated-slashes", "/home//dev///x/", "P", "/home/dev/x", "p"),
    # --- relative paths
    c("rel-windows-cwd", "src\\a.py", "W", "c:/proj/src/a.py", "w"),
    c("rel-posix-cwd", "src/a.py", "P", "/home/dev/proj/src/a.py", "p", d="bash"),
    c("rel-dotdot-leaves-project", "../x", "P", "/home/dev/x", "p"),
    c("rel-dotdot-way-up", "../../../../xx", "P", "/xx", "p"),
    c("rel-dot-only", ".", "P", "/home/dev/proj", "p"),
    c("rel-no-cwd", "a/b", "N", "a/b", "p", d="bash", unc=True, r=("no-cwd",), ab=False),
    c("rel-no-cwd-dotdot-kept", "../x", "N", "../x", "p", unc=True, ab=False),
    c("rel-no-cwd-dot", ".", "N", ".", "p", unc=True, ab=False),
    c("rel-no-cwd-windows-casefold", "A\\B", "N", "a/b", "w", d="powershell", unc=True, ab=False),
    c(
        "rel-no-cwd-backslash-in-bash-ambiguous",
        "a\\b",
        "N",
        "a/b",
        "w",
        d="bash",
        unc=True,
        r=("backslash-ambiguous",),
        ab=False,
    ),
    c("rel-backslash-is-literal-with-posix-cwd", "a\\b", "P", "/home/dev/proj/a\\b", "p", d="bash"),
    c("rel-bare-name-no-cwd", "x", "N", "x", "p", unc=True, ab=False),
    # --- empty
    c("empty", "", "W", "", "w", unc=True, r=("empty",), ab=False),
    c("whitespace", "   ", "P", "", "p", unc=True, r=("empty",), ab=False),
    c("tab-newline", "\t\n", "N", "", "p", unc=True, ab=False),
    # --- tilde and variables
    c("tilde-home", "~/.ssh/id_rsa", "W", "c:/users/bob/.ssh/id_rsa", "w"),
    c("tilde-alone", "~", "P", "/home/dev", "p"),
    c("tilde-backslash", "~\\x", "W", "c:/users/bob/x", "w"),
    c("tilde-without-home", "~/x", "N", "~/x", "p", unc=True, r=("unresolved-home",), ab=False),
    c("tilde-user", "~bob/x", "P", "~bob/x", "p", unc=True, r=("tilde-user",), ab=False),
    c("var-dollar-home", "$HOME/.ssh", "P", "/home/dev/.ssh", "p", d="bash"),
    c("var-braced-home", "${HOME}/.ssh", "P", "/home/dev/.ssh", "p", d="bash"),
    c("var-pwd", "$PWD/x", "P", "/home/dev/proj/x", "p", d="bash"),
    c(
        "var-env-colon-userprofile",
        "$env:USERPROFILE\\.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
        d="powershell",
    ),
    c(
        "var-braced-env-colon",
        "${env:USERPROFILE}\\.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
        d="powershell",
    ),
    c(
        "var-percent-in-tool-is-uncertain",
        "%USERPROFILE%\\.ssh",
        "W",
        "c:/users/bob/.ssh",
        "w",
        unc=True,
        r=("variable-syntax-mismatch",),
    ),
    c("var-appdata", "%APPDATA%\\x", "W", "c:/users/bob/appdata/roaming/x", "w", unc=True),
    c(
        "var-localappdata-powershell",
        "$env:LOCALAPPDATA\\x",
        "W",
        "c:/users/bob/appdata/local/x",
        "w",
        d="powershell",
    ),
    c(
        "var-temp-case-insensitive-powershell",
        "$env:temp\\x",
        "W",
        "c:/users/bob/appdata/local/temp/x",
        "w",
        d="powershell",
    ),
    c(
        "var-bash-names-are-case-sensitive",
        "$home/x",
        "P",
        "$home/x",
        "p",
        d="bash",
        unc=True,
        r=("unresolved-variable:home",),
        ab=False,
    ),
    c(
        "var-unresolved",
        "$FOO/x",
        "P",
        "$FOO/x",
        "p",
        d="bash",
        unc=True,
        r=("unresolved-variable:FOO",),
        ab=False,
    ),
    c(
        "var-unresolved-percent",
        "%NOPE%\\x",
        "W",
        "%nope%/x",
        "w",
        unc=True,
        r=("unresolved-variable:NOPE",),
        ab=False,
    ),
    c(
        "var-command-substitution",
        "$(pwd)/x",
        "P",
        "$(pwd)/x",
        "p",
        d="bash",
        unc=True,
        r=("command-substitution",),
        ab=False,
    ),
    c("var-unterminated-brace", "${HOME/x", "P", "${HOME/x", "p", d="bash", unc=True, ab=False),
    c("var-special-parameter", "$1/x", "P", "$1/x", "p", d="bash", unc=True, ab=False),
    c(
        "var-absolute-value-mid-path",
        "/tmp/$HOME",
        "P",
        "/tmp/home/dev",
        "p",
        d="bash",
        unc=True,
        r=("variable-mid-path",),
    ),
    c("var-unset", "$EMPTY/x", "P", "$EMPTY/x", "p", d="bash", unc=True, ab=False),
    c(
        "var-dollar-in-real-name-stays-literal",
        "C:\\$Recycle.Bin\\x",
        "W",
        "c:/$recycle.bin/x",
        "w",
        unc=True,
        r=("unresolved-variable:Recycle",),
    ),
    # --- wildcards
    c("glob-star", "*.py", "P", "/home/dev/proj/*.py", "p", d="bash", unc=True, r=("glob",)),
    c(
        "glob-question-windows",
        "C:\\proj\\a?.txt",
        "W",
        "c:/proj/a?.txt",
        "w",
        unc=True,
        r=("glob",),
    ),
    c(
        "glob-bracket",
        "/home/dev/proj/[ab]",
        "P",
        "/home/dev/proj/[ab]",
        "p",
        unc=True,
        r=("glob",),
    ),
    c("glob-brace", "/home/dev/{a,b}", "P", "/home/dev/{a,b}", "p", unc=True, r=("brace",)),
    c(
        "glob-windows-invalid-char",
        "C:\\proj\\a|b",
        "W",
        "c:/proj/a|b",
        "w",
        unc=True,
        r=("invalid-char",),
    ),
    # --- 8.3 short names
    c(
        "short-program-files",
        "C:\\PROGRA~1\\x",
        "W",
        "c:/progra~1/x",
        "w",
        unc=True,
        r=("short-name-unresolved",),
    ),
    c(
        "short-project-dir",
        "C:\\PROJ~1\\x",
        "W",
        "c:/proj~1/x",
        "w",
        unc=True,
        r=("short-name-unresolved",),
    ),
    c(
        "short-with-extension",
        "C:\\proj\\LONGFI~1.TXT",
        "W",
        "c:/proj/longfi~1.txt",
        "w",
        unc=True,
        r=("short-name-unresolved",),
    ),
    c("short-double-digit", "C:\\proj\\ABCDE~12", "W", "c:/proj/abcde~12", "w", unc=True),
    c("short-lookalike-too-long", "C:\\proj\\verylongname~1", "W", "c:/proj/verylongname~1", "w"),
    c("short-lookalike-no-digits", "C:\\proj\\abc~x", "W", "c:/proj/abc~x", "w"),
    c("short-not-on-posix", "/home/dev/PROJ~1", "P", "/home/dev/PROJ~1", "p"),
    # --- Unicode is left alone
    c(
        "unicode-fullwidth-drive-is-not-a-drive",
        "\uff23\uff1a\\proj",
        "W",
        "c:/proj/\uff43\uff1a/proj",
        "w",
    ),
    c(
        "unicode-cyrillic-drive-is-not-a-drive",
        "\u0421:\\proj",
        "W",
        "c:/proj/\u0441/proj",
        "w",
        r=("ads-stripped",),
    ),
    c("unicode-combining-is-not-composed", "C:\\proj\\e\u0301", "W", "c:/proj/e\u0301", "w"),
    c("unicode-precomposed", "C:\\proj\\\u00e9", "W", "c:/proj/\u00e9", "w"),
    c("unicode-fullwidth-letters", "C:\\proj\\\uff21", "W", "c:/proj/\uff41", "w"),
    c("unicode-posix-kept", "/home/dev/\u00c4", "P", "/home/dev/\u00c4", "p"),
    # --- garbage
    c("nul-byte", "C:\\proj\\a\x00b", "W", "c:/proj/a\x00b", "w", unc=True, r=("nul-byte",)),
    c("lone-surrogate", "C:\\proj\\\ud800", "W", "c:/proj/\ud800", "w"),
    c(
        "too-long",
        "a" * 70000,
        "P",
        "/home/dev/proj/" + "a" * 65536,
        "p",
        unc=True,
        r=("too-long",),
    ),
]


@pytest.mark.parametrize(
    ("raw", "ctx", "dialect", "key", "flavor", "unc", "reasons", "absolute", "device"), LEXICAL
)
def test_lexical(
    raw: str,
    ctx: str,
    dialect: Dialect,
    key: str,
    flavor: str,
    unc: bool,
    reasons: tuple[str, ...],
    absolute: bool,
    device: bool,
) -> None:
    got = norm(raw, ctx, dialect)
    assert got.key == key
    assert got.flavor == ("windows" if flavor == "w" else "posix")
    assert got.uncertain is unc
    assert got.is_device is device
    assert got.absolute is absolute
    assert got.raw == raw
    for tag in reasons:
        assert tag in got.reasons
    if unc:
        assert got.reasons, "an uncertain path must say why"


def test_table_is_big_enough() -> None:
    assert len(LEXICAL) >= 60


def _idempotence_exempt(first: NormPath, ctx: str) -> bool:
    # "//srv/share" means UNC to Windows but "/srv/share" to POSIX: that spelling cannot round
    # trip through a POSIX world (the key format is fixed by the contract).
    unc_key = first.key.startswith("//") and not first.key.startswith("//./")
    return (unc_key and ctx != "W") or "too-long" in first.reasons


@pytest.mark.parametrize(
    ("raw", "ctx", "dialect", "key", "flavor", "unc", "reasons", "absolute", "device"), LEXICAL
)
def test_lexical_keys_are_idempotent(
    raw: str,
    ctx: str,
    dialect: Dialect,
    key: str,
    flavor: str,
    unc: bool,
    reasons: tuple[str, ...],
    absolute: bool,
    device: bool,
) -> None:
    first = norm(raw, ctx, dialect)
    if _idempotence_exempt(first, ctx):
        pytest.skip("UNC key cannot round trip through a POSIX world")
    second = norm(first.key, ctx, dialect)
    assert second.key == first.key


# --- environment and file system purity --------------------------------------------------------


def test_lexical_layer_reads_neither_environment_nor_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/evil")
    monkeypatch.setenv("USERPROFILE", "C:\\evil")
    monkeypatch.setenv("FOO", "evil")

    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("the lexical layer touched the file system")

    for name in ("getcwd", "listdir", "scandir"):
        monkeypatch.setattr(os, name, boom)
    monkeypatch.setattr(os.path, "realpath", boom)
    monkeypatch.setattr(os.path, "exists", boom)
    for ctx_name in CONTEXTS:
        cwd, _, _ = CONTEXTS[ctx_name]
        for raw in ("$HOME/x", "%USERPROFILE%\\x", "~/x", "$FOO", "rel/x", "C:\\x\\..\\y"):
            got = normalize_path(raw, cwd=cwd, home=None, env={}, dialect="bash")
            assert "evil" not in got.key
    got = normalize_path("$HOME/x", cwd=None, home=None, env=None, dialect="bash")
    assert got.uncertain
    assert "unresolved-variable:HOME" in got.reasons
    assert inside_project(got, norm("C:\\proj")) is None
    assert key_of_home("/home/dev") == "/home/dev"


def test_substituted_values_are_not_expanded_again() -> None:
    env = {"A": "$B", "B": "/secret"}
    got = normalize_path("$A/x", cwd="/home/dev", home=None, env=env, dialect="bash")
    assert got.key == "$B/x"
    assert got.uncertain


def test_env_lookup_ignores_non_string_values() -> None:
    env: Any = {"X": 5, 7: "y"}
    got = normalize_path("$X/a", cwd="/h", home=None, env=env, dialect="bash")
    assert got.uncertain


def test_invalid_dialect_and_non_string_input_do_not_crash() -> None:
    bad: Any = "nonsense"
    got = normalize_path("/ab/b", cwd=None, home=None, dialect=bad)
    assert got.key == "/ab/b"
    not_text: Any = None
    got2 = normalize_path(not_text, cwd=None, home=None)
    assert got2.uncertain
    assert got2.key == ""


def test_internal_error_is_reported_as_uncertain(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> NormPath:
        raise RuntimeError("bug")

    monkeypatch.setattr(paths_module, "_norm", boom)
    got = normalize_path("C:\\x", cwd=None, home=None)
    assert got.uncertain
    assert got.reasons == ("internal-error",)
    assert key_of_home("C:\\x") == ""
    assert inside_project(got, got) is None


def test_normpath_is_frozen_and_slotted() -> None:
    got = norm("C:\\x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        got.key = "x"  # type: ignore[misc]
    assert not hasattr(got, "__dict__")


# --- key_of_home -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("home", "key"),
    [
        pytest.param("C:\\Users\\Bob", "c:/users/bob", id="windows"),
        pytest.param("C:\\Users\\Bob\\", "c:/users/bob", id="trailing-sep"),
        pytest.param("c:/Users/Bob", "c:/users/bob", id="forward"),
        pytest.param("/home/Dev/", "/home/Dev", id="posix-case-kept"),
        pytest.param("/c/Users/Bob", "c:/users/bob", id="msys"),
        pytest.param("\\\\?\\C:\\Users\\Bob", "c:/users/bob", id="extended-prefix"),
        pytest.param("", "", id="empty"),
        pytest.param("   ", "", id="blank"),
        pytest.param("$HOME", "$HOME", id="taken-literally"),
    ],
)
def test_key_of_home(home: str, key: str) -> None:
    assert key_of_home(home) == key


def test_key_of_home_matches_what_tilde_expands_to() -> None:
    for home in ("C:\\Users\\Bob", "/home/Dev", "\\\\srv\\share\\bob"):
        expanded = normalize_path("~/.ssh", cwd=None, home=home, dialect="tool")
        assert expanded.key == key_of_home(home).rstrip("/") + "/.ssh"


# --- unusual contexts (cwd / home / env given in other shapes) ----------------------------------


def custom(
    raw: str,
    *,
    cwd: str | None = None,
    home: str | None = None,
    env: Mapping[str, str] | None = None,
    dialect: Dialect = "tool",
) -> NormPath:
    return normalize_path(raw, cwd=cwd, home=home, env=env, dialect=dialect)


@pytest.mark.parametrize(
    ("raw", "kwargs", "key", "unc", "tag"),
    [
        pytest.param("x", {"cwd": "\\\\srv\\share\\p"}, "//srv/share/p/x", False, "", id="unc-cwd"),
        pytest.param(
            "\\x",
            {"cwd": "\\\\srv\\share\\p"},
            "//srv/share/x",
            True,
            "rooted-current-drive",
            id="unc-cwd-rooted",
        ),
        pytest.param("x", {"cwd": "\\\\srv"}, "//srv/x", True, "cwd-uncertain", id="server-cwd"),
        pytest.param(
            "\\\\\\?\\C:\\x",
            {"cwd": "C:\\proj"},
            "//./c/x",
            True,
            "odd-leading-separators",
            id="extended-prefix-with-too-many-separators",
        ),
        pytest.param("x", {"cwd": "rel/dir"}, "x", True, "cwd-unusable", id="relative-cwd"),
        pytest.param("x", {"cwd": "NUL"}, "x", True, "cwd-unusable", id="device-cwd"),
        pytest.param("x", {"cwd": "  "}, "x", True, "no-cwd", id="blank-cwd-is-none"),
        pytest.param(
            "x",
            {"cwd": "C:\\PROGRA~1\\app"},
            "c:/progra~1/app/x",
            True,
            "cwd-uncertain",
            id="short-name-cwd",
        ),
        pytest.param("x", {"cwd": "C:\\*"}, "c:/*/x", False, "", id="literal-cwd-is-not-a-glob"),
        pytest.param(
            "~/x",
            {"env": {"HOME": "/hh"}, "dialect": "bash"},
            "/hh/x",
            False,
            "home-expanded",
            id="tilde-from-env-home",
        ),
        pytest.param(
            "~/x",
            {"env": {"USERPROFILE": "C:\\u"}},
            "c:/u/x",
            False,
            "home-expanded",
            id="tilde-from-env-userprofile",
        ),
        pytest.param(
            "~/x",
            {"env": {"USERPROFILE": "C:\\u"}, "dialect": "bash"},
            "~/x",
            True,
            "unresolved-home",
            id="bash-tilde-ignores-userprofile",
        ),
        pytest.param(
            "$USERPROFILE\\x",
            {"home": "C:\\Users\\bob", "dialect": "powershell"},
            "c:/users/bob/x",
            True,
            "variable-syntax-mismatch",
            id="userprofile-falls-back-to-home",
        ),
        pytest.param(
            "$HOME\\x",
            {"env": {"USERPROFILE": "C:\\u"}, "dialect": "powershell"},
            "c:/u/x",
            False,
            "variable-expanded",
            id="powershell-home-is-userprofile",
        ),
        pytest.param(
            "$USERPROFILE/x",
            {"home": "/hh", "dialect": "bash"},
            "$USERPROFILE/x",
            True,
            "unresolved-variable:USERPROFILE",
            id="bash-userprofile-is-not-home",
        ),
        pytest.param(
            "$E/x",
            {"env": {"E": ""}, "dialect": "bash", "cwd": "/ww"},
            "$E/x",
            True,
            "empty-variable:E",
            id="empty-variable",
        ),
        pytest.param("$E/x", {"env": {"E": " "}, "dialect": "bash"}, "$E/x", True, "", id="blank"),
        pytest.param(" /", {}, "", True, "empty", id="blank-relative-component"),
        pytest.param(
            "%PWD%/x",
            {"cwd": "/ww", "dialect": "bash"},
            "%PWD%/x",
            True,
            "unresolved-variable:PWD",
            id="percent-pwd-is-not-a-variable",
        ),
        pytest.param("$$/x", {"dialect": "bash", "cwd": "/ww"}, "$$/x", True, "", id="pid"),
        pytest.param(
            "a$", {"dialect": "bash", "cwd": "/ww"}, "/ww/a$", False, "", id="lone-dollar"
        ),
        pytest.param(
            "a%b", {"dialect": "bash", "cwd": "/ww"}, "/ww/a%b", False, "", id="lone-percent"
        ),
    ],
)
def test_unusual_contexts(raw: str, kwargs: dict[str, Any], key: str, unc: bool, tag: str) -> None:
    got = custom(raw, **kwargs)
    assert got.key == key
    assert got.uncertain is unc
    if tag:
        assert tag in got.reasons


def test_inside_project_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("bug")

    monkeypatch.setattr(paths_module, "_inside_project", boom)
    got = norm("C:\\proj\\x")
    assert inside_project(got, got) is None


# --- inside_project: the direction rule --------------------------------------------------------


def ip(raw: str, root: str, ctx: str = "W", dialect: Dialect = "tool") -> bool | None:
    return inside_project(norm(raw, ctx, dialect), norm(root, ctx, "tool"))


def ipc(name: str, raw: str, root: str, ctx: str, expect: bool | None, d: Dialect = "tool") -> Any:
    return pytest.param(raw, root, ctx, d, expect, id=name)


WROOT = "C:\\proj"
PROOT = "/home/dev/proj"
INSIDE = [
    # --- definitely inside
    ipc("win-root-itself", "C:\\proj", WROOT, "W", True),
    ipc("win-child", "C:\\proj\\a\\b.py", WROOT, "W", True),
    ipc("win-case-insensitive", "c:\\PROJ\\X", WROOT, "W", True),
    ipc("win-dotdot-stays-inside", "C:\\proj\\a\\..\\b", WROOT, "W", True),
    ipc("win-forward-slashes", "C:/proj/x", WROOT, "W", True),
    ipc("win-relative-resolved-against-cwd", "src\\a.py", WROOT, "W", True),
    ipc("win-extended-prefix", "\\\\?\\C:\\proj\\x", WROOT, "W", True),
    ipc("win-ads-suffix-same-file", "C:\\proj\\x::$DATA", WROOT, "W", True),
    ipc("win-ads-on-root", "C:\\proj::$DATA", WROOT, "W", True),
    ipc("win-trailing-dot-same-dir", "c:\\PROJ.\\x", WROOT, "W", True),
    ipc("win-trailing-dots-on-last-component", "C:\\proj\\x. ", WROOT, "W", True),
    ipc("win-trailing-dots-and-spaces-mid-path-is-unsure", "C:\\proj \\x. ", WROOT, "W", None),
    ipc("none-trailing-space-on-project-dir", "C:\\proj \\x", WROOT, "W", None),
    ipc("none-two-trailing-dots-on-project-dir", "C:\\proj..\\x", WROOT, "W", None),
    ipc("none-three-dots-dir", "C:\\proj\\...\\x", WROOT, "W", None),
    ipc("win-msys-form", "/c/proj/x", WROOT, "W", True, "bash"),
    ipc("win-cygdrive-form", "/cygdrive/c/proj/x", WROOT, "W", True, "bash"),
    ipc("win-wsl-form", "/mnt/c/proj/x", WROOT, "W", True, "bash"),
    ipc("win-admin-share-of-localhost", "\\\\localhost\\c$\\proj\\x", WROOT, "W", True),
    ipc("win-tilde", "~\\..\\..\\proj\\x", WROOT, "W", True),
    ipc("win-drive-root-project", "C:\\x", "C:\\", "W", True),
    ipc("win-unc-project", "\\\\SRV\\Share\\proj\\x", "\\\\srv\\share\\proj", "W", True),
    ipc("posix-root-itself", "/home/dev/proj", PROOT, "P", True),
    ipc("posix-child", "/home/dev/proj/a/b", PROOT, "P", True),
    ipc("posix-relative", "a/b", PROOT, "P", True),
    ipc("posix-dot-slash", "./x", PROOT, "P", True),
    ipc("posix-dotdot-back-in", "/home/dev/proj/../proj/x", PROOT, "P", True),
    ipc("posix-repeated-slashes", "/home/dev/proj//x", PROOT, "P", True),
    ipc("posix-home-variable", "$HOME/proj/x", PROOT, "P", True, "bash"),
    ipc("posix-tilde", "~/proj/x", PROOT, "P", True, "bash"),
    ipc("posix-filesystem-root-project", "/anything/at/all", "/", "P", True),
    # --- definitely outside
    ipc("win-sibling-prefix", "C:\\proj2", WROOT, "W", False),
    ipc("win-sibling-prefix-child", "C:\\proj2\\x", WROOT, "W", False),
    ipc("win-sibling-dash", "C:\\proj-evil\\x", WROOT, "W", False),
    ipc("win-parent", "C:\\", WROOT, "W", False),
    ipc("win-shorter-name", "C:\\pro\\x", WROOT, "W", False),
    ipc("win-dotdot-to-ssh", "C:\\proj\\..\\..\\Users\\bob\\.ssh", WROOT, "W", False),
    ipc("win-dotdot-lower", "c:\\proj\\..\\secret", WROOT, "W", False),
    ipc("win-ssh-via-home", "~\\.ssh\\id_rsa", WROOT, "W", False),
    ipc("win-dotdot-over-root-clamps", "C:\\..\\..\\proj\\x", WROOT, "W", True),
    ipc("win-unc-sibling-dir", "\\\\srv\\share\\proj2\\x", "\\\\srv\\share\\proj", "W", False),
    ipc("posix-sibling-prefix", "/home/dev/proj2", PROOT, "P", False),
    ipc("posix-case-sensitive", "/home/dev/PROJ/x", PROOT, "P", False),
    ipc("posix-case-sensitive-root", "/Home/dev/proj/x", PROOT, "P", False),
    ipc("posix-parent", "/home/dev", PROOT, "P", False),
    ipc("posix-dotdot-out", "/home/dev/proj/../x", PROOT, "P", False),
    ipc("posix-relative-dotdot-out", "../x", PROOT, "P", False),
    ipc("posix-passwd", "/etc/passwd", PROOT, "P", False),
    ipc("posix-dotdot-to-ssh", "/home/dev/proj/../../.ssh/id_rsa", PROOT, "P", False),
    ipc("posix-triple-slash", "///etc/passwd", PROOT, "P", False),
    ipc("posix-trailing-dot-is-different", "/home/dev/proj./x", PROOT, "P", False),
    # --- unsure: never True
    ipc("none-other-drive", "D:\\proj\\x", WROOT, "W", None),
    ipc("none-drive-relative", "C:foo", WROOT, "W", None),
    ipc("none-drive-relative-bare", "C:", WROOT, "W", None),
    ipc("none-short-name", "C:\\PROJ~1\\x", WROOT, "W", None),
    ipc("none-short-name-program-files", "C:\\PROGRA~1\\x", WROOT, "W", None),
    ipc("none-unc-vs-drive", "\\\\srv\\share\\proj", WROOT, "W", None),
    ipc("none-other-share", "\\\\srv\\share2\\proj\\x", "\\\\srv\\share\\proj", "W", None),
    ipc("none-glob", "C:\\proj\\*", WROOT, "W", None),
    ipc("none-device", "NUL.txt", WROOT, "W", None),
    ipc("none-device-in-project", "C:\\proj\\nul", WROOT, "W", None),
    ipc("none-device-pipe", "\\\\.\\pipe\\x", WROOT, "W", None),
    ipc("none-extended-dotdot", "\\\\?\\C:\\proj\\..\\x", WROOT, "W", None),
    ipc("none-extended-dotdot-looks-inside", "\\\\?\\C:\\proj\\x\\..\\y", WROOT, "W", None),
    ipc("none-unresolved-variable", "%NOPE%\\x", WROOT, "W", None),
    ipc("none-rooted-no-drive", "\\x", WROOT, "W", None),
    ipc("none-msys-dotdot-escape", "/c/../proj/x", WROOT, "W", None, "bash"),
    ipc("none-git-bash-tmp", "/tmp/x", WROOT, "W", None, "bash"),
    ipc("none-git-bash-looks-like-project", "/home/dev/proj/x", WROOT, "W", None, "bash"),
    ipc("none-posix-in-windows-project", "/mnt/wsl/x", WROOT, "W", None, "bash"),
    ipc("none-windows-path-in-posix-project", "C:\\proj\\x", PROOT, "P", None),
    ipc("none-wsl-form-vs-posix-project", "/mnt/c/proj/x", PROOT, "P", None, "bash"),
    ipc("none-posix-unresolved-variable", "$X/x", PROOT, "P", None, "bash"),
    ipc("none-posix-glob", "*.py", PROOT, "P", None, "bash"),
    ipc("none-posix-double-slash", "//home/dev/proj/x", PROOT, "P", None, "bash"),
    ipc("none-posix-command-substitution", "$(pwd)/x", PROOT, "P", None, "bash"),
    ipc("none-posix-tilde-user", "~root/x", PROOT, "P", None, "bash"),
    ipc("none-nul-byte", "/home/dev/proj/a\x00/../../x", PROOT, "P", None),
    ipc("none-empty", "", PROOT, "P", None),
]


@pytest.mark.parametrize(("raw", "root", "ctx", "dialect", "expect"), INSIDE)
def test_inside_project(
    raw: str, root: str, ctx: str, dialect: Dialect, expect: bool | None
) -> None:
    assert ip(raw, root, ctx, dialect) is expect


def test_inside_project_has_at_least_sixty_adversarial_rows() -> None:
    assert len(INSIDE) >= 60


def test_inside_project_without_root_is_unknown() -> None:
    assert inside_project(norm("C:\\proj\\x"), None) is None


@pytest.mark.parametrize(
    "bad_root",
    [
        pytest.param("%NOPE%\\proj", id="unresolved-variable"),
        pytest.param("proj", id="relative"),
        pytest.param("C:proj", id="drive-relative"),
        pytest.param("NUL", id="device"),
        pytest.param("C:\\PROJ~1", id="short-name"),
        pytest.param("", id="empty"),
    ],
)
def test_inside_project_with_unsure_root_is_unknown(bad_root: str) -> None:
    root = normalize_path(bad_root, cwd=None, home=None, dialect="tool")
    assert inside_project(norm("C:\\proj\\x"), root) is None


def test_inside_project_mixed_flavors_is_unknown() -> None:
    assert inside_project(norm("C:\\proj\\x", "W"), norm("/home/dev/proj", "P")) is None
    assert inside_project(norm("/home/dev/proj/x", "P"), norm("C:\\proj", "W")) is None


def test_inside_project_distrusts_a_hand_built_key() -> None:
    root = norm("C:\\proj")
    sneaky = dataclasses.replace(norm("C:\\proj\\x"), key="c:/proj/../secret")
    assert inside_project(sneaky, root) is None
    nul = dataclasses.replace(norm("C:\\proj\\x"), key="c:/proj/x\x00")
    assert inside_project(nul, root) is None
    dot = dataclasses.replace(norm("C:\\proj\\x"), key="c:/proj/x/..")
    assert inside_project(dot, root) is None
    anchorless = dataclasses.replace(norm("C:\\proj\\x"), key="proj/x")
    assert inside_project(anchorless, root) is None


# --- reasons are stable tags -------------------------------------------------------------------


def test_reasons_have_no_duplicates() -> None:
    got = norm("C:\\a. \\b. \\c::$DATA", "W")
    assert len(set(got.reasons)) == len(got.reasons)


def test_reason_names_for_the_common_cases() -> None:
    assert "unresolved-variable:NOPE" in norm("$NOPE", "P", "bash").reasons
    assert "glob" in norm("*", "P", "bash").reasons
    assert "drive-relative" in norm("C:x").reasons
    assert "device:NUL" in norm("NUL").reasons
    assert "unc" in norm("\\\\a\\b").reasons
    assert "short-name-unresolved" in norm("C:\\PROGRA~1").reasons
    assert "git-bash-root" in norm("/tmp", "W", "bash").reasons
    assert "msys-translated" in norm("/c/x", "W", "bash").reasons


# --- property tests ----------------------------------------------------------------------------

FRAGMENTS = [
    "C:", "c:", "D:", "\\", "/", "\\\\", "//", "..", ".", "a", "proj", "Users", "bob", ".ssh",
    "nul", "NUL", "con", "com1", "~", "$HOME", "${HOME}", "%TEMP%", "$env:TEMP", "$FOO", "*", "?",
    "[", "{a,b}", ":", "::$DATA", " ", "\\\\?\\", "\\\\.\\", "PROGRA~1", "mnt", "cygdrive", "x",
    "\x00", "$(", "\u00e9", "\uff21", "UNC", "share", "localhost", "C$", "\ud800", "\\??\\", "%",
    "$", "{", "}", "|", "<", "\t",
]  # fmt: skip
ODD_ALPHABET = ["\ud800", "\udfff", "\x00", "a", "A", "\\", "/", ":", ".", " ", "~", "$", "%", "é"]

path_text = st.one_of(
    st.lists(st.sampled_from(FRAGMENTS), max_size=14).map("".join),
    st.text(max_size=60),
    st.text(alphabet=st.sampled_from(ODD_ALPHABET), max_size=40),
)
contexts = st.sampled_from(["W", "P", "N"])
dialects: st.SearchStrategy[Dialect] = st.sampled_from(["bash", "powershell", "tool"])


@settings(max_examples=400, deadline=None)
@given(raw=path_text, ctx=contexts, dialect=dialects)
def test_never_raises_and_returns_a_wellformed_result(raw: str, ctx: str, dialect: Dialect) -> None:
    got = norm(raw, ctx, dialect)
    assert isinstance(got, NormPath)
    assert isinstance(got.key, str)
    assert got.raw == raw
    assert got.flavor in ("windows", "posix")
    assert "internal-error" not in got.reasons
    if got.uncertain:
        assert got.reasons
    if got.is_device:
        assert got.uncertain
        assert got.flavor == "windows"
    got.key.encode("utf-8", errors="surrogatepass")  # must be storable and printable by callers


@settings(max_examples=400, deadline=None)
@given(raw=path_text, ctx=contexts, dialect=dialects)
def test_normalization_is_idempotent(raw: str, ctx: str, dialect: Dialect) -> None:
    first = norm(raw, ctx, dialect)
    assume(not _idempotence_exempt(first, ctx))
    second = norm(first.key, ctx, dialect)
    assert second.key == first.key


@settings(max_examples=300, deadline=None)
@given(raw=path_text, ctx=contexts, dialect=dialects)
def test_a_certain_absolute_path_is_inside_itself(raw: str, ctx: str, dialect: Dialect) -> None:
    got = norm(raw, ctx, dialect)
    assume(got.absolute and not got.uncertain and not got.is_device)
    assert inside_project(got, got) is True


@settings(max_examples=400, deadline=None)
@given(raw=path_text, root_raw=path_text, ctx=contexts, dialect=dialects)
def test_inside_is_never_true_for_an_uncertain_path(
    raw: str, root_raw: str, ctx: str, dialect: Dialect
) -> None:
    path = norm(raw, ctx, dialect)
    root = norm(root_raw, ctx, dialect)
    verdict = inside_project(path, root)
    if path.uncertain or root.uncertain or path.is_device or not path.absolute:
        assert verdict is None
    if verdict is True:
        assert path.flavor == root.flavor
        assert path.key == root.key or path.key.startswith(root.key.rstrip("/") + "/")


safe_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    min_size=1,
    max_size=8,
)


@settings(max_examples=200, deadline=None)
@given(names=st.lists(safe_name, min_size=1, max_size=4), sibling=safe_name)
def test_children_are_inside_and_siblings_are_not(names: list[str], sibling: str) -> None:
    assume(not any(n.upper() in {"CON", "PRN", "AUX", "NUL"} for n in [*names, sibling]))
    assume(not any(n.upper().startswith(("COM", "LPT")) and len(n) == 4 for n in [*names, sibling]))
    win_root = "C:\\proj"
    child = win_root + "\\" + "\\".join(names)
    assert ip(child, win_root, "W") is True
    assert ip(win_root.upper() + "\\" + "/".join(names).lower(), win_root, "W") is True
    assert ip(win_root + sibling + "\\" + names[0], win_root, "W") is False
    posix_child = PROOT + "/" + "/".join(names)
    assert ip(posix_child, PROOT, "P") is True
    assert ip(PROOT + sibling + "/" + names[0], PROOT, "P") is False
    assert ip(posix_child.replace("/proj/", "/PROJ/", 1), PROOT, "P") is False


@settings(max_examples=200, deadline=None)
@given(depth=st.integers(min_value=0, max_value=12))
def test_dotdot_can_never_climb_out_of_the_root(depth: int) -> None:
    assert norm("C:\\" + "..\\" * depth + "x").key == "c:/x"
    assert norm("/" + "../" * depth + "xx", "P").key == "/xx"
    assert norm("\\\\srv\\share\\" + "..\\" * depth + "x").key == "//srv/share/x"
    assert norm("../" * depth + "xx", "P").key.startswith("/")


# --- hostile sizes -----------------------------------------------------------------------------

_N = 65000
PATHOLOGICAL = {
    "many-segments": "a/" * (_N // 2),
    "many-variables": "".join(f"$a{i}/" for i in range(_N // 7)),
    "open-braces": "${" * (_N // 2),
    "percent-pairs": "%a" * (_N // 2),
    "dotdots": "../" * (_N // 3),
    "windows-dots": "C:\\" + "a. \\" * (_N // 4),
    "unc-segments": "\\\\" + "s\\" * (_N // 2),
    "substitutions": "$(" * (_N // 2),
    "short-names": "C:\\" + "ab~1\\" * (_N // 5),
    "streams": "C:\\" + "a:b\\" * (_N // 4),
    "env-colons": "$env:" * (_N // 5),
    "backslashes": "\\" * _N,
    "oversize": "x" * (4 * _N),
}


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_hostile_sizes_are_handled_quickly(name: str) -> None:
    import time

    raw = PATHOLOGICAL[name]
    for ctx in ("W", "P", "N"):
        started = time.perf_counter()
        got = norm(raw, ctx, "bash")
        assert time.perf_counter() - started < 5.0, "must be linear, not quadratic"
        assert len(got.reasons) <= 64
        assert got.uncertain or got.key


# --- file system layer -------------------------------------------------------------------------


def real(p: Path) -> NormPath:
    return normalize_path(str(p), cwd=None, home=None, dialect="tool")


def symlink_or_skip(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")


def expected_key(p: Path) -> str:
    return normalize_path(os.path.realpath(p), cwd=None, home=None, dialect="tool").key


def test_resolve_on_disk_plain_path_keeps_its_key(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f.txt").write_text("x", encoding="utf-8")
    path = real(tmp_path / "d" / "f.txt")
    got = resolve_on_disk(path)
    assert got.raw == path.raw
    assert got.key == expected_key(tmp_path / "d" / "f.txt")
    assert not got.is_device


def test_resolve_on_disk_nonexistent_path_does_not_fail(tmp_path: Path) -> None:
    ghost = tmp_path / "nope" / "deeper" / "x.txt"
    got = resolve_on_disk(real(ghost))
    assert got.key == expected_key(ghost)
    assert got.raw == str(ghost)


def test_resolve_on_disk_expands_symlinked_directory(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.txt").write_text("x", encoding="utf-8")
    symlink_or_skip(tmp_path / "real", tmp_path / "link")
    lexical = real(tmp_path / "link" / "f.txt")
    got = resolve_on_disk(lexical)
    assert got.key == expected_key(tmp_path / "real" / "f.txt")
    assert got.key.endswith("/real/f.txt")
    assert got.raw == lexical.raw
    assert "resolved-on-disk" in got.reasons


def test_resolve_on_disk_exposes_a_symlink_that_leaves_the_project(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    outside = tmp_path / "out"
    project.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("s", encoding="utf-8")
    symlink_or_skip(outside, project / "lnk")
    root = resolve_on_disk(real(project))
    path = real(project / "lnk" / "secret.txt")
    assert inside_project(path, real(project)) in (True, None)  # lexically it looks inside
    assert inside_project(resolve_on_disk(path), root) is False


def test_resolve_on_disk_follows_a_symlinked_file_and_a_loop(tmp_path: Path) -> None:
    (tmp_path / "target.txt").write_text("x", encoding="utf-8")
    symlink_or_skip(tmp_path / "target.txt", tmp_path / "flink.txt")
    assert resolve_on_disk(real(tmp_path / "flink.txt")).key == expected_key(
        tmp_path / "target.txt"
    )
    (tmp_path / "loop").mkdir()
    symlink_or_skip(tmp_path / "loop", tmp_path / "loop" / "again")
    resolve_on_disk(real(tmp_path / "loop" / "again" / "again" / "x"))  # must not raise or hang


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("*.py", id="glob"),
        pytest.param("$NOPE/x", id="unresolved-variable"),
        pytest.param("relative/no/cwd", id="relative"),
        pytest.param("NUL", id="device"),
        pytest.param("C:foo", id="drive-relative"),
        pytest.param("\\\\srv\\share\\x", id="unc"),
        pytest.param("", id="empty"),
        pytest.param("/tmp/a\x00b", id="nul"),
        pytest.param("\\\\.\\pipe\\x", id="pipe"),
    ],
)
def test_resolve_on_disk_leaves_unresolvable_paths_alone(raw: str) -> None:
    path = normalize_path(raw, cwd=None, home=None, dialect="bash")
    assert resolve_on_disk(path) == path


def test_resolve_on_disk_foreign_flavor_is_unchanged() -> None:
    foreign = "/home/dev/x" if sys.platform == "win32" else "C:\\Users\\bob\\x"
    path = normalize_path(foreign, cwd=None, home=None, dialect="tool")
    assert resolve_on_disk(path) == path


def test_resolve_on_disk_never_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> str:
        raise OSError("disk on fire")

    path = real(tmp_path / "x")
    monkeypatch.setattr(os.path, "realpath", boom)
    assert resolve_on_disk(path) == path
    monkeypatch.setattr(os.path, "realpath", lambda p: "relative/result")
    assert resolve_on_disk(path) == path


def test_resolve_on_disk_keeps_other_uncertainty(tmp_path: Path) -> None:
    path = dataclasses.replace(real(tmp_path / "x"), uncertain=True, reasons=("glob",))
    assert resolve_on_disk(path) == path


@pytest.mark.windows
def test_certain_drive_paths_agree_with_win32_full_path_name() -> None:
    """Differential test: for paths we call certain, Win32's own normalizer must say the same.

    ``GetFullPathNameW`` is the reference for ``.``/``..``, repeated separators and trailing
    dots and spaces (it does not touch streams or 8.3 names, which the generator avoids).
    """
    import ctypes
    import random

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetFullPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
    ]

    def full(p: str) -> str:
        buf = ctypes.create_unicode_buffer(4096)
        return buf.value if kernel32.GetFullPathNameW(p, 4096, buf, None) else "?"

    frags = [
        "a",
        "b",
        "proj",
        "..",
        ".",
        "...",
        ".. ",
        " ",
        "x.",
        "x ",
        "x. .",
        "A",
        "B",
        "x..",
        "y",
    ]
    rng = random.Random(20261010)  # noqa: S311 - fixed seed test data, not security
    checked = 0
    for _ in range(4000):
        n = rng.randint(1, 7)
        raw = "C:" + "".join(rng.choice(["\\", "/", "\\\\"]) + rng.choice(frags) for _ in range(n))
        got = normalize_path(raw, cwd="C:\\proj", home=None, dialect="tool")
        if got.uncertain or got.is_device:
            continue
        reference = full(raw).replace("\\", "/").casefold()
        assert reference.rstrip("/") == got.key.rstrip("/"), raw
        checked += 1
    assert checked > 500


@pytest.mark.windows
def test_resolve_on_disk_follows_a_junction(tmp_path: Path) -> None:
    import _winapi  # type: ignore[import-not-found,unused-ignore]

    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.txt").write_text("x", encoding="utf-8")
    try:
        _winapi.CreateJunction(str(tmp_path / "real"), str(tmp_path / "junc"))
    except OSError as exc:
        pytest.skip(f"cannot create a junction here: {exc}")
    got = resolve_on_disk(real(tmp_path / "junc" / "f.txt"))
    assert got.key == expected_key(tmp_path / "real" / "f.txt")
    assert "/real/" in got.key
    assert "resolved-on-disk" in got.reasons


@pytest.mark.windows
def test_resolve_on_disk_expands_short_names(tmp_path: Path) -> None:
    import ctypes

    long_dir = tmp_path / "a_rather_long_directory_name"
    long_dir.mkdir()
    target = long_dir / "some_long_file_name.txt"
    target.write_text("x", encoding="utf-8")
    get_short: Callable[[str, Any, int], int] = ctypes.windll.kernel32.GetShortPathNameW  # type: ignore[attr-defined,unused-ignore]
    buf = ctypes.create_unicode_buffer(1024)
    if not get_short(str(target), buf, 1024) or buf.value.lower() == str(target).lower():
        pytest.skip("8.3 short names are disabled on this volume")
    short = normalize_path(buf.value, cwd=None, home=None, dialect="tool")
    assert short.uncertain
    assert "short-name-unresolved" in short.reasons
    assert inside_project(short, real(long_dir)) is None
    got = resolve_on_disk(short)
    assert got.key == expected_key(target)
    assert not got.uncertain
    assert "short-name-unresolved" not in got.reasons
    assert got.raw == buf.value
    assert inside_project(got, resolve_on_disk(real(long_dir))) is True


@pytest.mark.posix
def test_resolve_on_disk_posix_keeps_case(tmp_path: Path) -> None:
    (tmp_path / "MixedCase").mkdir()
    got = resolve_on_disk(real(tmp_path / "MixedCase" / "F"))
    assert got.flavor == "posix"
    assert got.key.endswith("/MixedCase/F")


# --- additions: literal globs, expanded_text, expand_glob, local-disk guard ----------------------


def test_glob_literal_keeps_brackets_and_stars_as_ordinary_characters() -> None:
    plain = norm("app/[id]/page.tsx", "P", "tool")
    assert plain.uncertain
    assert "glob" in plain.reasons
    cwd, home, env = CONTEXTS["P"]
    lit = normalize_path(
        "app/[id]/page.tsx", cwd=cwd, home=home, env=env, dialect="tool", glob_literal=True
    )
    assert not lit.uncertain
    assert "glob" not in lit.reasons
    assert lit.key == "/home/dev/proj/app/[id]/page.tsx"
    tilde = normalize_path("~/x*", cwd=cwd, home=home, env=env, dialect="tool", glob_literal=True)
    assert tilde.key == "/home/dev/x*"
    assert not tilde.uncertain


def test_literal_skips_tilde_and_variable_expansion() -> None:
    cwd, home, env = CONTEXTS["P"]
    got = normalize_path("~/x", cwd=cwd, home=home, env=env, dialect="bash", literal=True)
    assert got.key == "~/x"  # kept as text, not expanded to the home directory
    assert got.uncertain  # a leading "~" is still never trusted
    star = normalize_path("a*b", cwd=cwd, home=home, env=env, dialect="bash", literal=True)
    assert star.key == "/home/dev/proj/a*b"
    assert not star.uncertain


@pytest.mark.parametrize(
    ("raw", "ctx", "dialect", "expected"),
    [
        pytest.param("~/a/../b", "P", "bash", "/home/dev/a/../b", id="tilde"),
        pytest.param("$HOME/x/..", "P", "bash", "/home/dev/x/..", id="home-var"),
        pytest.param("x/../y", "P", "bash", "/home/dev/proj/x/../y", id="relative"),
        pytest.param("/a/b/../c", "P", "bash", "/a/b/../c", id="absolute"),
        pytest.param("$NOPE/x", "P", "bash", None, id="unresolved"),
        pytest.param("x/../y", "N", "bash", None, id="no-cwd"),
        pytest.param("", "P", "bash", None, id="empty"),
        pytest.param("a*/../b", "P", "bash", "/home/dev/proj/a*/../b", id="glob-is-text"),
    ],
)
def test_expanded_text_keeps_dotdot_uncollapsed(
    raw: str, ctx: str, dialect: Dialect, expected: str | None
) -> None:
    cwd, home, env = CONTEXTS[ctx]
    got = paths_module.expanded_text(raw, cwd=cwd, home=home, env=env, dialect=dialect)
    assert got == expected


def test_expanded_text_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(paths_module, "_expand", boom)
    assert paths_module.expanded_text("~/x", cwd="/p", home="/h", env=None) is None


def _glob_path(p: Path, pattern: str) -> NormPath:
    return normalize_path(str(p).replace("\\", "/") + "/" + pattern, cwd=None, home=None)


def _names(result: Any) -> list[str]:
    return sorted(os.path.basename(m) for m in result.matches)


@pytest.fixture
def globdir(tmp_path: Path) -> Path:
    for name in ("a.txt", "b.txt", "c.py", ".hidden", ".env"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "d.txt").write_text("x", encoding="utf-8")
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_rsa").write_text("x", encoding="utf-8")
    return tmp_path


def test_expand_glob_enumerates_matches_on_disk(globdir: Path) -> None:
    got = paths_module.expand_glob(_glob_path(globdir, "*.txt"))
    assert got.status == "ok"
    assert _names(got) == ["a.txt", "b.txt"]
    deep = paths_module.expand_glob(_glob_path(globdir, "*/*.txt"))
    assert _names(deep) == ["d.txt"]
    cls = paths_module.expand_glob(_glob_path(globdir, "[ab].txt"))
    assert _names(cls) == ["a.txt", "b.txt"]
    neg = paths_module.expand_glob(_glob_path(globdir, "[!a].txt"))
    assert _names(neg) == ["b.txt"]
    caret = paths_module.expand_glob(_glob_path(globdir, "[^a].txt"))
    assert _names(caret) == ["b.txt"]
    one = paths_module.expand_glob(_glob_path(globdir, "?.py"))
    assert _names(one) == ["c.py"]


def test_expand_glob_follows_the_leading_dot_rule(globdir: Path) -> None:
    star = paths_module.expand_glob(_glob_path(globdir, "*"))
    assert ".env" not in _names(star)
    assert ".hidden" not in _names(star)
    dots = paths_module.expand_glob(_glob_path(globdir, ".*"))
    assert _names(dots) == [".env", ".hidden", ".ssh"]
    nested = paths_module.expand_glob(_glob_path(globdir, ".ss*/*"))
    assert _names(nested) == ["id_rsa"]
    assert paths_module.expand_glob(_glob_path(globdir, ".env*")).matches != ()


def test_expand_glob_reports_none_and_missing_directories(globdir: Path) -> None:
    assert paths_module.expand_glob(_glob_path(globdir, "*.nothing")).status == "none"
    assert paths_module.expand_glob(_glob_path(globdir, "nodir/*.txt")).status == "none"
    assert paths_module.expand_glob(_glob_path(globdir, "x*/y")).status == "none"
    gone = normalize_path(str(globdir / "gone" / "*").replace("\\", "/"), cwd=None, home=None)
    assert paths_module.expand_glob(gone).status == "none"


def test_expand_glob_is_bounded(globdir: Path) -> None:
    for i in range(20):
        (globdir / f"many{i}.log").write_text("x", encoding="utf-8")
    capped = paths_module.expand_glob(_glob_path(globdir, "many*.log"), limit=5)
    assert capped.status == "too-many"
    scanned = paths_module.expand_glob(_glob_path(globdir, "many*.log"), max_entries=3)
    assert scanned.status == "too-many"
    late = paths_module.expand_glob(_glob_path(globdir, "*.log"), deadline=0.0)
    assert late.status == "budget"


def test_expand_glob_refuses_what_it_cannot_enumerate_safely(globdir: Path) -> None:
    relative = normalize_path("*.txt", cwd=None, home=None, dialect="bash")
    assert paths_module.expand_glob(relative).status == "unsupported"
    unc = normalize_path("\\\\srv\\share\\*.txt", cwd=None, home=None, dialect="tool")
    assert paths_module.expand_glob(unc).status == "unsupported"
    device = normalize_path("\\\\.\\pipe\\*", cwd=None, home=None, dialect="tool")
    assert paths_module.expand_glob(device).status == "unsupported"
    var = normalize_path(str(globdir) + "/$X/*", cwd=None, home=None, dialect="bash")
    assert paths_module.expand_glob(var).status == "unsupported"
    foreign = "/home/dev/*" if sys.platform == "win32" else "C:\\Users\\bob\\*"
    other = normalize_path(foreign, cwd=None, home=None, dialect="tool")
    assert paths_module.expand_glob(other).status == "unsupported"
    deep = normalize_path(str(globdir) + "/*" + "/x" * 80, cwd=None, home=None, dialect="tool")
    assert paths_module.expand_glob(deep).status == "unsupported"


def test_expand_glob_never_raises(monkeypatch: pytest.MonkeyPatch, globdir: Path) -> None:
    def burn(*args: object, **kwargs: object) -> object:
        raise OSError("disk on fire")

    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("bug")

    monkeypatch.setattr(os, "scandir", burn)
    assert paths_module.expand_glob(_glob_path(globdir, "*.txt")).status == "none"
    monkeypatch.setattr(paths_module, "_expand_glob", boom)
    assert paths_module.expand_glob(_glob_path(globdir, "*.txt")).status == "unsupported"


def test_local_disk_guard_rejects_network_and_device_paths() -> None:
    unc = normalize_path("\\\\srv\\share\\x", cwd=None, home=None, dialect="tool")
    assert not paths_module.is_local_disk(unc)
    dev = normalize_path("\\\\.\\pipe\\x", cwd=None, home=None, dialect="tool")
    assert not paths_module.is_local_disk(dev)
    relative = normalize_path("x", cwd=None, home=None, dialect="bash")
    assert not paths_module.is_local_disk(relative)


def test_local_disk_guard_follows_the_drive_type(monkeypatch: pytest.MonkeyPatch) -> None:
    drive = normalize_path("C:\\x", cwd=None, home=None, dialect="tool")
    monkeypatch.setattr(paths_module, "_drive_type", lambda letter: 4)  # DRIVE_REMOTE
    assert not paths_module.is_local_disk(drive)
    monkeypatch.setattr(paths_module, "_drive_type", lambda letter: 3)  # DRIVE_FIXED
    # a drive path is only "local" on a Windows host; on POSIX it is a foreign-flavor path
    assert paths_module.is_local_disk(drive) == (os.name == "nt")
    posix = normalize_path("/home/x", cwd=None, home=None, dialect="tool")
    assert paths_module.is_local_disk(posix) == (sys.platform != "win32")


@pytest.mark.windows
def test_resolve_on_disk_skips_remote_drives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "real").mkdir()
    called: list[str] = []
    monkeypatch.setattr(paths_module, "_drive_type", lambda letter: 4)
    monkeypatch.setattr(os.path, "realpath", lambda p: called.append(p) or p)
    path = real(tmp_path / "real")
    assert resolve_on_disk(path) == path
    assert called == []


@pytest.mark.windows
def test_drive_type_asks_the_os_about_a_real_drive() -> None:
    assert paths_module._drive_type(os.path.splitdrive(os.getcwd())[0][0]) in (2, 3, 4, 5, 6)
