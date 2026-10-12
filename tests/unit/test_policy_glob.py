"""Tests for ``boundkeep.policy.glob``: syntax, semantics, limits, linear time, a regex oracle."""

from __future__ import annotations

import re
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boundkeep.policy.glob import (
    MAX_KEY_LENGTH,
    MAX_PATTERN_LENGTH,
    Glob,
    GlobError,
    compile_glob,
    first_match,
)


def matches(pattern: str, key: str) -> bool:
    return compile_glob(pattern).match(key)


# ---------------------------------------------------------------------------- semantics

MATCH_CASES = [
    # **/name: any depth, also directly at the root and as a bare relative name
    pytest.param("**/.env", ".env", True, id="dstar-bare-name"),
    pytest.param("**/.env", "/.env", True, id="dstar-at-root"),
    pytest.param("**/.env", "/home/u/proj/.env", True, id="dstar-posix"),
    pytest.param("**/.env", "c:/users/bob/proj/.env", True, id="dstar-windows-key"),
    pytest.param("**/.env", "/HOME/U/.ENV", True, id="dstar-case-insensitive-key"),
    pytest.param("**/.env", "/home/u/.envrc", False, id="dstar-envrc-is-not-env"),
    pytest.param("**/.env", "/home/u/xenv", False, id="dstar-xenv-is-not-env"),
    pytest.param("**/.env", "/home/u/x.env", False, id="dstar-needs-segment-boundary"),
    pytest.param("**/.env", "/home/u/.env/secret", False, id="dstar-not-a-prefix"),
    pytest.param("**/.env", "/home/u/.env.bak", False, id="dstar-not-env-bak"),
    pytest.param("**/.env.*", "/home/u/.env.local", True, id="env-star-variant"),
    pytest.param("**/.env.*", "/home/u/.env", False, id="env-star-needs-a-dot"),
    pytest.param("**/.env.*", "/home/u/.envrc", False, id="env-star-envrc"),
    pytest.param("**/.claude/settings*.json", "/p/.claude/settings.json", True, id="claude-plain"),
    pytest.param(
        "**/.claude/settings*.json", "/p/.claude/settings.local.json", True, id="claude-local"
    ),
    pytest.param("**/.claude/settings*.json", "c:/p/.CLAUDE/Settings.JSON", True, id="claude-case"),
    pytest.param(
        "**/.claude/settings*.json", "/p/.claude/settings.json.bak", False, id="claude-bak"
    ),
    pytest.param(
        "**/.claude/settings*.json", "/p/.claude/sub/settings.json", False, id="claude-sub"
    ),
    pytest.param("**/.claude/settings*.json", "/p/claude/settings.json", False, id="claude-no-dot"),
    pytest.param("**/*.pem", "/a/b/key.pem", True, id="pem-nested"),
    pytest.param("**/*.pem", "key.pem", True, id="pem-bare"),
    pytest.param("**/*.pem", "/a/.pem", True, id="pem-empty-stem"),
    pytest.param("**/*.pem", "/a/key.pem/x", False, id="pem-dir-named-pem"),
    pytest.param("**/*.pem", "/a/key.pemx", False, id="pem-suffix-only"),
    pytest.param("**/*.pem", "/a/pem", False, id="pem-no-dot"),
    # trailing /** : the directory itself and everything below
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bob/.ssh/id_rsa", True, id="tail-file"),
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bob/.ssh", True, id="tail-dir-itself"),
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bob/.ssh/a/b/c", True, id="tail-deep"),
    pytest.param("c:/users/bob/.ssh/**", "C:/Users/Bob/.SSH/ID_RSA", True, id="tail-case"),
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bob/.sshx", False, id="tail-sibling-prefix"),
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bob/.ssh_old/x", False, id="tail-sibling-dir"),
    pytest.param("c:/users/bob/.ssh/**", "c:/users/bobby/.ssh/x", False, id="tail-other-user"),
    pytest.param("c:/users/bob/.ssh/**", "d:/users/bob/.ssh/x", False, id="tail-other-drive"),
    pytest.param("/a/**/**", "/a/b", True, id="doubled-tail"),
    # * and ? never cross a slash
    pytest.param("/a/*", "/a/b", True, id="star-one-level"),
    pytest.param("/a/*", "/a/b/c", False, id="star-not-two-levels"),
    pytest.param("/a/*", "/a/", True, id="star-empty-tail"),
    pytest.param("/a/*/c", "/a/b/c", True, id="star-mid"),
    pytest.param("/a/*/c", "/a/b/d/c", False, id="star-mid-not-two"),
    pytest.param("/a/?.txt", "/a/b.txt", True, id="qmark-one"),
    pytest.param("/a/?.txt", "/a/bb.txt", False, id="qmark-not-two"),
    pytest.param("/a/?.txt", "/a//.txt", False, id="qmark-not-slash"),
    pytest.param("/a*b", "/axxb", True, id="star-inside-segment"),
    pytest.param("/a*b", "/ax/xb", False, id="star-inside-segment-no-slash"),
    # ** inside a segment crosses directories (over-matching is the safe direction)
    pytest.param("/a**b", "/ax/y/b", True, id="dstar-inside-segment"),
    pytest.param("/a/**/b", "/a/b", True, id="dstar-mid-zero-dirs"),
    pytest.param("/a/**/b", "/a/x/b", True, id="dstar-mid-one-dir"),
    pytest.param("/a/**/b", "/a/x/y/b", True, id="dstar-mid-two-dirs"),
    pytest.param("/a/**/b", "/a/xb", False, id="dstar-mid-needs-boundary"),
    pytest.param("/a/**/b", "/ab", False, id="dstar-mid-not-glued"),
    pytest.param("**", "/any/thing", True, id="bare-dstar"),
    pytest.param("***/x", "/y/x", True, id="three-stars-are-dstar"),
    # classes
    pytest.param("/a/[abc].txt", "/a/b.txt", True, id="class-member"),
    pytest.param("/a/[abc].txt", "/a/d.txt", False, id="class-non-member"),
    pytest.param("/a/[!abc].txt", "/a/d.txt", True, id="class-negated"),
    pytest.param("/a/[^abc].txt", "/a/a.txt", False, id="class-caret-negated"),
    pytest.param("/a/[!abc].txt", "/a//.txt", False, id="negated-class-not-slash"),
    pytest.param("/a/[a-c].txt", "/a/B.txt", True, id="class-range-case"),
    pytest.param("/a/[A-C].txt", "/a/b.txt", True, id="class-upper-range"),
    pytest.param("/a/[]x]", "/a/]", True, id="class-leading-bracket-literal"),
    pytest.param("/a/[*]", "/a/*", True, id="class-literal-star"),
    pytest.param("/a/[*]", "/a/b", False, id="class-literal-star-only"),
    pytest.param("/a/[[]", "/a/[", True, id="class-literal-open-bracket"),
    pytest.param("/a/[a-]", "/a/-", True, id="class-trailing-dash"),
    pytest.param("~/x", "~/x", True, id="tilde-is-literal-when-not-expanded"),
    # literals and anchors
    pytest.param("/etc/passwd", "/etc/passwd", True, id="absolute-literal"),
    pytest.param("/etc/passwd", "/etc/passwd2", False, id="literal-no-prefix-match"),
    pytest.param("/etc/passwd", "etc/passwd", False, id="literal-needs-leading-slash"),
    pytest.param("//server/share/**", "//server/share/x/y", True, id="unc"),
    pytest.param("//server/share/**", "/server/share/x", False, id="unc-needs-two-slashes"),
    pytest.param("?:/windows/**", "c:/windows/system32", True, id="drive-wildcard"),
    pytest.param("?:/windows/**", "cc:/windows/x", False, id="drive-wildcard-one-char"),
    pytest.param("/straße", "/STRASSE", True, id="casefold-both-sides"),
    pytest.param("/a/b", "/a/b/", False, id="key-with-trailing-slash-is-different"),
]


@pytest.mark.parametrize(("pattern", "key", "expected"), MATCH_CASES)
def test_glob_semantics(pattern: str, key: str, expected: bool) -> None:
    assert matches(pattern, key) is expected


def test_the_documented_examples_together() -> None:
    home = "c:/users/bob"
    ssh = f"{home}/.ssh/**"
    assert matches(ssh, "c:/users/bob/.ssh/id_rsa")
    assert matches("**/.env", ".env")
    assert not matches("**/.env", ".envrc")
    assert not matches("**/.env", "xenv")


def test_empty_and_overlong_keys_never_match() -> None:
    assert not matches("**", "")
    assert not matches("**/x", "")
    assert not matches("**", "/" + "a" * MAX_KEY_LENGTH)
    assert matches("**", "/" + "a" * (MAX_KEY_LENGTH - 1))


def test_non_string_keys_do_not_match_or_raise() -> None:
    glob = compile_glob("**")
    for bad in (None, 5, b"/a", ("/a",)):
        assert glob.match(bad) is False  # type: ignore[arg-type]


def test_keys_with_surrogates_nul_and_odd_unicode() -> None:
    assert matches("**/x", "/a\x00b/x")
    assert matches("/a/?", "/a/\ud800")
    assert matches("/a/*", "/a/\u200b\u202e")
    assert not matches("**/.env", "/a/.env\u0000")
    assert matches("/İ/x", "/i̇/x")  # casefold expands: both sides fold the same way


def test_case_folding_is_applied_to_the_pattern_too() -> None:
    assert matches("C:/Users/*", "c:/users/bob")
    assert matches("c:/users/*", "C:/USERS/BOB")
    assert matches("**/.SSH/**", "/home/u/.ssh/id_rsa")


# ---------------------------------------------------------------------------- compile errors


@pytest.mark.parametrize(
    ("pattern", "needle"),
    [
        pytest.param("", "empty", id="empty"),
        pytest.param("/a/", "ends with '/'", id="trailing-slash"),
        pytest.param("**/", "ends with '/'", id="dstar-trailing-slash"),
        pytest.param("/a\\b", "backslash", id="backslash"),
        pytest.param("/a/[abc", "unterminated", id="unterminated-class"),
        pytest.param("/a/[", "unterminated", id="bare-open-bracket"),
        pytest.param("/a/[]", "unterminated", id="empty-class"),
        pytest.param("/a/[a/b]", "'/' inside", id="slash-in-class"),
        pytest.param("/a/[a-/]", "'/' inside", id="slash-range-end"),
        pytest.param("/a/[z-a]", "reversed", id="reversed-range"),
        pytest.param("/a\x00b", "control", id="nul"),
        pytest.param("/a\nb", "control", id="newline"),
        pytest.param("/" + "a" * MAX_PATTERN_LENGTH, "longer than", id="too-long"),
        pytest.param("\ufb03" * 400, "too complex", id="casefold-expansion-too-complex"),
    ],
)
def test_bad_patterns_are_rejected_with_a_clear_message(pattern: str, needle: str) -> None:
    with pytest.raises(GlobError, match=re.escape(needle)) as info:
        compile_glob(pattern)
    assert str(info.value).isascii()
    assert len(str(info.value)) < 400  # the pattern is shown truncated, ASCII-escaped


def test_pattern_at_the_length_limit_compiles() -> None:
    assert matches("/" + "a" * (MAX_PATTERN_LENGTH - 1), "/" + "A" * (MAX_PATTERN_LENGTH - 1))


def test_non_string_pattern_is_an_error() -> None:
    with pytest.raises(GlobError, match="string"):
        Glob(5)  # type: ignore[arg-type]


def test_compile_is_cached_and_repr_is_useful() -> None:
    assert compile_glob("/a/*") is compile_glob("/a/*")
    assert repr(compile_glob("/a/*")) == "Glob('/a/*')"


def test_first_match_returns_the_selecting_pattern() -> None:
    patterns = ("/x/*", "**/.env", "/y/**")
    assert first_match(patterns, "/p/.env") == "**/.env"
    assert first_match(patterns, "/y") == "/y/**"
    assert first_match(patterns, "/z") is None
    assert first_match((), "/z") is None


# ---------------------------------------------------------------------------- linear time


def test_classic_exponential_patterns_are_fast() -> None:
    key = "a" * 20000
    for pattern in ("*a" * 40 + "b", "**/" * 100 + "b", "a*" * 200 + "c", "[ab]*" * 90 + "z"):
        start = time.perf_counter()
        assert not matches("/" + pattern, "/" + key)
        assert time.perf_counter() - start < 3.0


def test_matching_cost_grows_linearly_with_the_key() -> None:
    glob = compile_glob("/" + "*a" * 60 + "b")

    def cost(n: int) -> float:
        key = "/" + "a" * n
        start = time.perf_counter()
        for _ in range(3):
            glob.match(key)
        return time.perf_counter() - start

    cost(1000)  # warm the per-character cache
    small, large = cost(4000), cost(32000)
    # 8x the input; a quadratic matcher would need ~64x. Leave generous noise margin.
    assert large < small * 30 + 0.05


def test_pattern_with_many_stars_collapses_consecutive_stars() -> None:
    assert matches("/a" + "*" * 400 + "b", "/axyzb")
    assert matches("/" + "**/" * 150 + "b", "/b")


def test_mask_cache_is_bounded() -> None:
    glob = compile_glob("/*")
    for code in range(0x4E00, 0x4E00 + 3000):
        assert glob.match("/" + chr(code))
    assert glob.match("/ok")


# ---------------------------------------------------------------------------- oracle (hypothesis)


def _text_to_regex(text: str) -> str:
    return "".join({"*": "[^/]*", "?": "[^/]"}.get(ch, re.escape(ch)) for ch in text)


def oracle_regex(leading: bool, segments: list[str], tail: bool) -> str:
    """A regex for the documented semantics of a pattern built from simple segments."""
    parts: list[str] = ["/" if leading else ""]
    for index, seg in enumerate(segments):
        last = index == len(segments) - 1
        if seg == "**":
            parts.append("(?:.*/)?")
        else:
            parts.append(_text_to_regex(seg) + ("" if last else "/"))
    if tail:
        parts.append("(?:/.*)?")
    return "".join(parts)


_seg_text = st.text(alphabet="ab.*?", min_size=1, max_size=3).filter(
    lambda s: "**" not in s and s != "**"
)


@st.composite
def simple_patterns(draw: st.DrawFn) -> tuple[str, str]:
    """(pattern, oracle regex) over a small alphabet: literals, *, ?, **/ and a trailing /**."""
    leading = draw(st.booleans())
    inner = draw(st.lists(st.one_of(_seg_text, st.just("**")), min_size=0, max_size=3))
    last = draw(_seg_text)
    tail = draw(st.booleans())
    segments = [*inner, last]
    pattern = ("/" if leading else "") + "/".join(segments) + ("/**" if tail else "")
    return pattern, oracle_regex(leading, segments, tail)


@settings(max_examples=400, deadline=None)
@given(simple_patterns(), st.text(alphabet="abAB./", max_size=10))
def test_glob_agrees_with_a_regex_oracle_on_simple_patterns(
    case: tuple[str, str], key: str
) -> None:
    pattern, regex = case
    expected = bool(key) and re.fullmatch(regex, key.casefold(), re.DOTALL) is not None
    assert matches(pattern, key) is expected, (pattern, regex, key)


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=40), st.text(max_size=40))
def test_matching_never_raises_even_for_garbage_that_compiles(pattern: str, key: str) -> None:
    try:
        glob = compile_glob(pattern)
    except GlobError:
        return
    assert glob.match(key) in (True, False)


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="ab/", min_size=1, max_size=8))
def test_a_literal_pattern_only_matches_itself(text: str) -> None:
    if text.endswith("/"):
        return
    glob = compile_glob(text)
    assert glob.match(text)
    assert not glob.match(text + "x")
    assert not glob.match("x" + text)
