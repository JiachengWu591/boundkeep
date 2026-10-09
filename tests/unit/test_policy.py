"""Tests for the M0 policy schema and loader (hostile inputs, edits, shipped default, matcher)."""

from __future__ import annotations

import contextlib
import importlib.resources
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from boundkeep.policy import (
    MAX_POLICY_BYTES,
    Policy,
    PolicyError,
    default_policy_text,
    load_policy,
    parse_policy_text,
    set_mode,
    taint_sources_to_matcher,
    write_default_policy,
)
from boundkeep.policy import loader as loader_module
from boundkeep.policy.schema import Defaults, Taint

REPO_DEFAULT = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"

FULL = """\
version: 1
mode: audit-only
defaults:
  emit_allow: true
taint:
  sources: [WebFetch, "mcp__*", Read.x]
"""


def write(path: Path, text: str | bytes) -> str:
    path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
    return str(path)


def fails(text: str, *needles: str) -> PolicyError:
    """Parse ``text``, require a PolicyError, require every needle in its message."""
    with pytest.raises(PolicyError) as info:
        parse_policy_text(text)
    for needle in needles:
        assert needle in str(info.value)
    return info.value


# --------------------------------------------------------------------------- valid files


def test_minimal_file_gets_defaults() -> None:
    policy = parse_policy_text("version: 1\n")
    assert policy.version == 1
    assert policy.mode == "enforce"
    assert policy.defaults.emit_allow is False
    assert policy.taint.sources == ("WebFetch", "WebSearch", "mcp__*")


def test_full_file() -> None:
    policy = parse_policy_text(FULL)
    assert policy.mode == "audit-only"
    assert policy.defaults.emit_allow is True
    assert policy.taint.sources == ("WebFetch", "mcp__*", "Read.x")


def test_models_are_frozen() -> None:
    policy = parse_policy_text("version: 1\n")
    with pytest.raises(ValidationError):
        policy.mode = "audit-only"
    with pytest.raises(ValidationError):
        policy.defaults.emit_allow = True
    with pytest.raises(ValidationError):
        policy.taint.sources = ("evil",)


def test_policy_is_deeply_immutable_and_hashable() -> None:
    """A frozen model holding a list is not frozen: any holder could append unvalidated entries."""
    policy = parse_policy_text("version: 1\n")
    assert isinstance(policy.taint.sources, tuple)
    assert not hasattr(policy.taint.sources, "append")
    assert hash(policy) == hash(parse_policy_text("version: 1\n"))
    assert policy == parse_policy_text("version: 1\n")


def test_default_taint_sources_are_a_tuple_and_cannot_be_mutated_through_an_instance() -> None:
    a, b = Taint(), Taint()
    assert a.sources == b.sources == ("WebFetch", "WebSearch", "mcp__*")
    assert isinstance(a.sources, tuple)
    assert Defaults().emit_allow is False


def test_taint_model_only_accepts_a_list_or_a_valid_tuple() -> None:
    # YAML gives lists; the validator converts exactly that type, the rest is validated as before.
    assert Taint.model_validate({"sources": ["A", "B"]}).sources == ("A", "B")
    assert Taint.model_validate({"sources": ("A",)}).sources == ("A",)
    for bad in ("WebFetch", {"a": "b"}, None, 5, {"A"}):
        with pytest.raises(ValidationError):
            Taint.model_validate({"sources": bad})
    with pytest.raises(ValidationError):
        Taint.model_validate({"sources": ["ok", "a b|c"]})


def test_crlf_text_parses() -> None:
    assert parse_policy_text(FULL.replace("\n", "\r\n")).mode == "audit-only"


def test_quoted_and_comment_decorated_values() -> None:
    policy = parse_policy_text('version: 1  # the schema\nmode: "audit-only"  # note\n')
    assert policy.mode == "audit-only"


def test_duplicate_sources_are_removed_keeping_first_order() -> None:
    policy = parse_policy_text("version: 1\ntaint:\n  sources: [B, A, B, A, C]\n")
    assert policy.taint.sources == ("B", "A", "C")


def test_source_length_limit_is_inclusive() -> None:
    ok = "a" * 127 + "*"  # 128 characters
    assert parse_policy_text(f"version: 1\ntaint:\n  sources: ['{ok}']\n").taint.sources == (ok,)
    fails(f"version: 1\ntaint:\n  sources: ['{ok}b']\n", "128")


def test_sixty_four_sources_ok_sixty_five_rejected() -> None:
    names = [f"T{i}" for i in range(65)]
    ok = parse_policy_text("version: 1\ntaint:\n  sources: " + str(names[:64]) + "\n")
    assert len(ok.taint.sources) == 64
    fails("version: 1\ntaint:\n  sources: " + str(names) + "\n", "64")


def test_the_limit_counts_raw_entries_not_unique_ones() -> None:
    fails("version: 1\ntaint:\n  sources: " + str(["A"] * 65) + "\n", "64")


def test_empty_sources_list_is_valid() -> None:
    assert parse_policy_text("version: 1\ntaint:\n  sources: []\n").taint.sources == ()


# --------------------------------------------------------------------------- files on disk


def test_load_policy_roundtrip(tmp_path: Path) -> None:
    assert load_policy(write(tmp_path / "p.yaml", FULL)).mode == "audit-only"


def test_load_policy_tolerates_bom(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", b"\xef\xbb\xbf" + FULL.encode())
    assert load_policy(path).mode == "audit-only"


def test_load_policy_crlf_file(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", FULL.replace("\n", "\r\n"))
    assert load_policy(path).defaults.emit_allow is True


def test_load_policy_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", b"version: 1\n# \xff\xfe\n")
    with pytest.raises(PolicyError, match="UTF-8") as info:
        load_policy(path)
    assert path in str(info.value)


def test_load_policy_rejects_utf16(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", "version: 1\n".encode("utf-16"))
    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_rejects_oversize_file(tmp_path: Path) -> None:
    body = b"version: 1\n#" + b"x" * (MAX_POLICY_BYTES - 11)  # exactly one byte over
    assert len(body) == MAX_POLICY_BYTES + 1
    with pytest.raises(PolicyError, match="larger than"):
        load_policy(write(tmp_path / "p.yaml", body))


def test_load_policy_accepts_file_at_the_limit(tmp_path: Path) -> None:
    body = b"version: 1\n#" + b"x" * (MAX_POLICY_BYTES - 12)
    assert len(body) == MAX_POLICY_BYTES
    assert load_policy(write(tmp_path / "p.yaml", body)).version == 1


def test_parse_policy_text_rejects_oversize_text() -> None:
    fails("version: 1\n#" + "x" * MAX_POLICY_BYTES, "larger than")


def test_load_policy_missing_file(tmp_path: Path) -> None:
    missing = str(tmp_path / "nope.yaml")
    with pytest.raises(PolicyError, match="not found") as info:
        load_policy(missing)
    assert missing in str(info.value)


def test_load_policy_directory(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="regular file"):
        load_policy(str(tmp_path))


def test_load_policy_error_has_path_and_line(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", "version: 1\n\nmodee: audit-only\n")
    with pytest.raises(PolicyError) as info:
        load_policy(path)
    assert info.value.path == path
    assert info.value.line == 3
    assert f"{path}:3:" in str(info.value)
    assert "modee" in str(info.value)


_BAD_PATHS = [
    "a\0b",
    "\0",
    "p.yaml\0",
    "\ud800.yaml",  # lone surrogate: cannot be encoded on POSIX, a legal NTFS name on Windows
]


@pytest.mark.parametrize(
    "bad",
    [
        *_BAD_PATHS,
        # "path too long": the OS layer raises ValueError on Windows. An explicit id keeps the
        # 100 000 characters out of the test id (pytest puts it in an environment variable).
        pytest.param("x" * 100_000, id="path-too-long"),
        pytest.param("x" * 100_000 + "/p.yaml", id="directory-too-long"),
    ],
)
def test_bad_paths_only_ever_raise_policy_error(
    bad: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path string can come from JSON settings or the environment; never a bare ValueError."""
    monkeypatch.chdir(tmp_path)  # relative paths resolve here, never in the repository
    with pytest.raises(PolicyError):
        load_policy(bad)
    with pytest.raises(PolicyError):
        set_mode(bad, "audit-only")
    if bad.startswith("\ud800"):
        # A lone surrogate is a legal NTFS file name, so writing may really succeed; the only
        # requirement is that nothing but PolicyError can come out.
        with contextlib.suppress(PolicyError):
            write_default_policy(bad)
        return
    with pytest.raises(PolicyError):
        write_default_policy(bad)
    with pytest.raises(PolicyError):
        write_default_policy(bad, overwrite=True)
    assert os.listdir(tmp_path) == []  # and nothing was created next to the test


def test_bad_paths_relative_to_the_working_directory_leave_nothing_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    for bad in ("a\0b", "sub/a\0b"):
        with pytest.raises(PolicyError, match="NUL"):
            write_default_policy(bad)
    assert os.listdir(tmp_path) == []


def test_nul_in_path_is_named_in_the_message() -> None:
    with pytest.raises(PolicyError, match="NUL character"):
        load_policy("a\0b")


@pytest.mark.parametrize("bad", [None, 5, b"p.yaml", ["p.yaml"]])
def test_non_string_paths_are_refused(bad: Any) -> None:
    for call in (
        lambda: load_policy(bad),
        lambda: set_mode(bad, "audit-only"),
        lambda: write_default_policy(bad),
    ):
        with pytest.raises(PolicyError, match="must be a string"):
            call()


def test_path_in_the_message_is_cleaned_and_bounded_but_kept_raw_on_the_error() -> None:
    nasty = "\x1b[2J\ud800" + "d" * 5000 + ".yaml"
    with pytest.raises(PolicyError) as info:
        load_policy(nasty)
    message = str(info.value)
    assert info.value.path == nasty  # the attribute is for programs, the message for people
    assert "\x1b" not in message
    assert "\ud800" not in message
    assert message.isprintable()
    assert len(message) < 800
    message.encode("gbk")  # printing on a Chinese console must not raise UnicodeEncodeError


def test_policy_error_with_path_survives_with_path_and_long_input() -> None:
    err = PolicyError("boom", line=2).with_path("\ud800" * 1000)
    assert err.line == 2
    assert len(str(err)) < 500
    str(err).encode("utf-8")


# --------------------------------------------------------------------------- malformed YAML


def test_duplicate_top_level_key() -> None:
    err = fails("version: 1\nmode: enforce\nmode: audit-only\n", "duplicate key", "mode")
    assert err.line == 3


def test_duplicate_nested_key() -> None:
    fails("version: 1\ndefaults:\n  emit_allow: true\n  emit_allow: false\n", "duplicate key")


def test_duplicate_key_in_flow_mapping() -> None:
    fails("version: 1\ndefaults: {emit_allow: true, emit_allow: false}\n", "duplicate key")


def test_duplicate_keys_with_different_spellings_of_one_value() -> None:
    fails("version: 1\n1: a\n1.0: b\n", "duplicate")


def test_anchor_is_rejected() -> None:
    fails("version: 1\ndefaults: &d\n  emit_allow: false\n", "anchors")


def test_alias_is_rejected() -> None:
    # The anchor is refused first, before the parser ever reaches the alias.
    fails("version: 1\ntaint:\n  sources: &a [X]\nother: *a\n", "anchors")


def test_alias_without_anchor_is_rejected_with_the_alias_message() -> None:
    """The only input that reaches the dedicated alias branch: an alias with no anchor before it
    (any alias with an anchor is refused at the anchor). Pins the message and the line."""
    err = fails("version: 1\nmode: *missing\n", "aliases are not allowed")
    assert err.line == 2
    assert "anchors" not in str(err)


def test_billion_laughs_is_rejected_quickly() -> None:
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\n"
    for name, prev in zip("bcdefghi", "abcdefgh", strict=True):
        bomb += f"{name}: &{name} [" + ", ".join([f"*{prev}"] * 9) + "]\n"
    fails("version: 1\n" + bomb, "not allowed")


def test_merge_key_with_alias_is_rejected() -> None:
    fails("base: &b {emit_allow: true}\nversion: 1\ndefaults:\n  <<: *b\n", "not allowed")


def test_merge_key_with_inline_mapping_is_rejected() -> None:
    fails("version: 1\ndefaults:\n  <<: {emit_allow: true}\n", "merge keys")


def test_quoted_merge_looking_key_is_just_an_unknown_key() -> None:
    fails('version: 1\ndefaults:\n  "<<": 1\n', "unknown key")


def test_multi_document_is_rejected() -> None:
    fails("version: 1\n---\nversion: 1\n", "invalid YAML")


def test_explicit_document_start_is_fine() -> None:
    assert parse_policy_text("---\nversion: 1\n").version == 1


@pytest.mark.parametrize("text", ["", "   \n", "# only a comment\n"])
def test_empty_documents_are_rejected(text: str) -> None:
    fails(text, "empty")


@pytest.mark.parametrize(
    "text", ["- a\n- b\n", "just a string\n", "42\n", "[version, 1]\n", "---\n", "null\n"]
)
def test_non_mapping_top_level_is_rejected(text: str) -> None:
    fails(text, "mapping")


@pytest.mark.parametrize(
    "text",
    [
        "version: !!python/object/apply:os.getcwd []\n",
        "version: !!python/name:os.getcwd\n",
        "!!python/object:os.PathLike {}\n",
        "version: !!binary |\n  AAAA\n",
    ],
)
def test_unsafe_tags_are_rejected(text: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy_text(text)


_TAGS = ["!!int", "!!bool", "!!float", "!!timestamp", "!!str", "!!null", "!!binary", "!!seq", "!x"]
_TAG_VALUES = ["", " x", " maybe", " 1", " true", " ''", " 2001-13-45", " [1]", " yes"]


@pytest.mark.parametrize("tag", _TAGS)
@pytest.mark.parametrize("value", _TAG_VALUES)
def test_explicit_tags_never_leak_a_non_policy_error(tag: str, value: str) -> None:
    """PyYAML's constructors raise KeyError / IndexError / AttributeError for many of these."""
    for text in (
        f"version: 1\nmode: {tag}{value}\n",
        f"version: {tag}{value}\n",
        f"version: 1\ndefaults:\n  emit_allow: {tag}{value}\n",
        f"version: 1\nx: {tag}{value}\n",
    ):
        err = fails(text)
        assert "tags are not allowed" in str(err)


def test_construction_errors_of_any_type_become_policy_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backstop: whatever PyYAML's construction raises, the caller sees PolicyError only."""
    for exc in (KeyError("secret-content"), IndexError(), AttributeError("x"), MemoryError()):

        def boom(_self: Any, _node: Any, _exc: BaseException = exc) -> None:
            raise _exc

        monkeypatch.setattr(loader_module._StrictLoader, "construct_document", boom)
        err = fails("version: 1\n", "invalid YAML", type(exc).__name__)
        assert "secret-content" not in str(err)


def test_core_scalars_that_resolve_implicitly_cannot_leak_either() -> None:
    for value in ("2001-13-45", "0b2", "0x", "1_", "1:99:99", ".inf", "-.nan", "9" * 5000):
        fails(f"version: 1\nmode: {value}\n")
    for value in ("2001-13-45", "0b2", "0x", "1:99:99", ".inf", "-.nan", "9" * 5000):
        fails(f"version: {value}\n")


def test_syntax_error_reports_line_without_source_snippet() -> None:
    err = fails("version: 1\nmode: [unclosed\nother: 1\n", "invalid YAML")
    assert err.line is not None
    assert "other: 1" not in str(err)


def test_deep_nesting_is_rejected_without_recursion_error() -> None:
    fails("version: 1\nx: " + "[" * 5000 + "]" * 5000 + "\n", "deeper")
    fails("version: 1\nx: " + "{a: " * 200 + "1" + "}" * 200 + "\n", "deeper")


def test_impossible_timestamp_does_not_leak_a_value_error() -> None:
    fails("version: 1\nmode: 2001-13-45\n")


def test_huge_integer_does_not_leak_a_value_error() -> None:
    fails("version: " + "9" * 6000 + "\n")
    fails("version: " + "9" * 1000 + "\n", "version")  # below the scalar cap: a plain type error


def _nested(levels: int) -> str:
    """``levels`` nodes deep counting the root mapping: root + (levels - 1) nested sequences."""
    inner = levels - 1
    return "version: 1\nx: " + "[" * inner + "]" * inner + "\n"


def test_nesting_depth_boundary_is_exactly_thirty_two() -> None:
    # Depth 32 passes the loader, so the error is the schema's unknown key; depth 33 is cut off.
    ok = fails(_nested(32), "unknown key")
    assert "deeper" not in str(ok)
    fails(_nested(33), "deeper than 32 levels")


def test_scalar_length_boundary() -> None:
    fine = "k" * 1024
    assert "longer" not in str(fails(f"version: 1\nmode: '{fine}'\n", "mode"))
    fails(f"version: 1\nmode: '{fine}k'\n", "longer than 1024")
    fails(f"version: 1\nmode: {fine}k\n", "longer than 1024")  # plain scalar
    fails(f"version: 1\ntaint:\n  sources: ['{fine}k']\n", "longer than 1024")
    fails(f"version: 1\nmode: >\n  {fine}k\n", "longer than 1024")  # block scalar
    # A key longer than 1024 never reaches the cap: PyYAML refuses it as a simple key itself.
    fails(f"version: 1\n{fine}k: 1\n", "invalid YAML")


def test_sexagesimal_integer_bomb_is_rejected_fast() -> None:
    """PyYAML builds 1:1:1:... in quadratic time; the scalar cap stops it before construction."""
    bomb = "1" + ":1" * 126_000  # about 250 KB, under MAX_POLICY_BYTES
    assert len(bomb) < MAX_POLICY_BYTES - 100
    start = time.monotonic()
    fails("version: 1\nx: " + bomb + "\n", "longer than")
    assert time.monotonic() - start < 1.0


def test_node_count_cap_stops_huge_flow_collections_fast() -> None:
    items = ", ".join(["1"] * 60_000)  # 180 KB, under MAX_POLICY_BYTES
    start = time.monotonic()
    fails(f"version: 1\ntaint:\n  sources: [{items}]\n", "more than 10000 nodes")
    assert time.monotonic() - start < 2.0
    # Just under the cap is the schema's business (here: too many sources, and not strings).
    fails("version: 1\ntaint:\n  sources: [" + ", ".join(["A"] * 9000) + "]\n", "64")


@pytest.mark.parametrize("char", ["\x85", "\u2028", "\u2029"])
def test_hidden_line_breaks_are_rejected_wherever_they_are(char: str) -> None:
    """PyYAML ends a comment at these, so a mode line could hide inside a 'comment'."""
    hidden = f"version: 1\n# harmless note{char}mode: audit-only\n"
    err = fails(hidden, f"U+{ord(char):04X}")
    assert err.line == 2
    fails(f"version: 1{char}mode: audit-only\n", "line break")
    fails(f"version: 1\nmode: enforce # {char}\n", "line break")
    fails(f"{char}version: 1\n", "line break")


def test_hidden_line_break_reports_the_right_line_with_mixed_newlines() -> None:
    err = fails("version: 1\r\n\r# a\n# b\u2028c\n", "U+2028")
    assert err.line == 4  # CRLF, lone CR and LF each count once


def test_hidden_line_breaks_are_rejected_when_loading_a_file(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", "version: 1\n# note\u2028mode: audit-only\n")
    with pytest.raises(PolicyError, match="U\\+2028"):
        load_policy(path)
    with pytest.raises(PolicyError, match="U\\+2028"):
        set_mode(path, "enforce")
    assert Path(path).read_bytes() == "version: 1\n# note\u2028mode: audit-only\n".encode()


def test_byte_order_mark_only_at_the_very_start() -> None:
    assert parse_policy_text("\ufeffversion: 1\n").version == 1
    fails("version: 1\n# a\ufeffb\n", "U+FEFF")
    fails("version: 1\nmode: audit-only\ufeff\n", "U+FEFF")
    fails("\ufeff\ufeffversion: 1\n", "U+FEFF")


def test_double_byte_order_mark_in_a_file_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", b"\xef\xbb\xbf\xef\xbb\xbfversion: 1\n")
    with pytest.raises(PolicyError, match="byte order mark"):
        load_policy(path)


@pytest.mark.parametrize("word", ["yes", "Yes", "YES", "no", "on", "On", "off", "OFF", "y", "n"])
def test_yaml_one_point_one_booleans_are_not_booleans(word: str) -> None:
    """``emit_allow: yes`` must not silently switch off Claude Code's confirmation prompt."""
    fails(f"version: 1\ndefaults:\n  emit_allow: {word}\n", "emit_allow")
    fails(f"%YAML 1.2\n---\nversion: 1\ndefaults:\n  emit_allow: {word}\n", "emit_allow")


@pytest.mark.parametrize(
    ("word", "value"),
    [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
    ],
)
def test_true_and_false_are_the_only_booleans(word: str, value: bool) -> None:
    policy = parse_policy_text(f"version: 1\ndefaults:\n  emit_allow: {word}\n")
    assert policy.defaults.emit_allow is value


@pytest.mark.parametrize("word", ["tRUE", "fALSE", "truee", "t", "f", "True1"])
def test_other_spellings_of_true_and_false_are_strings(word: str) -> None:
    fails(f"version: 1\ndefaults:\n  emit_allow: {word}\n", "emit_allow")


def test_non_string_policy_text_is_refused() -> None:
    for bad in (b"version: 1\n", "version: 1\n".encode("utf-16"), None, 5):
        with pytest.raises(PolicyError, match="must be a string"):
            parse_policy_text(bad)  # type: ignore[arg-type]


def test_control_characters_are_rejected() -> None:
    fails("version: 1\nmode: enf\x00orce\n", "invalid YAML")
    fails("version: 1\n\x07\n", "invalid YAML")


def test_lone_surrogate_text_is_rejected() -> None:
    fails("version: 1\n# \ud800\n", "invalid YAML")


def test_complex_key_is_rejected() -> None:
    fails("version: 1\n? [a, b]\n: c\n")


# --------------------------------------------------------------------------- schema strictness


def test_unknown_key_at_top_level() -> None:
    err = fails("version: 1\nmodee: audit-only\n", "unknown key", "modee")
    assert err.line == 2


def test_unknown_key_in_defaults() -> None:
    err = fails("version: 1\ndefaults:\n  emit_alow: true\n", "unknown key", "defaults.emit_alow")
    assert err.line == 3


def test_unknown_key_in_taint() -> None:
    err = fails("version: 1\ntaint:\n  source: [A]\n", "unknown key", "taint.source")
    assert err.line == 3


def test_homoglyph_keys_are_shown_escaped_so_they_cannot_pass_for_the_real_word() -> None:
    """A Cyrillic 'o' in 'mode' is rejected, and the message must not print it as 'mode'."""
    err = fails("version: 1\nm\u043ede: audit-only\n", "unknown key")
    assert "m\\u043ede" in str(err)
    assert "m\u043ede" not in str(err)
    assert str(err).isascii()
    dup = fails("version: 1\nm\u043ede: a\nm\u043ede: b\n", "duplicate key")
    assert "m\\u043ede" in str(dup)
    assert str(dup).isascii()
    nested = fails("version: 1\ndefaults:\n  \u0435mit_allow: true\n", "unknown key")
    assert "defaults.\\u0435mit_allow" in str(nested)


def test_homoglyph_source_names_are_shown_escaped() -> None:
    err = fails("version: 1\ntaint:\n  sources: ['W\u0435bFetch']\n", "sources[0]")
    assert "W\\u0435bFetch" in str(err)
    assert str(err).isascii()


def test_rules_key_is_unknown_in_m0() -> None:
    fails("version: 1\nrules: []\n", "unknown key", "rules")


def test_missing_version() -> None:
    fails("mode: enforce\n", "version")


@pytest.mark.parametrize("value", ["2", "0", "'1'", "true", "1.0", "null", "[1]", "-1"])
def test_bad_version(value: str) -> None:
    fails(f"version: {value}\n", "version")


@pytest.mark.parametrize(
    "value", ["Enforce", "audit_only", "off", "yes", "true", "1", "null", "''", "[enforce]"]
)
def test_bad_mode(value: str) -> None:
    fails(f"version: 1\nmode: {value}\n", "mode")


@pytest.mark.parametrize("value", ["'yes'", "1", "0", "'true'", "null", "[]"])
def test_bad_emit_allow(value: str) -> None:
    fails(f"version: 1\ndefaults:\n  emit_allow: {value}\n", "emit_allow")


@pytest.mark.parametrize("value", ["[]", "null", "true", "x", "[a]"])
def test_defaults_and_taint_must_be_mappings(value: str) -> None:
    fails(f"version: 1\ndefaults: {value}\n", "defaults")
    fails(f"version: 1\ntaint: {value}\n", "taint")


@pytest.mark.parametrize("value", ["WebFetch", "null", "{a: b}", "42"])
def test_sources_must_be_a_list(value: str) -> None:
    fails(f"version: 1\ntaint:\n  sources: {value}\n", "sources")


@pytest.mark.parametrize(
    "entry",
    [
        "''",
        "'a b'",
        "'a,b'",
        "'a|b'",
        "'a*b'",
        "'**'",
        "'a**'",
        "'*'",
        "'*a'",
        "'a\\n'",
        '"a\\n"',
        "'a/b'",
        "'a(b)'",
        "'a\\\\b'",
        "'na\u00efve'",
        "'\u5de5\u5177'",
        "1",
        "true",
        "null",
        "[A]",
        "{a: b}",
    ],
)
def test_bad_source_entries(entry: str) -> None:
    err = fails(f"version: 1\ntaint:\n  sources: [{entry}]\n")
    assert "sources" in str(err)


def test_error_for_bad_source_names_the_index_and_line() -> None:
    err = fails("version: 1\ntaint:\n  sources:\n    - A\n    - 'b c'\n", "sources[1]")
    assert err.line == 5


def test_error_messages_are_bounded_and_do_not_echo_large_content() -> None:
    huge = "k" * 100_000
    err = fails(f"version: 1\n{huge}: 1\n")
    assert len(str(err)) < 600
    err2 = fails(f"version: 1\ntaint:\n  sources: ['{huge}']\n")
    assert len(str(err2)) < 600


def test_error_messages_hide_control_characters() -> None:
    err = fails('version: 1\n"a\\x1b[31mred": 1\n')
    assert "\x1b" not in str(err)


def test_many_errors_are_summarised() -> None:
    keys = "".join(f"k{i}: 1\n" for i in range(20))
    err = fails("version: 1\n" + keys, "more")
    assert len(str(err)) < 1200


def test_policy_error_formats() -> None:
    assert str(PolicyError("boom")) == "boom"
    assert str(PolicyError("boom", line=3)) == "line 3: boom"
    assert str(PolicyError("boom", path="p.yaml")) == "p.yaml: boom"
    assert str(PolicyError("boom", path="p.yaml", line=3)) == "p.yaml:3: boom"
    assert PolicyError("boom", line=3).with_path("p.yaml").line == 3


# --------------------------------------------------------------------------- set_mode

COMMENTED = """\
# boundkeep policy
version: 1

# enforce or audit-only
mode: enforce

defaults:
  emit_allow: false  # keep false

taint:
  sources: [WebFetch]
"""


def test_set_mode_changes_only_the_mode_line(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    set_mode(path, "audit-only")
    expected = COMMENTED.replace("mode: enforce", "mode: audit-only")
    assert Path(path).read_bytes() == expected.encode()
    assert load_policy(path).mode == "audit-only"
    set_mode(path, "enforce")
    assert Path(path).read_bytes() == COMMENTED.encode()


def test_set_mode_keeps_crlf(tmp_path: Path) -> None:
    text = COMMENTED.replace("\n", "\r\n")
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("mode: enforce", "mode: audit-only").encode()


def test_set_mode_keeps_mixed_line_endings(tmp_path: Path) -> None:
    text = "version: 1\r\nmode: enforce\n# tail\rdefaults: {}\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


def test_set_mode_keeps_inline_comment_and_spacing(tmp_path: Path) -> None:
    text = "version: 1\nmode:    enforce    # why: because\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


def test_set_mode_keeps_space_before_colon(tmp_path: Path) -> None:
    text = "version: 1\nmode :   enforce\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


@pytest.mark.parametrize("quote", ["'", '"'])
def test_set_mode_keeps_quote_style(tmp_path: Path, quote: str) -> None:
    text = f"version: 1\nmode: {quote}enforce{quote}  # q\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


def test_set_mode_with_whole_document_indented(tmp_path: Path) -> None:
    text = "# c\n    version: 1\n    mode: enforce\n    defaults:\n      emit_allow: true\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


def test_set_mode_with_document_start_marker_and_directive(tmp_path: Path) -> None:
    text = "%YAML 1.1\n---\nversion: 1\nmode: audit-only\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "enforce")
    assert Path(path).read_bytes() == text.replace("audit-only", "enforce").encode()


def test_set_mode_mode_line_first_in_file(tmp_path: Path) -> None:
    text = "mode: enforce\nversion: 1\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == b"mode: audit-only\nversion: 1\n"


def test_set_mode_preserves_bom(tmp_path: Path) -> None:
    raw = b"\xef\xbb\xbfmode: enforce\nversion: 1\n"
    path = write(tmp_path / "p.yaml", raw)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == b"\xef\xbb\xbfmode: audit-only\nversion: 1\n"


def test_set_mode_preserves_non_ascii_comments(tmp_path: Path) -> None:
    text = "# \u7b56\u7565\u6587\u4ef6\nversion: 1\nmode: enforce\n"
    path = write(tmp_path / "p.yaml", text)
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.replace("enforce", "audit-only").encode()


def test_set_mode_without_trailing_newline(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", "version: 1\nmode: enforce")
    set_mode(path, "audit-only")
    assert Path(path).read_bytes() == b"version: 1\nmode: audit-only"


def test_set_mode_same_mode_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)

    def boom(*_: Any, **__: Any) -> None:
        raise AssertionError("must not write")

    monkeypatch.setattr(loader_module, "_atomic_write", boom)
    set_mode(path, "enforce")
    assert Path(path).read_bytes() == COMMENTED.encode()


def test_set_mode_rejects_unknown_mode_and_leaves_file(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    for bad in ("off", "", "Enforce", "enforce\n", "audit-only # x"):
        with pytest.raises(PolicyError, match="unknown mode"):
            set_mode(path, bad)  # type: ignore[arg-type]
    assert Path(path).read_bytes() == COMMENTED.encode()


def test_set_mode_without_mode_line_raises_and_does_not_insert(tmp_path: Path) -> None:
    text = "version: 1\ndefaults:\n  emit_allow: false\n"
    path = write(tmp_path / "p.yaml", text)
    with pytest.raises(PolicyError, match="mode"):
        set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.encode()


def test_set_mode_ignores_a_nested_mode_key_and_so_refuses(tmp_path: Path) -> None:
    # Refused by the schema here (``defaults.mode`` is an unknown key) before the line editor is
    # reached; the editor's own indentation logic is pinned by the _replace_mode_line tests below.
    text = "version: 1\ndefaults:\n  mode: enforce\n"
    path = write(tmp_path / "p.yaml", text)
    with pytest.raises(PolicyError):
        set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.encode()


def test_replace_mode_line_only_touches_the_top_level_line() -> None:
    """Direct tests of the pure line editor: nested look-alikes must be left alone."""
    replace = loader_module._replace_mode_line
    text = "version: 1\nx:\n  mode: enforce\nmode: enforce\ny:\n    mode: enforce\n"
    assert replace(text, "audit-only") == text.replace("\nmode: enforce\n", "\nmode: audit-only\n")


def test_replace_mode_line_has_no_top_level_line_when_only_nested_ones_exist() -> None:
    replace = loader_module._replace_mode_line
    with pytest.raises(PolicyError, match="no top-level"):
        replace("version: 1\ndefaults:\n  mode: enforce\n", "audit-only")


def test_replace_mode_line_uses_the_first_content_line_as_the_top_indent() -> None:
    replace = loader_module._replace_mode_line
    text = "  version: 1\n  mode: enforce\nmode: x\n"  # the unindented line is not top level
    with pytest.raises(PolicyError, match="no top-level"):
        replace("# c\n    version: 1\nmode: enforce\n", "audit-only")
    assert replace(text, "audit-only") == "  version: 1\n  mode: audit-only\nmode: x\n"


def test_replace_mode_line_refuses_to_guess_between_two_top_level_lines() -> None:
    replace = loader_module._replace_mode_line
    with pytest.raises(PolicyError, match="more than one top-level"):
        replace("version: 1\nmode: enforce\nmode: audit-only\n", "enforce")


def test_replace_mode_line_without_any_content() -> None:
    replace = loader_module._replace_mode_line
    for text in ("", "# only a comment\n", "---\n", "%YAML 1.1\n---\n...\n"):
        with pytest.raises(PolicyError, match="no top-level"):
            replace(text, "audit-only")


def test_set_mode_flow_style_top_level_has_no_editable_line(tmp_path: Path) -> None:
    text = "{version: 1, mode: enforce}\n"
    path = write(tmp_path / "p.yaml", text)
    with pytest.raises(PolicyError, match="mode"):
        set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.encode()


def test_set_mode_unusual_value_form_is_refused(tmp_path: Path) -> None:
    for text in ("version: 1\nmode:\n  enforce\n", "version: 1\nmode: >\n  enforce\n"):
        path = write(tmp_path / "p.yaml", text)
        with pytest.raises(PolicyError):
            set_mode(path, "audit-only")
        assert Path(path).read_bytes() == text.encode()


def test_set_mode_refuses_duplicate_mode_lines(tmp_path: Path) -> None:
    # Stopped by the parser's duplicate-key check; the editor's own guard is tested above.
    text = "version: 1\nmode: enforce\nmode: audit-only\n"
    path = write(tmp_path / "p.yaml", text)
    with pytest.raises(PolicyError, match="duplicate"):
        set_mode(path, "enforce")
    assert Path(path).read_bytes() == text.encode()


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nmode: enforse\n",
        "version: 2\nmode: enforce\n",
        "version: 1\nmode: enforce\nbogus: 1\n",
        "mode: enforce\n",
        "",
    ],
)
def test_set_mode_on_invalid_current_file_leaves_it_untouched(tmp_path: Path, text: str) -> None:
    path = write(tmp_path / "p.yaml", text)
    with pytest.raises(PolicyError) as info:
        set_mode(path, "audit-only")
    assert path in str(info.value)
    assert Path(path).read_bytes() == text.encode()
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_set_mode_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        set_mode(str(tmp_path / "nope.yaml"), "audit-only")


def test_set_mode_replace_failure_leaves_original_and_no_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)

    def failing_replace(*_: Any, **__: Any) -> None:
        raise PermissionError(13, "locked")

    monkeypatch.setattr(os, "replace", failing_replace)
    monkeypatch.setattr(loader_module, "_REPLACE_RETRY_DELAYS", (0.0, 0.0))
    with pytest.raises(PolicyError, match="cannot write"):
        set_mode(path, "audit-only")
    monkeypatch.undo()
    assert Path(path).read_bytes() == COMMENTED.encode()
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_replace_is_retried_while_another_process_holds_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    real_replace = os.replace
    calls: list[int] = []

    def flaky_replace(src: Any, dst: Any) -> None:
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError(13, "in use")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    monkeypatch.setattr(loader_module, "_RETRY_REPLACE", True)
    monkeypatch.setattr(loader_module, "_REPLACE_RETRY_DELAYS", (0.0, 0.0, 0.0))
    set_mode(path, "audit-only")
    assert len(calls) == 3
    monkeypatch.undo()
    assert load_policy(path).mode == "audit-only"
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_replace_gives_up_after_the_retries_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    calls: list[int] = []

    def locked(*_: Any, **__: Any) -> None:
        calls.append(1)
        raise PermissionError(13, "in use")

    monkeypatch.setattr(os, "replace", locked)
    monkeypatch.setattr(loader_module, "_RETRY_REPLACE", True)
    monkeypatch.setattr(loader_module, "_REPLACE_RETRY_DELAYS", (0.0, 0.0))
    with pytest.raises(PolicyError, match="open in another program"):
        set_mode(path, "audit-only")
    assert len(calls) == 3  # the first try plus two retries
    monkeypatch.undo()
    assert Path(path).read_bytes() == COMMENTED.encode()
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_replace_is_not_retried_off_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    calls: list[int] = []

    def locked(*_: Any, **__: Any) -> None:
        calls.append(1)
        raise PermissionError(13, "denied")

    monkeypatch.setattr(os, "replace", locked)
    monkeypatch.setattr(loader_module, "_RETRY_REPLACE", False)
    with pytest.raises(PolicyError, match="cannot write"):
        set_mode(path, "audit-only")
    assert len(calls) == 1


def test_replace_over_a_directory_is_final_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "policy.yaml"
    target.mkdir()
    monkeypatch.setattr(loader_module, "_RETRY_REPLACE", True)
    monkeypatch.setattr(loader_module, "_REPLACE_RETRY_DELAYS", (5.0, 5.0))  # would hang if retried
    start = time.monotonic()
    with pytest.raises(PolicyError):
        write_default_policy(str(target), overwrite=True)
    assert time.monotonic() - start < 4.0
    assert os.listdir(tmp_path) == ["policy.yaml"]


@pytest.mark.windows
def test_set_mode_succeeds_when_a_reader_releases_the_file_shortly(tmp_path: Path) -> None:
    """Real Windows behaviour: os.replace fails while any handle is open (no FILE_SHARE_DELETE)."""
    path = write(tmp_path / "p.yaml", COMMENTED)
    handle = open(path, "rb")  # noqa: SIM115 - held open on purpose, closed by the timer below
    timer = threading.Timer(0.2, handle.close)
    timer.start()
    try:
        set_mode(path, "audit-only")
    finally:
        timer.join()
        handle.close()
    assert load_policy(path).mode == "audit-only"
    assert os.listdir(tmp_path) == ["p.yaml"]


@pytest.mark.windows
def test_set_mode_reports_a_file_that_stays_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    monkeypatch.setattr(loader_module, "_REPLACE_RETRY_DELAYS", (0.01, 0.01))
    with open(path, "rb"), pytest.raises(PolicyError, match="cannot write"):
        set_mode(path, "audit-only")
    assert Path(path).read_bytes() == COMMENTED.encode()
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_set_mode_leaves_no_temp_file_on_success(tmp_path: Path) -> None:
    path = write(tmp_path / "p.yaml", COMMENTED)
    set_mode(path, "audit-only")
    assert os.listdir(tmp_path) == ["p.yaml"]


def test_set_mode_result_must_equal_old_policy_except_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the text edit ever changed anything but mode, nothing is written."""
    text = "version: 1\nmode: enforce\n"
    path = write(tmp_path / "p.yaml", text)
    monkeypatch.setattr(
        loader_module,
        "_replace_mode_line",
        lambda _text, _mode: "version: 1\nmode: audit-only\ndefaults:\n  emit_allow: true\n",
    )
    with pytest.raises(PolicyError, match="more than 'mode'"):
        set_mode(path, "audit-only")
    assert Path(path).read_bytes() == text.encode()


# --------------------------------------------------------------------------- shipped default


def test_default_policy_text_equals_the_repo_file_and_parses() -> None:
    expected = REPO_DEFAULT.read_bytes().decode("utf-8").replace("\r\n", "\n")
    text = default_policy_text()
    assert text == expected
    assert "\r" not in text
    assert not text.startswith("\ufeff")
    policy = parse_policy_text(text)
    assert policy.mode == "enforce"
    assert policy.defaults.emit_allow is False
    assert policy.taint.sources == ("WebFetch", "WebSearch", "mcp__*")


def test_default_file_has_exactly_the_four_keys() -> None:
    raw = yaml.safe_load(REPO_DEFAULT.read_bytes().decode("utf-8"))
    assert set(raw) == {"version", "mode", "defaults", "taint"}
    assert set(raw["defaults"]) == {"emit_allow"}
    assert set(raw["taint"]) == {"sources"}


def test_default_policy_comes_from_package_data_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "default.yaml").write_text("version: 1\nmode: audit-only\n", encoding="utf-8")
    monkeypatch.setattr(importlib.resources, "files", lambda _pkg: tmp_path)
    assert default_policy_text() == "version: 1\nmode: audit-only\n"


def test_default_policy_falls_back_to_the_repo_file(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_package(_pkg: str) -> Any:
        raise ModuleNotFoundError("no package data")

    monkeypatch.setattr(importlib.resources, "files", no_package)
    assert default_policy_text() == REPO_DEFAULT.read_bytes().decode().replace("\r\n", "\n")


def test_default_policy_missing_everywhere_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(importlib.resources, "files", lambda _pkg: tmp_path)
    monkeypatch.setattr(loader_module, "_repo_default_path", lambda: str(tmp_path / "none.yaml"))
    with pytest.raises(PolicyError, match="missing"):
        default_policy_text()


def test_invalid_shipped_default_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "default.yaml").write_text("version: 1\nmodee: x\n", encoding="utf-8")
    monkeypatch.setattr(importlib.resources, "files", lambda _pkg: tmp_path)
    with pytest.raises(PolicyError, match="invalid"):
        default_policy_text()
    with pytest.raises(PolicyError):
        write_default_policy(str(tmp_path / "out.yaml"))
    assert not (tmp_path / "out.yaml").exists()


def test_write_default_policy_creates_parents_lf_no_bom(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "policy.yaml"
    assert write_default_policy(str(target)) is True
    raw = target.read_bytes()
    assert raw == default_policy_text().encode("utf-8")
    assert b"\r" not in raw
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert load_policy(str(target)).mode == "enforce"
    assert os.listdir(target.parent) == ["policy.yaml"]


def test_write_default_policy_does_not_overwrite_by_default(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("# mine\nversion: 1\nmode: audit-only\n", encoding="utf-8")
    assert write_default_policy(str(target)) is False
    assert target.read_text(encoding="utf-8") == "# mine\nversion: 1\nmode: audit-only\n"


def test_write_default_policy_does_not_overwrite_an_invalid_file_either(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.write_bytes(b"\xff garbage")
    assert write_default_policy(str(target)) is False
    assert target.read_bytes() == b"\xff garbage"


def test_write_default_policy_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("version: 1\nmode: audit-only\n", encoding="utf-8")
    assert write_default_policy(str(target), overwrite=True) is True
    assert target.read_text(encoding="utf-8") == default_policy_text()


def test_write_default_policy_onto_a_directory_fails_cleanly(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.mkdir()
    with pytest.raises(PolicyError):
        write_default_policy(str(target), overwrite=True)
    assert target.is_dir()
    assert os.listdir(tmp_path) == ["policy.yaml"]


def test_write_default_policy_parent_is_a_file(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(PolicyError):
        write_default_policy(str(blocker / "policy.yaml"))


def test_set_mode_on_the_written_default_preserves_every_comment(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    write_default_policy(str(target))
    set_mode(str(target), "audit-only")
    expected = default_policy_text().replace("\nmode: enforce\n", "\nmode: audit-only\n")
    assert target.read_text(encoding="utf-8") == expected
    assert load_policy(str(target)).mode == "audit-only"


# --------------------------------------------------------------------------- matcher


def test_matcher_plain_names_use_the_exact_list_form() -> None:
    assert taint_sources_to_matcher(["WebFetch", "WebSearch"]) == "WebFetch|WebSearch"
    assert taint_sources_to_matcher(["Read"]) == "Read"
    assert taint_sources_to_matcher(["a-b", "c_d", "E1"]) == "a-b|c_d|E1"


def test_matcher_glob_uses_an_anchored_regex() -> None:
    assert taint_sources_to_matcher(["mcp__*"]) == "^(?:mcp__.*)$"


def test_matcher_mixed() -> None:
    assert (
        taint_sources_to_matcher(["WebFetch", "WebSearch", "mcp__*"])
        == "^(?:WebFetch|WebSearch|mcp__.*)$"
    )


def test_matcher_dot_in_a_plain_name_is_escaped_and_forces_regex_form() -> None:
    assert taint_sources_to_matcher(["a.b"]) == r"^(?:a\.b)$"
    assert taint_sources_to_matcher(["a.b", "c*"]) == r"^(?:a\.b|c.*)$"
    assert taint_sources_to_matcher(["a.b*"]) == r"^(?:a\.b.*)$"


def test_matcher_removes_duplicates_keeping_order() -> None:
    assert taint_sources_to_matcher(["B", "A", "B"]) == "B|A"
    assert taint_sources_to_matcher(["m*", "x", "m*"]) == "^(?:m.*|x)$"


def test_matcher_accepts_any_sequence() -> None:
    assert taint_sources_to_matcher(("A", "B")) == "A|B"


@pytest.mark.parametrize("bare", ["WebFetch", "a", "", b"WebFetch", bytearray(b"Web"), "mcp__*"])
def test_matcher_refuses_a_bare_string(bare: Any) -> None:
    """A str is a Sequence of one-character strings: 'WebFetch' must not become 'W|e|b|F|t|c|h'."""
    with pytest.raises(PolicyError, match="not a single string"):
        taint_sources_to_matcher(bare)


@pytest.mark.parametrize("other", [None, 5, {"A", "B"}, {"A": 1}, iter(["A"]), (x for x in "A")])
def test_matcher_refuses_things_that_are_not_a_list_or_tuple(other: Any) -> None:
    with pytest.raises(PolicyError):
        taint_sources_to_matcher(other)


def test_matcher_enforces_the_schema_entry_limit() -> None:
    sixty_four = [f"T{i}" for i in range(64)]
    assert taint_sources_to_matcher(sixty_four) == "|".join(sixty_four)
    with pytest.raises(PolicyError, match="at most 64"):
        taint_sources_to_matcher([*sixty_four, "T64"])
    with pytest.raises(PolicyError, match="at most 64"):
        taint_sources_to_matcher(["A"] * 5000)  # duplicates count, as in the schema


def test_matcher_empty_list_raises() -> None:
    with pytest.raises(PolicyError, match="every tool"):
        taint_sources_to_matcher([])


@pytest.mark.parametrize(
    "bad", ["", "a b", "a|b", "a*b", "**", "*", "a)", "(a", "a\n", "x" * 129, "\u00e9", "a/b"]
)
def test_matcher_rejects_bad_sources(bad: str) -> None:
    with pytest.raises(PolicyError):
        taint_sources_to_matcher(["Read", bad])


def test_matcher_rejects_non_string_entries() -> None:
    with pytest.raises(PolicyError):
        taint_sources_to_matcher([1])  # type: ignore[list-item]


def test_matcher_never_yields_an_empty_or_match_all_string() -> None:
    for sources in (["*"], [""], []):
        with pytest.raises(PolicyError):
            taint_sources_to_matcher(sources)


def test_matcher_from_the_default_policy_matches_the_right_tools() -> None:
    matcher = taint_sources_to_matcher(default_policy_text_sources())
    assert re.search(matcher, "mcp__github__create_issue")
    assert re.search(matcher, "WebFetch")
    assert not re.search(matcher, "Read")
    assert not re.search(matcher, "xWebFetch")
    assert not re.search(matcher, "WebFetchX")


def default_policy_text_sources() -> tuple[str, ...]:
    return parse_policy_text(default_policy_text()).taint.sources


def test_policy_type_is_exported() -> None:
    assert isinstance(parse_policy_text("version: 1\n"), Policy)


# --------------------------------------------------------------------------- hypothesis

_TOKENS = [
    "version: 1\n",
    "mode: enforce\n",
    "mode: ",
    "audit-only",
    "defaults:\n",
    "  emit_allow: true\n",
    "taint:\n  sources: ",
    "[A, 'b*']",
    "&a ",
    "*a",
    "<<: ",
    "---\n",
    "...\n",
    "!!python/name:os.getcwd ",
    "[",
    "]",
    "{",
    "}",
    "? ",
    ": ",
    "- ",
    "\t",
    "\r\n",
    "\n",
    '"',
    "'",
    "#",
    "2001-13-45",
    "9" * 30,
    "\x00",
    "\ufeff",
    "\x85",
    "\u2028",
    "\u2029",
    "!!int ",
    "!!bool ",
    "!!float ",
    "!!timestamp ",
    "!!str ",
    "!!null ",
    "!!binary ",
    "!!set ",
    "!!omap ",
    "!x ",
    "!",
    "x",
    "maybe",
    "yes",
    "on",
    "true",
    "False",
    "1:1:1",
    "0x",
    "0b2",
    ".inf",
    "~",
    "%YAML 1.2\n",
]


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_arbitrary_text_only_ever_raises_policy_error(text: str) -> None:
    try:
        result = parse_policy_text(text)
    except PolicyError:
        return
    assert isinstance(result, Policy)


@settings(max_examples=600, deadline=None)
@given(st.lists(st.sampled_from(_TOKENS), max_size=25).map("".join))
def test_yaml_shaped_text_only_ever_raises_policy_error(text: str) -> None:
    message: str | None = None
    try:
        result = parse_policy_text(text)
    except PolicyError as exc:
        message = str(exc)
    else:
        assert isinstance(result, Policy)
        assert result.version == 1
    if message is not None:
        assert len(message) < 2000
        assert message.isprintable()


@settings(max_examples=200, deadline=None)
@given(st.lists(st.text(max_size=140), max_size=70))
def test_arbitrary_sources_are_validated_without_other_exceptions(entries: list[str]) -> None:
    try:
        matcher = taint_sources_to_matcher(entries)
    except PolicyError:
        return
    assert matcher
    assert "\n" not in matcher
