"""settings_io: lossless, style-preserving, refusing-when-unsure handling of settings.json."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from boundkeep import settings_io as sio
from boundkeep.settings_io import (
    MAX_NESTING_DEPTH,
    MAX_SETTINGS_BYTES,
    SettingsDoc,
    SettingsError,
    backup_file,
    load_settings,
    render_settings,
    write_atomic,
)

BOM = b"\xef\xbb\xbf"


def put(tmp_path: Path, content: bytes, name: str = "settings.json") -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def dumps(data: Any, indent: int | str | None = 2, nl: str = "\n", final: bool = True) -> bytes:
    text = json.dumps(data, indent=indent, ensure_ascii=False)
    text = text.replace("\n", nl)
    return (text + (nl if final else "")).encode("utf-8")


SAMPLE: dict[str, Any] = {
    "model": "opus",
    "permissions": {"allow": ["Read", "PowerShell(Write-Output *)"], "deny": []},
    "env": {"A": "1"},
    "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]},
}


# ---- load: success paths --------------------------------------------------------------------


def test_missing_file_gives_empty_doc_with_defaults(tmp_path: Path) -> None:
    doc = load_settings(str(tmp_path / "nope" / "settings.json"))
    assert doc.exists is False
    assert doc.data == {}
    assert doc.raw == b""
    assert (doc.had_bom, doc.newline, doc.indent, doc.trailing_newline) == (False, "\n", 2, True)
    assert render_settings(doc, {"a": 1}) == b'{\n  "a": 1\n}\n'
    assert not (tmp_path / "nope").exists()  # loading never writes anything


def test_bom_is_read_and_never_written(tmp_path: Path) -> None:
    raw = BOM + dumps(SAMPLE)
    doc = load_settings(put(tmp_path, raw))
    assert doc.had_bom is True
    assert doc.data == SAMPLE
    assert doc.raw == raw
    out = render_settings(doc, doc.data)
    assert not out.startswith(BOM)
    assert out == dumps(SAMPLE)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("final", [True, False])
def test_newline_style_and_trailing_newline_preserved(
    tmp_path: Path, newline: str, final: bool
) -> None:
    raw = dumps(SAMPLE, nl=newline, final=final)
    doc = load_settings(put(tmp_path, raw))
    assert doc.newline == newline
    assert doc.trailing_newline is final
    out = render_settings(doc, doc.data)
    assert out == raw
    assert out.count(b"\r\n") == (out.count(b"\n") if newline == "\r\n" else 0)


def test_mixed_newlines_follow_the_majority(tmp_path: Path) -> None:
    crlf_major = b'{\r\n  "a": 1,\r\n  "b": 2,\n  "c": 3\r\n}\r\n'
    assert load_settings(put(tmp_path, crlf_major)).newline == "\r\n"
    lf_major = b'{\n  "a": 1,\r\n  "b": 2,\n  "c": 3\n}\n'
    assert load_settings(put(tmp_path, lf_major, "b.json")).newline == "\n"


@pytest.mark.parametrize(
    ("indent", "expected"),
    [(2, 2), (4, 4), ("\t", "\t"), (0, 0), (None, None)],
)
def test_indent_detection(tmp_path: Path, indent: int | str | None, expected: object) -> None:
    raw = dumps(SAMPLE, indent=indent)
    doc = load_settings(put(tmp_path, raw))
    assert doc.indent == expected
    assert render_settings(doc, doc.data) == raw


def test_minified_without_spaces_is_kept_minified(tmp_path: Path) -> None:
    raw = json.dumps(SAMPLE, separators=(",", ":")).encode() + b"\n"
    doc = load_settings(put(tmp_path, raw))
    assert doc.indent is None
    assert render_settings(doc, doc.data) == raw
    # A colon inside a string must not fool the detection.
    tricky = b'{"a":"x: y","b":1}'
    doc = load_settings(put(tmp_path, tricky, "t.json"))
    assert render_settings(doc, doc.data) == tricky


def test_empty_object_gets_the_default_indent(tmp_path: Path) -> None:
    doc = load_settings(put(tmp_path, b"{}\n"))
    assert doc.exists
    assert doc.data == {}
    assert doc.indent == 2
    assert render_settings(doc, doc.data) == b"{}\n"
    assert render_settings(doc, {"hooks": {}}) == b'{\n  "hooks": {}\n}\n'


def test_mixed_tab_and_space_indent_is_normalized_to_default(tmp_path: Path) -> None:
    doc = load_settings(put(tmp_path, b'{\n \t"a": 1\n}\n'))
    assert doc.indent == 2
    assert doc.data == {"a": 1}


def test_non_ascii_text_stays_utf8(tmp_path: Path) -> None:
    data = {"提示": "你好 \u2713", "env": {"路径": "C:\\用户\\测试 目录"}, "emoji": "\U0001f600"}
    raw = dumps(data)
    assert b"\\u" not in raw
    doc = load_settings(put(tmp_path, raw))
    assert doc.data == data
    out = render_settings(doc, {**doc.data, "新": "键"})
    assert out.decode("utf-8").count("你好 \u2713") == 1
    assert b"\\u" not in out
    assert json.loads(out)["新"] == "键"
    assert list(json.loads(out)) == ["提示", "env", "emoji", "新"]


def test_escaped_non_ascii_input_is_written_as_text(tmp_path: Path) -> None:
    doc = load_settings(put(tmp_path, b'{\n  "a": "\\u4f60\\u597d"\n}\n'))
    assert render_settings(doc, doc.data) == '{\n  "a": "你好"\n}\n'.encode()


def test_crlf_inside_a_string_value_is_not_confused_with_layout(tmp_path: Path) -> None:
    data = {"note": "line1\r\nline2\nline3"}
    raw = dumps(data, nl="\r\n")
    doc = load_settings(put(tmp_path, raw))
    assert render_settings(doc, doc.data) == raw
    assert load_settings(put(tmp_path, render_settings(doc, doc.data), "r.json")).data == data


def test_render_changes_only_what_changed(tmp_path: Path) -> None:
    raw = dumps(SAMPLE, indent=4, nl="\r\n")
    doc = load_settings(put(tmp_path, raw))
    new = dict(doc.data)
    new["model"] = "sonnet"
    out = render_settings(doc, new).decode()
    assert out == raw.decode().replace('"opus"', '"sonnet"')


def test_key_order_is_preserved(tmp_path: Path) -> None:
    raw = b'{"z": 1, "a": 2, "m": {"y": 1, "b": 2}}'
    doc = load_settings(put(tmp_path, raw))
    out = json.loads(render_settings(doc, doc.data))
    assert list(out) == ["z", "a", "m"]
    assert list(out["m"]) == ["y", "b"]


# ---- load: refusals -------------------------------------------------------------------------


def refuse(tmp_path: Path, raw: bytes) -> str:
    path = put(tmp_path, raw)
    with pytest.raises(SettingsError) as excinfo:
        load_settings(path)
    message = str(excinfo.value)
    assert path in message, "the message must say where"
    return message


def test_duplicate_top_level_key_is_refused(tmp_path: Path) -> None:
    message = refuse(tmp_path, b'{"hooks": {}, "model": "a", "hooks": {}}')
    assert "duplicate key" in message
    assert "'hooks'" in message


def test_duplicate_key_in_nested_object_is_refused(tmp_path: Path) -> None:
    message = refuse(tmp_path, b'{"permissions": {"allow": [], "deny": [], "allow": ["x"]}}')
    assert "duplicate key 'allow'" in message


def test_duplicate_key_inside_array_of_objects_is_refused(tmp_path: Path) -> None:
    refuse(tmp_path, b'{"a": [{"k": 1, "k": 2}]}')


@pytest.mark.parametrize(
    "raw",
    [b'{"a": 1,}', b'{"a": }', b"{'a': 1}", b'{"a": 1} trailing', b'{"a": 1', b"// c\n{}"],
)
def test_invalid_json_is_refused_with_a_position(tmp_path: Path, raw: bytes) -> None:
    message = refuse(tmp_path, raw)
    assert "invalid JSON" in message
    assert "line" in message


@pytest.mark.parametrize(
    ("raw", "word"),
    [(b"[1, 2]", "list"), (b"null", "null"), (b'"text"', "str"), (b"42", "int"), (b"true", "bool")],
)
def test_non_object_top_level_is_refused(tmp_path: Path, raw: bytes, word: str) -> None:
    message = refuse(tmp_path, raw)
    assert "top level must be a JSON object" in message
    assert word in message


def test_invalid_utf8_is_refused(tmp_path: Path) -> None:
    message = refuse(tmp_path, b'{"a": "\xff\xfe\x80"}')
    assert "UTF-8" in message


def test_gbk_encoded_chinese_is_refused_not_mangled(tmp_path: Path) -> None:
    raw = '{"a": "你好"}'.encode("gbk")
    assert "UTF-8" in refuse(tmp_path, raw)


def test_utf16_is_refused_with_a_hint(tmp_path: Path) -> None:
    raw = b"\xff\xfe" + '{"a": 1}'.encode("utf-16-le")
    assert "UTF-16" in refuse(tmp_path, raw)


def test_oversize_is_refused(tmp_path: Path) -> None:
    filler = b"x" * (MAX_SETTINGS_BYTES)
    message = refuse(tmp_path, b'{"a": "' + filler + b'"}')
    assert "4 MiB" in message


def test_file_of_exactly_the_limit_is_accepted(tmp_path: Path) -> None:
    head, tail = b'{"a": "', b'"}'
    raw = head + b"x" * (MAX_SETTINGS_BYTES - len(head) - len(tail)) + tail
    assert len(raw) == MAX_SETTINGS_BYTES
    assert load_settings(put(tmp_path, raw)).exists


@pytest.mark.parametrize("raw", [b"", b"  \r\n\t", BOM])
def test_empty_file_is_refused(tmp_path: Path, raw: bytes) -> None:
    assert "empty" in refuse(tmp_path, raw)


@pytest.mark.parametrize("raw", [b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}'])
def test_non_json_constants_are_refused(tmp_path: Path, raw: bytes) -> None:
    refuse(tmp_path, raw)


def test_number_overflowing_to_infinity_is_refused(tmp_path: Path) -> None:
    refuse(tmp_path, b'{"a": 1e999}')


def test_unpaired_surrogate_escape_is_refused(tmp_path: Path) -> None:
    # Python parses it, but it could never be written back as UTF-8.
    assert "surrogate" in refuse(tmp_path, b'{"a": "\\ud800"}')
    assert "surrogate" in refuse(tmp_path, b'{"\\udc00": 1}')
    # A valid pair is fine.
    load_settings(put(tmp_path, b'{"a": "\\ud83d\\ude00"}', "ok.json"))


def test_absurdly_deep_nesting_is_refused(tmp_path: Path) -> None:
    deep = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    refuse(tmp_path, deep)


def test_directory_in_place_of_file_is_refused(tmp_path: Path) -> None:
    d = tmp_path / "settings.json"
    d.mkdir()
    with pytest.raises(SettingsError):
        load_settings(str(d))


def test_load_never_modifies_the_file(tmp_path: Path) -> None:
    raw = BOM + dumps(SAMPLE, nl="\r\n")
    path = put(tmp_path, raw)
    before = os.stat(path).st_mtime_ns
    load_settings(path)
    assert Path(path).read_bytes() == raw
    assert os.stat(path).st_mtime_ns == before


# ---- render ---------------------------------------------------------------------------------


def test_render_refuses_values_json_cannot_hold(tmp_path: Path) -> None:
    doc = load_settings(put(tmp_path, dumps(SAMPLE)))
    with pytest.raises(SettingsError):
        render_settings(doc, {"a": {1, 2}})
    with pytest.raises(SettingsError):
        render_settings(doc, {"a": float("nan")})
    with pytest.raises(SettingsError):
        render_settings(doc, {"a": "\ud800"})


def test_render_does_not_mutate_the_document(tmp_path: Path) -> None:
    doc = load_settings(put(tmp_path, dumps(SAMPLE)))
    snapshot = json.dumps(doc.data)
    render_settings(doc, {**doc.data, "x": 1})
    assert json.dumps(doc.data) == snapshot


def test_doc_is_frozen() -> None:
    doc = SettingsDoc("p", False, {}, b"", False, "\n", 2, True)
    with pytest.raises(AttributeError):
        doc.path = "q"  # type: ignore[misc]


# ---- round trip (hypothesis) ----------------------------------------------------------------

scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**63)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=12)
)
values = st.recursive(
    scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4)
    ),
    max_leaves=12,
)
documents = st.dictionaries(st.text(max_size=6), values, max_size=5)
styles = st.sampled_from([2, 4, "\t", 0, None, "compact"])
newlines = st.sampled_from(["\n", "\r\n"])


def _serialize(data: dict[str, Any], style: int | str | None, newline: str, final: bool) -> bytes:
    if style == "compact":
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(data, ensure_ascii=False, indent=style)
    text = text.replace("\n", newline)
    return (text + (newline if final else "")).encode("utf-8")


@settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=documents, style=styles, newline=newlines, final=st.booleans(), bom=st.booleans())
def test_round_trip_law(
    tmp_path_factory: pytest.TempPathFactory,
    data: dict[str, Any],
    style: int | str | None,
    newline: str,
    final: bool,
    bom: bool,
) -> None:
    """render(load(raw), data) == raw for files json.dumps wrote (ensure_ascii=False) in one of
    the styles above, with LF or CRLF, with or without a trailing newline; a BOM is dropped.
    """
    body = _serialize(data, style, newline, final)
    path = put(tmp_path_factory.mktemp("rt"), (BOM + body) if bom else body)
    doc = load_settings(path)
    assert doc.data == data
    assert list(doc.data) == list(data)
    assert render_settings(doc, doc.data) == body


@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=documents, new=documents, style=styles, newline=newlines)
def test_values_and_key_order_never_change(
    tmp_path_factory: pytest.TempPathFactory,
    data: dict[str, Any],
    new: dict[str, Any],
    style: int | str | None,
    newline: str,
) -> None:
    """Whatever is rendered parses back to exactly the data given, in the same key order, and a
    second load-render cycle is a fixed point."""
    path = put(tmp_path_factory.mktemp("rt2"), _serialize(data, style, newline, True))
    doc = load_settings(path)
    out = render_settings(doc, new)
    again = load_settings(put(tmp_path_factory.mktemp("rt3"), out))
    assert json.dumps(again.data) == json.dumps(new)
    if new:
        assert render_settings(again, again.data) == out


def test_messy_whitespace_normalizes_but_values_and_order_hold(tmp_path: Path) -> None:
    raw = b'  \r\n{ "b" :\t1 ,\n"a":   [ 1 ,2,\n {"z": null , "y" : "\xe4\xbd\xa0"} ] }  \n\n'
    doc = load_settings(put(tmp_path, raw))
    out = render_settings(doc, doc.data)
    parsed = json.loads(out)
    assert parsed == {"b": 1, "a": [1, 2, {"z": None, "y": "你"}]}
    assert list(parsed) == ["b", "a"]
    assert list(parsed["a"][2]) == ["z", "y"]


# ---- write_atomic ---------------------------------------------------------------------------


def test_write_atomic_creates_parents_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "settings.json"
    write_atomic(str(target), b"{}\n")
    assert target.read_bytes() == b"{}\n"
    assert [p.name for p in target.parent.iterdir()] == ["settings.json"]


def test_write_atomic_replaces_existing_content(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"old")
    write_atomic(str(target), "新".encode())
    assert target.read_bytes() == "新".encode()
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_failure_keeps_original_and_removes_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"original")

    def boom(src: str, dst: str) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated"):
        write_atomic(str(target), b"new")
    assert target.read_bytes() == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_failure_while_writing_keeps_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"original")

    def boom(fd: int) -> None:
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError, match="fsync"):
        write_atomic(str(target), b"new")
    assert target.read_bytes() == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_failure_creating_a_new_file_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "new" / "settings.json"

    def boom(src: str, dst: str) -> None:
        raise OSError("simulated")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated"):
        write_atomic(str(target), b"x")
    assert not target.exists()
    assert list((tmp_path / "new").iterdir()) == []


@pytest.mark.posix
def test_write_atomic_keeps_file_mode(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"old")
    target.chmod(0o640)
    write_atomic(str(target), b"new")
    assert (target.stat().st_mode & 0o777) == 0o640


def test_write_atomic_through_a_symlink_keeps_the_link(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles" / "settings.json"
    real.parent.mkdir()
    real.write_bytes(b"old")
    link = tmp_path / "settings.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    write_atomic(str(link), b"new")
    assert link.is_symlink()
    assert real.read_bytes() == b"new"


# ---- backup_file ----------------------------------------------------------------------------


def test_backup_of_missing_file_is_none(tmp_path: Path) -> None:
    assert backup_file(str(tmp_path / "nope.json"), str(tmp_path / "bk")) is None
    assert not (tmp_path / "bk").exists()


def test_backup_name_content_and_timestamp(tmp_path: Path) -> None:
    src = tmp_path / "settings.json"
    src.write_bytes(BOM + b'{"a": "\xe4\xbd\xa0"}')
    dest = backup_file(str(src), str(tmp_path / "bk"), now=0)
    assert dest is not None
    name = os.path.basename(dest)
    assert re.fullmatch(r"settings\.json-[0-9a-f]{8}-19700101T000000Z\.bak", name)
    assert Path(dest).read_bytes() == src.read_bytes()
    assert os.path.dirname(dest) == str(tmp_path / "bk")


def test_backup_never_overwrites(tmp_path: Path) -> None:
    src = tmp_path / "settings.json"
    src.write_bytes(b"v1")
    first = backup_file(str(src), str(tmp_path / "bk"), now=1_700_000_000)
    src.write_bytes(b"v2")
    second = backup_file(str(src), str(tmp_path / "bk"), now=1_700_000_000)
    src.write_bytes(b"v3")
    third = backup_file(str(src), str(tmp_path / "bk"), now=1_700_000_000)
    assert first
    assert second
    assert third
    assert len({first, second, third}) == 3
    assert second.endswith("-1.bak")
    assert third.endswith("-2.bak")
    assert [Path(p).read_bytes() for p in (first, second, third)] == [b"v1", b"v2", b"v3"]


def test_backup_names_differ_for_same_base_name_in_different_directories(tmp_path: Path) -> None:
    a = tmp_path / "proj-a" / ".claude" / "settings.json"
    b = tmp_path / "proj-b" / ".claude" / "settings.json"
    for p in (a, b):
        p.parent.mkdir(parents=True)
        p.write_bytes(b"{}")
    da = backup_file(str(a), str(tmp_path / "bk"), now=5)
    db = backup_file(str(b), str(tmp_path / "bk"), now=5)
    assert da
    assert db
    assert da != db
    assert not da.endswith("-1.bak")
    assert not db.endswith("-1.bak")


def test_backup_sanitizes_the_base_name(tmp_path: Path) -> None:
    src = tmp_path / "my settings (copy)#1.json"
    src.write_bytes(b"{}")
    dest = backup_file(str(src), str(tmp_path / "bk"), now=5)
    assert dest is not None
    name = os.path.basename(dest)
    assert re.fullmatch(r"[\w.\-]+\.bak", name)
    assert " " not in name
    assert "(" not in name
    assert "#" not in name


def test_backup_of_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    with pytest.raises(SettingsError):
        backup_file(str(tmp_path / "d"), str(tmp_path / "bk"))


def test_backup_uses_the_current_time_by_default(tmp_path: Path) -> None:
    src = tmp_path / "s.json"
    src.write_bytes(b"{}")
    dest = backup_file(str(src), str(tmp_path / "bk"))
    assert dest is not None
    assert re.search(r"-\d{8}T\d{6}Z\.bak$", dest)


# ---- regression tests for the adversarial review --------------------------------------------
# Each test below failed against the first implementation (see the finding it names).


def nested(depth: int) -> bytes:
    """A document whose deepest container sits ``depth`` levels down (the top object is 1)."""
    return b'{"x": ' + b"[" * (depth - 1) + b"]" * (depth - 1) + b"}"


# Finding: load_settings accepted ~900 levels of nesting that merge/remove then crashed on.
def test_nesting_up_to_the_limit_is_accepted_and_one_more_level_is_refused(tmp_path: Path) -> None:
    assert MAX_NESTING_DEPTH <= 200  # editing code copies the document recursively
    doc = load_settings(put(tmp_path, nested(MAX_NESTING_DEPTH)))
    assert doc.exists
    assert json.loads(render_settings(doc, doc.data)) == doc.data
    message = refuse(tmp_path, nested(MAX_NESTING_DEPTH + 1))
    assert "nested" in message
    assert str(MAX_NESTING_DEPTH) in message


@pytest.mark.parametrize("depth", [300, 600, 900, 990])
def test_deep_nesting_that_python_can_still_parse_is_refused(tmp_path: Path, depth: int) -> None:
    assert "nested" in refuse(tmp_path, nested(depth))


def test_deep_nesting_inside_objects_is_refused_too(tmp_path: Path) -> None:
    raw = b'{"a":' * (MAX_NESTING_DEPTH + 1) + b"1" + b"}" * (MAX_NESTING_DEPTH + 1)
    assert "nested" in refuse(tmp_path, raw)


# Finding: os.replace on Windows fails with PermissionError while an editor, an indexer or a
# second writer holds the file; a raw PermissionError escaped after one attempt.
class FlakyReplace:
    """os.replace that raises PermissionError ``failures`` times, then really replaces."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0
        self._real = os.replace

    def __call__(self, src: str, dst: str) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise PermissionError(13, "Access is denied", dst)
        self._real(src, dst)


@pytest.fixture
def fast_windows(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Pretend to be Windows and make the retry back-off instant; returns the sleeps asked for."""
    sleeps: list[float] = []
    monkeypatch.setattr(sio, "_IS_WINDOWS", True)
    monkeypatch.setattr(sio.time, "sleep", sleeps.append)
    return sleeps


def test_write_atomic_retries_a_transient_sharing_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fast_windows: list[float]
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"old")
    flaky = FlakyReplace(failures=3)
    monkeypatch.setattr(os, "replace", flaky)
    write_atomic(str(target), b"new")
    assert flaky.calls == 4
    assert len(fast_windows) == 3
    assert target.read_bytes() == b"new"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_gives_up_with_a_readable_settings_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fast_windows: list[float]
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"original")
    flaky = FlakyReplace(failures=10_000)
    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(SettingsError) as excinfo:
        write_atomic(str(target), b"new")
    assert str(target) in str(excinfo.value)
    assert "locked" in str(excinfo.value) or "read-only" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, PermissionError)
    assert 2 <= flaky.calls <= 50  # bounded
    assert sum(fast_windows) < 5  # and the total wait is bounded too
    assert target.read_bytes() == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_does_not_retry_other_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fast_windows: list[float]
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"original")
    calls: list[int] = []

    def boom(src: str, dst: str) -> None:
        calls.append(1)
        raise OSError("disk exploded")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk exploded"):
        write_atomic(str(target), b"new")
    assert len(calls) == 1
    assert fast_windows == []
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_does_not_retry_on_posix_but_still_reports_readably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"original")
    flaky = FlakyReplace(failures=10_000)
    monkeypatch.setattr(sio, "_IS_WINDOWS", False)
    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(SettingsError, match="permission"):
        write_atomic(str(target), b"new")
    assert flaky.calls == 1  # nothing transient to wait for outside Windows
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


@pytest.mark.windows
def test_write_atomic_survives_a_file_held_open_for_a_moment(tmp_path: Path) -> None:
    import threading

    target = tmp_path / "settings.json"
    target.write_bytes(b"old")
    with open(target, "rb") as handle:  # no FILE_SHARE_DELETE: os.replace fails while open
        timer = threading.Timer(0.3, handle.close)
        timer.start()
        try:
            write_atomic(str(target), b"new")
        finally:
            timer.join()
    assert target.read_bytes() == b"new"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


@pytest.mark.windows
def test_write_atomic_on_a_file_held_open_for_good_fails_readably(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"old")
    started = time.monotonic()
    with open(target, "rb"), pytest.raises(SettingsError, match="locked"):
        write_atomic(str(target), b"new")
    assert time.monotonic() - started < 15
    assert target.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_concurrent_writers_never_crash_and_leave_a_complete_file(tmp_path: Path) -> None:
    import threading

    target = tmp_path / "settings.json"
    target.write_bytes(b"0")
    errors: list[BaseException] = []
    payloads = {f"w{n}": json.dumps({"writer": n, "pad": "x" * 2000}).encode() for n in range(4)}

    def worker(name: str) -> None:
        try:
            for _ in range(25):
                write_atomic(str(target), payloads[name])
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(name,)) for name in payloads]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert target.read_bytes() in payloads.values()
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


# Finding: a concurrent edit between load and write was overwritten silently. ``expect_raw`` lets
# the caller (init, uninstall) refuse to write over a file that is not what it read.
def test_write_atomic_expect_raw_refuses_a_file_that_changed(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b'{"a": 1}')
    doc = load_settings(str(target))
    target.write_bytes(b'{"a": 2}')  # somebody edited it after we read it
    with pytest.raises(SettingsError, match="changed"):
        write_atomic(str(target), b'{"a": 3}', expect_raw=doc.raw)
    assert target.read_bytes() == b'{"a": 2}'
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_write_atomic_expect_raw_accepts_an_unchanged_file(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(BOM + b'{"a": 1}')
    doc = load_settings(str(target))
    write_atomic(str(target), b'{"a": 3}', expect_raw=doc.raw)
    assert target.read_bytes() == b'{"a": 3}'


def test_write_atomic_expect_raw_for_a_file_that_did_not_exist(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "settings.json"
    doc = load_settings(str(target))
    assert doc.exists is False
    write_atomic(str(target), b"{}", expect_raw=doc.raw)
    assert target.read_bytes() == b"{}"
    # It appeared meanwhile (another init run): do not overwrite it.
    other = tmp_path / "other.json"
    doc2 = load_settings(str(other))
    other.write_bytes(b'{"theirs": true}')
    with pytest.raises(SettingsError, match="changed"):
        write_atomic(str(other), b"{}", expect_raw=doc2.raw)
    assert other.read_bytes() == b'{"theirs": true}'


def test_write_atomic_expect_raw_refuses_a_file_that_vanished(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b'{"a": 1}')
    doc = load_settings(str(target))
    target.unlink()
    with pytest.raises(SettingsError, match="changed"):
        write_atomic(str(target), b"{}", expect_raw=doc.raw)
    assert not target.exists()


def test_write_atomic_without_expect_raw_keeps_the_old_behaviour(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"a")
    write_atomic(str(target), b"b")
    assert target.read_bytes() == b"b"


# Finding: new files on POSIX were chmod'ed to 0644 regardless of the umask. A fresh user
# settings.json may later hold tokens in "env": it keeps mkstemp's 0600 instead.
def test_preserved_mode_is_none_for_a_new_file_on_every_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = str(tmp_path / "nope.json")
    assert sio._preserved_mode(missing) is None
    monkeypatch.setattr(sio, "_IS_WINDOWS", False)
    assert sio._preserved_mode(missing) is None  # the POSIX branch, simulated on any OS


def test_preserved_mode_follows_the_existing_file_on_posix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = tmp_path / "s.json"
    existing.write_bytes(b"{}")
    monkeypatch.setattr(sio, "_IS_WINDOWS", False)
    assert sio._preserved_mode(str(existing)) == (existing.stat().st_mode & 0o777)
    monkeypatch.setattr(sio, "_IS_WINDOWS", True)
    assert sio._preserved_mode(str(existing)) is None


def test_write_atomic_never_chmods_a_new_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sio, "_IS_WINDOWS", False)
    chmods: list[tuple[str, int]] = []
    monkeypatch.setattr(os, "chmod", lambda p, m, **kw: chmods.append((str(p), m)))
    write_atomic(str(tmp_path / "new" / "settings.json"), b"{}")
    assert chmods == []


@pytest.mark.posix
def test_new_file_is_private_whatever_the_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        target = tmp_path / "settings.json"
        write_atomic(str(target), b"{}")
        assert (target.stat().st_mode & 0o777) == 0o600
    finally:
        os.umask(old)
