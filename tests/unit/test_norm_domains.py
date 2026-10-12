"""normalize.domains: host canonicalization and allowlist matching (adversarial)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from boundkeep.normalize.domains import (
    Host,
    canonical_host,
    extract_hosts,
    host_matches,
    hosts_of,
)

UNKNOWN = "unknown"

# (raw, expected name, expected kind); name None means "the name is not interesting" (unknown)
CANON_CASES = [
    # --- plain names, case, trailing dot, ports, schemes
    pytest.param("github.com", "github.com", "domain", id="bare"),
    pytest.param("GitHub.COM", "github.com", "domain", id="uppercase"),
    pytest.param("github.com.", "github.com", "domain", id="trailing-dot"),
    pytest.param("https://github.com/org/repo", "github.com", "domain", id="https-path"),
    pytest.param("https://GitHub.com:443/x?y#z", "github.com", "domain", id="port-query-fragment"),
    pytest.param("github.com:443", "github.com", "domain", id="bare-port"),
    pytest.param("ftp://ftp.example.com/pub", "ftp.example.com", "domain", id="ftp"),
    pytest.param("ssh://git@github.com/org/repo", "github.com", "domain", id="ssh-url"),
    pytest.param("ssh://git@github.com:22/org/repo", "github.com", "domain", id="ssh-url-port"),
    pytest.param("git://github.com/org/repo.git", "github.com", "domain", id="git-scheme"),
    pytest.param("ws://a.example/socket", "a.example", "domain", id="ws"),
    pytest.param("wss://a.example:443/socket", "a.example", "domain", id="wss"),
    pytest.param("HTTP://EXAMPLE.org", "example.org", "domain", id="uppercase-scheme"),
    pytest.param("//cdn.example.com/x.js", "cdn.example.com", "domain", id="scheme-relative"),
    # --- scp-like
    pytest.param("git@github.com:org/repo.git", "github.com", "domain", id="scp-git"),
    pytest.param("user@host.example:path/x", "host.example", "domain", id="scp-user"),
    pytest.param("host.example:/srv/x", "host.example", "domain", id="scp-nouser"),
    # --- userinfo tricks: the host is what follows the LAST @
    pytest.param("http://user:pw@github.com/x", "github.com", "domain", id="userinfo"),
    pytest.param("github.com@evil.com", "evil.com", "domain", id="at-bare"),
    pytest.param("http://github.com@evil.com/", "evil.com", "domain", id="at-url"),
    pytest.param("http://github.com:80@evil.com", "evil.com", "domain", id="at-port-lookalike"),
    pytest.param("http://user@github.com@evil.com", None, UNKNOWN, id="two-ats"),
    pytest.param("http://evil.com#@github.com", "evil.com", "domain", id="fragment-at"),
    pytest.param("http://evil.com?@github.com", "evil.com", "domain", id="query-at"),
    pytest.param("http://evil.com/@github.com", "evil.com", "domain", id="path-at"),
    pytest.param("http://github.com.evil.com", "github.com.evil.com", "domain", id="suffix-trick"),
    # --- ambiguous between clients: never a clean host
    pytest.param("http://github.com\\@evil.com", None, UNKNOWN, id="backslash-url"),
    pytest.param("github.com\\@evil.com", None, UNKNOWN, id="backslash-bare"),
    pytest.param("http://github.com%2eevil.com", None, UNKNOWN, id="percent-url"),
    pytest.param("github.com%2eevil.com", None, UNKNOWN, id="percent-bare"),
    pytest.param("http://github.com\n.evil.com", None, UNKNOWN, id="newline-in-host"),
    pytest.param("http://github.com\t.evil.com", None, UNKNOWN, id="tab-in-host"),
    pytest.param("a\x00b.com", None, UNKNOWN, id="nul"),
    pytest.param("exa mple.com", None, UNKNOWN, id="space-inside"),
    pytest.param("http://github.com:99999/", None, UNKNOWN, id="port-too-big"),
    pytest.param("http://github.com:abc/", None, UNKNOWN, id="port-not-number"),
    pytest.param("http://github.com:80:80/", None, UNKNOWN, id="two-ports"),
    pytest.param("http://:80/", None, UNKNOWN, id="empty-host-with-port"),
    pytest.param("http:///evil.com", None, UNKNOWN, id="triple-slash"),
    pytest.param("http://", None, UNKNOWN, id="empty-authority-http"),
    pytest.param("a..b", None, UNKNOWN, id="empty-label"),
    pytest.param(".github.com", None, UNKNOWN, id="leading-dot"),
    pytest.param("github.com..", None, UNKNOWN, id="two-trailing-dots"),
    pytest.param("a" * 64 + ".com", None, UNKNOWN, id="label-too-long"),
    pytest.param(("a" * 60 + ".") * 5 + "com", None, UNKNOWN, id="name-too-long"),
    pytest.param("x" * 3000, None, UNKNOWN, id="input-too-long"),
    pytest.param("\ud800.com", None, UNKNOWN, id="lone-surrogate"),
    pytest.param("evil*.com", None, UNKNOWN, id="wildcard"),
    # --- IPv4 spellings
    pytest.param("127.0.0.1", "127.0.0.1", "ip", id="ipv4-dotted"),
    pytest.param("2130706433", "127.0.0.1", "ip", id="ipv4-decimal"),
    pytest.param("http://2130706433/", "127.0.0.1", "ip", id="ipv4-decimal-url"),
    pytest.param("0x7f000001", "127.0.0.1", "ip", id="ipv4-hex-single"),
    pytest.param("0x7f.1", "127.0.0.1", "ip", id="ipv4-hex-short"),
    pytest.param("0177.0.0.1", "127.0.0.1", "ip", id="ipv4-octal"),
    pytest.param("0300.0250.0.1", "192.168.0.1", "ip", id="ipv4-octal-192"),
    pytest.param("127.1", "127.0.0.1", "ip", id="ipv4-two-parts"),
    pytest.param("127.0.1", "127.0.0.1", "ip", id="ipv4-three-parts"),
    pytest.param("1.2.3", "1.2.0.3", "ip", id="ipv4-last-fills"),
    pytest.param("127.0.0.1.", "127.0.0.1", "ip", id="ipv4-trailing-dot"),
    pytest.param("1.2.3.4:8080", "1.2.3.4", "ip", id="ipv4-port"),
    pytest.param("0xffffffff", "255.255.255.255", "ip", id="ipv4-max"),
    pytest.param(
        "\uff11\uff12\uff17.\uff10.\uff10.\uff11", "127.0.0.1", "ip", id="ipv4-fullwidth-digits"
    ),
    pytest.param("256.1.1.1", None, UNKNOWN, id="ipv4-octet-too-big"),
    pytest.param("1.2.3.4.5", None, UNKNOWN, id="ipv4-five-parts"),
    pytest.param("08.0.0.1", None, UNKNOWN, id="ipv4-bad-octal"),
    pytest.param("4294967296", None, UNKNOWN, id="ipv4-decimal-overflow"),
    pytest.param("foo.1", None, UNKNOWN, id="numeric-tld-is-not-a-domain"),
    # --- IPv6
    pytest.param("[::1]", "::1", "ip", id="ipv6-loopback"),
    pytest.param("[::1]:8080", "::1", "ip", id="ipv6-port"),
    pytest.param("http://[::1]:8080/x", "::1", "ip", id="ipv6-url"),
    pytest.param("[2001:DB8:0:0::1]", "2001:db8::1", "ip", id="ipv6-compress-lower"),
    pytest.param("[fe80::1%25eth0]", "fe80::1", "ip", id="ipv6-zone-escaped"),
    pytest.param("[fe80::1%eth0]", "fe80::1", "ip", id="ipv6-zone"),
    pytest.param("::1", "::1", "ip", id="ipv6-bare"),
    pytest.param("[::ffff:127.0.0.1]", "127.0.0.1", "ip", id="ipv6-mapped-v4"),
    pytest.param("[::1", None, UNKNOWN, id="ipv6-unclosed"),
    pytest.param("[::1]x", None, UNKNOWN, id="ipv6-trailing-junk"),
    pytest.param("[zzz]", None, UNKNOWN, id="ipv6-garbage"),
    pytest.param("[::1%]", None, UNKNOWN, id="ipv6-empty-zone"),
    # --- localhost
    pytest.param("localhost", "localhost", "localhost", id="localhost"),
    pytest.param("LOCALHOST:3000", "localhost", "localhost", id="localhost-port"),
    pytest.param("foo.localhost", "foo.localhost", "localhost", id="localhost-subdomain"),
    pytest.param("http://localhost./x", "localhost", "localhost", id="localhost-trailing-dot"),
    # --- IDN
    pytest.param("b\u00fccher.de", "xn--bcher-kva.de", "domain", id="idn-umlaut"),
    pytest.param(
        "\uff27\uff29\uff34\uff28\uff35\uff22\u3002\uff23\uff2f\uff2d",
        "github.com",
        "domain",
        id="idn-fullwidth-and-dot",
    ),
    pytest.param("http://m\u00fcnchen.de/x", "xn--mnchen-3ya.de", "domain", id="idn-url"),
    pytest.param("xn--bcher-kva.de", "xn--bcher-kva.de", "domain", id="punycode-kept"),
    pytest.param("\u2100.example", None, UNKNOWN, id="idn-slash-expansion"),
    pytest.param("github.com\uff20evil.com", None, UNKNOWN, id="idn-fullwidth-at"),
    pytest.param("github.com\uff0fx.evil.com", None, UNKNOWN, id="idn-fullwidth-slash"),
    pytest.param("fu\u00dfball.de", None, UNKNOWN, id="idna-deviation-sharp-s"),
    pytest.param("http://a@b@c.example", None, UNKNOWN, id="three-parts-two-ats"),
    pytest.param(
        "http://github.com%40@evil.com", "evil.com", "domain", id="escaped-at-in-userinfo"
    ),
]


@pytest.mark.parametrize(("raw", "name", "kind"), CANON_CASES)
def test_canonical_host_table(raw: str, name: str | None, kind: str) -> None:
    host = canonical_host(raw)
    assert host is not None
    assert host.kind == kind
    if name is not None:
        assert host.name == name
    assert host.raw == raw[:512]


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param("file:///etc/passwd", id="file-url"),
        pytest.param("/just/a/path", id="path"),
        pytest.param("?x=1", id="query-only"),
    ],
)
def test_canonical_host_none_means_no_host(raw: str) -> None:
    assert canonical_host(raw) is None


def test_homograph_is_not_the_ascii_name() -> None:
    host = canonical_host("g\u0131thub.com")  # dotless i
    assert host is not None
    assert host.kind == "domain"
    assert host.name != "github.com"
    assert host.name.startswith("xn--")


def test_kelvin_sign_maps_like_a_browser_would() -> None:
    host = canonical_host("\u212aube.example")  # KELVIN SIGN lower-cases to k
    assert host is not None
    assert host.name == "kube.example"


ALLOW = ["github.com"]
MATCH_CASES = [
    pytest.param("github.com", ALLOW, True, id="exact"),
    pytest.param("GITHUB.COM", ALLOW, True, id="exact-uppercase"),
    pytest.param("api.github.com", ALLOW, True, id="subdomain"),
    pytest.param("a.b.github.com", ALLOW, True, id="deep-subdomain"),
    pytest.param("api.github.com.", ALLOW, True, id="subdomain-trailing-dot"),
    pytest.param("https://api.github.com:443/x", ALLOW, True, id="url-subdomain"),
    pytest.param("evilgithub.com", ALLOW, False, id="suffix-without-dot"),
    pytest.param("notgithub.com", ALLOW, False, id="notgithub"),
    pytest.param("xgithub.com", ALLOW, False, id="prefix-letter"),
    pytest.param("github.com.evil.com", ALLOW, False, id="allowed-as-prefix"),
    pytest.param("github.co", ALLOW, False, id="shorter-tld"),
    pytest.param("github.com@evil.com", ALLOW, False, id="userinfo-trick"),
    pytest.param("https://github.com@evil.com/", ALLOW, False, id="userinfo-trick-url"),
    pytest.param("github.com%2eevil.com", ALLOW, False, id="percent-escaped-dot"),
    pytest.param("http://github.com\\@evil.com", ALLOW, False, id="backslash-trick"),
    pytest.param("github.com:80@evil.com", ALLOW, False, id="port-lookalike-userinfo"),
    pytest.param("evil.com#@github.com", ALLOW, False, id="fragment-trick"),
    pytest.param("1.2.3.4", ALLOW, False, id="ip-vs-domain-entry"),
    pytest.param("github.com", [], False, id="empty-allowlist"),
    pytest.param("github.com", ["*.github.com"], False, id="wildcard-entry-ignored"),
    pytest.param("api.github.com", [".github.com"], False, id="leading-dot-entry-ignored"),
    pytest.param("github.com", ["https://github.com"], False, id="url-entry-ignored"),
    pytest.param("github.com", ["github.com/x"], False, id="path-entry-ignored"),
    pytest.param("github.com", [""], False, id="empty-entry"),
    pytest.param("github.com", ["gith ub.com"], False, id="garbage-entry"),
    pytest.param("api.github.com", ["PyPI.org", " GitHub.com "], True, id="entry-normalized"),
    pytest.param("files.pythonhosted.org", ["pypi.org", "files.pythonhosted.org"], True, id="list"),
    pytest.param("127.0.0.1", ["127.0.0.1"], True, id="ip-exact"),
    pytest.param("2130706433", ["127.0.0.1"], True, id="ip-decimal-spelling"),
    pytest.param("0x7f.1", ["127.0.0.1"], True, id="ip-hex-spelling"),
    pytest.param("127.0.0.2", ["127.0.0.1"], False, id="ip-other"),
    pytest.param("10.0.0.5", ["10.0.0.0/8"], False, id="cidr-entry-ignored"),
    pytest.param("1.2.3.4", ["3.4"], False, id="ip-never-matches-suffix"),
    pytest.param("[::1]", ["::1"], True, id="ipv6-exact"),
    pytest.param("[::ffff:7f00:1]", ["127.0.0.1"], True, id="ipv6-mapped-matches-v4"),
    pytest.param("github.com", ["127.0.0.1"], False, id="domain-vs-ip-entry"),
    pytest.param("localhost", ["localhost"], True, id="localhost"),
    pytest.param("dev.localhost", ["localhost"], True, id="localhost-sub"),
    pytest.param("b\u00fccher.de", ["xn--bcher-kva.de"], True, id="idn-vs-punycode-entry"),
    pytest.param("xn--bcher-kva.de", ["b\u00fccher.de"], True, id="punycode-vs-idn-entry"),
]


@pytest.mark.parametrize(("raw", "allowed", "expected"), MATCH_CASES)
def test_host_matches_table(raw: str, allowed: list[str], expected: bool) -> None:
    host = canonical_host(raw)
    assert host is not None
    assert host_matches(host, allowed) is expected


def test_host_matches_unknown_kind_never_matches() -> None:
    assert host_matches(Host("github.com", "unknown", "x"), ["github.com"]) is False


def test_host_matches_renormalizes_hand_built_host() -> None:
    assert host_matches(Host("GitHub.com", "domain", "x"), ["github.com"]) is True
    assert host_matches(Host("evil.com", "domain", "x"), ["github.com"]) is False
    assert host_matches(Host("", "domain", ""), ["github.com"]) is False


EXTRACT_CASES = [
    pytest.param("curl https://a.example/x", ["a.example"], id="url"),
    pytest.param(
        "http://a.example/x?u=https://b.example/y", ["a.example", "b.example"], id="nested"
    ),
    pytest.param("git@github.com:o/r.git", ["github.com"], id="scp"),
    pytest.param(
        "clone ssh://u@h.example:22/p and git@gitlab.com:x/y",
        ["h.example", "gitlab.com"],
        id="mixed",
    ),
    pytest.param("see (http://c.example)", ["c.example"], id="trailing-paren"),
    pytest.param('{"u":"http://d.example"}', ["d.example"], id="json"),
    pytest.param("http://a.example http://a.example", ["a.example"], id="dedupe"),
    pytest.param("no urls here", [], id="none"),
    pytest.param("file:///etc/passwd", [], id="file-url"),
    pytest.param("http://github.com@evil.com/x", ["evil.com"], id="userinfo"),
    pytest.param("x=http://2130706433:8000/", ["127.0.0.1"], id="ip-spelling"),
    pytest.param("-Ohttp://e.example/", ["e.example"], id="glued-to-option"),
]


@pytest.mark.parametrize(("text", "names"), EXTRACT_CASES)
def test_extract_hosts_table(text: str, names: list[str]) -> None:
    assert [h.name for h in extract_hosts(text)] == names


def test_extract_hosts_flags_ambiguous_authority_as_unknown() -> None:
    (host,) = extract_hosts("http://github.com\\@evil.com/")
    assert host.kind == UNKNOWN
    (host,) = extract_hosts("http://github.com\n.evil.com/")
    assert host.kind == UNKNOWN


def test_extract_hosts_truncation_is_never_silent() -> None:
    text = ("http://a.example/ " * 6000) + "http://github.com"
    hosts = extract_hosts(text)
    assert hosts[-1].kind == UNKNOWN  # marker
    many = " ".join(f"http://h{i}.example/" for i in range(100))
    out = extract_hosts(many)
    assert len(out) == 65
    assert out[-1].kind == UNKNOWN


def test_hosts_of_combines_own_host_and_embedded_urls() -> None:
    names = [h.name for h in hosts_of(["example.com/x?u=http://b.example", "user@h.example"])]
    assert names == ["example.com", "b.example", "h.example"]


def test_internal_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from boundkeep.normalize import domains

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    with monkeypatch.context() as m:
        m.setattr(domains, "_canonical_host", boom)
        host = canonical_host("github.com")
        assert host is not None
        assert host.kind == UNKNOWN
        assert host_matches(Host("github.com", "domain", "x"), ["github.com"]) is False
    with monkeypatch.context() as m:
        m.setattr(domains, "_extract", boom)
        (marker,) = extract_hosts("http://github.com")
        assert marker.kind == UNKNOWN
    with monkeypatch.context() as m:
        m.setattr(domains, "_allowed_entry", boom)
        assert host_matches(Host("github.com", "domain", "x"), ["github.com"]) is False


# ---------------------------------------------------------------- hypothesis

HOSTISH = st.text(
    alphabet=st.sampled_from(
        [
            *list("abcxyz019.-_:@/\\?#%[]() \t\n*"),
            "\x00",
            "\u00e9",
            "\u3002",
            "\uff10",
            "K",
            "\ufffd",
        ]
    ),
    max_size=40,
)
ANYTEXT = st.one_of(st.text(max_size=200), HOSTISH)
LABEL = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=10)
DOMAIN = st.lists(LABEL, min_size=1, max_size=4).map(".".join)


@settings(max_examples=400, deadline=None)
@given(ANYTEXT)
def test_canonical_host_never_raises_and_is_bounded(raw: str) -> None:
    host = canonical_host(raw)
    assert host is None or (isinstance(host, Host) and len(host.name) <= 512)
    for found in extract_hosts(raw):
        assert isinstance(found, Host)
    assert isinstance(host_matches(host, ["github.com"]) if host else False, bool)


@settings(max_examples=600, deadline=None)
@given(ANYTEXT)
def test_canonical_host_is_idempotent(raw: str) -> None:
    host = canonical_host(raw)
    if host is None or host.kind == UNKNOWN:
        return
    again = canonical_host(host.name)
    assert again is not None
    assert (again.name, again.kind) == (host.name, host.kind)


@settings(max_examples=600, deadline=None)
@given(ANYTEXT, DOMAIN)
def test_host_matches_only_on_label_boundary(raw: str, allowed: str) -> None:
    host = canonical_host(raw)
    if host is None:
        return
    if host_matches(host, [allowed]):
        assert host.kind in ("domain", "localhost", "ip")
        assert host.name == allowed or host.name.endswith("." + allowed) or host.kind == "ip"
        if host.kind != "ip":
            assert host.kind != UNKNOWN


@settings(max_examples=300, deadline=None)
@given(DOMAIN, DOMAIN)
def test_suffix_construction_matches_only_with_a_dot(prefix: str, allowed: str) -> None:
    glued = canonical_host(prefix + allowed)
    dotted = canonical_host(prefix + "." + allowed)
    assert glued is not None
    assert dotted is not None
    if glued.kind == "domain" and prefix + allowed != allowed:
        # without the dot the allowed name is not a label-aligned suffix unless it already was
        expected = (prefix + allowed).lower().endswith("." + allowed.lower()) or (
            prefix + allowed
        ).lower() == allowed.lower()
        assert host_matches(glued, [allowed]) is expected
    if dotted.kind == "domain":
        assert host_matches(dotted, [allowed]) is True


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_every_ipv4_spelling_agrees(n: int) -> None:
    dotted = f"{n >> 24}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"
    for spelling in (str(n), hex(n), f"{n >> 24}.{n & 0xFFFFFF}", dotted):
        host = canonical_host(spelling)
        assert host is not None
        assert host.kind == "ip"
        assert host.name == dotted
    octal = ".".join("0" + format(int(part), "o") for part in dotted.split("."))
    host = canonical_host(octal)
    assert host is not None
    assert host.name == dotted


# --- review fixes: scp-like ambiguity (a ':' before the first '@' without a scheme)


@pytest.mark.parametrize(
    "raw",
    [
        "evil.com:x@github.com",
        "evil.com:x@github.com:/tmp",
        "evil.com:github.com@github.com:/tmp",
        "user:pw@github.com",
        "evil.com:@github.com",
    ],
)
def test_scheme_less_colon_before_at_is_ambiguous(raw: str) -> None:
    """scp / rsync read ``HOST:PATH`` while curl / ssh read ``USER:PASS@HOST``: no clean host."""
    host = canonical_host(raw)
    assert host is not None
    assert host.kind == UNKNOWN
    assert not host_matches(host, ["github.com"])
    assert all(h.kind == UNKNOWN or h.name != "github.com" for h in hosts_of([raw]))


@pytest.mark.parametrize(
    ("raw", "name"),
    [
        ("git@github.com:org/repo", "github.com"),  # the ':' comes after the '@': plain scp-like
        ("github.com:443", "github.com"),
        ("http://user:pw@github.com/x", "github.com"),  # with a scheme userinfo is unambiguous
        ("ssh://git@github.com:22/x", "github.com"),
        ("evil.com@github.com:org/x", "github.com"),
    ],
)
def test_colon_after_at_or_with_scheme_is_still_understood(raw: str, name: str) -> None:
    host = canonical_host(raw)
    assert host is not None
    assert (host.name, host.kind) == (name, "domain")


def test_scp_command_operands_with_the_trick_are_never_github() -> None:
    for raw in ("evil.com:x@github.com", "evil.com:github.com@github.com:/tmp"):
        names = {h.name for h in hosts_of([raw]) if h.kind != UNKNOWN}
        assert "github.com" not in names
