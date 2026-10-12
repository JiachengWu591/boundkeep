"""Host canonicalization and allowlist matching (docs/m1-design.md, module E).

Everything here is pure and never raises. The three guarantees a network allowlist depends on:

* ``canonical_host`` returns the host a *client* would contact, never a lookalike: userinfo
  (``github.com@evil.com`` is ``evil.com``), ports, trailing dots, case, IDN, and every IPv4
  spelling (``2130706433``, ``0x7f.1``, ``0177.0.0.1``) are normalized; anything ambiguous
  between clients (backslash in the authority, ``%`` escapes, control characters, bad ports, and a
  scheme-less ``:`` before the first ``@`` as in ``evil.com:x@github.com``, which scp reads as
  host ``evil.com`` and curl as userinfo) becomes ``kind="unknown"``, which no allowlist entry
  ever matches.
* ``host_matches`` is exact-or-true-subdomain on label boundaries; IPs only match exactly.
* ``None`` from ``canonical_host`` only ever means "this string contains no host at all"
  (empty, or a ``file:`` URL); a malformed host is ``unknown``, never silently dropped.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

HostKind = Literal["domain", "ip", "localhost", "unknown"]

_MAX_HOST_INPUT = 2048  # a single host / URL longer than this is "unknown", not parsed
_MAX_TEXT = 1 << 16  # extract_hosts scans at most this much text
_MAX_HOSTS = 64  # extract_hosts returns at most this many hosts (then one "unknown" marker)
_MAX_NAME = 253
_MAX_LABEL = 63
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = frozenset("0123456789abcdef")
_AUTH_END = "/?#\\"  # characters that end the authority of a URL
_TRAILING_PUNCT = ")>}\"',;!*"  # trimmed from the end of an authority found inside free text
# characters whose IDNA2003 mapping (Python) differs from UTS 46 / IDNA2008 (browsers): refuse
_IDNA_DEVIATIONS = frozenset("\u00df\u03c2\u200c\u200d")
_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")


@dataclass(frozen=True, slots=True)
class Host:
    """A canonical host: lower-case, no port, no userinfo, punycode, normalized IP."""

    name: str
    kind: HostKind
    raw: str


def _unknown(raw: str) -> Host:
    """An unparseable or ambiguous host. Its name is the raw text, never a clean-looking host."""
    return Host(name=raw[:_MAX_NAME], kind="unknown", raw=raw[:512])


def _is_scheme(text: str) -> bool:
    return (
        bool(text)
        and text[0].isascii()
        and text[0].isalpha()
        and all(c in _SCHEME_CHARS for c in text)
    )


def _parse_number(part: str) -> int | None:
    """One IPv4 part in the inet_aton syntax (decimal, 0x hex, 0 octal); None if invalid."""
    if not part:
        return None
    try:
        if part.startswith("0x"):
            digits = part[2:]
            if any(c not in _HEX for c in digits):
                return None
            return int(digits, 16) if digits else 0
        if len(part) > 1 and part.startswith("0"):
            if any(c not in "01234567" for c in part):
                return None
            return int(part, 8)
        if not part.isdigit() or not part.isascii():
            return None
        return int(part, 10)
    except ValueError:
        return None


def _ends_in_number(label: str) -> bool:
    if not label:
        return False
    if label.isascii() and label.isdigit():
        return True
    return label.startswith("0x") and all(c in _HEX for c in label[2:])


def _parse_ipv4(parts: list[str]) -> str | None:
    """inet_aton / WHATWG IPv4 parsing: 1-4 parts, the last one fills the remaining bytes."""
    if not 1 <= len(parts) <= 4:
        return None
    numbers: list[int] = []
    for part in parts:
        value = _parse_number(part)
        if value is None:
            return None
        numbers.append(value)
    *head, last = numbers
    if any(n > 255 for n in head):
        return None
    if last >= 256 ** (5 - len(numbers)):
        return None
    address = last
    for i, n in enumerate(head):
        address += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(address))


def _canon_name(host: str) -> tuple[str, HostKind] | None:
    """Canonical (name, kind) for a host without brackets/port/userinfo; None when invalid."""
    if host.endswith("."):
        host = host[:-1]
    if not host or "%" in host:
        return None
    if host.isascii():
        low = host.lower()
    else:
        if any(c in _IDNA_DEVIATIONS for c in host):
            return None
        try:
            low = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
        if low.endswith("."):
            low = low[:-1]
    if not low or len(low) > _MAX_NAME:
        return None
    labels = low.split(".")
    for label in labels:
        if not label or len(label) > _MAX_LABEL or any(c not in _HOST_CHARS for c in label):
            return None
    if _ends_in_number(labels[-1]):
        ip4 = _parse_ipv4(labels)
        return None if ip4 is None else (ip4, "ip")
    if low == "localhost" or low.endswith(".localhost"):
        return low, "localhost"
    return low, "domain"


def _canon_ipv6(text: str) -> str | None:
    zone = ""
    if "%" in text:
        text, _, zone = text.partition("%")
        if not zone or len(zone) > 64 or any(c in "[]/\\" or c <= " " or c == "\x7f" for c in zone):
            return None
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None
    mapped = address.ipv4_mapped
    return str(mapped) if mapped is not None else str(address)


def _valid_port(port: str) -> bool:
    return port == "" or (
        port.isascii() and port.isdigit() and len(port) <= 5 and int(port) <= 65535
    )


def _parse_authority(authority: str, raw: str, *, scheme: str) -> Host | None:
    """Canonical host of ``[userinfo@]host[:port]``; ``scheme == ""`` allows the scp-like form."""
    if not authority:
        return None if scheme in ("", "file") else _unknown(raw)
    if any(c <= " " or c == "\x7f" for c in authority):
        return _unknown(raw)
    if authority.count("@") > 1:
        return _unknown(raw)  # clients disagree on which "@" ends the userinfo
    first_at = authority.find("@")
    if not scheme and first_at > 0 and ":" in authority[:first_at]:
        # "evil.com:x@github.com": scp / rsync read HOST:PATH, curl / ssh read USER:PASS@HOST.
        return _unknown(raw)
    at = authority.rfind("@")
    hostport = authority[at + 1 :] if at >= 0 else authority
    if not hostport:
        return _unknown(raw)
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            return _unknown(raw)
        after = hostport[end + 1 :]
        if after and not (after.startswith(":") and _valid_port(after[1:])):
            return _unknown(raw)
        ip6 = _canon_ipv6(hostport[1:end])
        return _unknown(raw) if ip6 is None else Host(ip6, "ip", raw[:512])
    colons = hostport.count(":")
    if colons >= 2:
        # Only a bare (scheme-less, port-less) IPv6 address may contain several colons.
        ip6 = _canon_ipv6(hostport) if not scheme else None
        return _unknown(raw) if ip6 is None else Host(ip6, "ip", raw[:512])
    host = hostport
    if colons == 1:
        host, _, port = hostport.partition(":")
        if not _valid_port(port) and scheme:
            return _unknown(raw)
        # scheme-less "host:path" is the scp-like form: the part after ':' is a path, not a port.
        if not host:
            return _unknown(raw)
    canon = _canon_name(host)
    if canon is None:
        return _unknown(raw)
    return Host(canon[0], canon[1], raw[:512])


def _authority_of(rest: str) -> tuple[str, bool]:
    """Cut the authority off ``rest``; the flag is True when a backslash ended it (ambiguous)."""
    for i, c in enumerate(rest):
        if c in _AUTH_END:
            return rest[:i], c == "\\"
    return rest, False


def _canonical_host(raw: str) -> Host | None:
    text = raw.strip()
    if not text:
        return None
    if len(text) > _MAX_HOST_INPUT:
        return _unknown(raw)
    scheme = ""
    rest = text
    sep = text.find("://")
    if sep > 0 and _is_scheme(text[:sep]):
        scheme = text[:sep].lower()
        rest = text[sep + 3 :]
    elif text.startswith("//"):
        rest = text[2:]
    authority, backslash = _authority_of(rest)
    if backslash:
        # "http://github.com\@evil.com": WHATWG clients read a path separator, others userinfo.
        return _unknown(raw)
    return _parse_authority(authority, raw, scheme=scheme)


def canonical_host(raw: str) -> Host | None:
    """Canonical host of a URL, ``host[:port]``, ``user@host``, scp-like ``user@host:path``, or IP.

    Returns None only when ``raw`` contains no host at all (empty, or a ``file:`` URL); anything
    malformed or ambiguous between clients is ``Host(kind="unknown")`` so it never matches an
    allowlist. Never raises; inputs over 2048 characters are ``unknown``.
    """
    try:
        return _canonical_host(raw)
    except Exception:  # noqa: BLE001 - a host parser that raises would fail the gate open
        return _unknown(raw if isinstance(raw, str) else "")


def _scheme_start(text: str, sep: int) -> int:
    """Index where the scheme in front of ``text[sep:sep+3] == '://'`` starts (sep if none)."""
    j = sep
    while j > 0 and text[j - 1] in _SCHEME_CHARS:
        j -= 1
    while j < sep and not (text[j].isascii() and text[j].isalpha()):
        j += 1
    return j


def _scp_candidate(token: str) -> bool:
    """True for ``user@host:path`` shaped tokens (no '://', one '@' before the first ':')."""
    at = token.find("@")
    if at <= 0 or "://" in token:
        return False
    head = token[:at]
    if "/" in head or ":" in head or "\\" in head:
        return False
    rest = token[at + 1 :]
    if rest.startswith("["):
        end = rest.find("]")
        return end > 0 and rest[end + 1 : end + 2] == ":"
    colon = rest.find(":")
    return colon > 0 and "/" not in rest[:colon]


def _extract(text: str) -> list[Host]:
    found: list[Host] = []
    idx = 0
    while True:
        sep = text.find("://", idx)
        if sep < 0:
            break
        idx = sep + 3
        start = _scheme_start(text, sep)
        if start == sep:
            continue
        scheme = text[start:sep].lower()
        end = idx
        while end < len(text) and text[end] not in _AUTH_END and text[end] != " ":
            end += 1
        authority = text[idx:end]
        backslash = end < len(text) and text[end] == "\\"
        while authority and authority[-1] in _TRAILING_PUNCT:
            authority = authority[:-1]
        raw = text[start:end]
        if backslash:
            found.append(_unknown(raw))
            continue
        host = _parse_authority(authority, raw, scheme=scheme)
        if host is not None:
            found.append(host)
    for token in text.split():
        if _scp_candidate(token):
            host = _canonical_host(token.strip("'\"`,;()<>"))
            if host is not None:
                found.append(host)
    return found


def extract_hosts(text: str) -> tuple[Host, ...]:
    """All hosts named in ``text``: every ``scheme://authority`` and scp-like ``user@host:path``.

    Works on free text (a whole argument such as ``--data '{"u":"http://x.example"}'``). Duplicates
    are removed (first occurrence wins). Never raises. Text over 64 KiB is scanned only up to its
    last whitespace before the limit and an ``unknown`` marker host is appended; more than 64 hosts
    are cut with the same marker, so truncation is never silent.
    """
    try:
        marker: list[Host] = []
        if len(text) > _MAX_TEXT:
            head = text[:_MAX_TEXT]
            cut = max(head.rfind(" "), head.rfind("\n"), head.rfind("\t"))
            text = head[:cut] if cut > 0 else ""
            marker.append(_unknown("<text-too-long>"))
        seen: set[tuple[str, str]] = set()
        out: list[Host] = []
        for host in _extract(text):
            key = (host.name, host.kind)
            if key in seen:
                continue
            seen.add(key)
            out.append(host)
        if len(out) > _MAX_HOSTS:
            out = out[:_MAX_HOSTS]
            marker.append(_unknown("<too-many-hosts>"))
        return tuple(out + marker)
    except Exception:  # noqa: BLE001 - never raise; unknown never matches an allowlist
        return (_unknown("<error>"),)


def hosts_of(url_args: Sequence[str]) -> tuple[Host, ...]:
    """Hosts for ``CmdInfo.urls`` entries: each is a target itself and may embed more URLs.

    For every string: its own canonical host (``example.com/x``, ``user@host``, a URL) plus every
    URL embedded in it. Deduplicated, order kept, never raises.
    """
    out: list[Host] = []
    seen: set[tuple[str, str]] = set()
    for arg in url_args:
        candidates: list[Host] = []
        own = canonical_host(arg)
        if own is not None:
            candidates.append(own)
        candidates.extend(extract_hosts(arg))
        for host in candidates:
            key = (host.name, host.kind)
            if key not in seen:
                seen.add(key)
                out.append(host)
    return tuple(out)


@lru_cache(maxsize=512)
def _allowed_entry(entry: str) -> Host | None:
    """A trusted allowlist entry as a Host; None when it is not a plain domain or IP."""
    text = entry.strip()
    if not text or any(c in text for c in "/@?#\\%*") or text.startswith("."):
        return None
    host = canonical_host(text)
    if host is None or host.kind == "unknown":
        return None
    if ":" in text and host.kind != "ip" and not text.rsplit(":", 1)[1].isdigit():
        return None
    return host


def host_matches(host: Host, allowed: Sequence[str]) -> bool:
    """True when ``host`` equals an allowlist entry or is a true subdomain of a domain entry.

    ``api.github.com`` matches ``github.com``; ``evilgithub.com``, ``github.com.evil.com`` and
    ``notgithub.com`` do not (the match is on label boundaries). An IP entry only matches the same
    IP, and a domain entry never matches an IP. ``unknown`` hosts never match. Invalid entries
    (wildcards, URLs, empty) are skipped, which can only make the answer False. ``host.name`` is
    re-canonicalized, so a hand-built ``Host`` cannot smuggle in a non-canonical name. Never raises.
    """
    try:
        if host.kind == "unknown":
            return False
        probe = canonical_host(host.name)
        if probe is None or probe.kind == "unknown":
            return False
        for entry in allowed:
            allowed_host = _allowed_entry(entry)
            if allowed_host is None:
                continue
            if allowed_host.kind == "ip":
                if probe.kind == "ip" and probe.name == allowed_host.name:
                    return True
            elif probe.kind in ("domain", "localhost") and (
                probe.name == allowed_host.name or probe.name.endswith("." + allowed_host.name)
            ):
                return True
        return False
    except Exception:  # noqa: BLE001 - never raise; False is the safe answer
        return False
