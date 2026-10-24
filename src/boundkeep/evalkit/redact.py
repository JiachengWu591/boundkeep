"""Find (and remove) what must never be in a committed sample: secrets, personal paths, real hosts.

Two users: ``dataset.validate`` calls ``find_leaks`` on every sample (the test that keeps real data
out), and the session importer calls ``redact`` before anything is written to disk. Both share one
set of patterns, so what the importer removes is exactly what the validator would reject.

Everything is pure text in, text out; nothing touches the network or the disk.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

#: placeholder user names the fake machines and the samples use: they are not personal
FAKE_USERS = frozenset({"testuser", "user", "alice", "bob", "runner", "example", "you", "me"})

#: host names that point nowhere (RFC 2606 / 6761) or only at this machine
RESERVED_SUFFIXES = (".invalid", ".example", ".test", ".localhost")
RESERVED_HOSTS = frozenset(
    {"example.com", "example.org", "example.net", "localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{24,}")),
)
_WIN_HOME = re.compile(r"(?i)\b([A-Z]:[\\/]+Users[\\/]+)([^\\/\s\"'<>|:*?]+)")
_POSIX_HOME = re.compile(r"(?<![\w.-])(/(?:home|Users)/)([^/\s\"'<>|:*?]+)")
_URL_HOST = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?:[^/\s@\"']*@)?(\[[0-9a-f:]+\]|[^/\s:?#\"']+)")
_CJK = re.compile(r"[㐀-鿿]")


@dataclass(frozen=True)
class Leak:
    kind: str
    text: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.text!r}"


def is_reserved_host(host: str) -> bool:
    low = host.strip("[]").lower().rstrip(".")
    return low in RESERVED_HOSTS or low.endswith(RESERVED_SUFFIXES)


def _is_personal(name: str) -> bool:
    if name.lower() in FAKE_USERS or name.startswith(("%", "$", "<", "{")):
        return False
    if re.fullmatch(r"(?i)testus~\d", name):  # the 8.3 short name of "testuser"
        return False
    return not name.startswith("~")


def find_leaks(text: str, *, strict_hosts: bool = False) -> list[Leak]:
    """What in ``text`` looks like real data. ``strict_hosts``: any URL host that is not reserved
    is a leak (attack samples); off, only secrets and personal paths count (benign samples may
    mention github.com or pypi.org)."""
    found: list[Leak] = []
    for kind, pattern in _SECRET_PATTERNS:
        found.extend(Leak(kind, m.group(0)) for m in pattern.finditer(text))
    for pattern in (_WIN_HOME, _POSIX_HOME):
        found.extend(
            Leak("personal-path", m.group(0)) for m in pattern.finditer(text) if _is_personal(m[2])
        )
    if strict_hosts:
        found.extend(
            Leak("real-host", m.group(1))
            for m in _URL_HOST.finditer(text)
            if not is_reserved_host(m.group(1))
        )
    return found


def has_cjk(text: str) -> bool:
    return _CJK.search(text) is not None


def redact(text: str, *, extra_names: Iterable[str] = ()) -> str:
    """``text`` with secrets removed and personal paths turned into the fake machine's.

    ``extra_names``: user or machine names that appear outside a path (a Windows user name in a
    prompt, a host name); every occurrence becomes ``testuser``.
    """
    for kind, pattern in _SECRET_PATTERNS:
        text = pattern.sub(f"<REDACTED-{kind.upper()}>", text)
    text = _WIN_HOME.sub(lambda m: m[1] + ("testuser" if _is_personal(m[2]) else m[2]), text)
    text = _POSIX_HOME.sub(lambda m: m[1] + ("testuser" if _is_personal(m[2]) else m[2]), text)
    for name in extra_names:
        if name and name.lower() not in FAKE_USERS:
            text = re.sub(re.escape(name), "testuser", text, flags=re.IGNORECASE)
    return text
