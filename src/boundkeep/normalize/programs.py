"""Program knowledge: turn one parsed simple command into facts rules match on.

``classify(program, args, shell=..., redirects=...)`` answers, for ONE simple command: which program
and subcommand, which flags, which paths are touched and how (read / write / unknown), which URL or
host strings it contacts, whether it talks to the network, and which risk tags apply.

Design rules (docs/m1-design.md "底线"):

* Knowledge is DATA: option tables (``_opts``), per-program ``Spec`` rows and subcommand tables
  sit at the top of each section; the handlers below only interpret them.
* Never raises (any internal error becomes ``known=False`` plus a gray reason and all risk tags).
* Never infers safety. Unknown things are listed (paths as ``"unknown"``), over-listed rather than
  dropped; a ``gray`` reason is added only when the meaning of the command itself is unknowable
  (dynamic program name, a lone ``$X`` that may be an option, inline code, a script file whose
  contents decide what is written, ...).
* Words with ``expands`` or ``glob`` are never dropped: they stay in ``paths`` / ``urls`` and the
  path layer marks them uncertain.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from urllib.parse import unquote

from boundkeep.normalize.model import Access, Redirect, RiskTag, Shell, Word

__all__ = ["CmdInfo", "classify", "derive_risk_tags", "is_code_env"]

_ALL_TAGS: tuple[RiskTag, ...] = (
    "network_egress",
    "file_write",
    "exec",
    "secret_access",
    "config_tamper",
)


def _fs(text: str) -> frozenset[str]:
    """A frozenset of the whitespace-separated words of ``text`` (compact table rows)."""
    return frozenset(text.split())


@dataclass(frozen=True, slots=True)
class CmdInfo:
    """What one simple command does, as far as the knowledge tables can tell."""

    known: bool
    subcommand: str | None
    flags: tuple[str, ...]
    paths: tuple[tuple[Word, Access], ...]
    urls: tuple[str, ...]
    network: bool
    tags: tuple[RiskTag, ...]
    gray: tuple[str, ...]


# ---------------------------------------------------------------------------------------------
# Risk tags: the ONE place where tags are derived.
# ---------------------------------------------------------------------------------------------

_EXEC_PROGRAMS = _fs(
    "sh bash zsh dash ksh csh tcsh fish ash python python2 python3 pypy pypy3 node nodejs deno "
    "perl ruby php lua pwsh powershell cmd eval source . exec busybox su runuser chroot nsenter "
    "unshare watch script flock systemd-run at batch screen tmux parallel entr gdb strace ltrace "
    "xvfb-run setarch taskset valgrind perf cpulimit winpty start dbus-launch rlwrap torsocks "
    "runas faketime chrt proxychains proxychains4 tsocks unbuffer eatmydata firejail fakeroot "
    "prlimit setpriv"
)
_SECRET_DIRS = frozenset(
    {".ssh", ".aws", ".gnupg", ".azure", ".kube", ".password-store", ".gcloud", ".oci"}
)
_SECRET_BASENAMES = frozenset(
    {
        ".env",
        ".netrc",
        "_netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".pgpass",
        ".my.cnf",
        ".htpasswd",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "shadow",
        "gshadow",
        "sudoers",
        ".bash_history",
        ".zsh_history",
        "login data",
        "cookies",
        "logins.json",
        "key4.db",
        "cookies.sqlite",
        "secrets.yml",
        "secrets.yaml",
        "credentials.json",
        "service-account.json",
    }
)
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".jks", ".keystore", ".ppk")
_SECRET_PAIRS = frozenset(
    {
        (".config", "gcloud"),
        (".config", "gh"),
        (".docker", "config.json"),
        (".config", "git"),
        ("microsoft", "credentials"),
        ("microsoft", "protect"),
    }
)
_CONFIG_BASENAMES = frozenset(
    {
        ".claude.json",
        "claude.md",
        ".mcp.json",
        "managed-settings.json",
        "claude_desktop_config.json",
        ".gitconfig",
        ".gitmodules",
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".inputrc",
        "authorized_keys",
        "authorized_keys2",
        "sshd_config",
        "ssh_config",
        "known_hosts",
        "crontab",
        "microsoft.powershell_profile.ps1",
        "profile.ps1",
    }
)


def _path_parts(text: str) -> list[str]:
    return [p for p in text.replace("\\", "/").lower().split("/") if p not in ("", ".")]


def _is_secret_path(text: str) -> bool:
    """Obvious credential locations by name only (no filesystem, no variable expansion)."""
    parts = _path_parts(text)
    if not parts:
        return False
    base = parts[-1]
    if any(p in _SECRET_DIRS for p in parts):
        return True
    if base in _SECRET_BASENAMES or base.startswith(".env.") or base.endswith(_SECRET_SUFFIXES):
        return True
    if base == "credentials" and ".aws" in parts:
        return True
    if base == "environ" and "proc" in parts:
        return True
    return any(pair in _SECRET_PAIRS for pair in pairwise(parts))


def _is_config_path(text: str) -> bool:
    """Obvious agent / tool / shell configuration by name only."""
    parts = _path_parts(text)
    if not parts:
        return False
    base = parts[-1]
    if ".boundkeep" in parts or ".claude" in parts[:-1] or base == ".claude":
        return True
    if base in _CONFIG_BASENAMES:
        return True
    pairs = set(pairwise(parts))
    if (".git", "hooks") in pairs or (".git", "config") in pairs or (".git", "info") in pairs:
        return True
    if ".vscode" in parts[:-1] and base in ("settings.json", "tasks.json", "launch.json"):
        return True
    return ".ssh" in parts or ".husky" in parts[:-1] or (".github", "workflows") in pairs


def derive_risk_tags(
    *,
    program: str,
    subcommand: str | None,
    flags: Sequence[str],
    paths: Sequence[tuple[Word, Access]],
    network: bool,
    exec_hint: bool = False,
    write_hint: bool = False,
    secret_hint: bool = False,
) -> tuple[RiskTag, ...]:
    """Derive the risk tags of one command. THE single place tags are decided (audit here).

    Rules (a tag is only ever ADDED by these rules; tags never lower a verdict):

    * ``network_egress``: ``network`` is True (a known network program or subcommand, or any URL /
      host string was found in the arguments).
    * ``file_write``: some path has access ``write`` or ``unknown`` (unknown means "may write"), or
      the handler says the command writes without naming a path (``write_hint``: ``pip install``,
      ``git commit``, ...).
    * ``exec``: the program is an interpreter, shell, ``eval`` / ``source`` / ``.`` or a command
      launcher (``_EXEC_PROGRAMS``), or the handler saw an executes-code option or subcommand
      (``exec_hint``: ``find -exec``, ``git -c core.pager=``, ``npm run``, ``docker run``, ...).
    * ``secret_access``: any path (any access) names an obvious credential location by name:
      a ``.ssh`` / ``.aws`` / ``.gnupg`` / ``.kube`` / ... directory component, ``.env`` /
      ``.env.*``, ``.netrc``, ``.npmrc``, ``id_rsa``-style key files, ``*.pem`` / ``*.key`` /
      ``*.p12``, ``.git-credentials``, ``/etc/shadow``; or the handler says so (``secret_hint``:
      ``gh auth token``, ``git credential``).
    * ``config_tamper``: a path with access ``write`` or ``unknown`` names an agent / tool / shell
      configuration: ``.claude/**``, ``.claude.json``, ``CLAUDE.md``, ``.mcp.json``,
      ``.boundkeep/**``, ``.git/hooks`` and ``.git/config``, ``.gitconfig``, shell rc and profile
      files, ``authorized_keys``, ``.vscode/{settings,tasks,launch}.json``, ``.github/workflows``.

    Only obvious cases are recognised, lexically, on the text of the word (variables unresolved,
    symlinks not followed). The PATH-LEVEL POLICY RULES (``path_glob`` + ``access``, after the path
    layer's normalization) are the authority; tags exist for session-taint escalation and audit.
    """
    tags: list[RiskTag] = []
    if network:
        tags.append("network_egress")
    if write_hint or any(access in ("write", "unknown") for _, access in paths):
        tags.append("file_write")
    if exec_hint or program in _EXEC_PROGRAMS:
        tags.append("exec")
    if secret_hint or any(_is_secret_path(w.text) for w, _ in paths):
        tags.append("secret_access")
    if any(access != "read" and _is_config_path(w.text) for w, access in paths):
        tags.append("config_tamper")
    return tuple(tags)


# ---------------------------------------------------------------------------------------------
# Small word helpers
# ---------------------------------------------------------------------------------------------

_BENIGN_DEVICES = frozenset(
    {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero"}
)
_NET_DEVICES = ("/dev/tcp/", "/dev/udp/")
_SYSTEM_BIN_DIRS = frozenset(
    {
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/sbin",
        "/usr/sbin",
        "/usr/local/sbin",
        "/opt/homebrew/bin",
        "/snap/bin",
    }
)
_DYNAMIC_PROGRAM_CHARS = frozenset("$`*?[]{}\x00\n(;|&<>")
_VERSIONED = frozenset({"python", "pip", "pypy", "ruby", "perl", "php", "lua", "node"})


def _sub(w: Word, text: str) -> Word:
    """A word derived from ``w`` (same dynamic-ness), e.g. the value part of ``--out=VALUE``."""
    return Word(text, w.expands, w.glob, w.quoted)


def _drive(text: str) -> bool:
    return (
        len(text) >= 2
        and text[0].isascii()
        and text[0].isalpha()
        and text[1] == ":"
        and (len(text) == 2 or text[2] in "/\\")
    )


def _pathlike(text: str) -> bool:
    """Looks like a path: has a separator, starts with ``~`` or ``.``, or a drive letter."""
    return bool(text) and ("/" in text or "\\" in text or text[0] in "~." or _drive(text))


def _outside_like(text: str) -> bool:
    """Absolute, home, parent or dot-relative: where a non-path word could not plausibly be."""
    return bool(text) and (text[0] in "/\\~." or _drive(text))


def _scp_like(text: str) -> bool:
    at = text.find("@")
    if at <= 0 or "/" in text[:at]:
        return False
    colon = text.find(":", at)
    return colon > at and "/" not in text[:colon]


def _urllike(text: str) -> bool:
    return "://" in text or _scp_like(text)


def _canon_program(name: str) -> str:
    """``python3.12`` -> ``python``, ``pip3`` -> ``pip``; other names unchanged."""
    base = name.rstrip("0123456789.")
    if base != name and base in _VERSIONED:
        return base
    return name


# ---------------------------------------------------------------------------------------------
# Option tables
# ---------------------------------------------------------------------------------------------
# Roles of an option's value ("+" chains several values: "x+r" = a name then a file):
#   r / w / u   path read / write / unknown access        x    value that is not a path
#   url         host or URL (network)                      ru   read path, or URL when it has "://"
#   cmd         value is a command that gets executed      code inline source code (exec + gray)
#   at          curl "@file" reads a file                  form curl -F name=@file
#   durl        curl --data-urlencode forms                cookie curl -b file-or-string
#   cfg         config file whose contents we cannot see   resolve / connect  curl host overrides
#   vol / mount docker bind mounts                         jump ssh -J host list
#   sshopt      ssh -o Key=Value                           wgete wget -e wgetrc command
#   gF          gh api -F key=@file                        secret docker build --secret


@dataclass(frozen=True, slots=True)
class Opts:
    short: Mapping[str, str]  # letter -> role, the value is attached or the next word
    long: Mapping[str, str]  # "--name" -> role (value after "=" or the next word)
    long_flags: frozenset[str]  # value-less long options, only for unique-prefix resolution
    attached: Mapping[str, str]  # letter -> role, optional value that is ONLY attached (sed -i)


def _opts(short: str = "", long: str = "", flags: str = "", attached: str = "") -> Opts:
    def pairs(text: str, prefix: str = "") -> dict[str, str]:
        out: dict[str, str] = {}
        for item in text.split():
            name, _, role = item.partition("=")
            out[prefix + name] = role or "x"
        return out

    return Opts(
        short=pairs(short),
        long=pairs(long, "--"),
        long_flags=frozenset("--" + f for f in flags.split()),
        attached=pairs(attached),
    )


_NOOPTS = _opts()
_ROLE_ORDER = ("cmd", "w", "u", "r", "ru", "url", "x")


def _resolve_long(name: str, opts: Opts) -> tuple[list[str], str, str | None]:
    """(flags to report, canonical key, role) for a long option, resolving unique prefixes."""
    if name in opts.long:
        return [name], name, opts.long[name]
    if name in opts.long_flags:
        return [name], name, None
    cands = [k for k in (*opts.long, *opts.long_flags) if k.startswith(name)]
    if not cands:
        return [name], name, None
    roles = {opts.long.get(k) for k in cands}
    chosen: str | None = None
    for r in _ROLE_ORDER:
        if r in roles:
            chosen = r
            break
    key = cands[0] if len(cands) == 1 else name
    return [name, *cands], key, chosen


@dataclass(slots=True)
class _Scan:
    flags: list[str] = field(default_factory=list)
    values: list[tuple[str, str, Word]] = field(default_factory=list)
    pos: list[Word] = field(default_factory=list)
    dd_at: int = -1  # number of positionals before a "--" (-1: no "--")
    dynamic: bool = False  # a positional that is entirely an expansion (may be an option)
    stop: Word | None = None  # with stop_at_pos: the first positional
    rest: list[Word] = field(default_factory=list)  # with stop_at_pos: the words after it


def _scan(
    args: Sequence[Word],
    opts: Opts,
    *,
    single_dash_long: bool = False,
    stop_at_pos: bool = False,
) -> _Scan:
    """Split ``args`` into flags, option values and positionals (GNU style, options anywhere).

    Short groups report both spellings (``-rf`` -> ``-rf``, ``-r``, ``-f``); long options drop
    ``=value`` and unique prefixes are resolved (``--recurs`` also reports ``--recursive``);
    everything after ``--`` is positional.
    """
    sc = _Scan()
    n = len(args)
    i = 0
    after = False
    while i < n:
        w = args[i]
        t = w.text
        i += 1
        if after:
            sc.pos.append(w)
            continue
        if t == "--":
            after = True
            sc.dd_at = len(sc.pos)
            continue
        if len(t) > 2 and t.startswith("--") and not single_dash_long:
            name, eq, val = t.partition("=")
            names, key, role = _resolve_long(name, opts)
            sc.flags.extend(names)
            if w.expands and ("$" in name or "`" in name):
                sc.dynamic = True  # the option name itself is not known
            if role is None:
                if eq and _pathlike(val) and not _urllike(val):
                    sc.values.append((key, "u", _sub(w, val)))
                continue
            first = True
            for r in role.split("+"):
                if first and eq:
                    sc.values.append((key, r, _sub(w, val)))
                elif i < n:
                    sc.values.append((key, r, args[i]))
                    i += 1
                else:
                    break
                first = False
            continue
        if len(t) > 1 and t[0] == "-":
            if single_dash_long:
                sc.flags.append(t.partition("=")[0])
                continue
            body = t[1:]
            head = body.partition("=")[0]
            if w.expands and ("$" in head or "`" in head):
                sc.dynamic = True  # the flags themselves are not known
            if len(head) > 1:
                sc.flags.append("-" + head)
            j = 0
            while j < len(body):
                ch = body[j]
                if ch in opts.short:
                    sc.flags.append("-" + ch)
                    rest = body[j + 1 :]
                    first = True
                    for r in opts.short[ch].split("+"):
                        if first and rest:
                            sc.values.append(("-" + ch, r, _sub(w, rest)))
                            if rest.startswith("="):
                                sc.values.append(("-" + ch, r, _sub(w, rest[1:])))
                        elif i < n:
                            sc.values.append(("-" + ch, r, args[i]))
                            i += 1
                        else:
                            break
                        first = False
                    break
                if ch in opts.attached:
                    sc.flags.append("-" + ch)
                    rest = body[j + 1 :]
                    if rest:
                        sc.values.append(("-" + ch, opts.attached[ch], _sub(w, rest)))
                    break
                if ch == "=":
                    break
                if ch.isascii() and ch.isalnum():
                    sc.flags.append("-" + ch)
                    j += 1
                    continue
                rest = body[j:]
                if _pathlike(rest) and not _urllike(rest):
                    opt = "-" + body[j - 1] if j else "-"
                    sc.values.append((opt, "u", _sub(w, rest)))
                break
            continue
        if w.expands and t[:1] in ("$", "`") and "/" not in t and "\\" not in t:
            sc.dynamic = True
        if stop_at_pos:
            sc.stop = w
            sc.rest = list(args[i:])
            return sc
        sc.pos.append(w)
    return sc


# ---------------------------------------------------------------------------------------------
# Accumulator
# ---------------------------------------------------------------------------------------------


class _Acc:
    """Collects what the handlers find. Dedupes, never drops."""

    __slots__ = (
        "exec_hint",
        "flags",
        "gray",
        "known",
        "network",
        "paths",
        "prog",
        "secret_hint",
        "sub",
        "urls",
        "write_hint",
    )

    def __init__(self, prog: str) -> None:
        self.prog = prog
        self.flags: list[str] = []
        self.paths: list[tuple[Word, Access]] = []
        self.urls: list[str] = []
        self.gray: list[str] = []
        self.network = False
        self.known = True
        self.sub: str | None = None
        self.exec_hint = False
        self.write_hint = False
        self.secret_hint = False

    def path(self, w: Word, access: Access) -> None:
        t = w.text
        if t.startswith(_NET_DEVICES):
            # Bash opens a socket for /dev/tcp/HOST/PORT and /dev/udp/HOST/PORT: that is network
            # egress, not a file (the host goes to the domain check; the port is not needed).
            kind, _, rest = t[5:].partition("/")
            self.url(f"{kind}://{rest.partition('/')[0]}")
            return
        if not (w.expands or w.glob) and (t == "-" or t in _BENIGN_DEVICES):
            return
        self.paths.append((w, access))

    def url(self, text: str) -> None:
        self.urls.append(text)
        self.network = True

    def target(self, w: Word) -> None:
        """A URL-or-host word: ``file:`` URLs read a local path, everything else is a URL."""
        t = w.text
        if t[:5].lower() == "file:":
            rest = t[5:]
            if rest.startswith("//"):
                rest = rest[2:]
                if rest[:10].lower() == "localhost/":
                    rest = rest[9:]
                elif rest and rest[0] != "/":
                    rest = "//" + rest
            self.path(_sub(w, rest), "read")
            return
        self.url(t)

    def note_dynamic(self, sc: _Scan) -> None:
        if sc.dynamic:
            self.gray.append("dynamic-argument-may-be-option")


def _apply(a: _Acc, opt: str, role: str, w: Word) -> None:
    """Interpret one option value according to its role."""
    t = w.text
    if role == "r":
        a.path(w, "read")
    elif role == "w":
        a.path(w, "write")
    elif role == "u":
        a.path(w, "unknown")
    elif role == "url":
        a.target(w)
    elif role == "ru":
        if "://" in t:
            a.url(t)
        else:
            a.path(w, "read")
    elif role == "cmd":
        a.exec_hint = True
        a.gray.append(f"exec-option:{opt}")
    elif role == "at":
        if t.startswith("@"):
            a.path(_sub(w, t[1:]), "read")
    elif role == "form":
        value = t.partition("=")[2].strip("\"'")
        if value[:1] in ("@", "<"):
            a.path(_sub(w, value[1:].partition(";")[0].strip("\"'")), "read")
    elif role == "durl":
        if "=" not in t and "@" in t:
            a.path(_sub(w, t.partition("@")[2]), "read")
    elif role == "cvar":
        # curl --variable NAME=content | NAME@file (reads a file) | %NAME (an environment variable)
        at, eq = t.find("@"), t.find("=")
        if at >= 0 and (eq < 0 or at < eq):
            a.path(_sub(w, t[at + 1 :]), "read")
    elif role == "cookie":
        if "=" not in t:
            a.path(w, "read")
    elif role == "cfg":
        a.path(w, "read")
        a.gray.append(f"config-file:{opt}")
    elif role == "resolve":
        for part in t.split(","):
            fields = part.split(":")
            if len(fields) >= 3:
                a.url(fields[0].lstrip("+-"))
                a.url(":".join(fields[2:]).strip("[]"))
            else:
                a.url(part)
    elif role == "connect":
        fields = t.split(":")
        a.url(fields[0])
        if len(fields) >= 3:
            a.url(fields[2])
    elif role == "vol":
        _docker_volume(a, w)
    elif role == "mount":
        for part in t.split(","):
            key, _, value = part.partition("=")
            if key in ("source", "src") and _pathlike(value):
                a.path(_sub(w, value), "unknown")
    elif role == "jump":
        for part in t.split(","):
            a.url(part)
    elif role == "sshopt":
        _ssh_option(a, w)
    elif role == "wgete":
        _wget_execute(a, w)
    elif role == "gF":
        value = t.partition("=")[2]
        if value.startswith("@"):
            a.path(_sub(w, value[1:]), "read")
    elif role == "secret":
        for part in t.split(","):
            key, _, value = part.partition("=")
            if key in ("src", "source"):
                a.path(_sub(w, value), "read")
    elif role == "out" and ("=" not in t or "dest=" in t):
        dest = t.partition("dest=")[2].partition(",")[0] if "dest=" in t else t
        a.path(_sub(w, dest), "write")
    # role "x" (and anything unknown): the value is not a path


def _apply_values(a: _Acc, values: Sequence[tuple[str, str, Word]]) -> None:
    for opt, role, w in values:
        _apply(a, opt, role, w)


def _docker_volume(a: _Acc, w: Word) -> None:
    """``-v SRC[:DST[:OPTIONS]]``: a host path (a bind mount) the container can read AND write.

    Only an explicit ``ro`` option makes it read-only; otherwise the access is ``unknown``
    (may read,
    may write), exactly like ``--mount``: a rule that protects a path from reads must see it.
    """
    t = w.text
    if _drive(t[:3]) or (len(t) > 1 and t[1] == ":" and t[0].isalpha()):
        src = t[:2] + t[2:].split(":")[0]
        rest = t[len(src) :]
    else:
        src = t.split(":")[0]
        rest = t[len(src) :]
    if _outside_like(src) or w.expands or w.glob:
        fields = rest.split(":")  # ["", DST, OPTIONS...]
        options = fields[2].split(",") if len(fields) > 2 else []
        a.path(_sub(w, src), "read" if "ro" in [o.strip() for o in options] else "unknown")


_SSH_PATH_OPTS = frozenset(
    {
        "identityfile",
        "certificatefile",
        "userknownhostsfile",
        "globalknownhostsfile",
        "controlpath",
        "pkcs11provider",
        "securitykeyprovider",
        "include",
        "revokedhostkeys",
    }
)
_SSH_EXEC_OPTS = frozenset({"proxycommand", "localcommand", "knownhostscommand", "remotecommand"})


def _ssh_option(a: _Acc, w: Word) -> None:
    text = w.text
    key, sep, value = text.partition("=")
    if not sep:
        key, _, value = text.partition(" ")
    low = key.strip().lower()
    value = value.strip()
    if low in _SSH_EXEC_OPTS or "exec" in value.lower().split()[:1]:
        a.exec_hint = True
        a.gray.append(f"ssh-option-exec:{low}")
    elif low in ("proxyjump", "hostname"):
        for part in value.split(","):
            a.url(part)
    elif low in _SSH_PATH_OPTS:
        a.path(_sub(w, value), "read" if low in ("identityfile", "certificatefile") else "unknown")


_WGET_PROXY_KEYS = frozenset({"http_proxy", "https_proxy", "ftp_proxy"})
_WGET_HARMLESS_KEYS = frozenset({"use_proxy", "no_proxy", "robots", "timestamping", "verbose"})


def _wget_execute(a: _Acc, w: Word) -> None:
    key, _, value = w.text.partition("=")
    low = key.strip().lower()
    if low in _WGET_PROXY_KEYS:
        a.url(value.strip())
    elif low not in _WGET_HARMLESS_KEYS:
        a.gray.append(f"wget-execute:{low}")


# ---------------------------------------------------------------------------------------------
# Section 1: file reading / writing programs (generic table-driven handler)
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Spec:
    """How a file-oriented program treats its arguments."""

    opts: Opts = _NOOPTS
    access: Access = "read"  # access of the positional paths
    pos_access: tuple[Access, ...] = ()  # per position (the last repeats); overrides ``access``
    skip: int = 0  # leading positionals that are not paths (grep PATTERN, chmod MODE)
    no_skip_flags: frozenset[str] = frozenset()  # options that remove that leading positional
    flip_read: frozenset[str] = frozenset()  # flags that turn the positionals into reads
    cwd_default: frozenset[str] | None = None  # no path given: acts on "."; None never,
    #                                            empty set always, else only with these flags
    mode_letters: str = ""  # chmod: the real short options; any other letter means the MODE is
    #                         written like a flag ("chmod -x f") and no positional is skipped


_FILES: dict[str, Spec] = {}


def _reg(names: str, spec: Spec) -> None:
    for name in names.split():
        _FILES[name] = spec


# --- read programs
_reg("cat tac rev paste fold expand unexpand column readlink realpath lsattr getfacl namei", Spec())
_reg("nl pr", Spec(opts=_opts(short="b=x d=x f=x h=x i=x l=x n=x s=x v=x w=x")))
_reg(
    "less more most",
    Spec(
        opts=_opts(
            short="p=x P=x t=x T=x o=w O=w k=r x=x y=x z=x h=x j=x", long="log-file=w LOG-FILE=w"
        )
    ),
)
_reg(
    "head tail",
    Spec(
        opts=_opts(
            short="n=x c=x s=x",
            long="lines=x bytes=x pid=x sleep-interval=x max-unchanged-stats=x",
            flags="quiet silent verbose follow retry zero-terminated",
        )
    ),
)
_reg("wc", Spec(opts=_opts(long="files0-from=r", flags="bytes chars lines words max-line-length")))
_reg(
    "cut",
    Spec(
        opts=_opts(
            short="d=x f=x c=x b=x",
            long="delimiter=x fields=x characters=x bytes=x output-delimiter=x",
        )
    ),
)
_reg("join", Spec(opts=_opts(short="1=x 2=x j=x o=x t=x e=x a=x v=x", long="field=x")))
_reg("comm cmp", Spec(opts=_opts(short="i=x n=x s=x")))
_reg(
    "diff diff3 sdiff",
    Spec(
        opts=_opts(
            short="x=x X=r I=x L=x U=x C=x W=x D=x F=x S=x",
            long="exclude=x exclude-from=r ignore-matching-lines=x label=x from-file=r to-file=r "
            "starting-file=r width=x",
            flags="recursive unified brief new-file",
        )
    ),
)
_reg("file", Spec(opts=_opts(short="f=r m=r F=x e=x P=x", long="files-from=r magic-file=r")))
_reg("stat", Spec(opts=_opts(short="c=x", long="format=x printf=x")))
_reg(
    "ls dir vdir",
    Spec(
        opts=_opts(
            short="I=x w=x T=x",
            long="ignore=x width=x tabsize=x block-size=x time-style=x time=x sort=x format=x "
            "hide=x indicator-style=x quoting-style=x",
            flags="recursive all almost-all",
        ),
        cwd_default=frozenset(),
    ),
)
_reg(
    "tree",
    Spec(
        opts=_opts(
            short="L=x P=x I=x H=x T=x o=w",
            long="charset=x filelimit=x sort=x timefmt=x output=w",
        ),
        cwd_default=frozenset(),
    ),
)
_reg(
    "du df",
    Spec(
        opts=_opts(
            short="d=x B=x t=x X=r",
            long="max-depth=x block-size=x threshold=x exclude-from=r files0-from=r exclude=x",
        ),
        cwd_default=frozenset(),
    ),
)
_reg("xxd", Spec(opts=_opts(short="s=x l=x c=x g=x o=x n=x b=x"), pos_access=("read", "write")))
_reg(
    "od",
    Spec(
        opts=_opts(
            short="A=x j=x N=x t=x w=x S=x", long="skip-bytes=x read-bytes=x format=x width=x"
        )
    ),
)
_reg(
    "strings", Spec(opts=_opts(short="n=x t=x e=x T=x", long="bytes=x radix=x encoding=x target=x"))
)
_reg("hexdump hd", Spec(opts=_opts(short="n=x s=x e=x f=r L=x")))
_reg("base64 base32", Spec(opts=_opts(short="w=x", long="wrap=x")))
_reg("md5sum sha1sum sha224sum sha256sum sha384sum sha512sum b2sum cksum sum", Spec())
_reg(
    "bat batcat",
    Spec(opts=_opts(short="l=x r=x H=x m=x", long="language=x theme=x style=x line-range=x")),
)
_reg(
    "jq",
    Spec(
        opts=_opts(
            short="f=r L=x",
            long="from-file=r arg=x+x argjson=x+x slurpfile=x+r rawfile=x+r indent=x tab=x",
        ),
        skip=1,
        no_skip_flags=_fs("-f --from-file"),
    ),
)
_reg("yq xmllint", Spec())

# --- searchers: the first positional is the pattern unless -e / -f gave it
_GREP_OPTS = _opts(
    short="e=x f=r m=x A=x B=x C=x d=x D=x",
    long="regexp=x file=r max-count=x after-context=x before-context=x context=x include=x "
    "exclude=x exclude-dir=x exclude-from=r label=x binary-files=x directories=x devices=x",
    flags="recursive dereference-recursive count ignore-case invert-match line-number "
    "files-with-matches files-without-match only-matching quiet silent no-messages with-filename "
    "no-filename word-regexp line-regexp null text extended-regexp fixed-strings basic-regexp "
    "perl-regexp initial-tab null-data byte-offset",
)
_REC = _fs("-r -R --recursive --dereference-recursive")
_reg(
    "grep egrep fgrep zgrep",
    Spec(opts=_GREP_OPTS, skip=1, no_skip_flags=_fs("-e -f --regexp --file"), cwd_default=_REC),
)
_reg(
    "rg",
    Spec(
        opts=_opts(
            short="e=x f=r g=x t=x T=x A=x B=x C=x m=x j=x M=x r=x E=x d=x",
            long="regexp=x file=r glob=x iglob=x type=x type-not=x type-add=x type-clear=x "
            "max-count=x max-depth=x maxdepth=x threads=x replace=x sort=x sortr=x ignore-file=r "
            "pre=cmd pre-glob=x hostname-bin=cmd after-context=x before-context=x context=x "
            "encoding=x max-columns=x max-filesize=x path-separator=x color=x colors=x "
            "context-separator=x field-context-separator=x field-match-separator=x "
            "dfa-size-limit=x regex-size-limit=x engine=x",
            flags="files type-list null",
        ),
        skip=1,
        no_skip_flags=_fs("-e -f --regexp --file --files --type-list"),
        cwd_default=frozenset(),
    ),
)
_reg(
    "ag ack",
    Spec(
        opts=_opts(
            short="A=x B=x C=x G=x g=x m=x",
            long="ignore=x depth=x file-search-regex=x pager=cmd path-to-ignore=r workers=x "
            "after=x before=x context=x max-count=x",
        ),
        skip=1,
        no_skip_flags=_fs("-g -f"),
        cwd_default=frozenset(),
    ),
)

# --- write programs
_reg(
    "rm",
    Spec(
        opts=_opts(
            short="",
            flags="recursive force no-preserve-root preserve-root dir interactive "
            "one-file-system verbose",
        ),
        access="write",
    ),
)
_reg(
    "rmdir unlink shred",
    Spec(opts=_opts(short="n=x s=x", long="iterations=x size=x"), access="write"),
)
_reg(
    "touch",
    Spec(opts=_opts(short="r=r d=x t=x", long="reference=r date=x time=x"), access="write"),
)
_reg("mkdir", Spec(opts=_opts(short="m=x Z=x", long="mode=x context=x"), access="write"))
_reg("tee", Spec(opts=_opts(long="output-error=x"), access="write"))
_reg(
    "truncate",
    Spec(opts=_opts(short="s=x r=r", long="size=x reference=r"), access="write"),
)
_reg(
    "mkfifo mknod fallocate",
    Spec(opts=_opts(short="m=x l=x o=x", long="mode=x length=x offset=x"), access="write"),
)
_reg(
    "mktemp",
    Spec(opts=_opts(short="p=w", long="tmpdir=w suffix=x"), access="write"),
)
_reg(
    "chmod chown chgrp setfacl chattr",
    Spec(
        opts=_opts(
            short="", long="reference=r from=x", flags="recursive changes silent quiet verbose"
        ),
        access="write",
        skip=1,
        no_skip_flags=_fs("--reference"),
        mode_letters="cfvRhHLP",
    ),
)
_reg(
    "sponge",
    Spec(access="write"),
)
_reg(
    "uniq",
    Spec(
        opts=_opts(short="f=x s=x w=x", long="skip-fields=x skip-chars=x check-chars=x"),
        pos_access=("read", "write"),
    ),
)
_reg(
    "split",
    Spec(
        opts=_opts(
            short="a=x b=x l=x n=x C=x t=x", long="suffix-length=x bytes=x lines=x number=x"
        ),
        pos_access=("read", "write"),
    ),
)
_reg(
    "sort",
    Spec(
        opts=_opts(
            short="o=w T=w t=x k=x S=x",
            long="output=w temporary-directory=w files0-from=r field-separator=x key=x "
            "buffer-size=x compress-program=cmd parallel=x batch-size=x random-source=r",
        ),
    ),
)
_reg(
    "gzip gunzip bzip2 bunzip2 xz unxz zstd unzstd lz4 compress uncompress lzma unlzma",
    Spec(
        opts=_opts(short="S=x b=x", long="suffix=x"),
        access="write",
        flip_read=_fs("-c --stdout --to-stdout -l --list -t --test"),
    ),
)
_reg("zcat bzcat xzcat zstdcat lz4cat zless zmore", Spec())
_reg(
    "vi vim nvim view nano pico emacs ed ex code subl gedit notepad micro vimdiff rvim rview gvim",
    Spec(opts=_opts(short="c=x u=x S=x s=x w=w W=w", long="cmd=x"), access="unknown"),
)
_EDITORS_WITH_COMMANDS = _fs("vi vim nvim view ex vimdiff rvim rview gvim emacs")


def _h_files(a: _Acc, args: Sequence[Word], spec: Spec) -> None:
    sc = _scan(args, spec.opts)
    a.flags.extend(sc.flags)
    _apply_values(a, sc.values)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    seen.update(opt for opt, _, _ in sc.values)
    skip = 0 if seen & spec.no_skip_flags else spec.skip
    if spec.mode_letters and any(
        len(f) == 2 and f[1].isalpha() and f[1] not in spec.mode_letters for f in sc.flags
    ):
        skip = 0
    mode: Access = spec.access
    if seen & spec.flip_read:
        mode = "read"
    listed = 0
    for idx, w in enumerate(sc.pos[skip:]):
        access = spec.pos_access[min(idx, len(spec.pos_access) - 1)] if spec.pos_access else mode
        a.path(w, access)
        listed += 1
    if (
        listed == 0
        and spec.cwd_default is not None
        and (not spec.cwd_default or seen & spec.cwd_default)
    ):
        a.path(Word("."), mode)


# ---------------------------------------------------------------------------------------------
# Section 2: programs with their own argument grammar
# ---------------------------------------------------------------------------------------------

_NO_PATH_PROGRAMS = _fs(
    "echo printf true false pwd date sleep whoami id uname hostname basename dirname seq yes tr "
    "expr test [ printenv export unset set read alias unalias type which whereis hash wait exit "
    "return : local declare typeset readonly shift umask ulimit jobs fg bg kill pkill pgrep ps "
    "top htop free uptime nproc arch getconf locale tty clear reset history help man info "
    "nice nohup time command builtin getopts let"
)


def _h_nopath(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _NOOPTS)
    a.flags.extend(sc.flags)


def _h_cd(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _NOOPTS)
    a.flags.extend(sc.flags)
    for w in sc.pos[:1]:
        if w.text != "-":
            a.path(w, "read")


# --- writes INTO a directory: the directory hides the written file names --------------------------
#
# ``cp x .claude/`` writes ``.claude/x``; a rule on ``**/.claude/settings*.json`` can only see that
# if the name is spelled out. So wherever a program drops files into a directory, the handlers list
# the directory itself AND one synthetic path ``DIR/NAME`` (access ``write``) per file name they can
# work out. When the names cannot be known (glob / variable sources, archive members, recursive
# copies, ``-J`` / Content-Disposition) the action is gray with ``directory-write`` or
# ``archive-members-unknown``: the directory is listed, but what lands in it is not understood.

_NAME_UNSAFE = frozenset("$`*?[]{}()\x00\n")
_NO_NAME = frozenset({"", ".", "..", "~", "-"})


def _is_dirlike(w: Word) -> bool:
    """A destination that is certainly a directory by spelling (``d/``, ``.``, ``..``, ``~``)."""
    t = w.text
    return t in (".", "..", "~") or t.endswith(("/", "\\", "/.", "\\.", "/..", "\\.."))


def _child_names(text: str) -> tuple[str, ...] | None:
    """File names ``text`` gets when copied into a directory; None when they cannot be known.

    Both separator styles are tried (``\\`` may be a separator on Windows); a name with a glob or
    expansion character, an empty name, ``.``, ``..`` and ``~`` are unknowable.
    """
    t = text.rstrip("/\\")
    names = dict.fromkeys((t.rsplit("/", 1)[-1], t.replace("\\", "/").rsplit("/", 1)[-1]))
    for name in names:
        if name in _NO_NAME or any(c in _NAME_UNSAFE for c in name):
            return None
    return tuple(names)


def _join_child(directory: Word, name: str) -> Word | None:
    """``DIR/NAME`` as a word that is as dynamic as DIR is (the name itself is a clean literal)."""
    base = directory.text.rstrip("/\\")
    if not directory.text or directory.text.startswith(_NET_DEVICES):
        return None
    return Word(f"{base}/{name}", directory.expands, directory.glob, directory.quoted)


def _write_children(
    a: _Acc, directory: Word, names: Sequence[tuple[str, ...] | None], *, gray: bool = True
) -> None:
    """List ``DIR/NAME`` for every known name; gray ``directory-write`` for an unknown one."""
    unknown = False
    for group in names:
        if group is None:
            unknown = True
            continue
        for name in group:
            child = _join_child(directory, name)
            if child is not None:
                a.path(child, "write")
    if unknown and gray:
        a.gray.append("directory-write")


_TRANSFER_OPTS = _opts(
    short="t=w S=x",
    long="target-directory=w suffix=x preserve=x sparse=x reflink=x backup=x strip-program=cmd "
    "context=x",
    flags="recursive force archive no-clobber update verbose parents link symbolic-link "
    "no-target-directory dereference interactive no-preserve",
)


_INSTALL_OPTS = _opts(
    short="t=w S=x m=x o=x g=x",
    long="target-directory=w suffix=x mode=x owner=x group=x strip-program=cmd",
)


def _h_transfer(a: _Acc, args: Sequence[Word]) -> None:
    """cp / mv / install / ln: sources, destination, ``-t DIR``, ``-T``."""
    prog = a.prog
    sc = _scan(args, _INSTALL_OPTS if prog == "install" else _TRANSFER_OPTS)
    a.flags.extend(sc.flags)
    _apply_values(a, sc.values)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    pos = sc.pos
    if prog == "install" and "-d" in seen:
        for w in pos:
            a.path(w, "write")
        return
    src_access: Access = "write" if prog == "mv" else "read"
    if prog == "ln":
        src_access = "read"
    parents = "--parents" in seen
    recursive = prog == "cp" and bool(seen & _fs("-r -R -a --recursive --archive"))
    if recursive:
        a.gray.append("directory-write")  # a copied directory brings members we cannot see
    tdirs = [w for opt, _, w in sc.values if opt in ("-t", "--target-directory")]
    if tdirs:
        for w in pos:
            a.path(w, src_access)
        for d in tdirs:
            _copy_into(a, d, pos, dirlike=True, parents=parents)
        return
    if not pos:
        return
    if len(pos) == 1:
        a.path(pos[0], src_access)
        if prog == "ln":
            a.path(Word("."), "write")
            _copy_into(a, Word("."), pos, dirlike=False, parents=False)
        return
    for w in pos[:-1]:
        a.path(w, src_access)
    dest = pos[-1]
    a.path(dest, "write")
    if "-T" not in seen and "--no-target-directory" not in seen:
        # the destination may be an existing directory whatever its spelling (``cp x .claude``)
        _copy_into(a, dest, pos[:-1], dirlike=_is_dirlike(dest), parents=parents)


def _copy_into(
    a: _Acc, directory: Word, sources: Sequence[Word], *, dirlike: bool, parents: bool
) -> None:
    """List ``DIR/<name of each source>`` as written (and, with ``--parents``, ``DIR/<source>``)."""
    _write_children(a, directory, [_child_names(s.text) for s in sources], gray=dirlike)
    if parents:
        for s in sources:
            rel = s.text.lstrip("/\\")
            if rel and not any(c in _NAME_UNSAFE for c in rel):
                child = _join_child(directory, rel)
                if child is not None:
                    a.path(child, "write")


def _h_dd(a: _Acc, args: Sequence[Word]) -> None:
    for w in args:
        t = w.text
        key, eq, val = t.partition("=")
        if eq and key == "if":
            a.path(_sub(w, val), "read")
        elif eq and key == "of":
            a.path(_sub(w, val), "write")
        elif eq:
            if w.expands and ("$" in key or "`" in key):
                a.gray.append("dd-dynamic-operand")
        elif t.startswith("-"):
            a.flags.append(t.partition("=")[0])
        elif w.expands or w.glob:
            a.gray.append("dd-dynamic-operand")
        else:
            a.gray.append("dd-unknown-operand")


def _h_source(a: _Acc, args: Sequence[Word]) -> None:
    a.exec_hint = True
    sc = _scan(args, _NOOPTS)
    a.flags.extend(sc.flags)
    for w in sc.pos[:1]:
        a.path(w, "read")
    for w in sc.pos[1:]:
        _generic_arg(a, w)


def _h_eval(a: _Acc, args: Sequence[Word]) -> None:
    a.exec_hint = True
    a.gray.append("eval")
    for w in args:
        _generic_arg(a, w)


# --- sed ---------------------------------------------------------------------------------------

_SED_OPTS = _opts(
    short="e=sed f=r l=x",
    long="expression=sed file=r line-length=x",
    flags="in-place quiet silent regexp-extended null-data separate unbuffered debug sandbox "
    "posix follow-symlinks binary",
    attached="i=x",
)


def _sed_read_until(s: str, i: int, delim: str, *, brackets: bool) -> int:
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if brackets and c == "[":
            j = i + 1
            if j < n and s[j] == "^":
                j += 1
            if j < n and s[j] == "]":
                j += 1
            while j < n and s[j] != "]":
                if s[j] == "[" and j + 1 < n and s[j + 1] in ":.=":
                    close = s.find(s[j + 1] + "]", j + 2)
                    if close < 0:
                        return -1
                    j = close + 2
                    continue
                j += 1
            if j >= n:
                return -1
            i = j + 1
            continue
        if c == delim:
            return i
        i += 1
    return -1


def _sed_regex_end(s: str, i: int, delim: str) -> int:
    """End of a regex part; -1 when bracket handling would change where it ends (ambiguous)."""
    plain = _sed_read_until(s, i, delim, brackets=False)
    smart = _sed_read_until(s, i, delim, brackets=True)
    return plain if plain == smart else -1


def _sed_scan(s: str) -> tuple[list[str], list[str], bool, bool]:
    """(files written, files read, executes commands, parsed ok) for a sed script."""
    writes: list[str] = []
    reads: list[str] = []
    run = False
    n = len(s)
    i = 0

    def eol(j: int) -> int:
        k = s.find("\n", j)
        return n if k < 0 else k

    while i < n:
        c = s[i]
        if c in " \t\n;{}":
            i += 1
            continue
        if c == "#":
            i = eol(i)
            continue
        # up to two addresses
        for _ in range(2):
            if i < n and s[i].isdigit():
                while i < n and s[i].isdigit():
                    i += 1
                if i < n and s[i] == "~":
                    i += 1
                    while i < n and s[i].isdigit():
                        i += 1
            elif i < n and s[i] == "$":
                i += 1
            elif i < n and s[i] in "/\\":
                if s[i] == "\\":
                    if i + 1 >= n:
                        return writes, reads, run, False
                    delim = s[i + 1]
                    i += 2
                else:
                    delim = "/"
                    i += 1
                end = _sed_regex_end(s, i, delim)
                if end < 0:
                    return writes, reads, run, False
                i = end + 1
                while i < n and s[i] in "IM":
                    i += 1
            else:
                break
            if i < n and s[i] == ",":
                i += 1
                if i < n and s[i] in "+~":
                    i += 1
                continue
            break
        while i < n and s[i] in " \t!":
            i += 1
        if i >= n:
            return writes, reads, run, False
        c = s[i]
        i += 1
        if c == "s":
            if i >= n or s[i] in "\n\\":
                return writes, reads, run, False
            delim = s[i]
            end = _sed_regex_end(s, i + 1, delim)
            if end < 0:
                return writes, reads, run, False
            end2 = _sed_read_until(s, end + 1, delim, brackets=False)
            if end2 < 0:
                return writes, reads, run, False
            i = end2 + 1
            while i < n and s[i] in "gpiImMe0123456789":
                if s[i] == "e":
                    run = True
                i += 1
            if i < n and s[i] == "w":
                writes.append(s[i + 1 : eol(i)].strip())
                i = eol(i)
            elif i < n and s[i] not in " \t\n;}#":
                return writes, reads, run, False
        elif c == "y":
            if i >= n or s[i] in "\n\\":
                return writes, reads, run, False
            delim = s[i]
            end = _sed_read_until(s, i + 1, delim, brackets=False)
            end2 = -1 if end < 0 else _sed_read_until(s, end + 1, delim, brackets=False)
            if end2 < 0:
                return writes, reads, run, False
            i = end2 + 1
        elif c in "wW":
            writes.append(s[i : eol(i)].strip())
            i = eol(i)
        elif c in "rR":
            reads.append(s[i : eol(i)].strip())
            i = eol(i)
        elif c == "e":
            run = True
            i = eol(i)
        elif c in "aic":
            j = i
            while True:
                k = eol(j)
                if 0 < k < n and s[k - 1] == "\\":
                    j = k + 1
                    continue
                break
            i = k
        elif c in "btT:":
            while i < n and s[i] in " \t":
                i += 1
            while i < n and s[i] not in " \t\n;}":
                i += 1
        elif c in "lLqQ":
            while i < n and s[i] in " \t":
                i += 1
            while i < n and s[i].isdigit():
                i += 1
        elif c == "v":
            while i < n and s[i] not in "\n;":
                i += 1
        elif c in "=dDgGhHnNpPxzF{":
            continue
        else:
            return writes, reads, run, False
    return writes, reads, run, True


def _h_sed(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _SED_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    in_place = "-i" in seen or "--in-place" in seen
    has_script_opt = bool(seen & {"-e", "--expression", "-f", "--file"})
    scripts: list[Word] = []
    for opt, role, w in sc.values:
        if role == "sed":
            scripts.append(w)
        else:
            _apply(a, opt, role, w)
    pos = list(sc.pos)
    if not has_script_opt and pos:
        scripts.append(pos.pop(0))
    if ("-f" in seen or "--file" in seen) and "--sandbox" not in seen:
        a.gray.append("sed-script-file")
    if "--sandbox" not in seen:
        for sw in scripts:
            if sw.expands or sw.glob:
                a.gray.append("sed-script-dynamic")
                continue
            writes, reads, run, ok = _sed_scan(sw.text)
            if not ok:
                a.gray.append("sed-script-unparsed")
            for p in writes:
                a.path(_sub(sw, p), "write")
            for p in reads:
                a.path(_sub(sw, p), "read")
            if run:
                a.exec_hint = True
                a.gray.append("sed-exec")
    access: Access = "write" if in_place else "read"
    # BSD "sed -i '' script file": the script is listed as a file too (over-listing, never less)
    for w in pos:
        a.path(w, access)


# --- awk ---------------------------------------------------------------------------------------

_AWK_OPTS = _opts(
    short="F=x v=x f=r i=x e=awk E=r l=x W=x",
    long="field-separator=x assign=x file=r include=x source=awk exec=r load=x",
    flags="posix traditional re-interval sandbox",
)


def _awk_risks(text: str) -> tuple[list[str], bool]:
    reasons: list[str] = []
    run = False
    if "system" in text:
        reasons.append("awk-system")
        run = True
    if "|" in text:
        reasons.append("awk-pipe")
        run = True
    if "getline" in text:
        reasons.append("awk-getline")
    if "print" in text and ">" in text:
        reasons.append("awk-redirect-possible")
    if "@include" in text or "@load" in text:
        reasons.append("awk-include")
    return reasons, run


def _h_awk(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _AWK_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    inplace = False
    programs: list[Word] = []
    for opt, role, w in sc.values:
        if role == "awk":
            programs.append(w)
        else:
            _apply(a, opt, role, w)
            if opt in ("-i", "--include") and "inplace" in w.text:
                inplace = True
    pos = list(sc.pos)
    has_prog_opt = bool(seen & {"-f", "--file", "-e", "--source", "-E", "--exec"})
    if not has_prog_opt and pos:
        programs.append(pos.pop(0))
    if seen & {"-f", "--file", "-E", "--exec"}:
        a.gray.append("awk-program-file")
    for pw in programs:
        if pw.expands or pw.glob:
            a.gray.append("awk-program-dynamic")
            continue
        reasons, run = _awk_risks(pw.text)
        a.gray.extend(reasons)
        a.exec_hint = a.exec_hint or run
    for w in pos:
        a.path(w, "write" if inplace else "read")


# --- find --------------------------------------------------------------------------------------

_FIND_VALUE_PRIMARIES = _fs(
    "-name -iname -path -ipath -wholename -iwholename -regex -iregex -lname -ilname -type -xtype "
    "-perm -user -group -uid -gid -size -mtime -atime -ctime -mmin -amin -cmin -maxdepth "
    "-mindepth -printf -fstype -links -inum -context -used -newer -anewer -cnewer -samefile "
    "-fprint -fprint0 -fprintf -fls"
)
_FIND_WRITE_PRIMARIES = _fs("-fprint -fprint0 -fprintf -fls")
_FIND_READ_PRIMARIES = _fs("-newer -anewer -cnewer -samefile")
_FIND_EXEC = _fs("-exec -execdir -ok -okdir")


def _h_find(a: _Acc, args: Sequence[Word]) -> None:
    i = 0
    n = len(args)
    starts: list[Word] = []
    while i < n and args[i].text in ("-H", "-L", "-P", "-E", "-X", "-x", "-s", "-d"):
        a.flags.append(args[i].text)
        i += 1
    if i < n and args[i].text == "-D" and i + 1 < n:
        a.flags.append("-D")
        i += 2
    while i < n and args[i].text[:1] != "-" and args[i].text not in ("(", ")", "!", ",", "\\("):
        starts.append(args[i])
        i += 1
    delete = False
    while i < n:
        w = args[i]
        t = w.text
        i += 1
        if t.startswith("-") and len(t) > 1:
            a.flags.append(t)
            if t == "-delete":
                delete = True
            if t in _FIND_EXEC:
                a.exec_hint = True
                a.gray.append(f"find-{t[1:]}")
                while i < n and args[i].text not in (";", "+", "\\;"):
                    i += 1
                i += 1
            elif t in _FIND_VALUE_PRIMARIES or (t.startswith("-newer") and len(t) == 8):
                if i < n:
                    if t in _FIND_WRITE_PRIMARIES:
                        a.path(args[i], "write")
                    elif t in _FIND_READ_PRIMARIES or t.startswith("-newer"):
                        a.path(args[i], "read")
                    i += 1
        elif w.expands and t[:1] in ("$", "`"):
            a.gray.append("dynamic-argument-may-be-option")
    access: Access = "write" if delete else "read"
    if starts:
        for w in starts:
            a.path(w, access)
    else:
        a.path(Word("."), access)


# --- tar / zip / unzip --------------------------------------------------------------------------

_TAR_OPTS = _opts(
    short="f=tarf C=tarC T=r X=r I=cmd F=cmd g=r K=x N=x b=x L=x V=x H=x",
    long="file=tarf directory=tarC files-from=r exclude-from=r use-compress-program=cmd "
    "to-command=cmd checkpoint-action=cmd info-script=cmd new-volume-script=cmd "
    "listed-incremental=r newer=x exclude=x transform=x xform=x strip-components=x "
    "one-top-level=w owner=x group=x blocking-factor=x label=x format=x",
    flags="create extract get list append update diff compare concatenate delete verbose "
    "gzip bzip2 xz zstd bunzip2 gunzip to-stdout absolute-names dereference preserve-permissions "
    "same-permissions keep-old-files overwrite",
)
_TAR_CREATE = _fs("-c --create")
_TAR_APPEND = _fs("-r -u --append --update -A --concatenate")
_TAR_READ = _fs("-x -t -d --extract --get --list --diff --compare")
_TAR_RENAMING = _fs("--transform --xform --strip-components --one-top-level -T --files-from")
_MEMBER_PATTERN = frozenset("*?[]\\")


def _extract_members(
    a: _Acc,
    directories: Sequence[Word],
    members: Sequence[Word],
    *,
    renamed: bool,
    absolute: bool,
    junk_paths: bool = False,
) -> None:
    """Archive extraction: the files written are the named members, or unknown (gray).

    ``members`` are the names given on the command line; with none the whole archive is extracted
    and its member names are not known. A member that is a pattern (``*.json``), dynamic, or an
    archive whose names an option rewrites (``--transform``, ``--strip-components``) is unknown too.
    ``absolute`` (``tar -P``) lets an absolute member name escape the directory.
    """
    names_known = (
        bool(members)
        and not renamed
        and not any(
            w.expands or w.glob or any(c in _MEMBER_PATTERN or c in _NAME_UNSAFE for c in w.text)
            for w in members
        )
    )
    if not names_known:
        a.gray.append("archive-members-unknown")
        return
    for d in directories:
        for w in members:
            rel = w.text.lstrip("/\\")
            variants = [rel, rel.replace("\\", "/").rsplit("/", 1)[-1]] if junk_paths else [rel]
            for variant in dict.fromkeys(variants):
                child = _join_child(d, variant) if variant else None
                if child is not None:
                    a.path(child, "write")
    if absolute:
        for w in members:
            if w.text.startswith("/"):
                a.path(w, "write")


def _h_tar(a: _Acc, args: Sequence[Word]) -> None:
    argv = list(args)
    if (
        argv
        and argv[0].text
        and argv[0].text[0] != "-"
        and argv[0].text.isascii()
        and argv[0].text.isalpha()
    ):
        argv[0] = _sub(argv[0], "-" + argv[0].text)  # old style: tar xzf a.tgz
    sc = _scan(argv, _TAR_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    creating = bool(seen & _TAR_CREATE)
    appending = bool(seen & _TAR_APPEND)
    reading = bool(seen & _TAR_READ)
    extracting = bool(seen & _fs("-x --extract --get"))
    if not (creating or appending or reading or "--delete" in seen):
        a.gray.append("tar-mode-unknown")
    chdirs = [w for _, role, w in sc.values if role == "tarC"]
    for opt, role, w in sc.values:
        if role == "tarf":
            a.path(w, "write" if (creating or appending or "--delete" in seen) else "read")
        elif role == "tarC":
            a.path(w, "write" if extracting else "read")
        else:
            _apply(a, opt, role, w)
    if extracting and not chdirs and not seen & {"-O", "--to-stdout"}:
        a.path(Word("."), "write")
    if extracting and not seen & {"-O", "--to-stdout"}:
        _extract_members(
            a,
            chdirs or [Word(".")],
            sc.pos,
            renamed=bool(seen & _TAR_RENAMING),
            absolute=bool(seen & {"-P", "--absolute-names"}),
        )
    if creating or appending:
        for w in sc.pos:
            a.path(w, "read")
            if chdirs and not w.text.startswith(("/", "\\", "~")):
                joined = chdirs[-1].text.rstrip("/\\") + "/" + w.text
                a.path(
                    Word(joined, chdirs[-1].expands or w.expands, chdirs[-1].glob or w.glob),
                    "read",
                )


_UNZIP_OPTS = _opts(short="d=w x=x P=x O=x I=x Z=x")


def _h_unzip(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _UNZIP_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    seen = set(sc.flags)
    for w in sc.pos[:1]:
        a.path(w, "read")
    extracting = not seen & _fs("-l -t -p -v -z -Z -c")
    dirs = [w for opt, _, w in sc.values if opt == "-d"]
    if extracting and not dirs:
        a.path(Word("."), "write")
    if extracting:
        _extract_members(
            a,
            dirs or [Word(".")],
            sc.pos[1:],
            renamed=False,
            absolute=False,
            junk_paths="-j" in seen,
        )


_ZIP_OPTS = _opts(short="b=w O=w n=x t=x Z=x P=x s=x i=x x=x", long="output-file=w temp-path=w")


def _h_zip(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _ZIP_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    pos = sc.pos
    if pos:
        a.path(pos[0], "write")
    if "-d" not in set(sc.flags):
        for w in pos[1:]:
            a.path(w, "read")


# --- patch / git apply helpers -------------------------------------------------------------------

_PATCH_OPTS = _opts(
    short="i=r o=w d=w p=x D=x F=x r=w V=x B=x z=x",
    long="input=r output=w directory=w reject-file=w",
)


def _h_patch(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _PATCH_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    for w in sc.pos[:1]:
        a.path(w, "write")
    if not sc.pos:
        a.gray.append("patch-targets-in-patch")
        a.write_hint = True
    for w in sc.pos[1:]:
        a.path(w, "read")


# ---------------------------------------------------------------------------------------------
# Section 3: interpreters
# ---------------------------------------------------------------------------------------------

_INTERP_OPTS: dict[str, Opts] = {
    "python": _opts(short="c=code m=mod W=x X=x Q=x"),
    "node": _opts(
        short="e=code p=code r=r C=x",
        long="eval=code print=code require=r import=x loader=x conditions=x input-type=x "
        "experimental-loader=x",
    ),
    "perl": _opts(short="e=code E=code I=r M=x m=x x=x l=x F=x 0=x", attached="i=x"),
    "ruby": _opts(short="e=code r=r I=r C=r x=x E=x F=x K=x 0=x", attached="i=x"),
    "php": _opts(short="r=code f=r d=x c=r z=x B=code R=code F=r E=code"),
    "shell": _opts(short="c=shc o=x O=x", long="rcfile=r init-file=r"),
}
_SHELLS = _fs("sh bash zsh dash ksh csh tcsh fish ash")
_INTERP_FAMILY = {
    "python": "python",
    "python2": "python",
    "python3": "python",
    "pypy": "python",
    "pypy3": "python",
    "node": "node",
    "nodejs": "node",
    "perl": "perl",
    "ruby": "ruby",
    "php": "php",
}


def _h_interp(a: _Acc, args: Sequence[Word], family: str) -> None:
    a.exec_hint = True
    sc = _scan(args, _INTERP_OPTS[family])
    a.flags.extend(sc.flags)
    seen = set(sc.flags)
    inline = False
    module: Word | None = None
    for opt, role, w in sc.values:
        if role == "code":
            inline = True
            a.gray.append(f"inline-code:{opt}")
        elif role == "shc":
            inline = True  # the Bash parser recurses into -c strings; nothing to list here
        elif role == "mod":
            module = w
        else:
            _apply(a, opt, role, w)
    if module is not None and module.text == "pip":
        sub = _Acc("pip")
        _h_pkg(sub, sc.pos, _PKG["pip"])
        a.flags.extend(sub.flags)
        a.paths.extend(sub.paths)
        a.urls.extend(sub.urls)
        a.gray.extend(sub.gray)
        a.network = a.network or sub.network
        a.sub = sub.sub
        a.write_hint = a.write_hint or sub.write_hint
        return
    pos = list(sc.pos)
    inplace = family in ("perl", "ruby") and "-i" in seen
    if not inline and module is None and pos and "-s" not in seen:
        a.path(pos.pop(0), "read")
    for w in pos:
        if inplace:
            a.path(w, "write")
        else:
            _generic_arg(a, w)


# ---------------------------------------------------------------------------------------------
# Section 4: network programs
# ---------------------------------------------------------------------------------------------

_CURL = _opts(
    short="A=x b=cookie c=w C=x d=at D=w e=x E=r F=form H=at K=cfg m=x o=w P=x Q=x r=x t=x T=r "
    "u=x U=x w=at x=url X=x y=x Y=x z=x",
    long="output=w output-dir=w dump-header=w upload-file=r data=at data-ascii=at data-binary=at "
    "data-raw=x data-urlencode=durl form=form form-string=x json=at header=at proxy-header=at "
    "user=x user-agent=x referer=x request=x cookie=cookie cookie-jar=w config=cfg cert=r key=r "
    "cacert=r capath=r crlfile=r netrc-file=r proxy=url preproxy=url socks4=url socks4a=url "
    "socks5=url socks5-hostname=url proxy1.0=url resolve=resolve connect-to=connect doh-url=url "
    "url=url url-query=x write-out=at range=x max-time=x connect-timeout=x retry=x retry-delay=x "
    "retry-max-time=x limit-rate=x interface=x local-port=x dns-servers=x ciphers=x trace=w "
    "trace-ascii=w stderr=w unix-socket=r abstract-unix-socket=x ftp-port=x quote=x "
    "telnet-option=x time-cond=x oauth2-bearer=x aws-sigv4=x proxy-user=x proxy-cacert=r "
    "proxy-cert=r proxy-key=r hsts=w alt-svc=w libcurl=w etag-save=w etag-compare=r cert-type=x "
    "key-type=x pass=x pinnedpubkey=r max-filesize=x max-redirs=x speed-limit=x speed-time=x "
    "rate=x request-target=x proto=x proto-redir=x proto-default=x tls-max=x mail-from=x "
    "mail-rcpt=x parallel-max=x egd-file=r random-file=r variable=cvar expand-data=at "
    "expand-header=at expand-json=at expand-url=url expand-output=w expand-write-out=at "
    "expand-dump-header=w",
    flags="remote-name remote-name-all location location-trusted silent show-error fail insecure "
    "head include verbose compressed netrc netrc-optional next globoff get anyauth basic digest "
    "ntlm negotiate http2 http1.1 http3 ipv4 ipv6 progress-bar no-progress-meter fail-with-body "
    "create-dirs remote-header-name remote-time",
)


def _relative(text: str) -> bool:
    """A path that is resolved against a base directory (not absolute, not ``~``)."""
    return bool(text) and not text.startswith(("/", "\\", "~")) and not _drive(text)


def _url_names(url: str, *, keep_query: bool, default: str = "") -> tuple[str, ...] | None:
    """The file names ``curl -O`` / ``wget`` store ``url`` under; () for none, None if unknowable.

    The last path segment, percent-decoded and raw (clients differ), with the query too for wget
    (``keep_query``); ``default`` stands in for an empty segment (wget: ``index.html``).
    """
    rest = url.split("://", 1)[1] if "://" in url else url
    path = rest.partition("/")[2].partition("#")[0]
    if "/" not in rest:
        return None if any(c in _NAME_UNSAFE for c in url) else ((default,) if default else ())
    plain, _, query = path.partition("?")
    segment = plain.rsplit("/", 1)[-1] or default
    candidates: dict[str, None] = {}
    for base in [segment, segment + "?" + query] if (keep_query and query) else [segment]:
        for name in (base, unquote(base)):
            if name:
                candidates[name] = None
    if any(c in _NAME_UNSAFE and c != "?" for name in candidates for c in name):
        return None
    return tuple(candidates)


def _h_curl(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _CURL)
    a.flags.extend(sc.flags)
    a.network = True
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    for w in sc.pos:
        a.target(w)
    seen = set(sc.flags)
    out_dirs = [w for opt, _, w in sc.values if opt == "--output-dir"]
    if seen & _fs("-O --remote-name --remote-name-all"):
        if not out_dirs:
            a.path(Word("."), "write")
        urls = [*sc.pos, *(w for opt, _, w in sc.values if opt == "--url")]
        groups = [_url_names(u.text, keep_query=False) for u in urls]
        for d in out_dirs or [Word(".")]:
            _write_children(a, d, groups)
        if seen & _fs("-J --remote-header-name"):
            a.gray.append("remote-header-name")  # the server picks the file name
    for opt, _, w in sc.values:
        if opt in ("-o", "--output") and _relative(w.text):
            for d in out_dirs:
                child = _join_child(d, w.text)
                if child is not None:
                    a.path(child, "write")


_WGET = _opts(
    short="O=w o=w a=w P=w i=wgeti B=x e=wgete U=x t=x T=x w=x l=x Q=x A=x R=x D=x I=x X=x Y=x",
    long="output-document=w output-file=w append-output=w directory-prefix=w input-file=wgeti "
    "base=x execute=wgete user-agent=x referer=x header=x post-data=x post-file=r body-data=x "
    "body-file=r method=x load-cookies=r save-cookies=w certificate=r private-key=r "
    "ca-certificate=r ca-directory=r crlfile=r random-file=r egd-file=r user=x password=x "
    "http-user=x http-password=x proxy-user=x proxy-password=x ftp-user=x ftp-password=x "
    "bind-address=x limit-rate=x wait=x waitretry=x timeout=x dns-timeout=x connect-timeout=x "
    "read-timeout=x tries=x level=x accept=x reject=x domains=x exclude-domains=x "
    "include-directories=x exclude-directories=x quota=x config=cfg use-askpass=cmd hsts-file=w "
    "warc-file=w rejected-log=w secure-protocol=x default-page=x prefer-family=x "
    "restrict-file-names=x regex-type=x backups=x progress=x report-speed=x",
    flags="spider recursive mirror page-requisites convert-links no-proxy no-check-certificate "
    "span-hosts continue timestamping no-clobber no-parent",
)


def _h_wget(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _WGET)
    a.flags.extend(sc.flags)
    a.network = True
    a.note_dynamic(sc)
    for opt, role, w in sc.values:
        if role == "wgeti":
            a.path(w, "read")
            a.gray.append("wget-input-file")
        else:
            _apply(a, opt, role, w)
    for w in sc.pos:
        a.target(w)
    seen = set(sc.flags)
    out_docs = [w for opt, _, w in sc.values if opt in ("-O", "--output-document")]
    prefixes = [w for opt, _, w in sc.values if opt in ("-P", "--directory-prefix")]
    if "--spider" in seen:
        return
    if not out_docs:
        if not prefixes:
            a.path(Word("."), "write")
        groups = [_url_names(w.text, keep_query=True, default="index.html") for w in sc.pos]
        for d in prefixes or [Word(".")]:
            _write_children(a, d, groups)
    else:
        for out in out_docs:
            if _relative(out.text):
                for d in prefixes:
                    child = _join_child(d, out.text)
                    if child is not None:
                        a.path(child, "write")
    if seen & _fs("-r --recursive -m --mirror -p --page-requisites"):
        a.gray.append("directory-write")  # a crawl writes a tree of files we cannot name
    if seen & _fs("--content-disposition --trust-server-names"):
        a.gray.append("remote-header-name")  # the server picks the file name


_SSH = _opts(
    short="b=x B=x c=x D=x E=w e=x F=r I=x i=r J=jump L=x l=x m=x O=x o=sshopt p=x Q=x R=x S=x "
    "W=url w=x",
)


def _h_ssh(a: _Acc, args: Sequence[Word]) -> None:
    a.network = True
    sc = _scan(args, _SSH)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    if set(sc.flags) & _fs("-L -R -D"):
        a.gray.append("ssh-forwarding")
    if sc.pos:
        a.url(sc.pos[0].text)
        if len(sc.pos) > 1:
            a.exec_hint = True  # a remote command


_SCP = _opts(short="c=x D=x F=r i=r J=jump l=x o=sshopt P=x S=cmd X=x")


def _remote_spec(text: str) -> str | None:
    """The host part of an scp / rsync remote operand, None for a local path."""
    if text.startswith(("rsync://", "scp://", "ssh://", "sftp://")):
        return text
    if "::" in text and "/" not in text.split("::", 1)[0]:
        return text.split("::", 1)[0]
    colon = text.find(":")
    if colon > 1 and "/" not in text[:colon] and "\\" not in text[:colon]:
        return text
    if colon > 0 and "@" in text[:colon] and "/" not in text[:colon]:
        return text
    return None


def _remote_path(text: str) -> str:
    """The path part of a remote operand (``host:/p``, ``host::module/p``, ``rsync://host/p``)."""
    if "://" in text:
        return text.split("://", 1)[1].partition("/")[2]
    if "::" in text:
        return text.split("::", 1)[1]
    return text.partition(":")[2]


def _source_names(text: str, *, remote: bool, contents_if_slash: bool) -> tuple[str, ...] | None:
    """File names a transferred source gets in a local directory (None: unknowable).

    ``contents_if_slash``: rsync copies the CONTENTS of ``dir/`` (names unknown), scp / cp do not.
    """
    path = _remote_path(text) if remote else text
    if contents_if_slash and path.endswith(("/", "\\")):
        return None
    return _child_names(path)


def _h_scp(a: _Acc, args: Sequence[Word]) -> None:
    a.network = True
    sc = _scan(args, _SCP)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    pos = sc.pos
    for idx, w in enumerate(pos):
        remote = _remote_spec(w.text)
        if remote is not None:
            a.url(remote)
        else:
            a.path(w, "write" if idx == len(pos) - 1 else "read")
    if len(pos) == 1 and _remote_spec(pos[0].text) is not None:
        a.path(Word("."), "write")
    if len(pos) == 1:
        dest, sources = Word("."), (pos if _remote_spec(pos[0].text) is not None else [])
    else:
        dest, sources = (pos[-1], pos[:-1]) if pos else (Word("."), [])
    if sources and _remote_spec(dest.text) is None:
        groups = [
            _source_names(s.text, remote=_remote_spec(s.text) is not None, contents_if_slash=False)
            for s in sources
        ]
        _write_children(a, dest, groups)
        if "-r" in sc.flags:
            a.gray.append("directory-write")  # a copied directory brings members we cannot see


_RSYNC = _opts(
    short="e=cmd f=x T=w B=x M=x @=x",
    long="rsh=cmd rsync-path=cmd files-from=r exclude-from=r include-from=r exclude=x include=x "
    "filter=x log-file=w backup-dir=w temp-dir=w partial-dir=w compare-dest=r copy-dest=r "
    "link-dest=r bwlimit=x port=x address=x sockopts=x timeout=x contimeout=x max-size=x "
    "min-size=x chmod=x chown=x usermap=x groupmap=x out-format=x info=x debug=x "
    "compress-level=x skip-compress=x checksum-choice=x password-file=r write-batch=w "
    "read-batch=r only-write-batch=w protocol=x iconv=x block-size=x modify-window=x suffix=x "
    "max-delete=x",
    flags="delete delete-before delete-after delete-during delete-excluded remove-source-files "
    "remove-sent-files dry-run archive recursive verbose compress checksum partial progress "
    "update inplace",
)


def _h_rsync(a: _Acc, args: Sequence[Word]) -> None:
    a.network = False
    sc = _scan(args, _RSYNC)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    seen = set(sc.flags)
    src_access: Access = (
        "write" if seen & _fs("--remove-source-files --remove-sent-files") else "read"
    )
    pos = sc.pos
    for idx, w in enumerate(pos):
        remote = _remote_spec(w.text)
        if remote is not None:
            a.url(remote)
        elif idx == len(pos) - 1 and len(pos) > 1:
            a.path(w, "write")
        else:
            a.path(w, src_access)
    if len(pos) > 1 and _remote_spec(pos[-1].text) is None:
        groups = [
            _source_names(s.text, remote=_remote_spec(s.text) is not None, contents_if_slash=True)
            for s in pos[:-1]
        ]
        _write_children(a, pos[-1], groups)
        if seen & _fs("-a -r -d --archive --recursive --dirs --files-from"):
            a.gray.append("directory-write")  # directories bring members we cannot see


_NC = _opts(
    short="e=cmd c=cmd p=x s=x w=x i=x x=url X=x T=x I=x O=x P=x q=x o=w",
    long="exec=cmd sh-exec=cmd lua-exec=cmd proxy=url proxy-type=x proxy-auth=x source-port=x "
    "source=x ssl-cert=r ssl-key=r ssl-trustfile=r output=w append-output=w hex-dump=w "
    "allowfile=r denyfile=r allow=x deny=x",
    flags="listen keep-open udp zero ssl",
)


def _h_nc(a: _Acc, args: Sequence[Word]) -> None:
    a.network = True
    sc = _scan(args, _NC)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    listening = bool(set(sc.flags) & {"-l", "--listen"})
    if listening and len(sc.pos) == 1:
        return
    for w in sc.pos[:1]:
        if _pathlike(w.text) and not _urllike(w.text) and set(sc.flags) & {"-U", "-u"}:
            a.path(w, "unknown")
        else:
            a.url(w.text)


_PING_OPTS = _opts(short="c=x i=x W=x w=x s=x t=x I=x m=x p=x Q=x S=x M=x")
_TRACE_OPTS = _opts(short="m=x q=x w=x p=x f=x s=x i=x g=x z=x")
_DIG_OPTS = _opts(short="p=x b=x c=x f=r k=r q=x t=x x=x y=x")
_NETHOST_OPTS: dict[str, Opts] = {
    "ping": _PING_OPTS,
    "ping6": _PING_OPTS,
    "traceroute": _TRACE_OPTS,
    "traceroute6": _TRACE_OPTS,
    "tracepath": _opts(short="m=x l=x p=x"),
    "dig": _DIG_OPTS,
    "whois": _opts(short="h=url p=x"),
    "sftp": _opts(short="b=r F=r i=r J=jump o=sshopt P=x S=cmd c=x D=cmd s=x l=x R=x B=x"),
    "nmap": _opts(short="p=x iL=r oN=w oX=w oG=w oA=w e=x S=x g=x", long="script=x"),
    "ftp": _NOOPTS,
}
_NETHOST_PROGRAMS = _fs(
    "ping ping6 traceroute traceroute6 tracepath mtr dig nslookup host whois nmap masscan telnet "
    "ftp sftp lftp tftp mosh socat"
)
_NETCLI_PROGRAMS = _fs(
    "aria2c axel http https xh xhs lynx links w3m elinks rclone aws gcloud az gsutil kubectl helm "
    "terraform pulumi heroku vercel netlify flyctl firebase doctl"
)


def _hostish(text: str) -> bool:
    return "." in text or ":" in text or "@" in text or "/" in text or text == "localhost"


def _h_nethost(a: _Acc, args: Sequence[Word]) -> None:
    """Programs whose positionals are hosts / URLs (ping, dig, telnet, ftp, cloud CLIs, ...)."""
    a.network = True
    sc = _scan(args, _NETHOST_OPTS.get(a.prog, _NOOPTS))
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    cli = a.prog in _NETCLI_PROGRAMS
    operands = sc.pos[:1] if a.prog in ("telnet", "mosh") else sc.pos  # the rest is a port/command
    for w in operands:
        t = w.text
        if _outside_like(t) and not _urllike(t):
            a.path(w, "unknown")
        elif not cli or _hostish(t) or w.expands or w.glob:
            a.target(_sub(w, t[1:]) if t[:1] == "@" and a.prog == "dig" else w)
    if a.prog == "socat":
        a.gray.append("socat-addresses")
        if any("EXEC:" in w.text.upper() or "SYSTEM:" in w.text.upper() for w in sc.pos):
            a.exec_hint = True


def _h_openssl(a: _Acc, args: Sequence[Word]) -> None:
    sc = _scan(args, _NOOPTS, single_dash_long=True)
    a.flags.extend(sc.flags)
    pos = list(sc.pos)
    sub = pos[0].text if pos else None
    a.sub = sub
    roles = {
        "-in": "r",
        "-inkey": "r",
        "-key": "r",
        "-CAfile": "r",
        "-cert": "r",
        "-certfile": "r",
        "-CApath": "r",
        "-out": "w",
        "-keyout": "w",
        "-writerand": "w",
        "-rand": "r",
        "-connect": "url",
        "-proxy": "url",
        "-servername": "url",
        "-host": "url",
    }
    i = 0
    while i < len(args):
        t = args[i].text
        if t in roles and i + 1 < len(args):
            _apply(a, t, roles[t], args[i + 1])
            i += 2
            continue
        i += 1
    if sub in ("s_client", "s_server", "s_time", "ocsp"):
        a.network = True


# ---------------------------------------------------------------------------------------------
# Section 5: git
# ---------------------------------------------------------------------------------------------

_GIT_READ_SUBS = _fs(
    "status log diff show ls-files ls-tree rev-parse rev-list describe blame grep shortlog "
    "cat-file name-rev show-ref show-branch for-each-ref count-objects fsck cherry merge-base "
    "range-diff reflog var check-ignore check-attr check-ref-format whatchanged diff-tree "
    "diff-index diff-files verify-commit verify-tag verify-pack help version annotate "
    "get-tar-commit-id fast-export ls-remote"
)
_GIT_WRITE_SUBS = _fs(
    "add rm mv commit checkout switch restore reset clean merge rebase cherry-pick revert stash "
    "tag branch init clone fetch pull push apply am config worktree gc prune repack maintenance "
    "bisect notes replace update-index update-ref symbolic-ref hash-object mktag commit-tree "
    "write-tree checkout-index read-tree sparse-checkout filter-branch format-patch bundle "
    "archive pack-refs prune-packed fast-import unpack-objects index-pack mailsplit mailinfo "
    "merge-file rerere submodule remote lfs subtree svn credential send-email request-pull "
    "difftool mergetool instaweb daemon gui"
)
_GIT_NETWORK_SUBS = _fs(
    "clone fetch pull push ls-remote submodule lfs svn send-email imap-send fetch-pack send-pack "
    "http-fetch http-push daemon subtree"
)
_GIT_REMOTE_NET = _fs("add set-url update show prune")
_GIT_REMOTE_WRITE = _fs("add set-url remove rm rename set-head set-branches prune")
_GIT_EXEC_SUBS = _fs("difftool mergetool filter-branch instaweb daemon gui")
_GIT_READ_FILE_SUBS = _fs("apply am hash-object mailsplit mailinfo")
_GIT_PATH_ALL = _fs("add rm mv clean restore apply am hash-object mailsplit mailinfo update-index")
_GIT_EXEC_FLAGS = _fs(
    "--exec --upload-pack --receive-pack --ext-diff --open-files-in-pager --exec-path"
)
_GIT_EXEC_CONFIG = _fs(
    "core.sshcommand core.pager core.editor core.fsmonitor core.hookspath core.askpass "
    "credential.helper diff.external sequence.editor gpg.program gpg.ssh.program "
    "http.sslcertpasswordprotected ssh.variant core.gitproxy"
)

_GIT_GLOBAL = _opts(
    short="C=gitC c=gitc",
    long="git-dir=r work-tree=r namespace=x super-prefix=x config-env=x attr-source=x",
    flags="paginate no-pager bare no-replace-objects literal-pathspecs glob-pathspecs "
    "noglob-pathspecs icase-pathspecs no-optional-locks no-lazy-fetch no-advice version help "
    "html-path man-path info-path exec-path",
)
_GIT_GLOBAL_FLAGS = _fs("-p -P")
_GIT_SUB_OPTS: dict[str, Opts] = {
    "commit": _opts(
        short="m=x F=r C=x c=x t=r",
        long="message=x file=r reuse-message=x reedit-message=x template=r author=x date=x "
        "fixup=x squash=x cleanup=x",
        attached="S=x",
    ),
    "tag": _opts(short="m=x F=r u=x", long="message=x file=r local-user=x", attached="s=x"),
    "merge": _opts(short="m=x F=r s=x X=x", long="message=x file=r strategy=x strategy-option=x"),
    "stash": _opts(short="m=x", long="message=x"),
    "push": _opts(
        short="o=x",
        long="push-option=x repo=x receive-pack=cmd exec=cmd signed=x",
        flags="force force-with-lease force-if-includes delete mirror all tags prune no-verify "
        "dry-run set-upstream follow-tags atomic thin verbose quiet progress porcelain",
    ),
    "fetch": _opts(
        short="j=x",
        long="upload-pack=cmd jobs=x depth=x deepen=x shallow-since=x shallow-exclude=x refmap=x "
        "negotiation-tip=x server-option=x filter=x",
    ),
    "pull": _opts(
        short="j=x s=x X=x",
        long="upload-pack=cmd jobs=x depth=x strategy=x strategy-option=x shallow-since=x "
        "shallow-exclude=x server-option=x filter=x",
    ),
    "ls-remote": _opts(long="upload-pack=cmd exec=cmd sort=x server-option=x", short="u=cmd"),
    "clone": _opts(
        short="b=x o=x u=cmd c=x j=x",
        long="branch=x origin=x upload-pack=cmd config=x jobs=x depth=x template=r reference=r "
        "reference-if-able=r separate-git-dir=w filter=x shallow-since=x shallow-exclude=x "
        "server-option=x bundle-uri=x",
    ),
    "checkout": _opts(
        short="b=x B=x",
        long="source=x orphan=x conflict=x pathspec-from-file=r",
    ),
    "switch": _opts(short="c=x C=x", long="orphan=x conflict=x"),
    "restore": _opts(short="s=x", long="source=x pathspec-from-file=r"),
    "branch": _opts(short="u=x", long="set-upstream-to=x sort=x format=x contains=x"),
    "log": _opts(
        short="n=x",
        long="output=w max-count=x since=x until=x author=x committer=x grep=x format=x pretty=x "
        "skip=x",
    ),
    "diff": _opts(long="output=w", short="O=r"),
    "show": _opts(long="output=w format=x pretty=x", short="O=r"),
    "format-patch": _opts(short="o=w n=x", long="output-directory=w from=x subject-prefix=x"),
    "archive": _opts(short="o=w", long="output=w remote=url exec=cmd prefix=x format=x"),
    "config": _opts(short="f=w", long="file=w blob=x default=x type=x"),
    "apply": _opts(short="p=x C=x", long="directory=w include=x exclude=x whitespace=x"),
    "am": _opts(short="p=x", long="directory=w whitespace=x"),
    "rebase": _opts(short="x=cmd s=x X=x", long="exec=cmd onto=x strategy=x strategy-option=x"),
    "cherry-pick": _opts(short="m=x", long="mainline=x"),
    "revert": _opts(short="m=x", long="mainline=x"),
    "init": _opts(
        short="b=x",
        long="template=r separate-git-dir=w initial-branch=x object-format=x shared=x",
    ),
    "submodule": _opts(long="reference=r name=x depth=x branch=x jobs=x", short="b=x j=x"),
    "notes": _opts(short="m=x F=r C=x c=x", long="message=x file=r ref=x"),
    "bundle": _opts(),
    "remote": _opts(short="m=x t=x", long="track=x master=x"),
}


_GIT_TREE_WRITERS = _fs(
    "checkout switch restore reset clean merge rebase cherry-pick revert stash pull apply am "
    "checkout-index read-tree sparse-checkout submodule worktree"
)


def _chain_dir(prev: Word | None, w: Word) -> Word:
    """``git -C a -C b`` works in ``a/b``; an absolute (or ``~``) directory starts over."""
    if prev is None or not _relative(w.text):
        return w
    return Word(
        prev.text.rstrip("/\\") + "/" + w.text, prev.expands or w.expands, prev.glob or w.glob
    )


def _scoped_path(a: _Acc, chain: Word | None, w: Word, access: Access) -> None:
    """A relative pathspec of ``git -C DIR ...`` is relative to DIR, not to the cwd."""
    if chain is not None and _relative(w.text) and w.text not in ("", ".", ".."):
        a.path(Word(chain.text.rstrip("/\\") + "/" + w.text, chain.expands or w.expands,
                    chain.glob or w.glob), access)  # fmt: skip


def _git_config_entry(a: _Acc, w: Word, key_value: str) -> None:
    """Judge one ``-c key=value`` (or ``git config key value``): code execution or URL rewriting."""
    key, _, value = key_value.partition("=")
    low = key.strip().lower()
    if (
        low.startswith("alias.")
        or (low.startswith("include") and low.endswith(".path"))
        or low in _GIT_EXEC_CONFIG
        or value.lstrip().startswith("!")
    ):
        a.exec_hint = True
        a.gray.append(f"git-config-exec:{low}")
    elif low.startswith("url.") and low.endswith(("insteadof", "pushinsteadof")):
        a.gray.append("git-url-rewrite")
        a.url(value)
    elif "://" in value or low.endswith((".proxy", ".url", "proxy")) or _scp_like(value):
        a.url(value)
    if low.endswith(("sslcert", "sslkey", "cainfo", "capath", "sshcommand")) and _pathlike(value):
        a.path(_sub(w, value), "read")


def _git_url_or_path(a: _Acc, w: Word, access: Access) -> None:
    t = w.text
    helper, sep, _ = t.partition("::")
    if sep and helper.replace("-", "").replace("+", "").isalnum():
        # "ext::sh -c ..." and friends: a remote helper program runs, destination unknowable
        a.exec_hint = True
        a.gray.append(f"git-remote-helper:{helper}")
        a.url(t)
        return
    if _urllike(t):
        a.target(w)
    elif _outside_like(t) or w.expands or w.glob:
        a.path(w, access)


def _h_git(a: _Acc, args: Sequence[Word]) -> None:
    n = len(args)
    i = 0
    scope_paths: list[Word] = []
    chain: Word | None = None  # where relative pathspecs land: the -C directories, composed
    work_tree = False
    while i < n:
        w = args[i]
        t = w.text
        if t == "--" or not t.startswith("-") or len(t) == 1:
            break
        i += 1
        name, eq, val = t.partition("=")
        if t == "-C" and i < n:
            scope_paths.append(args[i])
            chain = _chain_dir(chain, args[i])
            i += 1
            a.flags.append("-C")
        elif t == "-c" and i < n:
            _git_config_entry(a, args[i], args[i].text)
            i += 1
            a.flags.append("-c")
        elif name in _GIT_GLOBAL.long:
            a.flags.append(name)
            value = _sub(w, val) if eq else (args[i] if i < n else None)
            if not eq and i < n:
                i += 1
            if value is not None and _GIT_GLOBAL.long[name] == "r":
                scope_paths.append(value)
                work_tree = work_tree or name == "--work-tree"
            elif value is not None and name == "--config-env":
                _git_config_entry(a, value, value.text)
        elif name == "--exec-path" and eq:
            a.flags.append(name)
            a.exec_hint = True  # git subcommands are run from that directory
            a.gray.append("git-exec-path")
        elif name in _GIT_GLOBAL.long_flags or t in _GIT_GLOBAL_FLAGS or t in ("-v", "-h"):
            a.flags.append(name)
        else:
            a.flags.append(name)
            a.gray.append(f"git-unknown-global-option:{name}")
    if i >= n or args[i].text == "--":
        for w in scope_paths:
            a.path(w, "read")
        return
    sub_word = args[i]
    sub = sub_word.text
    i += 1
    a.sub = sub
    if sub_word.expands or sub_word.glob:
        a.gray.append("git-dynamic-subcommand")
    if sub not in _GIT_READ_SUBS and sub not in _GIT_WRITE_SUBS:
        a.gray.append(f"git-unknown-subcommand:{sub}")
    access: Access = "read" if sub in _GIT_READ_SUBS else "write"
    for w in scope_paths:
        a.path(w, access)
    if sub in _GIT_WRITE_SUBS and sub not in ("config", "remote"):
        a.write_hint = True
    if (chain is not None or work_tree) and sub in _GIT_TREE_WRITERS:
        # rewrites files in another work tree: which ones depends on the repository's contents
        a.gray.append("directory-write")
    if sub in _GIT_NETWORK_SUBS:
        a.network = True
    if sub in _GIT_EXEC_SUBS:
        a.exec_hint = True
        if sub == "filter-branch":
            a.gray.append("git-filter-branch")
    if sub in ("credential",):
        a.secret_hint = True
    rest = args[i:]
    sc = _scan(rest, _GIT_SUB_OPTS.get(sub, _NOOPTS))
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    seen = set(sc.flags)
    for opt, role, w in sc.values:
        if (role == "x" and opt == "-c" and sub == "clone") or (
            role == "x" and opt == "--config" and sub == "clone"
        ):
            _git_config_entry(a, w, w.text)
        else:
            _apply(a, opt, role, w)
    if seen & _GIT_EXEC_FLAGS:
        a.exec_hint = True
        a.gray.append("git-exec-option")
    pos = sc.pos
    sub2 = pos[0].text if pos else None
    if sub == "remote":
        if sub2 in _GIT_REMOTE_NET:
            a.network = True
        if sub2 in _GIT_REMOTE_WRITE:
            a.write_hint = True
        for w in pos[1:]:
            _git_url_or_path(a, w, "read")
        return
    if sub == "submodule":
        if sub2 == "foreach":
            a.exec_hint = True
            a.gray.append("git-submodule-foreach")
        for w in pos[1:]:
            _git_url_or_path(a, w, "write")
        return
    if sub == "config":
        _git_config(a, sc, seen)
        return
    if sub == "bundle":
        for w in pos[1:2]:
            a.path(w, "write" if sub2 == "create" else "read")
        return
    if sub == "clone":
        if pos:
            _git_url_or_path(a, pos[0], "read")
        a.gray.append("directory-write")  # the repository's files land in the directory
        if len(pos) >= 2:
            a.path(pos[1], "write")
        else:
            a.path(Word("."), "write")
            if pos:  # ``git clone URL`` creates ./<repo name>
                repo = pos[0].text.rstrip("/\\")
                if repo.endswith(".git"):
                    repo = repo[:-4]
                names = _child_names(repo.replace(":", "/"))
                _write_children(a, Word("."), [names])
        return
    if sub in ("fetch", "pull", "push", "ls-remote"):
        for idx, w in enumerate(pos):
            if idx == 0:
                _git_url_or_path(a, w, "write" if sub == "push" else "read")
            elif _urllike(w.text):
                a.target(w)
        if sub == "push":
            for w in pos[1:]:
                if w.text.startswith("+"):
                    a.flags.append("--force")
                if w.text.startswith(":"):
                    a.flags.append("--delete")
        return
    if sub in ("apply", "am"):
        a.gray.append("git-apply-targets-in-patch")
    if sub == "format-patch" and "--stdout" not in seen:
        has_out = any(opt in ("-o", "--output-directory") for opt, _, _ in sc.values)
        if not has_out:
            a.path(Word("."), "write")
    if sub == "diff" and "--no-index" in seen:
        for w in pos:
            a.path(w, "read")
        return
    if sub == "clean" and not pos:
        a.path(Word("."), "write")
    before = pos if sc.dd_at < 0 else pos[: sc.dd_at]
    after = [] if sc.dd_at < 0 else pos[sc.dd_at :]
    if sub in _GIT_PATH_ALL:
        file_access: Access = "read" if sub in _GIT_READ_FILE_SUBS else access
        for w in pos:
            a.path(w, file_access)
            _scoped_path(a, chain, w, file_access)
        return
    for w in before:
        if _outside_like(w.text) or w.expands or w.glob:
            a.path(w, access)
    for w in after:
        a.path(w, access)
        _scoped_path(a, chain, w, access)
    if sub == "checkout" and chain is not None and sc.dd_at < 0:
        # ``git -C d checkout settings.json``: without ``--`` a pathspec looks like a branch name
        for w in pos:
            _scoped_path(a, chain, w, access)


def _git_config(a: _Acc, sc: _Scan, seen: set[str]) -> None:
    pos = sc.pos
    reading = bool(
        seen
        & _fs(
            "--get --get-all --get-regexp --get-urlmatch --get-color --get-colorbool --list -l "
            "--name-only --show-origin"
        )
    ) or (bool(pos) and pos[0].text in ("get", "list") and len(pos) <= 2)
    writing = bool(
        seen
        & _fs(
            "--add --unset --unset-all --replace-all --rename-section --remove-section --edit "
            "-e --set"
        )
    ) or (not reading and len(pos) >= 2)
    explicit = any(opt in ("-f", "--file") for opt, _, _ in sc.values)
    if writing:
        a.write_hint = True
        if len(pos) >= 2:
            _git_config_entry(a, pos[0], f"{pos[0].text}={pos[1].text}")
        if not explicit:
            if "--global" in seen:
                scope = Word("~/.gitconfig", expands=True)
            elif "--system" in seen:
                scope = Word("/etc/gitconfig")
            else:
                scope = Word(".git/config")
            a.path(scope, "write")
    elif reading and not explicit:
        if "--global" in seen:
            a.path(Word("~/.gitconfig", expands=True), "read")
        elif "--system" in seen:
            a.path(Word("/etc/gitconfig"), "read")


# ---------------------------------------------------------------------------------------------
# Section 6: package managers, docker, gh
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PkgSpec:
    opts: Opts
    net: frozenset[str]  # subcommands that talk to a registry
    exec_subs: frozenset[str] = frozenset()  # subcommands that run package or project code
    write_subs: frozenset[str] = frozenset()  # subcommands that change files without a named path
    spec_subs: frozenset[str] = frozenset()  # subcommands whose positionals are package specs
    net_always: bool = False
    npm_shorthand: bool = False  # "user/repo", "github:user/repo" specs
    plain_args: frozenset[str] = frozenset()  # subs whose positionals are never paths


_PIP_OPTS = _opts(
    short="r=ru c=ru e=ru t=w d=w i=url f=ru",
    long="requirement=ru constraint=ru editable=ru target=w prefix=w root=w src=w dest=w "
    "cache-dir=w log=w cert=r client-cert=r index-url=url extra-index-url=url find-links=ru "
    "proxy=url trusted-host=url python=x platform=x abi=x implementation=x python-version=x "
    "only-binary=x no-binary=x progress-bar=x retries=x timeout=x exists-action=x "
    "config-settings=x global-option=x install-option=x report=w isolated=x",
    flags="user upgrade no-deps force-reinstall no-cache-dir ignore-installed pre editable quiet "
    "verbose require-hashes break-system-packages",
)
_NPM_OPTS = _opts(
    short="C=r w=x",
    long="registry=url prefix=w cwd=r userconfig=r globalconfig=r cache=w proxy=url "
    "https-proxy=url noproxy=x tag=x otp=x scope=x workspace=x loglevel=x omit=x include=x "
    "access=x package=x call=cmd script-shell=cmd node-options=x dir=r store-dir=w "
    "global-folder=w link-folder=w modules-folder=w registry-url=url",
    flags="global save save-dev dev production no-save no-audit no-fund force legacy-peer-deps "
    "ignore-scripts dry-run silent",
)
_APT_NET = _fs(
    "install update upgrade dist-upgrade full-upgrade download source build-dep reinstall"
)
_PKG: dict[str, PkgSpec] = {
    "pip": PkgSpec(
        opts=_PIP_OPTS,
        net=_fs("install download wheel index search lock"),
        exec_subs=_fs("install"),
        write_subs=_fs("install uninstall"),
        spec_subs=_fs("install download wheel uninstall"),
    ),
    "npm": PkgSpec(
        opts=_NPM_OPTS,
        net=_fs(
            "install i add ci update up upgrade publish unpublish deprecate dist-tag access owner "
            "team org hook token login logout adduser whoami profile search s find view info show "
            "v outdated audit fund ping exec x dlx create init prune dedupe ddp install-test it "
            "install-ci-test cit link ln"
        ),
        exec_subs=_fs(
            "install i add ci update up upgrade run run-script rum urn test t tst start stop "
            "restart exec x dlx create init rebuild install-test it install-ci-test cit link ln"
        ),
        write_subs=_fs("install i add ci update up upgrade uninstall rm remove un link ln pack"),
        spec_subs=_fs("install i add ci update up upgrade view info show v exec x dlx create"),
        npm_shorthand=True,
        plain_args=_fs("run run-script rum urn test t start stop restart"),
    ),
    "apt": PkgSpec(
        opts=_opts(short="o=x t=x c=r", long="option=x target-release=x config-file=r"),
        net=_APT_NET,
        exec_subs=_fs("install upgrade dist-upgrade full-upgrade reinstall"),
        write_subs=_fs("install remove purge upgrade dist-upgrade full-upgrade reinstall"),
        spec_subs=_fs("install remove purge download source build-dep reinstall"),
    ),
    "dnf": PkgSpec(
        opts=_opts(short="c=r", long="config=r installroot=w"),
        net=_fs(
            "install update upgrade reinstall downgrade check-update makecache download "
            "distro-sync groupinstall"
        ),
        exec_subs=_fs("install update upgrade reinstall downgrade distro-sync groupinstall"),
        write_subs=_fs(
            "install update upgrade reinstall remove erase downgrade distro-sync groupinstall"
        ),
        spec_subs=_fs("install update upgrade reinstall remove erase downgrade download"),
    ),
    "apk": PkgSpec(
        opts=_opts(short="p=w X=url", long="root=w repository=url"),
        net=_fs("add update upgrade fetch"),
        exec_subs=_fs("add upgrade"),
        write_subs=_fs("add del upgrade"),
        spec_subs=_fs("add del fetch"),
    ),
    "brew": PkgSpec(
        opts=_NOOPTS,
        net=_fs("install update upgrade reinstall fetch tap search cask"),
        exec_subs=_fs("install upgrade reinstall"),
        write_subs=_fs("install upgrade reinstall uninstall remove tap untap"),
        spec_subs=_fs("install reinstall fetch tap"),
    ),
    "gem": PkgSpec(
        opts=_opts(short="s=url i=w n=w", long="source=url install-dir=w bindir=w"),
        net=_fs("install update fetch push search"),
        exec_subs=_fs("install update"),
        write_subs=_fs("install update uninstall"),
        spec_subs=_fs("install update fetch push"),
    ),
    "cargo": PkgSpec(
        opts=_opts(short="C=r", long="manifest-path=r target-dir=w registry=x index=url config=x"),
        net=_fs(
            "install build b run r check c test t fetch update add publish search login vendor "
            "generate-lockfile doc clippy"
        ),
        exec_subs=_fs("install build b run r check c test t doc clippy"),
        write_subs=_fs("install build b run r check c test t add update vendor doc"),
        spec_subs=_fs("install add search"),
    ),
    "go": PkgSpec(
        opts=_opts(short="C=r o=w", long=""),
        net=_fs("get install mod build run test generate"),
        exec_subs=_fs("run test generate install build"),
        write_subs=_fs("get install mod build generate"),
        spec_subs=_fs("get install"),
    ),
    "composer": PkgSpec(
        opts=_opts(short="d=r", long="working-dir=r"),
        net=_fs("install update require create-project"),
        exec_subs=_fs("install update require create-project run-script"),
        write_subs=_fs("install update require remove create-project"),
        spec_subs=_fs("require create-project"),
    ),
    "uv": PkgSpec(
        opts=_opts(
            long="index-url=url extra-index-url=url find-links=ru directory=r project=r "
            "cache-dir=w python=x",
            short="p=x r=ru e=ru c=ru",
        ),
        net=_fs("add sync pip run tool lock install"),
        exec_subs=_fs("run tool sync"),
        write_subs=_fs("add sync pip lock install remove venv"),
        spec_subs=_fs("add install"),
    ),
    "poetry": PkgSpec(
        opts=_opts(short="C=r", long="directory=r"),
        net=_fs("install add update publish lock self"),
        exec_subs=_fs("install run build"),
        write_subs=_fs("install add update remove lock build"),
        spec_subs=_fs("add"),
    ),
    "pipx": PkgSpec(
        opts=_opts(long="index-url=url pip-args=x python=x spec=x"),
        net=_fs("install run upgrade upgrade-all inject reinstall-all"),
        exec_subs=_fs("install run inject"),
        write_subs=_fs("install uninstall upgrade inject"),
        spec_subs=_fs("install run inject upgrade"),
    ),
    "conda": PkgSpec(
        opts=_opts(short="n=x p=w c=x f=r", long="name=x prefix=w channel=x file=r"),
        net=_fs("install create update upgrade search"),
        exec_subs=_fs("install create update upgrade"),
        write_subs=_fs("install create update upgrade remove"),
        spec_subs=_fs("install create update upgrade remove"),
    ),
}
for _alias, _target in (
    ("pip3", "pip"),
    ("pipenv", "pip"),
    ("yarn", "npm"),
    ("pnpm", "npm"),
    ("bun", "npm"),
    ("apt-get", "apt"),
    ("aptitude", "apt"),
    ("yum", "dnf"),
    ("microdnf", "dnf"),
    ("mamba", "conda"),
    ("micromamba", "conda"),
):
    _PKG[_alias] = _PKG[_target]
_NPX_PROGRAMS = _fs("npx bunx pnpx")


def _pkg_spec_word(a: _Acc, w: Word, spec: PkgSpec) -> None:
    t = w.text
    low = t.lower()
    if _urllike(t):
        a.target(w)
    elif spec.npm_shorthand and low[:7] == "github:":
        a.url("https://github.com/" + t[7:])
    elif spec.npm_shorthand and low[:7] == "gitlab:":
        a.url("https://gitlab.com/" + t[7:])
    elif spec.npm_shorthand and low[:10] == "bitbucket:":
        a.url("https://bitbucket.org/" + t[10:])
    elif low[:5] == "file:":
        a.path(_sub(w, t[5:]), "read")
    elif (
        _outside_like(t)
        or "\\" in t
        or low.endswith((".whl", ".tgz", ".tar.gz", ".zip", ".tar", ".tar.bz2"))
        or w.expands
        or w.glob
    ):
        a.path(w, "read")
    elif (
        spec.npm_shorthand
        and t.count("/") == 1
        and t[0] != "@"
        and not t.startswith(".")
        and "@" not in t
    ):
        a.url("https://github.com/" + t)


def _h_pkg(a: _Acc, args: Sequence[Word], spec: PkgSpec) -> None:
    sc = _scan(args, spec.opts)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    pos = list(sc.pos)
    sub: str | None = None
    if pos:
        sub = pos.pop(0).text
    a.sub = sub
    if sub is None:
        a.network = a.network or spec.net_always
        return
    if sub in spec.net or spec.net_always:
        a.network = True
    if sub in spec.exec_subs:
        a.exec_hint = True
    if sub in spec.write_subs:
        a.write_hint = True
    if sub in spec.spec_subs or spec.net_always:
        for w in pos:
            _pkg_spec_word(a, w, spec)
    elif sub not in spec.plain_args:
        for w in pos:
            _generic_arg(a, w)


def _h_npm(a: _Acc, args: Sequence[Word], spec: PkgSpec) -> None:
    """npm / yarn / pnpm / bun: ``config set`` rewrites ~/.npmrc, bare ``yarn`` installs."""
    _h_pkg(a, args, spec)
    if a.sub in ("config", "c", "set") and any(w.text == "set" for w in args):
        a.write_hint = True
        a.path(Word("~/.npmrc", expands=True), "write")
        for w in args:
            if "://" in w.text:
                a.url(w.text)
    if a.prog in ("yarn", "bun") and a.sub is None:
        a.network = True
        a.exec_hint = True
        a.write_hint = True


def _h_npx(a: _Acc, args: Sequence[Word]) -> None:
    a.network = True
    a.exec_hint = True
    sc = _scan(args, _NPM_OPTS)
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    if "-c" in set(sc.flags):
        a.gray.append("npx-shell-command")
    for w in sc.pos[:1]:
        _pkg_spec_word(a, w, _PKG["npm"])
    for w in sc.pos[1:]:
        _generic_arg(a, w)


_DOCKER_GLOBAL = _opts(
    short="H=url c=x l=x",
    long="host=url config=r context=x log-level=x tlscacert=r tlscert=r tlskey=r",
    flags="debug tls tlsverify version help",
)
_DOCKER_GROUPS = _fs(
    "image container network volume system builder buildx compose manifest context trust plugin "
    "node service stack swarm secret config checkpoint"
)
_DOCKER_NET = _fs(
    "pull push run create build login search up import manifest scout install watch bake imagetools"
)
_DOCKER_EXEC = _fs("run exec create build up start watch bake")
_DOCKER_RUN_OPTS = _opts(
    short="v=vol e=x p=x w=x u=x h=x l=x a=x m=x c=x",
    long="volume=vol mount=mount env=x env-file=r publish=x workdir=x user=x name=x network=x "
    "net=x hostname=x entrypoint=cmd label=x platform=x add-host=x cap-add=x cap-drop=x "
    "device=u dns=x memory=x cpus=x restart=x pull=x log-driver=x security-opt=x tmpfs=x "
    "volumes-from=x group-add=x ulimit=x shm-size=x cidfile=w pid=x ipc=x uts=x userns=x "
    "cgroupns=x gpus=x health-cmd=cmd label-file=r",
    flags="rm detach interactive tty privileged read-only init",
)
_DOCKER_BUILD_OPTS = _opts(
    short="f=r t=x o=out",
    long="file=r tag=x build-arg=x secret=secret ssh=x output=out target=x platform=x network=x "
    "cache-from=x cache-to=x label=x progress=x iidfile=w add-host=x",
    flags="push load no-cache pull quiet",
)
_DOCKER_COMPOSE_OPTS = _opts(
    short="f=r p=x",
    long="file=r project-name=x project-directory=r env-file=r profile=x parallel=x progress=x "
    "ansi=x",
)
_DOCKER_SUB_OPTS: dict[str, Opts] = {
    "run": _DOCKER_RUN_OPTS,
    "create": _DOCKER_RUN_OPTS,
    "build": _DOCKER_BUILD_OPTS,
    "save": _opts(short="o=w", long="output=w"),
    "export": _opts(short="o=w", long="output=w"),
    "load": _opts(short="i=r", long="input=r"),
    "login": _opts(short="u=x p=x", long="username=x password=x"),
}


def _container_path(text: str) -> str | None:
    """The path part of ``CONTAINER:PATH`` (docker cp); None for a local path."""
    colon = text.find(":")
    if colon > 1 and "/" not in text[:colon]:
        return text[colon + 1 :]
    return None


def _docker_image(a: _Acc, w: Word) -> None:
    ref = w.text
    if "/" in ref:
        first = ref.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            a.url(first)
    elif w.expands or w.glob:
        a.url(ref)


def _h_docker(a: _Acc, args: Sequence[Word]) -> None:
    sc0 = _scan(args, _DOCKER_GLOBAL, stop_at_pos=True)
    a.flags.extend(sc0.flags)
    _apply_values(a, sc0.values)
    if sc0.stop is None:
        return
    sub = sc0.stop.text
    rest = sc0.rest
    group: str | None = None
    if sub in _DOCKER_GROUPS:
        group = sub
        gopts = _DOCKER_COMPOSE_OPTS if sub == "compose" else _NOOPTS
        sc1 = _scan(rest, gopts, stop_at_pos=True)
        a.flags.extend(sc1.flags)
        _apply_values(a, sc1.values)
        if sc1.stop is None:
            a.sub = sub
            return
        sub = sc1.stop.text
        rest = sc1.rest
    a.sub = sub
    if sc0.stop.expands or sc0.stop.glob:
        a.gray.append("docker-dynamic-subcommand")
    if sub in _DOCKER_NET or (group == "compose" and sub in ("pull", "push", "up", "build", "run")):
        a.network = True
    if sub in _DOCKER_EXEC:
        a.exec_hint = True
    sc = _scan(rest, _DOCKER_SUB_OPTS.get(sub, _NOOPTS))
    a.flags.extend(sc.flags)
    a.note_dynamic(sc)
    _apply_values(a, sc.values)
    if "--volumes-from" in sc.flags:
        a.gray.append("docker-volumes-from")  # mounts whatever host paths another container has
    pos = sc.pos
    if sub in ("pull", "push", "login", "search", "tag") or (group == "manifest"):
        for w in pos:
            if sub == "login":
                a.url(w.text)
            else:
                _docker_image(a, w)
    elif sub in ("run", "create"):
        if pos:
            _docker_image(a, pos[0])
    elif sub == "build":
        for w in pos[:1]:
            if _urllike(w.text):
                a.target(w)
            elif w.text != "-":
                a.path(w, "read")
    elif sub == "cp":
        in_container = [_container_path(w.text) for w in pos[:2]]
        for idx, w in enumerate(pos[:2]):
            if in_container[idx] is not None:
                continue
            a.path(w, "read" if idx == 0 else "write")
        if len(pos) >= 2 and in_container[0] is not None and in_container[1] is None:
            # the container path may be a directory: ``ctr:/etc/.`` copies its contents
            _write_children(a, pos[1], [_child_names(in_container[0])])
    elif sub == "import":
        for w in pos[:1]:
            if _urllike(w.text):
                a.target(w)
            else:
                a.path(w, "read")


_GH_OPTS = _opts(
    short="R=x t=x b=x H=x q=x X=x f=x B=x F=gF",
    long="repo=x title=x body=x base=x head=x method=x header=x jq=x template=x hostname=url "
    "input=r body-file=r notes-file=r cache=x field=gF raw-field=x branch=x",
    flags="paginate silent include verbose web draft",
)
_GH_LOCAL = _fs("config completion alias help version")


def _h_gh(a: _Acc, args: Sequence[Word]) -> None:
    sc0 = _scan(args, _GH_OPTS)
    a.flags.extend(sc0.flags)
    a.note_dynamic(sc0)
    pos = list(sc0.pos)
    sub = pos[0].text if pos else None
    a.sub = sub
    api = sub == "api"
    for opt, role, w in sc0.values:
        if opt == "-F":
            _apply(a, opt, "gF" if api else "r", w)
        else:
            _apply(a, opt, role, w)
    if sub is not None and sub not in _GH_LOCAL:
        a.network = True
    sub2 = pos[1].text if len(pos) > 1 else None
    seen = set(sc0.flags)
    if sub == "auth" and (sub2 == "token" or seen & {"-t", "--show-token"}):
        a.secret_hint = True
    if sub in ("gist", "release") and sub2 in ("create", "upload", "edit"):
        for w in pos[2:]:
            a.path(w, "read")
    else:
        for w in pos[1:]:
            if _urllike(w.text):
                a.target(w)
            elif _outside_like(w.text) or w.expands or w.glob:
                a.path(w, "unknown")


# ---------------------------------------------------------------------------------------------
# Programs that can run a shell command from inside (command-line ex commands, dot commands, ...)
# ---------------------------------------------------------------------------------------------

_EMACS_CODE = _fs(
    "--eval -eval --funcall -funcall -f --load -l -load --script -script --execute -execute"
)


def _gray_exec(a: _Acc, reason: str) -> None:
    a.exec_hint = True
    a.gray.append(reason)


def _h_editor(a: _Acc, args: Sequence[Word], spec: Spec) -> None:
    """vim / nvim / ex / emacs: ``-c '!cmd'``, ``+'!cmd'``, ``-S script`` and friends run code.

    Any command given on the command line (any ex command can say ``!``, ``:py3``, ``:source``,
    ``:terminal``) makes the action gray with the ``exec`` tag; plain ``vim file`` stays as it was.
    """
    _h_files(a, args, spec)
    sc = _scan(args, spec.opts)
    for opt, _, w in sc.values:
        if opt == "-c":
            _gray_exec(a, "editor-command:-c")
        elif opt in ("-S", "-s"):
            _gray_exec(a, "editor-script")
        elif opt == "-u" and w.text not in ("NONE", "NORC", "DEFAULTS"):
            _gray_exec(a, "editor-vimrc")
    for w in args:
        t = w.text
        if t.startswith("+") and len(t) > 1 and not t[1:].isdigit():
            _gray_exec(a, "editor-command:+")
        elif t == "--cmd" or t.startswith("--cmd="):
            _gray_exec(a, "editor-command:--cmd")
        elif a.prog == "emacs" and t.partition("=")[0] in _EMACS_CODE:
            _gray_exec(a, "editor-command:emacs")


_SQLITE_SAFE_DOT = _fs(
    ".tables .schema .headers .header .mode .help .quit .exit .indexes .indices .databases .show "
    ".timer .width .separator .nullvalue .dump .fullschema .print .bail .changes .stats .eqp"
)
_SQLITE_RISKY_SQL = ("attach", "load_extension", "writefile", "readfile", "edit(", "vacuum")


def _dot_command(stripped: str) -> str | None:
    """The name of a sqlite3 dot command (``.shell id`` -> ``.shell``), None for anything else."""
    if not stripped.startswith("."):
        return None
    head = stripped.split()[0]
    return head.lower() if head[1:].isalpha() else None


def _h_sqlite(a: _Acc, args: Sequence[Word]) -> None:
    """sqlite3: ``.shell`` / ``.system`` run commands; ``.output`` / ``.read`` / ``.load`` / SQL
    ``ATTACH`` / ``writefile()`` touch arbitrary files or code. Only listing dot commands are
    fine."""
    _h_unknown(a, args)
    texts: list[str] = []
    rest: list[Word] = []
    pending = ""
    for w in args:
        if pending:
            if pending == "-cmd":
                texts.append(w.text)
            else:
                a.path(w, "read")
                _gray_exec(a, "sqlite-init-file")
            pending = ""
        elif w.text in ("-cmd", "-init"):
            pending = w.text
        else:
            rest.append(w)
    sc = _scan(rest, _NOOPTS)
    for w in sc.pos[:1]:
        a.path(w, "unknown")  # the database file: may be created, read or written
    texts += [w.text for w in sc.pos[1:]]
    for text in texts:
        for line in text.splitlines() or [""]:
            stripped = line.strip()
            dot = _dot_command(stripped)
            if dot is not None:
                if dot not in _SQLITE_SAFE_DOT:
                    _gray_exec(a, f"sqlite-dot-command:{dot}")
            elif any(token in stripped.lower() for token in _SQLITE_RISKY_SQL):
                _gray_exec(a, "sqlite-sql-file-or-code")


_PSQL_BENIGN_META = _fs(
    "d dt di ds dv dn df du dg dp dT dD dx dE conninfo l list timing x c connect q ?"
)


def _h_psql(a: _Acc, args: Sequence[Word]) -> None:
    """psql: ``-c '\\\\! cmd'`` (and ``\\\\o |cmd``, ``\\\\copy .. program``) run local commands; a
    ``-f`` script may contain any of them."""
    _h_unknown(a, args)
    pairs = list(pairwise(args))
    values = [w.text for prev, w in pairs if prev.text in ("-c", "--command")]
    values += [w.text.partition("=")[2] for w in args if w.text.startswith("--command=")]
    values += [w.text[2:] for w in args if w.text.startswith("-c") and len(w.text) > 2]
    for text in values:
        for line in text.splitlines() or [""]:
            stripped = line.strip()
            if stripped.startswith("\\"):
                words = stripped[1:].split(None, 1)
                meta = words[0] if words else ""
                name = "!" if meta.startswith("!") else meta.rstrip("+S")
                if name not in _PSQL_BENIGN_META:
                    _gray_exec(a, f"psql-meta-command:{name or '?'}")
            elif "program" in stripped.lower() and "copy" in stripped.lower():
                _gray_exec(a, "psql-copy-program")
    files = [w for prev, w in pairs if prev.text in ("-f", "--file")]
    files += [_sub(w, w.text[7:]) for w in args if w.text.startswith("--file=")]
    for w in files:
        a.path(w, "read")
        _gray_exec(a, "psql-script-file")  # a script may contain any meta command


_MYSQL_RISKY_BACKSLASH = frozenset({"\\!", "\\.", "\\P", "\\T", "\\e"})
_MYSQL_RISKY_WORDS = _fs("system source pager tee edit")


def _h_mysql(a: _Acc, args: Sequence[Word]) -> None:
    """mysql / mariadb: ``-e 'system cmd'`` / ``source file`` / ``pager cmd`` run local
    commands or read local files; ``--pager`` names a program."""
    _h_unknown(a, args)
    pairs = list(pairwise(args))
    values = [w.text for prev, w in pairs if prev.text in ("-e", "--execute", "--init-command")]
    for w in args:
        t = w.text
        if t.startswith(("--execute=", "--init-command=")):
            values.append(t.partition("=")[2])
        elif t.startswith("-e") and len(t) > 2 and not t.startswith("--"):
            values.append(t[2:])
        elif t.startswith(("--pager=", "--tee=")):
            _gray_exec(a, "mysql-pager")
    for text in values:
        low = text.lower()
        if "infile" in low or "outfile" in low or "dumpfile" in low:
            _gray_exec(a, "mysql-file-statement")
        for stmt in text.replace("\n", ";").split(";"):
            words = stmt.strip().split(None, 1)
            if not words:
                continue
            first = words[0]
            if first in _MYSQL_RISKY_BACKSLASH or first.lower() in _MYSQL_RISKY_WORDS:
                _gray_exec(a, f"mysql-statement:{first.lower()}")


# ---------------------------------------------------------------------------------------------
# Unknown programs and generic arguments
# ---------------------------------------------------------------------------------------------

# Names of programs that matter: when an UNKNOWN program is given one of them as an argument it
# may well run it (``mytool rm -rf ~``, ``wrapper-we-do-not-know git push``): the line is gray.
_PROGRAM_NAMES = _fs(
    "rm rmdir mv cp ln dd shred truncate chmod chown chgrp cat tee tar zip unzip git gh curl wget "
    "ssh scp sftp rsync nc ncat netcat socat telnet ftp sudo doas su bash sh zsh dash ksh fish "
    "python python2 python3 pypy perl ruby node nodejs php lua pwsh powershell cmd eval env xargs "
    "find awk sed docker podman kubectl npm npx pip pip3 openssl crontab at"
)


def _program_in_arguments(a: _Acc, args: Sequence[Word]) -> None:
    """Gray an unknown program whose arguments look like a known program name."""
    for w in args:
        text = w.text
        for candidate in (text, text.partition("=")[2]) if text.startswith("-") else (text,):
            base = candidate.replace("\\", "/").rsplit("/", 1)[-1]
            if base.lower().endswith(".exe"):
                base = base[:-4]
            name = _canon_program(base).lower()
            if name in _PROGRAM_NAMES:
                a.gray.append(f"program-in-arguments:{name}")
                return


def _url_tail(text: str) -> str:
    """The URL inside ``--proxy=http://h`` / ``key=http://h``: from the scheme start on."""
    sep = text.find("://")
    start = sep
    while (
        start > 0
        and text[start - 1].isascii()
        and (text[start - 1].isalnum() or text[start - 1] in "+.-")
    ):
        start -= 1
    while start < sep and not (text[start].isascii() and text[start].isalpha()):
        start += 1
    return text[start:]


def _generic_arg(a: _Acc, w: Word) -> None:
    """One argument of a program we have no grammar for: list paths and URLs, drop nothing."""
    t = w.text
    if t[:5].lower() == "file:":
        a.target(w)
    elif "://" in t:
        a.url(_url_tail(t))
    elif _scp_like(t):
        a.url(t)
    elif _pathlike(t) or w.expands or w.glob:
        a.path(w, "unknown")


def _h_unknown(a: _Acc, args: Sequence[Word], *, single_dash_long: bool = False) -> None:
    a.known = False
    sc = _scan(args, _NOOPTS, single_dash_long=single_dash_long)
    a.flags.extend(sc.flags)
    for opt, role, w in sc.values:
        _apply(a, opt, role, w)
    for w in args:
        if w.text.startswith("-") and "://" in w.text:
            a.url(_url_tail(w.text))
    for w in sc.pos:
        _generic_arg(a, w)
    if a.urls:
        a.network = True


# ---------------------------------------------------------------------------------------------
# Redirects, environment, dispatch
# ---------------------------------------------------------------------------------------------

_WRITE_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>"})
_ENV_PROXY = frozenset({"http_proxy", "https_proxy", "all_proxy", "ftp_proxy"})
_ENV_HOME = frozenset({"home", "pwd", "oldpwd"})  # what ``~`` and relative paths mean
_ENV_CODE = frozenset(
    {
        "ld_preload",
        "ld_library_path",
        "dyld_insert_libraries",
        "dyld_library_path",
        "bash_env",
        "env",
        "path",
        "pythonstartup",
        "pythonpath",
        "node_options",
        "git_ssh_command",
        "git_ssh",
        "git_proxy_command",
        "git_external_diff",
        "git_askpass",
        "ssh_askpass",
        "git_pager",
        "pager",
        "editor",
        "visual",
        "perl5opt",
        "rubyopt",
        "prompt_command",
        # expanded (with command substitution) or executed by a shell / pager / interpreter
        "ps4",
        "lessopen",
        "lessclose",
        "ld_audit",
        "shellopts",
        "bashopts",
        "pythonhome",
        "perl5lib",
        "rubylib",
        "node_path",
        "java_tool_options",
        "_java_options",
        "jdk_java_options",
    }
)


def is_code_env(name: str) -> bool:
    """True for an environment variable whose VALUE becomes code (or changes what loads).

    ``LD_PRELOAD``, ``PS4``, ``BASH_ENV``, ``PROMPT_COMMAND``, ``GIT_SSH_COMMAND``,
    ``PYTHONSTARTUP``, ``NODE_OPTIONS``, ``LESSOPEN``, ``BASH_FUNC_*``, ``GIT_CONFIG_*`` and the
    like (case-insensitive: Windows environment variables are). Used by the Bash parser for
    standalone / ``export`` / ``declare`` assignments and by ``classify`` for the ``NAME=v cmd``
    prefix, so both layers agree.
    """
    low = name.lower()
    return low in _ENV_CODE or low.startswith(("git_config_", "bash_func_"))


def _apply_redirects(a: _Acc, redirects: Sequence[Redirect]) -> None:
    for r in redirects:
        tgt = r.target
        if tgt is None:
            continue
        op = r.op
        t = tgt.text
        if op in _WRITE_REDIRECTS:
            a.path(tgt, "write")
        elif op == "<":
            a.path(tgt, "read")
        elif op == "<>":
            a.path(tgt, "unknown")
        elif op == ">&":
            if not (t.isascii() and t.isdigit()) and t != "-":
                a.path(tgt, "write")
        elif op == "<&":
            if not (t.isascii() and t.isdigit()) and t != "-":
                a.path(tgt, "read")
        elif op in ("<<", "<<<"):
            continue
        else:
            a.path(tgt, "unknown")  # an operator we do not know: assume it may touch the target


def _apply_env(a: _Acc, env: Sequence[tuple[str, Word]]) -> None:
    for name, w in env:
        low = name.lower()
        if low in _ENV_PROXY and a.network:
            a.url(w.text)
        elif is_code_env(name):
            a.exec_hint = True
            a.gray.append(f"env-code-injection:{name}")
        elif low in _ENV_HOME:
            a.gray.append("home-reassigned")
        elif low == "cdpath":
            a.gray.append("cdpath-set")


def _resolve_program(program: str) -> tuple[str, str]:
    """(canonical name, status) with status ok | dynamic | path | case."""
    if not program or any(c in _DYNAMIC_PROGRAM_CHARS for c in program):
        return program, "dynamic"
    name = program
    if "/" in name or "\\" in name:
        cut = max(name.rfind("/"), name.rfind("\\"))
        directory = name[:cut].replace("\\", "/") or "/"
        base = name[cut + 1 :]
        if directory not in _SYSTEM_BIN_DIRS or not base:
            return program, "path"
        name = base
    if name.lower().endswith(".exe"):
        name = name[:-4]
    name = _canon_program(name)
    return name, "ok"


_DispatchFn = Callable[[_Acc, Sequence[Word]], None]


def _dispatch(name: str) -> _DispatchFn | None:
    if name in _FILES:
        spec = _FILES[name]
        if name in _EDITORS_WITH_COMMANDS:
            return lambda a, args: _h_editor(a, args, spec)
        return lambda a, args: _h_files(a, args, spec)
    if name in _NO_PATH_PROGRAMS:
        return _h_nopath
    simple: dict[str, _DispatchFn] = {
        "cd": _h_cd,
        "pushd": _h_cd,
        "popd": _h_nopath,
        "cp": _h_transfer,
        "mv": _h_transfer,
        "install": _h_transfer,
        "ln": _h_transfer,
        "dd": _h_dd,
        "source": _h_source,
        ".": _h_source,
        "eval": _h_eval,
        "sed": _h_sed,
        "awk": _h_awk,
        "gawk": _h_awk,
        "mawk": _h_awk,
        "nawk": _h_awk,
        "find": _h_find,
        "tar": _h_tar,
        "unzip": _h_unzip,
        "zip": _h_zip,
        "patch": _h_patch,
        "curl": _h_curl,
        "wget": _h_wget,
        "ssh": _h_ssh,
        "scp": _h_scp,
        "rsync": _h_rsync,
        "nc": _h_nc,
        "ncat": _h_nc,
        "netcat": _h_nc,
        "openssl": _h_openssl,
        "git": _h_git,
        "docker": _h_docker,
        "podman": _h_docker,
        "gh": _h_gh,
        "npx": _h_npx,
        "bunx": _h_npx,
        "pnpx": _h_npx,
        "sqlite3": _h_sqlite,
        "psql": _h_psql,
        "mysql": _h_mysql,
        "mariadb": _h_mysql,
    }
    if name in simple:
        return simple[name]
    if name in _INTERP_FAMILY:
        family = _INTERP_FAMILY[name]
        return lambda a, args: _h_interp(a, args, family)
    if name in _SHELLS:
        return lambda a, args: _h_interp(a, args, "shell")
    if name in _PKG:
        pkg = _PKG[name]
        if name in ("npm", "yarn", "pnpm", "bun"):
            return lambda a, args: _h_npm(a, args, pkg)
        return lambda a, args: _h_pkg(a, args, pkg)
    if name in _NETHOST_PROGRAMS or name in _NETCLI_PROGRAMS:
        return _h_nethost
    return None


_LAUNCHERS = _fs(
    "su runuser chroot nsenter unshare watch script flock systemd-run at batch screen tmux "
    "parallel entr gdb strace ltrace xvfb-run setarch taskset busybox valgrind perf cpulimit "
    "winpty start dbus-launch rlwrap torsocks runas faketime chrt proxychains proxychains4 tsocks "
    "unbuffer eatmydata firejail fakeroot prlimit setpriv"
)


def _classify(
    program: str,
    args: Sequence[Word],
    shell: Shell,
    redirects: Sequence[Redirect],
    env: Sequence[tuple[str, Word]],
) -> CmdInfo:
    name, status = _resolve_program(program)
    a = _Acc(name)
    if shell != "bash":
        a.known = False
        a.gray.append("powershell-not-classified")
        _h_unknown(a, args, single_dash_long=True)
    elif status == "dynamic":
        a.gray.append("dynamic-program")
        _h_unknown(a, args)
    elif status == "path":
        a.path(Word(program, expands=program[:1] == "~"), "unknown")
        _h_unknown(a, args)
        _program_in_arguments(a, args)
    else:
        handler = _dispatch(name)
        if handler is None and name.lower() != name:
            handler = _dispatch(name.lower())
            if handler is not None:
                a.gray.append(f"program-case-variant:{name}")
                a.prog = name = name.lower()
        if handler is None:
            _h_unknown(a, args)
            _program_in_arguments(a, args)
        else:
            handler(a, args)
        if name in _LAUNCHERS:
            a.gray.append(f"command-launcher:{name}")
    _apply_redirects(a, redirects)
    _apply_env(a, env)
    paths: list[tuple[Word, Access]] = list(dict.fromkeys(a.paths))
    network = a.network or bool(a.urls)
    flags = tuple(dict.fromkeys(a.flags))
    tags = derive_risk_tags(
        program=name,
        subcommand=a.sub,
        flags=flags,
        paths=paths,
        network=network,
        exec_hint=a.exec_hint,
        write_hint=a.write_hint,
        secret_hint=a.secret_hint,
    )
    return CmdInfo(
        known=a.known,
        subcommand=a.sub,
        flags=flags,
        paths=tuple(paths),
        urls=tuple(dict.fromkeys(a.urls)),
        network=network,
        tags=tags,
        gray=tuple(dict.fromkeys(a.gray)),
    )


def classify(
    program: str,
    args: Sequence[Word],
    *,
    shell: Shell,
    redirects: Sequence[Redirect] = (),
    env: Sequence[tuple[str, Word]] = (),
) -> CmdInfo:
    """Classify ONE simple command (program name plus its argument words).

    ``program`` is the program word's text (a program containing ``$`` or other shell syntax is
    dynamic: ``known=False`` plus a gray reason). ``args`` are the words after it, wrappers already
    stripped. ``redirects`` become paths (``>``, ``>>``, ``&>`` write; ``<`` reads). ``env`` is the
    optional ``NAME=value`` prefix list: proxy variables become URLs when the command talks to the
    network and code-injecting ones (``LD_PRELOAD``, ``PATH``, ``GIT_SSH_COMMAND``, ...) make the
    command gray. For ``shell="powershell"`` nothing is understood: ``known=False``, gray.

    Never raises: an internal error yields ``known=False``, every risk tag and a gray reason.
    Unknown programs get ``known=False``; path-looking, expanding or globbing arguments become
    ``(word, "unknown")`` paths and URL-looking ones go to ``urls``. See ``derive_risk_tags`` for
    the tag rules.
    """
    try:
        return _classify(program, args, shell, redirects, env)
    except Exception:  # noqa: BLE001 - a classifier that raises would fail the gate open
        return CmdInfo(
            known=False,
            subcommand=None,
            flags=(),
            paths=(),
            urls=(),
            network=False,
            tags=_ALL_TAGS,
            gray=("classify-internal-error",),
        )
