"""Turn a Claude Code session file into candidate benign samples, redacted before anything is written.

Input: the session JSONL under ``~/.claude/projects/<project>/<session>.jsonl`` (``%USERPROFILE%`` on
Windows): one JSON object per line; the assistant lines carry ``tool_use`` blocks, the user lines
carry the prompts, and a user line with a ``permissionDecision`` of ``reject`` marks a call the user
or the permission mode refused (those are skipped: they are not normal operations).

Output: sample rows (dicts) with ``label: benign`` and ``label_confirmed: false``. Nothing here
decides that a call is harmless; a person confirms every sample before it can count.

What is removed, in this order (a sample that trips a DROP rule is discarded and counted, never
"fixed", so a secret is not half-redacted into the repository):

* DROP: secret-looking strings (keys, tokens, JWT, private keys, ``NAME_TOKEN=value``, URLs with a
  password or a token in the query), internal host names, a command or input too large to read,
  and any absolute path that is neither inside the project, inside the home directory nor a system
  directory (it would name a real directory of the person's machine).
* REWRITE: the project directory and the home directory become the fake machine's, other user
  names in paths become ``testuser``, e-mail addresses become ``user@example.invalid``, IPv4
  addresses become ``192.0.2.1``, long file contents become ``<content omitted: N chars>``.

The result is checked once more with the same ``find_leaks`` the dataset loader uses.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from boundkeep.evalkit import redact
from boundkeep.evalkit.dataset import inert_problems
from boundkeep.evalkit.schema import Sample, content_key, split_of

#: built-in tools whose calls become samples; ``mcp__*`` tools are kept except the host's own
KEPT_TOOLS = frozenset(
    {"Bash", "PowerShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"}
)
HOST_TOOL_PREFIXES = ("mcp__ccd_",)

MAX_INPUT_CHARS = 1500  # longer than this and it is not a command a person can review at a glance
KEEP_CONTENT_CHARS = 300  # file contents longer than this are replaced by a placeholder
MAX_INTENT_CHARS = 160
CONTENT_KEYS = frozenset(
    {"content", "old_string", "new_string", "new_source", "old_source", "text"}
)

FAKE = {
    "windows": {"home": "C:\\Users\\testuser", "project": "C:\\Users\\testuser\\proj"},
    "posix": {"home": "/home/testuser", "project": "/home/testuser/proj"},
}
_WINDOWS_SYSTEM = ("c:/windows", "c:/program files", "c:/programdata")
_POSIX_SYSTEM = (
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/tmp",  # noqa: S108
    "/dev",
    "/proc",
    "/sys",
    "/opt",
    "/var",
    "/lib",
)

_ENV_SECRET = re.compile(
    r"(?i)\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSW(?:OR)?D|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Z0-9_]*"
    r"\s*[=:]\s*['\"]?[^\s'\"$<{(]{6,}"
)
_URL_CREDENTIALS = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
_URL_TOKEN_QUERY = re.compile(
    r"(?i)[?&](?:token|key|secret|sig|signature|password|passwd|auth)=[^&\s]{6,}"
)
_TOKENISH = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_URL_HOST = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?:[^/\s@\"']*@)?(\[[0-9a-f:]+\]|[^/\s:?#\"']+)")
_WIN_ABS = re.compile(r"(?<![\w])[A-Za-z]:[\\/][^\s\"'<>|*?;,)]*")
_POSIX_ABS = re.compile(r"(?<![\w.:/~$-])/(?:[\w.@+-]+/)*[\w.@+-]+")
_PROMPT_NOISE = re.compile(r"(?s)<system-reminder>.*?</system-reminder>")
_REPO_CODE = re.compile(
    r"(?i)\b(?:pytest|ruff|mypy|pylint|flake8|black|isort|tox|nox|make|cmake|gradle|mvn|dotnet\s+(?:build|test|run)|"
    r"npm\s+(?:test|install|ci|run)|yarn|pnpm|cargo\s+(?:build|test|run)|go\s+(?:build|test|run)|"
    r"uv\s+(?:sync|run)|pip\s+install|docker\s+compose\s+up)\b"
)


@dataclass
class ImportStats:
    files: int = 0
    tool_calls: int = 0
    kept: int = 0
    dropped: Counter[str] = field(default_factory=Counter)

    def drop(self, reason: str) -> None:
        self.dropped[reason] += 1

    def lines(self) -> list[str]:
        out = [f"files: {self.files}", f"tool calls seen: {self.tool_calls}", f"kept: {self.kept}"]
        out += [f"dropped ({n}): {reason}" for reason, n in sorted(self.dropped.items())]
        return out


# ---------------------------------------------------------------------------- reading a session


def iter_session_files(paths: Iterable[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.jsonl"))
        else:
            yield path


def _entries(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                value = json.loads(raw)
            except ValueError:
                continue
            if isinstance(value, dict):
                out.append(value)
    return out


def _blocks(entry: dict[str, Any]) -> list[Any]:
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, list) else []


def _rejected_ids(entries: list[dict[str, Any]]) -> set[str]:
    """tool_use ids whose result carries a refusal (the call did not run as asked)."""
    out: set[str] = set()
    for entry in entries:
        decision = entry.get("permissionDecision")
        if isinstance(decision, dict) and decision.get("decision") == "reject":
            for block in _blocks(entry):
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    out.add(str(block.get("tool_use_id")))
    return out


def _prompt_text(entry: dict[str, Any]) -> str | None:
    """The text of a human prompt, or None when the entry is a tool result / meta / injected."""
    if entry.get("type") != "user" or entry.get("isMeta"):
        return None
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        text = " ".join(
            str(b.get("text", ""))
            for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        )
    else:
        return None
    text = _PROMPT_NOISE.sub(" ", text)
    if text.lstrip().startswith("<"):  # <command-name>, <local-command-stdout> ...
        return None
    text = " ".join(text.split())
    return text or None


# ---------------------------------------------------------------------------- what to drop


def _entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(c / len(token) * math.log2(c / len(token)) for c in counts.values())


def secret_reasons(text: str) -> list[str]:
    """Why ``text`` must not be committed even redacted (empty when nothing looks like a secret)."""
    reasons = [
        leak.kind
        for leak in redact.find_leaks(text)
        if leak.kind not in ("personal-path", "real-host")
    ]
    if _ENV_SECRET.search(text):
        reasons.append("secret-assignment")
    if _URL_CREDENTIALS.search(text):
        reasons.append("url-credentials")
    if _URL_TOKEN_QUERY.search(text):
        reasons.append("url-token")
    for match in _TOKENISH.finditer(text):
        token = match.group(0)
        mixed = any(c.islower() for c in token) and any(c.isupper() for c in token)
        if mixed and any(c.isdigit() for c in token) and _entropy(token) >= 3.8:
            reasons.append("high-entropy-token")
            break
    return reasons


def internal_host(text: str) -> str | None:
    for match in _URL_HOST.finditer(text):
        host = match.group(1).strip("[]").lower().rstrip(".")
        if redact.is_reserved_host(host):
            continue
        if "." not in host or host.endswith(
            (".local", ".internal", ".corp", ".lan", ".intranet", ".home")
        ):
            return host
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) and host.startswith(
            (
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.2",
                "172.30.",
                "172.31.",
                "169.254.",
            )
        ):
            return host
    return None


# ---------------------------------------------------------------------------- rewriting


@dataclass(frozen=True)
class Machine:
    """The real machine the session ran on, and the fake one the samples are rewritten to."""

    platform: str  # "windows" | "posix"
    project: str
    home: str
    user: str

    @property
    def fake_project(self) -> str:
        return FAKE[self.platform]["project"]

    @property
    def fake_home(self) -> str:
        return FAKE[self.platform]["home"]


def guess_machine(project: str, home: str | None) -> Machine:
    windows = bool(re.match(r"^[A-Za-z]:[\\/]", project)) or project.startswith("\\\\")
    if home is None:
        match = (
            re.match(r"^([A-Za-z]:[\\/]+Users[\\/]+[^\\/]+)", project)
            if windows
            else re.match(r"^(/(?:home|Users)/[^/]+)", project)
        )
        home = (
            match.group(1)
            if match
            else (project if windows else str(PurePosixPath(project).parent))
        )
    parts = PureWindowsPath(home).parts if windows else PurePosixPath(home).parts
    user = parts[-1] if parts else ""
    return Machine("windows" if windows else "posix", project, home, user)


def _replace_root(text: str, real: str, fake: str, windows: bool) -> str:
    if not real:
        return text
    if not windows:
        return text.replace(real.rstrip("/"), fake)
    back = real.rstrip("\\/").replace("/", "\\")
    forward = back.replace("\\", "/")
    text = re.sub(re.escape(back), lambda _m: fake, text, flags=re.IGNORECASE)
    return re.sub(re.escape(forward), lambda _m: fake.replace("\\", "/"), text, flags=re.IGNORECASE)


def rewrite(text: str, machine: Machine) -> str:
    windows = machine.platform == "windows"
    text = _replace_root(text, machine.project, machine.fake_project, windows)
    text = _replace_root(text, machine.home, machine.fake_home, windows)
    text = redact.redact(text, extra_names=[machine.user] if machine.user else [])
    text = _EMAIL.sub("user@example.invalid", text)
    keep = ("127.0.0.1", "0.0.0.0")  # noqa: S104
    return _IPV4.sub(lambda m: m.group(0) if m.group(0) in keep else "192.0.2.1", text)


def outside_paths(text: str, machine: Machine) -> list[str]:
    """Absolute paths in the (already rewritten) text that name a real directory elsewhere."""
    found: list[str] = []
    if machine.platform == "windows":
        roots = (*_WINDOWS_SYSTEM, machine.fake_home.replace("\\", "/").lower())
        for match in _WIN_ABS.finditer(text):
            norm = match.group(0).replace("\\", "/").lower()
            if not norm.startswith(roots):
                found.append(match.group(0))
    else:
        posix_roots = (*_POSIX_SYSTEM, machine.fake_home)
        for match in _POSIX_ABS.finditer(text):
            if not match.group(0).startswith(posix_roots):
                found.append(match.group(0))
    return found


def _walk(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {fn(str(k)): _walk(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, fn) for v in value]
    return value


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def omit_long_content(value: Any, key: str | None = None) -> Any:
    """File contents (``Write.content`` and friends) over the limit become a placeholder."""
    if isinstance(value, dict):
        return {k: omit_long_content(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [omit_long_content(v, key) for v in value]
    if isinstance(value, str) and key in CONTENT_KEYS and len(value) > KEEP_CONTENT_CHARS:
        return f"<content omitted: {len(value)} chars>"
    return value


def guess_runs_repo_code(tool: str, tool_input: dict[str, Any]) -> bool:
    """A starting point for the reviewer (who confirms it): does the command run project code?"""
    if tool not in ("Bash", "PowerShell"):
        return False
    return _REPO_CODE.search(str(tool_input.get("command", ""))) is not None


# ---------------------------------------------------------------------------- the importer


def tool_kept(name: str) -> bool:
    if name in KEPT_TOOLS:
        return True
    return name.startswith("mcp__") and not name.startswith(HOST_TOOL_PREFIXES)


def _build(
    tool: str,
    tool_input: dict[str, Any],
    intent: str,
    machine: Machine,
    stats: ImportStats,
    keep_intent: bool,
) -> dict[str, Any] | None:
    shortened = omit_long_content(tool_input)
    if len(json.dumps(shortened, ensure_ascii=False)) > MAX_INPUT_CHARS:
        stats.drop("too-long")
        return None
    texts = [*_strings(shortened), intent]
    for text in texts:
        reasons = secret_reasons(text)
        if reasons:
            stats.drop(f"secret:{reasons[0]}")
            return None
        host = internal_host(text)
        if host:
            stats.drop("internal-host")
            return None
    new_input = _walk(shortened, lambda s: rewrite(s, machine))
    if any(outside_paths(s, machine) for s in _strings(new_input)):
        stats.drop("outside-path")
        return None
    new_intent = rewrite(intent, machine)[:MAX_INTENT_CHARS] if keep_intent and intent else ""
    if not new_intent or outside_paths(new_intent, machine):
        new_intent = "(任务意图未记录)"
    platform = "windows" if (tool == "PowerShell" or machine.platform == "windows") else "posix"
    return {
        "category": "benign",
        "label": "benign",
        "platform": platform,
        "task_intent": new_intent,
        "tainted": False,
        "taint_sources": [],
        "tool": tool,
        "input": new_input,
        "expected_min_verdict": None,
        "rationale": "真实会话中的调用，已脱敏；待人工确认这是正常操作",
        "provenance": "redacted-real-session",
        "runs_repo_code": guess_runs_repo_code(tool, new_input),
        "label_confirmed": False,
    }


def import_session(
    path: Path,
    stats: ImportStats,
    *,
    project_dir: str | None = None,
    home: str | None = None,
    known: set[str] | None = None,
    keep_intent: bool = True,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Candidate benign samples from one session file (also updates ``stats``).

    ``known``: event keys already present (in the datasets or from earlier files); extended here.
    """
    stats.files += 1
    entries = _entries(path)
    rejected = _rejected_ids(entries)
    cwd = project_dir or next((str(e["cwd"]) for e in entries if isinstance(e.get("cwd"), str)), "")
    if not cwd:
        stats.drop("no-cwd")
        return []
    machine = guess_machine(cwd, home)
    session = next((str(e["sessionId"]) for e in entries if e.get("sessionId")), path.stem)
    tag = hashlib.sha1(session.encode("utf-8"), usedforsecurity=False).hexdigest()[:6]
    seen = known if known is not None else set()
    rows: list[dict[str, Any]] = []
    intent = ""
    call_index = 0  # position of the call in the session: the id never depends on what was dropped
    for entry in entries:
        prompt = _prompt_text(entry)
        if prompt is not None and not entry.get("isSidechain"):
            intent = prompt
        if entry.get("type") != "assistant":
            continue
        for block in _blocks(entry):
            if not (isinstance(block, dict) and block.get("type") == "tool_use"):
                continue
            stats.tool_calls += 1
            call_index += 1
            name = str(block.get("name", ""))
            tool_input = block.get("input")
            if not tool_kept(name) or not isinstance(tool_input, dict):
                stats.drop("tool-not-imported")
                continue
            if str(block.get("id")) in rejected:
                stats.drop("rejected-by-permission")
                continue
            row = _build(name, tool_input, intent, machine, stats, keep_intent)
            if row is None:
                continue
            row["id"] = f"ben-real-{tag}-{call_index:04d}"
            row["split"] = "dev"
            row["split"] = split_of(Sample.model_construct(**{**row, "pair": None}))
            try:
                sample = Sample.model_validate(row)
            except ValueError:
                stats.drop("invalid-sample")
                continue
            if inert_problems(sample):
                stats.drop("leak-after-redaction")
                continue
            key = content_key(sample)
            if key in seen:
                stats.drop("duplicate")
                continue
            seen.add(key)
            rows.append(row)
            stats.kept += 1
            if limit is not None and len(rows) >= limit:
                return rows
    return rows
