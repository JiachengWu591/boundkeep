"""Where boundkeep keeps its own files.

Standard library only (``os.path``, no ``pathlib``): the hook client imports this under
``python -I -S`` and pays for every import on every tool call.

Layout under the home directory (all private to the current user, see ``fsperm``)::

    <home>/endpoint.json     IPC endpoint written by ``init`` (transport, address with random token)
    <home>/policy.yaml       the active policy (M0: version, mode, emit_allow, taint.sources)
    <home>/installs.json     settings files ``init`` modified and the entries it owns
    <home>/logs/audit.jsonl  audit log (rotated: audit.jsonl.1, audit.jsonl.2, ...)
    <home>/serve.lock, serve.pid  single-instance lock and pid of the running daemon
    <home>/backups/          copies of settings files taken before ``init`` modifies them

``BOUNDKEEP_HOME`` overrides the home directory; tests always set it to a temporary directory so
they never touch the real one.
"""

from __future__ import annotations

import os

HOME_ENV = "BOUNDKEEP_HOME"


def home_dir() -> str:
    """The boundkeep home directory (not created here). ``~/.boundkeep`` unless overridden."""
    override = os.environ.get(HOME_ENV)
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), ".boundkeep")


def same_file(a: str, b: str) -> bool:
    """True when two spellings name the same file: equal after normalisation, or the same inode.

    Covers what a lexical compare misses on Windows (junctions, 8.3 short names, ``\\\\?\\``
    prefixes, trailing dots). Never raises: a file that cannot be inspected is just "not the same".
    """
    if os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b)):
        return True
    try:
        return os.path.samefile(a, b)
    except (OSError, ValueError):
        return False


def _under(name: str, home: str | None) -> str:
    return os.path.join(home if home is not None else home_dir(), name)


def endpoint_file(home: str | None = None) -> str:
    return _under("endpoint.json", home)


def policy_file(home: str | None = None) -> str:
    return _under("policy.yaml", home)


def manifest_file(home: str | None = None) -> str:
    return _under("installs.json", home)


def log_dir(home: str | None = None) -> str:
    return _under("logs", home)


def audit_log_file(home: str | None = None) -> str:
    return os.path.join(log_dir(home), "audit.jsonl")


def lock_file(home: str | None = None) -> str:
    return _under("serve.lock", home)


def pid_file(home: str | None = None) -> str:
    return _under("serve.pid", home)


def backups_dir(home: str | None = None) -> str:
    return _under("backups", home)
