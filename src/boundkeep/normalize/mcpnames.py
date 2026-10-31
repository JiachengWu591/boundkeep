"""What an MCP tool's name says about the paths in its arguments (read, or maybe written).

A module of its own, with no imports from the policy package: ``session.marks`` (imported by the
policy matcher) needs it, and ``normalize.event`` imports the policy package.
"""

from __future__ import annotations

import re
from typing import Final

from boundkeep.normalize.model import Access

# a tool whose name STARTS with one of these words and holds none of the write words only reads
# its paths; any other tool may read or write them (access "unknown" meets the read and the
# write rules): `get_and_store` may write (X1 review R10-1)
_MCP_READ_WORDS: Final = frozenset(
    {
        "read", "get", "list", "search", "find", "view", "show", "stat", "describe", "info",
        "cat", "head", "tail", "ls", "tree", "glob", "grep", "count", "lookup", "inspect",
        "query", "snapshot",
    }
)  # fmt: skip
_MCP_WRITE_WORDS: Final = frozenset(
    {
        "write", "create", "edit", "update", "delete", "remove", "move", "rename", "put", "post",
        "push", "send", "set", "add", "merge", "upload", "copy", "apply", "run", "exec",
        "execute", "insert", "drop", "share", "publish", "terminate", "kill", "install",
        "deploy", "commit", "close", "approve", "save", "patch", "replace", "append",
        "truncate", "download", "store", "persist", "sync", "import", "export", "transfer",
        "fork", "clone", "checkout", "mkdir", "touch", "chmod", "link", "archive", "restore",
        "reset", "revert", "rollback", "cancel", "stop", "start", "restart", "trigger", "invoke",
        "call", "submit", "assign", "comment", "reply", "review", "label", "tag", "release",
        "enable", "disable", "configure", "register", "login", "logout", "schedule", "generate",
        "build", "compile", "convert", "extract", "unzip", "zip", "encrypt", "decrypt", "sign",
        "render", "print", "cache", "clear", "clean", "purge", "prune", "destroy", "revoke",
        "grant", "mark", "lock", "unlock", "resolve", "dismiss",
    }
)  # fmt: skip
_CAMEL_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def mcp_access(name: str | None) -> Access:
    """How an MCP tool named ``name`` uses the paths in its arguments, judged by its verb: "read"
    or "unknown" (it may write; the project marks of revision 8 count it as a write, P-R6)."""
    words = [w.casefold() for w in _CAMEL_WORDS.findall(name or "")]
    if words and words[0] in _MCP_READ_WORDS and not set(words) & _MCP_WRITE_WORDS:
        return "read"
    return "unknown"
