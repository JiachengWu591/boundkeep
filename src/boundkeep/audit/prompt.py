"""The fixed system prompt of the audit (PROJECT_SPEC.md §9.6): one file, versioned, hashed.

``prompts/audit_system.md`` holds no user data; the hash of its text goes into every audit log
record and into the cache key, so a result is never reused across prompt versions. Every text the
prompt has had is listed in ``VERSIONS``: changing the file means adding its hash here (a unit test
fails otherwise), and from M3b on an entry in docs/prompt-changelog.md as well.
"""

from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PROMPT_PATH: Final = Path(__file__).with_name("prompts") / "audit_system.md"
VERSIONS: Final[dict[str, str]] = {
    "6af800076bda27df09348dea0e4f21751a8cb142ac90f13c493ce70d26ddf99d": "1",
}
UNVERSIONED: Final = "unversioned"


@dataclass(frozen=True, slots=True)
class SystemPrompt:
    text: str
    sha256: str
    version: str

    @property
    def short_hash(self) -> str:
        return self.sha256[:16]


@functools.lru_cache(maxsize=1)
def system_prompt() -> SystemPrompt:
    """The prompt as sent (line ends normalized to LF). Raises ``OSError`` / ``UnicodeError``."""
    text = PROMPT_PATH.read_bytes().decode("utf-8").replace("\r\n", "\n")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return SystemPrompt(text=text, sha256=digest, version=VERSIONS.get(digest, UNVERSIONED))
