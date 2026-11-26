"""The system prompt of policy proposals (PROJECT_SPEC.md §8.1): one file, hashed.

``prompts/propose.md`` holds no user data. The JSON Schemas of one rule and one test are exported
from the policy schema (pydantic) into it when it is loaded, so the prompt follows the schema; the
hash is taken of the text as sent. ``policy add`` sends exactly this text as the system prompt and
``policy prompt`` prints it, followed by the same user message (``send_gate.gate_policy_request``),
for the user to paste into any tool of their choice.
"""

from __future__ import annotations

import functools
import hashlib
import json
from pathlib import Path
from typing import Final

from boundkeep.audit.prompt import SystemPrompt
from boundkeep.policy.schema import PolicyTest, Rule

PROMPT_PATH: Final = Path(__file__).with_name("prompts") / "propose.md"
PROMPT_VERSION: Final = "1"

OFFLINE_HEADER: Final = (
    "Paste everything below this line into the LLM tool of your choice. Save its answer (the YAML "
    "of the proposal, a ```yaml block is fine) to a file and run, in your own terminal: "
    "boundkeep policy check <file>"
)
OFFLINE_ANSWER_FORMAT: Final = (
    "Answer with the proposal as one YAML document in a ```yaml block, and nothing else."
)


def _schema(model: type[Rule] | type[PolicyTest]) -> str:
    return json.dumps(model.model_json_schema(), ensure_ascii=True, sort_keys=True)


@functools.lru_cache(maxsize=1)
def system_prompt() -> SystemPrompt:
    """The prompt as sent (LF line ends, schemas filled in). Raises ``OSError`` /
    ``UnicodeError`` when the file is unreadable."""
    template = PROMPT_PATH.read_bytes().decode("utf-8").replace("\r\n", "\n")
    text = template.replace("{{RULE_SCHEMA}}", _schema(Rule)).replace(
        "{{TEST_SCHEMA}}", _schema(PolicyTest)
    )
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return SystemPrompt(text=text, sha256=digest, version=PROMPT_VERSION)


def offline_text(system: str, content: str) -> str:
    """What ``policy prompt`` prints after its header: the system prompt, the user message and the
    answer format, as one text to paste."""
    return f"{system.rstrip()}\n\n# The user's message\n\n{content}\n\n{OFFLINE_ANSWER_FORMAT}\n"
