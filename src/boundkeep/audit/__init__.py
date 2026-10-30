"""The optional LLM audit of gray tool calls (PROJECT_SPEC.md §9).

``send_gate`` is the only way content reaches a backend; ``backends`` are the adapters (``fake`` for
tests, ``openai_compatible``); ``verdict`` is the code's ruling on what a model said; ``cache``
remembers valid verdicts for a while; ``auditor`` puts them together for the pipeline.
"""

from __future__ import annotations
