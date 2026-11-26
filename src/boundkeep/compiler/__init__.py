"""Policy proposals and their compilation into the policy file (M4, PROJECT_SPEC.md §8.1).

A proposal (new rules and tests) comes from the configured LLM backend (``policy add``) or from a
YAML file the user pasted back from any tool (``policy prompt`` + ``policy check``). Either way it
goes through the same deterministic checks, the replay preview and the user's confirmation before
``writer`` appends it to the policy file. Nothing a proposal says decides what the checks find.
"""
