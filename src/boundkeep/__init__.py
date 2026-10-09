"""boundkeep: runtime guardrail for coding agents (Claude Code first).

Keep this module import-light: the hook client imports ``boundkeep.*`` submodules under
``python -I -S`` and every extra import is paid on every tool call.
"""

__version__ = "0.0.0.dev0"
