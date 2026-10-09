# boundkeep（守界）

**A runtime guardrail for coding agents (Claude Code first).** It sits between the agent and your machine and decides, for every tool call, whether to allow it, ask you, or block it. It works without any LLM; an LLM auditor is an optional add-on.

> Status: design phase, v0 in development. Nothing below is released yet; sections marked TODO are filled in only after they are built or measured.

## Why

Coding agents run commands, edit files and fetch web pages on your machine. Two things go wrong:

- The agent makes a mistake: a wrong `rm -rf`, a force push to the wrong branch.
- The agent is hijacked: a web page, issue or dependency README contains hidden instructions, and the agent follows them.

The usual options are poor. Confirm every step and you stop reading the prompts; allow everything and one bad action is a real incident.

## What it does

Every tool call passes up to three layers:

1. **Rules** decide the clear cases instantly: block reading `~/.ssh`, block recursive deletes outside the project, ask before a force push.
2. **Session state** remembers your task and whether the agent just read untrusted content, and tightens decisions accordingly.
3. **An optional LLM auditor** looks only at the gray areas and checks the action against what you actually asked the agent to do.

Without the LLM layer, gray-area actions simply ask you. When an action is blocked, the reason is fed back to the agent so it can take a safer path. Every decision is written to a local audit log.

By default it never auto-approves anything on your behalf: actions the rules consider safe are handed back to Claude Code's normal permission flow. Auto-approval is an explicit opt-in.

## Bring your own LLM (optional)

The auditor is pluggable. The planned reference backend speaks the OpenAI-compatible chat API (DeepSeek is the first preset); an Anthropic backend is an optional extra. You supply your own key through `BOUNDKEEP_LLM_API_KEY`. A backend is only listed as supported after it passes the backend contract tests and a real run. Results are always reported per backend and model; they are not extrapolated across models.

Your Claude Code subscription is for using Claude Code. boundkeep never uses it as an LLM backend.

## Demo

TODO: a short recording. Without boundkeep, an agent following a hidden instruction on a web page leaks a file. With it, the action is blocked and the reason is shown.

## Install

TODO (planned): `pip install boundkeep` then `boundkeep init`.
Start in `audit-only` mode to see what it would have done before you let it block anything. No API key is needed for the default setup.

## Development setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run pytest -q          # unit, platform and end-to-end tests: no network, no API keys
uv run ruff check .
uv run mypy
uv run boundkeep --help
```

Where the project stands (milestone M0): the path from a Claude Code hook to a resident daemon and the audit log works, fails safe (daemon down, timeouts, bad input all degrade to "ask"), and `boundkeep doctor` looks for the ways the gate can be switched off silently. **There are no rules yet**: the placeholder pipeline only blocks shell commands that contain the marker `BOUNDKEEP_CANARY`; real rules arrive in M1. Do not rely on it to protect anything today. Note that while the daemon is not running (`boundkeep serve`), every tool call pops up Claude Code's confirmation box, and in both VS Code and the CLI that box does not show boundkeep's explanation (verified in M0 manual acceptance); run `boundkeep doctor` if you see unexplained confirmations.

To try it in a throwaway directory (never your real project settings):

```
uv run boundkeep init --project-dir <throwaway-dir>
uv run boundkeep serve                      # keep this terminal open
uv run boundkeep doctor --project-dir <throwaway-dir>
uv run boundkeep uninstall --project-dir <throwaway-dir>
```

Platform support is stated per platform and host only after it has been run for real (`docs/platforms.md`); until then it is a design goal, not a claim.

## Results

TODO: filled from `eval/report.md` after the evaluation runs. No numbers are claimed until then.
Planned ablation: rules only, rules + taint, rules + LLM, rules + LLM + taint. Planned metrics: attack interception rate, false-positive rate on normal work, prompts per 100 actions, LLM call ratio, p50/p95 latency.

## Privacy

With no LLM backend configured, nothing leaves your machine. With a backend, only structured metadata about the action (tool, normalized command, paths, domains, a short task summary) is sent, after redaction; file contents and raw tool output are never sent. See `docs/privacy.md` (TODO) for each backend.

## What it is not

- Not a sandbox. Hooks run with your privileges; use a container or OS sandbox for strong isolation.
- Not perfect defense. The goal is to raise the cost of an attack, not to make attacks impossible.
- Only covers Claude Code tool calls, not other programs on your machine. Files you attach with `@` do not go through tool-call hooks.
- Taint tracking is coarse: sources are recognized by tool name only.

## Design origin

The layered design, fail-closed behavior and "raise attacker cost" goal come from [injection-blast-radius](https://github.com/JiachengWu591/injection-blast-radius), a prompt-injection defense reference design. boundkeep is its applied follow-up, developed as an independent project.

It is complementary to static scanners such as cc-audit, which check what you install; boundkeep checks what the agent does at runtime.

## Docs

- `PROJECT_SPEC.md`: full design, policy format and evaluation plan
- `IMPLEMENTATION_PROMPTS.md`: step-by-step implementation prompts
- `docs/architecture.md`: the hook-to-daemon path, protocol, degradation table
- `docs/hook-behavior.md`: measured Claude Code hook behavior (versioned)
- `docs/platforms.md`: what has been run on which platform and host
- `docs/threat-model.md`: TODO
- `docs/design-origin.md`: TODO

## License

MIT
