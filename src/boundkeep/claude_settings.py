"""What top-level keys a Claude Code settings.json is documented to have (for ``doctor``).

Standard library only. A GitHub report (anthropics/claude-code #98662) claims that an unknown
top-level key silently disables ALL hooks. That is UNVERIFIED (boundkeep has not reproduced it), so
every finding here is a warning or an info, never an error, and the message says so. A misplaced
hook event name (``PreToolUse`` next to ``hooks`` instead of inside it) and a typo of ``hooks`` are
the two mistakes that are wrong whatever Claude Code does with unknown keys: in both the gate the
user thinks they configured does not exist.

``KNOWN_TOP_LEVEL_KEYS`` is a snapshot of the official documentation and WILL lag behind Claude
Code; that is why an unrecognized key is only ``info``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from boundkeep import ownhook

# Read from the official settings reference. The reference page (settings-reference) lists the
# keys; the page at /docs/en/settings only covers files and precedence. Dotted entries in the
# reference (for example sandbox.enabled) are represented here by their top-level parent. The
# extraction was done through the WebFetch tool's summarizer over the whole page (418000
# characters, read in five slices), not by a person.
SNAPSHOT_DATE: Final = "2026-10-07"
SOURCE_URL: Final = "https://code.claude.com/docs/en/settings-reference"
SNAPSHOT_COMPLETE: Final = True

KNOWN_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",  # shown in the official example on /docs/en/settings
        "advisorModel",
        "agent",
        "agentPushNotifEnabled",
        "allowAllClaudeAiMcps",
        "allowClaudeInChromeWithManagedMcp",
        "allowedChannelPlugins",
        "allowedHttpHookUrls",
        "allowedMcpServers",
        "allowedProviders",
        "allowManagedHooksOnly",
        "allowManagedMcpServersOnly",
        "allowManagedPermissionRulesOnly",
        "alwaysThinkingEnabled",
        "apiKeyHelper",
        "appendPlugins",
        "askUserQuestionTimeout",
        "attribution",
        "autoCompactEnabled",
        "autoCompactWindow",
        "autoContinueAtUsageLimit",
        "autoMemoryDirectory",
        "autoMemoryEnabled",
        "autoMode",
        "autoScrollEnabled",
        "autoUpdatesChannel",
        "availableModels",
        "availableModelsMatch",
        "awaySummaryEnabled",
        "awsAuthRefresh",
        "awsCredentialExport",
        "axScreenReader",
        "bashEditDiffEnabled",
        "bashOutputMaxChars",
        "blockedMarketplaces",
        "browserExternalPageTools",
        "channelsEnabled",
        "claudeMd",
        "claudeMdExcludes",
        "cleanupPeriodDays",
        "companyAnnouncements",
        "crossSessionInbound",
        "defaultShell",
        "deniedMcpServers",
        "deniedModels",
        "desktopSessionCleanupPeriodDays",
        "dialogExpiry",
        "disableAgentView",
        "disableAllHooks",
        "disableArtifact",
        "disableAutoMode",
        "disableBrowserExternalNavigation",
        "disableBundledSkills",
        "disableClaudeAiConnectors",
        "disableCommandPluginSources",
        "disableDeepLinkRegistration",
        "disableDesktopLocalSessions",
        "disabledMcpjsonServers",
        "disableMobileSimulatorTools",
        "disableRemoteControl",
        "disableSideloadFlags",
        "disableSkillShellExecution",
        "disableWorkflows",
        "editorMode",
        "effortLevel",
        "emojiCompletionEnabled",
        "enableAllProjectMcpServers",
        "enableArtifact",
        "enabledMcpjsonServers",
        "enabledPlugins",
        "enableWorkflows",
        "enforceAvailableModels",
        "env",
        "extraKnownMarketplaces",
        "fallbackModel",
        "fastMode",
        "fastModePerSessionOptIn",
        "feedbackDrafts",
        "feedbackSurveyRate",
        "fileCheckpointingEnabled",
        "fileSuggestion",
        "footerLinksRegexes",
        "forceLoginGatewayUrl",
        "forceLoginMethod",
        "forceLoginOrgUUID",
        "forceRemoteSettingsRefresh",
        "gatewayInternalNetworks",
        "gcpAuthRefresh",
        "hooks",
        "httpHookAllowedEnvVars",
        "includeCoAuthoredBy",
        "includeGitInstructions",
        "inputNeededNotifEnabled",
        "isolatePeerMachines",
        "keybindingFlavor",
        "language",
        "managedMcpServers",
        "managedSourcesBehavior",
        "maxEffortLevel",
        "maxProseWidth",
        "minimumVersion",
        "model",
        "modelOverrides",
        "modelPicker",
        "modelPricing",
        "modelSettings",
        "otelHeadersHelper",
        "outputStyle",
        "parentSettingsBehavior",
        "permissions",
        "plansDirectory",
        "pluginConfigs",
        "pluginSuggestionMarketplaces",
        "pluginTrustMessage",
        "policyHelper",
        "preferredNotifChannel",
        "prefersReducedMotion",
        "prependPlugins",
        "processWrapper",
        "promptCacheTtl",
        "promptSuggestionEnabled",
        "prUrlTemplate",
        "remote",  # documented as remote.defaultEnvironmentId
        "remoteControlAtStartup",
        "requiredMaximumVersion",
        "requiredMinimumVersion",
        "respectGitignore",
        "respondToBashCommands",
        "sandbox",
        "showClearContextOnPlanAccept",
        "showThinkingSummaries",
        "showTurnDuration",
        "skillListingBudgetFraction",
        "skillListingMaxDescChars",
        "skillOverrides",
        "skipAutoPermissionPrompt",
        "skipDangerousModePermissionPrompt",
        "skipWebFetchPreflight",
        "spellcheck",
        "spinnerTipsEnabled",
        "spinnerTipsOverride",
        "spinnerVerbs",
        "sshConfigs",
        "sshHostAllowlist",
        "statusLine",
        "strictKnownMarketplaces",
        "strictPluginOnlyCustomization",
        "subagentPromptCacheTtl",
        "subagentStatusLine",
        "switchModelsOnFlag",
        "syncClaudeAiPlugins",
        "syncClaudeAiSkills",
        "syntaxHighlightingDisabled",
        "taskOutputMaxChars",
        "teammateMode",
        "terminalProgressBarEnabled",
        "terminalTitleFromRename",
        "theme",
        "timeFormat",
        "timeZone",
        "tui",
        "ultracode",
        "useAutoModeDuringPlan",
        "verbose",
        "viewMode",
        "vimInsertModeRemaps",
        "voice",
        "voiceEnabled",
        "wheelScrollAccelerationEnabled",
        "workflowKeywordTriggerEnabled",
        "workflowSizeGuideline",
        "worktree",
        "wslInheritsWindowsSettings",
    }
)

# Documented as "global config" keys: they belong in ~/.claude.json and the reference says Claude
# Code ignores them in settings.json. Two of them are documented as removed in current versions.
GLOBAL_CONFIG_ONLY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "autoConnectIde",
        "autoInstallIdeExtension",
        "claudeInChromeDefaultEnabled",
        "copyFullResponse",
        "copyOnSelect",
        "defaultToAgentsView",
        "diffTool",
        "externalEditorContext",
        "leftArrowOpensAgents",
        "permissionExplainerEnabled",
        "prStatusFooterEnabled",
        "teammateDefaultModel",
    }
)

# Hook event names from the official hooks reference (read 2026-10-07; the first 100000 of its
# 249988 characters, which hold the event overview). Used only to spot an event name written next
# to "hooks" instead of inside it.
HOOK_EVENT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "SessionStart",
        "Setup",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
        "PostToolUseFailure",
        "PostToolBatch",
        "Notification",
        "MessageDisplay",
        "SubagentStart",
        "SubagentStop",
        "TaskCreated",
        "TaskCompleted",
        "Stop",
        "StopFailure",
        "TeammateIdle",
        "InstructionsLoaded",
        "ConfigChange",
        "CwdChanged",
        "DirectoryAdded",
        "FileChanged",
        "WorktreeCreate",
        "WorktreeRemove",
        "PreCompact",
        "PostCompact",
        "PreModelSwitch",
        "PostModelSwitch",
        "Elicitation",
        "ElicitationResult",
        "SessionEnd",
    }
)
_HOOK_EVENTS_FOLDED: Final = {name.casefold(): name for name in HOOK_EVENT_NAMES}
_HOOK_KEYS: Final = ("hooks", "disableAllHooks")

_UNVERIFIED: Final = (
    "A GitHub report (anthropics/claude-code #98662) claims an unknown top-level key silently "
    "disables all hooks; boundkeep has not verified this."
)


@dataclass(frozen=True)
class SettingsFinding:
    key: str
    message: str
    severity: Literal["warning", "info"]
    # What kind of finding: "misplaced-event" (a hook event name next to "hooks"), "typo" (a
    # misspelling of hooks / disableAllHooks), "global-config", or "unknown" (not in the snapshot).
    kind: str = "unknown"


def _within_one_edit(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by at most one inserted, deleted or replaced character."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    if len(a) == len(b):
        return a[i + 1 :] == b[i + 1 :]
    return a[i:] == b[i + 1 :]


def _typo_of(key: str) -> str | None:
    """The hook setting ``key`` is probably a mistyped spelling of, if any."""
    for target in _HOOK_KEYS:
        if key == target:
            return None
        if key.casefold() == target.casefold() or _within_one_edit(
            key.casefold(), target.casefold()
        ):
            return target
    return None


def find_suspicious_top_level_keys(data: Mapping[str, Any]) -> list[SettingsFinding]:
    """Warnings and infos about top-level keys that may mean the hook configuration is not live.

    ``hooks`` and ``disableAllHooks`` themselves are never flagged (whether ``disableAllHooks`` is
    switched on is a different check, ``ownhook.disables_hooks``).
    """
    findings: list[SettingsFinding] = []
    for key in data:
        if key in _HOOK_KEYS:
            continue
        event = _HOOK_EVENTS_FOLDED.get(key.casefold())
        if event is not None:
            findings.append(
                SettingsFinding(
                    key,
                    f"{key!r} is a hook event name at the top level of the file. Hook events "
                    f'belong inside the "hooks" object, so this entry is probably not a hook '
                    f"that runs. {_UNVERIFIED}",
                    "warning",
                    "misplaced-event",
                )
            )
            continue
        if key in KNOWN_TOP_LEVEL_KEYS:
            continue
        typo = _typo_of(key)
        if typo is not None:
            findings.append(
                SettingsFinding(
                    key,
                    f"{key!r} looks like a misspelling of {typo!r}; if it was meant as that "
                    f"setting, it is not in effect. {_UNVERIFIED}",
                    "warning",
                    "typo",
                )
            )
            continue
        if key in GLOBAL_CONFIG_ONLY_KEYS:
            findings.append(
                SettingsFinding(
                    key,
                    f"{key!r} is documented as a global config key (~/.claude.json); Claude Code "
                    "ignores it in settings.json.",
                    "info",
                    "global-config",
                )
            )
            continue
        findings.append(
            SettingsFinding(
                key,
                f"{key!r} is not in boundkeep's snapshot of the documented top-level keys "
                f"({SNAPSHOT_DATE}, {SOURCE_URL}); the snapshot may lag behind Claude Code. "
                f"{_UNVERIFIED}",
                "info",
            )
        )
    return findings


# ---------------------------------------------------------------------------------------------
# Settings that may weaken the gate (init, doctor and the ConfigChange hook share this)
# ---------------------------------------------------------------------------------------------
#
# What real Claude Code does with most of these is UNTESTED (the security review of M1 and M1b
# could not run it), so every message says "may weaken", never that the gate is off. The one
# exception is ``disableAllHooks``, which M0a measured (docs/hook-behavior.md E12).

# ``hook_main._RISKY_ENV_NAMES`` (== ``BLOCKING_ENV``; a unit test keeps them in step): a settings
# ``env`` block that sets one of these can send the hook client to another boundkeep home (a fake
# daemon), name another project root, or make Claude Code skip hooks. Only names with that effect
# block. ``refuse`` is set for the home and hook switches (and BOUNDKEEP_*) because the ConfigChange
# hook would block every later edit of such a file.
HOME_REDIRECT_ENV: Final[frozenset[str]] = frozenset(
    {
        "USERPROFILE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_SIMPLE",
        "CLAUDE_CODE_SAFE_MODE",
    }
)
# CLAUDE_PROJECT_DIR is the one value the hook client forwards: it names the project root.
BLOCKING_ENV: Final[frozenset[str]] = HOME_REDIRECT_ENV | {"CLAUDE_PROJECT_DIR"}
BLOCKING_ENV_PREFIXES: Final = ("BOUNDKEEP_",)
# Names that change how programs are found or started. NOT blocked (review round 3, C-3): the
# re-review changed each of PATH, PATHEXT, COMSPEC, HOMEDRIVE, ... for the hook client (39
# mutations: delete, blank, point at nothing) and the client never exited with anything but 0 or 2,
# so there is no demonstrated attack; blocking them only stops legitimate setups. Noted as warn.
WARN_ENV: Final[frozenset[str]] = frozenset(
    {
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "PSMODULEPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "CLAUDE_CODE_GIT_BASH_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
    }
)
# The hook client runs ``python -I -S`` (PYTHON* is ignored) and PYTHONUTF8 is common on Chinese
# Windows: info only.
INFO_ENV_PREFIXES: Final = ("PYTHON",)
# Not a gate weakening, but they send the conversation or the traffic somewhere else.
NOTEWORTHY_ENV: Final[frozenset[str]] = frozenset(
    {"ANTHROPIC_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
)
# Settings keys that name a command Claude Code runs on its own, outside the tool-call review.
# (statusLine, apiKeyHelper, awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper
# and fileSuggestion are documented as commands; processWrapper, policyHelper and subagentStatusLine
# are included because their name says so, unverified.)
EXEC_KEYS: Final = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "fileSuggestion",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "policyHelper",
    "processWrapper",
    "statusLine",
    "subagentStatusLine",
)
# Settings keys that make Claude Code load code from elsewhere (plugins bring their own hooks,
# commands and MCP servers; a marketplace is where plugins come from; an MCP server is a program).
# Watched like EXEC_KEYS: the whole value is fingerprinted.
PLUGIN_KEYS: Final = (
    "appendPlugins",
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
    "enabledPlugins",
    "extraKnownMarketplaces",
    "managedMcpServers",
    "mcpServers",
    "pluginConfigs",
    "prependPlugins",
)
WATCHED_KEYS: Final = (*EXEC_KEYS, *PLUGIN_KEYS)
# Hook events where ANOTHER hook can change or approve what runs after boundkeep has looked: every
# foreign entry there is watched, whatever its type. In every OTHER event the foreign command (and
# unknown-typed) hooks are watched: they run programs outside boundkeep's review too (round 3, C-2).
WATCHED_HOOK_EVENTS: Final = ("PreToolUse", "PermissionRequest")
_NON_EXEC_HOOK_TYPES: Final = frozenset({"http", "prompt"})
# ``init`` stores this marker in the baseline it writes. A baseline without it was made by an older
# boundkeep that only watched EXEC_KEYS and the two events above; labels it never covered are
# reported but not blocked (run 'boundkeep init' again to record them).
BASELINE_MARK: Final = "@baseline"
BASELINE_VERSION: Final = "2"
_LEGACY_LABELS: Final = frozenset(
    {*EXEC_KEYS, *(f"hooks.{event}" for event in WATCHED_HOOK_EVENTS)}
)
_OBSERVED: Final = (
    "observed on 2026-10-18 (Claude Code CLI engine, -p mode): the hook's ask still took "
    "precedence; behaviour in other modes/hosts is untested"
)
_BLANKET_TOOLS: Final = frozenset(
    {"bash", "powershell", "write", "edit", "multiedit", "notebookedit"}
)
_BLANKET_ARGUMENTS: Final = frozenset({"", "*", "**", ":*"})

ConcernLevel = Literal["block", "warn", "info"]


@dataclass(frozen=True)
class Concern:
    """One way a settings document may weaken the gate.

    ``level``: ``block`` (the ConfigChange hook should refuse the change, ``doctor`` fails),
    ``warn`` or ``info``. ``refuse``: ``init`` refuses to install into such a file (the gate is
    certainly off or redirected, and the ConfigChange hook would block every later edit).
    ``layer_only``: matters only to a settings file that holds boundkeep's hooks (a key typo in an
    unrelated file does not break our entries).
    """

    key: str
    message: str
    level: ConcernLevel
    refuse: bool = False
    layer_only: bool = False
    # "watched" for a command-running key or a foreign hook judged against the init baseline.
    kind: str = ""


OwnIdentities = Sequence[tuple[str, Sequence[str]]]


def _fingerprint(value: object) -> str:
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        text = repr(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_ours(event: str, hook: object, own: OwnIdentities | None) -> bool:
    """Ours by install record (exact) when ``own`` is given, else by shape (no record)."""
    if own is None:
        return ownhook.is_own_hook(hook)
    return ownhook.is_exact_own(event, hook, own)


def _foreign_hooks(event: str, groups: object, own: OwnIdentities | None) -> list[object]:
    """The hook entries of one event's group list that are not boundkeep's, with their matcher.

    In an event other than ``WATCHED_HOOK_EVENTS`` an entry of a non-command type (``http``,
    ``prompt``) is not counted: it starts no program.
    """
    if not isinstance(groups, list):
        return []
    everything = event in WATCHED_HOOK_EVENTS
    found: list[object] = []
    for group in groups:
        if not isinstance(group, dict):
            found.append(group)
            continue
        inner = group.get("hooks")
        if not isinstance(inner, list):
            continue
        matcher = group.get("matcher")
        for hook in inner:
            if _is_ours(event, hook, own):
                continue
            if (
                not everything
                and isinstance(hook, dict)
                and hook.get("type") in _NON_EXEC_HOOK_TYPES
            ):
                continue
            found.append({"matcher": matcher, "hook": hook})
    return found


def watched_fingerprints(
    data: Mapping[str, Any], own: OwnIdentities | None = None
) -> dict[str, str]:
    """Label -> sha256 of the command-running keys and foreign hooks present in ``data``.

    ``own`` are the ``(hook_command, hook_args)`` pairs of the install records for this file: only
    entries exactly equal to those are boundkeep's, the rest (look-alikes included) are foreign.
    Without ``own`` the shape decides. Foreign hooks in EVERY event are covered, plus
    ``EXEC_KEYS`` and ``PLUGIN_KEYS``. ``init`` stores this (see ``make_baseline``) next to the
    install record; a later change that adds or alters one of these entries is then recognizable
    (the ConfigChange event carries no diff).
    """
    result: dict[str, str] = {}
    for key in WATCHED_KEYS:
        if key in data:
            value = data[key]
            if key in PLUGIN_KEYS and value in ({}, [], None, False):
                continue  # nothing named: nothing runs
            result[key] = _fingerprint(value)
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            if not isinstance(event, str):
                continue
            foreign = _foreign_hooks(event, groups, own)
            if foreign:
                result[f"hooks.{event}"] = _fingerprint(foreign)
    return result


def make_baseline(data: Mapping[str, Any], own: OwnIdentities | None = None) -> dict[str, str]:
    """What ``init`` records: ``watched_fingerprints`` plus the marker of the current coverage."""
    return {**watched_fingerprints(data, own), BASELINE_MARK: BASELINE_VERSION}


def _blanket_rule(rule: object) -> bool:
    """True for ``Bash``, ``Bash(*)``, ``PowerShell(**)``, ``Write(*)``, ``*`` and the like."""
    if not isinstance(rule, str):
        return False
    text = rule.strip()
    if text == "*":
        return True
    tool, paren, rest = text.partition("(")
    if tool.strip().lower() not in _BLANKET_TOOLS:
        return False
    if not paren:
        return True
    inner = rest.rstrip()
    if inner.endswith(")"):
        inner = inner[:-1]
    return inner.strip() in _BLANKET_ARGUMENTS


def _env_concerns(data: Mapping[str, Any]) -> list[Concern]:
    env = data.get("env")
    if env is None:
        return []
    if not isinstance(env, dict):
        return [Concern("env", "the settings 'env' entry is not an object", "block", refuse=True)]
    concerns: list[Concern] = []
    for name in env:
        upper = str(name).upper()
        if upper.startswith(BLOCKING_ENV_PREFIXES) or upper in HOME_REDIRECT_ENV:
            concerns.append(
                Concern(
                    "env",
                    f"the settings 'env' block sets {name}, which could redirect or bypass "
                    "boundkeep",
                    "block",
                    refuse=True,
                )
            )
        elif upper in BLOCKING_ENV:  # CLAUDE_PROJECT_DIR
            concerns.append(
                Concern(
                    "env",
                    f"the settings 'env' block sets {name}, which names the project root the "
                    "hook client reports to the daemon (may weaken boundkeep)",
                    "block",
                )
            )
        elif upper in WARN_ENV:
            concerns.append(
                Concern(
                    "env",
                    f"the settings 'env' block sets {name}, which may change which programs get "
                    "started; no effect on the hook client was found (39 variations measured "
                    "2026-10-18), so this is noted, not blocked",
                    "warn",
                )
            )
        elif upper.startswith(INFO_ENV_PREFIXES):
            concerns.append(
                Concern(
                    "env",
                    f"the settings 'env' block sets {name}; the hook client runs with python -I "
                    "and ignores it (noted only; it may still change other Python programs)",
                    "info",
                )
            )
        elif upper in NOTEWORTHY_ENV:
            concerns.append(
                Concern(
                    "env",
                    f"the settings 'env' block sets {name}, which sends Claude Code's traffic "
                    "somewhere else (not a boundkeep setting; noted only)",
                    "info",
                )
            )
    return concerns


def _permission_concerns(data: Mapping[str, Any]) -> list[Concern]:
    concerns: list[Concern] = []
    perms = data.get("permissions")
    if isinstance(perms, dict):
        mode = perms.get("defaultMode")
        if isinstance(mode, str) and mode.casefold() == "bypasspermissions":
            concerns.append(
                Concern(
                    "permissions.defaultMode",
                    "permissions.defaultMode is bypassPermissions, which may let Claude Code run "
                    f"tool calls without asking; {_OBSERVED} (may weaken boundkeep)",
                    "warn",
                )
            )
        elif mode == "auto":
            concerns.append(
                Concern(
                    "permissions.defaultMode",
                    "permissions.defaultMode is auto: whether a hook's ask still applies in that "
                    "mode is untested (may weaken boundkeep)",
                    "warn",
                )
            )
        allow = perms.get("allow")
        blanket = [rule for rule in allow if _blanket_rule(rule)] if isinstance(allow, list) else []
        if blanket:
            shown = ", ".join(repr(str(rule)) for rule in blanket[:5])
            concerns.append(
                Concern(
                    "permissions.allow",
                    f"permissions.allow holds blanket rules ({shown}), which may let calls of "
                    f"those tools run without asking; {_OBSERVED} (may weaken boundkeep)",
                    "warn",
                )
            )
    skip = data.get("skipDangerousModePermissionPrompt")
    if skip is not None and skip is not False:
        concerns.append(
            Concern(
                "skipDangerousModePermissionPrompt",
                "skipDangerousModePermissionPrompt is set, which may let Claude Code enter "
                f"bypass mode without its warning prompt; {_OBSERVED} (may weaken boundkeep)",
                "warn",
            )
        )
    return concerns


_ACCEPT_BASELINE: Final = (
    "Run 'boundkeep init' to accept the new command-running entries; until then every settings "
    "change to this file is blocked, because a ConfigChange event carries no diff and a harmless "
    "edit cannot be told from this one"
)
_NO_BASELINE: Final = (
    "is present; no baseline was recorded for this file ('boundkeep init' never wrote it, or an "
    "older version did), so a later change cannot be told from what was there and is NOT blocked"
)
_OLD_BASELINE: Final = (
    "is present; the install record's baseline predates this check, so it is not judged against "
    "it (run 'boundkeep init' again to record it)"
)


def _watched_message(label: str, when: str) -> str:
    if label.startswith("hooks."):
        event = label.split(".", 1)[1]
        if event in WATCHED_HOOK_EVENTS:
            effect = (
                "another hook can change or approve what Claude Code runs after boundkeep has "
                "judged it"
            )
        else:
            effect = "it runs a program on its own, outside boundkeep's review"
        return f"a {event} hook that is not boundkeep's {when}: {effect} (may weaken boundkeep)"
    if label in PLUGIN_KEYS:
        return (
            f"{label} {when}: it makes Claude Code load plugins, marketplaces or MCP servers, "
            "which run code outside boundkeep's review (may weaken boundkeep)"
        )
    return (
        f"{label} {when}: it names a command Claude Code runs on its own, which boundkeep "
        "does not review (may weaken boundkeep)"
    )


_AT_INIT: Final = (
    "is present and 'boundkeep init' records it as the baseline: a later change to it is blocked "
    "until 'boundkeep init' is run again"
)


def _watched_concerns(
    data: Mapping[str, Any],
    baseline: Mapping[str, str] | None,
    own: OwnIdentities | None = None,
    *,
    at_init: bool = False,
) -> list[Concern]:
    concerns: list[Concern] = []
    current = baseline is not None and baseline.get(BASELINE_MARK) == BASELINE_VERSION
    for label, fingerprint in watched_fingerprints(data, own).items():
        is_hook = label.startswith("hooks.")
        level: ConcernLevel
        if at_init:
            message = _watched_message(label, _AT_INIT)
            level = "warn" if is_hook else "info"
        elif baseline is not None and (current or label in _LEGACY_LABELS):
            if baseline.get(label) == fingerprint:
                continue  # as it was when 'boundkeep init' recorded the file
            when = "was added or changed since 'boundkeep init' recorded this file"
            message = _watched_message(label, when) + ". " + _ACCEPT_BASELINE
            level = "block"
        elif baseline is not None:
            message = _watched_message(label, _OLD_BASELINE)
            level = "warn" if is_hook else "info"
        else:
            message = _watched_message(label, _NO_BASELINE)
            level = "warn" if is_hook else "info"
        concerns.append(Concern(label, message, level, kind="watched"))
    return concerns


def _near_event(name: str) -> str | None:
    """The hook event ``name`` is probably a misspelling of (case or one edit), if any."""
    folded = name.casefold()
    for event in sorted(HOOK_EVENT_NAMES):
        if _within_one_edit(folded, event.casefold()):
            return event
    return None


def _key_concerns(data: Mapping[str, Any]) -> list[Concern]:
    concerns: list[Concern] = []
    for finding in find_suspicious_top_level_keys(data):
        if finding.kind in ("misplaced-event", "typo"):
            concerns.append(Concern(finding.key, finding.message, "block", layer_only=True))
        elif finding.kind == "unknown":
            concerns.append(Concern(finding.key, finding.message, "warn", layer_only=True))
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event in hooks:
            if not isinstance(event, str) or event in HOOK_EVENT_NAMES:
                continue
            near = _near_event(event)
            if near is not None:
                message = (
                    f"hooks.{event} is not a Claude Code hook event name (a misspelling of "
                    f"{near!r}?): a hook under it does not run, and Claude Code may reject the "
                    f"whole file. {_UNVERIFIED}"
                )
                concerns.append(Concern(f"hooks.{event}", message, "block", layer_only=True))
            else:
                message = (
                    f"hooks.{event} is not in boundkeep's snapshot of hook event names "
                    f"({SNAPSHOT_DATE}); the snapshot may lag behind Claude Code. {_UNVERIFIED}"
                )
                concerns.append(Concern(f"hooks.{event}", message, "warn", layer_only=True))
    return concerns


def assess_settings(
    data: Mapping[str, Any],
    *,
    baseline: Mapping[str, str] | None = None,
    own: OwnIdentities | None = None,
    at_init: bool = False,
) -> list[Concern]:
    """Everything in ``data`` that may weaken the gate, strongest findings first within a group.

    ``at_init``: ``boundkeep init`` is about to record ``data`` as the baseline, so what is present
    is worded as "recorded now" instead of being compared with a baseline.

    ``baseline`` is what ``init`` recorded for this file (``make_baseline``), or None when there is
    none (an old record, or a file init never touched: user-level settings during a project-level
    install, ``settings.local.json``): command-running keys and foreign hooks then only warn, since
    trust on first use is impossible (the event carries no diff). With a baseline, one that was
    added or changed is a ``block``. ``own``: see ``watched_fingerprints``.
    """
    concerns: list[Concern] = []
    if ownhook.disables_hooks(data):
        concerns.append(
            Concern(
                "disableAllHooks",
                "sets disableAllHooks: every hook is off, with no warning anywhere",
                "block",
                refuse=True,
            )
        )
    concerns += _env_concerns(data)
    concerns += _permission_concerns(data)
    concerns += _watched_concerns(data, baseline, own, at_init=at_init)
    concerns += _key_concerns(data)
    return concerns


def lookalike_reasons(data: Mapping[str, Any], own: OwnIdentities | None) -> list[str]:
    """One message per entry that looks like boundkeep's but is not what ``init`` recorded.

    Empty without ``own`` (no install record for the file: the shape is all there is, and a file
    that has no record is not ours to block).
    """
    reasons: list[str] = []
    for event, _matcher, hook in ownhook.lookalike_hooks(data, own or []):
        command = str(hook.get("command"))
        shown = command if len(command) <= 60 else command[:57] + "..."
        reasons.append(
            f"an extra hook that looks like boundkeep's ({event}, command {shown!r}) is not the "
            "entry 'boundkeep init' installed, so it runs something else next to boundkeep; "
            "remove it, or run 'boundkeep init' to replace our entries"
        )
    return reasons


def blocking_reasons(
    data: Mapping[str, Any],
    baseline: Mapping[str, str] | None = None,
    own: OwnIdentities | None = None,
) -> list[str]:
    """What the ConfigChange hook should refuse ``data`` for (messages; empty when it is fine).

    Findings that only matter to a file holding boundkeep's hooks (misspelled keys and event names)
    count only when ``data`` has such hooks, so an unrelated user file is not blocked for them.
    ``own`` (the ``(hook_command, hook_args)`` pairs of the file's install records) makes an entry
    count as boundkeep's only when it equals one exactly; an extra entry that merely looks like ours
    is then a block (``lookalike_reasons``).
    """
    has_own = any(True for _ in ownhook.own_hooks_in(data))
    reasons = [
        c.message
        for c in assess_settings(data, baseline=baseline, own=own)
        if c.level == "block" and (has_own or not c.layer_only)
    ]
    return [*lookalike_reasons(data, own), *reasons]  # the sharper message first
