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

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

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
