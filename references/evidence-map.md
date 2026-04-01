# Reverse-Claude: File:Line Evidence Map

Every pattern in the SKILL.md is anchored to specific source locations.

## Module 1: Permissioned Invocation & Runtime Safety

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Permission Decision Cascade | `src/tools/BashTool/bashPermissions.ts` | 1663-2266 | `bashToolHasPermission` master function |
| Per-Subcommand Check | `src/tools/BashTool/bashPermissions.ts` | 1050-1178 | `bashToolCheckPermission` priority chain |
| Three-Tier Rule Matching | `src/tools/BashTool/bashPermissions.ts` | 884-922 | Exact/prefix/wildcard with compound command guard |
| Asymmetric Env-Var Stripping (safe) | `src/tools/BashTool/bashPermissions.ts` | 524-615 | `stripSafeWrappers` two-phase design |
| Asymmetric Env-Var Stripping (all) | `src/tools/BashTool/bashPermissions.ts` | 733-776 | `stripAllLeadingEnvVars` with regex |
| Fixed-Point Iteration Stripping | `src/tools/BashTool/bashPermissions.ts` | 826-853 | Interleaved wrapper + env var stripping |
| SAFE_ENV_VARS Allowlist | `src/tools/BashTool/bashPermissions.ts` | 378-430 | Safe env var definitions |
| ANT_ONLY Safe Vars | `src/tools/BashTool/bashPermissions.ts` | 447-497 | `USER_TYPE === 'ant'` gated vars |
| Dangerous Shell Prefixes | `src/tools/BashTool/bashPermissions.ts` | 196-226 | `BARE_SHELL_PREFIXES` blocklist |
| Heredoc Prefix Extraction | `src/tools/BashTool/bashPermissions.ts` | 307-337 | `extractPrefixBeforeHeredoc` |
| Speculative Classifier | `src/tools/BashTool/bashPermissions.ts` | 1483-1658 | Race-the-user auto-approve |
| Compound Command Guards | `src/tools/BashTool/bashPermissions.ts` | 2162-2266 | cd+git, multiple cd, subcommand cap |
| Sandbox Auto-Allow + Deny | `src/tools/BashTool/bashPermissions.ts` | 1270-1359 | Deny checked in sandbox mode |
| Flag Validation Pipeline | `src/tools/BashTool/readOnlyValidation.ts` | 1246-1408 | `isCommandSafeViaFlagParsing` |
| CommandConfig Type | `src/tools/BashTool/readOnlyValidation.ts` | 128 | Declarative flag allowlist |
| $-Token Rejection | `src/tools/BashTool/readOnlyValidation.ts` | 1329-1368 | Parser differential defense |
| Quote-Aware Expansion Detection | `src/tools/BashTool/readOnlyValidation.ts` | 1600-1669 | `containsUnquotedExpansion` state machine |
| Git-Internal Path Detection | `src/tools/BashTool/readOnlyValidation.ts` | 1840-1864 | `commandWritesToGitInternalPaths` |
| Multi-Layer Git Safety | `src/tools/BashTool/readOnlyValidation.ts` | 1876-1990 | `checkReadOnlyConstraints` five checks |
| Per-Command Danger Callbacks | `src/tools/BashTool/readOnlyValidation.ts` | 420-1045 | ps, date, hostname, tput, lsof, sed, tree |
| Platform-Aware Validation | `src/tools/BashTool/readOnlyValidation.ts` | 1207-1209, 1903-1909 | Windows xargs, UNC path, base64 |

## Module 2: Plugin/Skill Discovery & Lifecycle

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Skill Permission Layering | `src/tools/SkillTool/SkillTool.ts` | 432-578 | `checkPermissions` deny-first |
| Skill Execution Modes | `src/tools/SkillTool/SkillTool.ts` | 580-900 | Inline/forked/remote dispatch |
| Safe Properties Auto-Allow | `src/tools/SkillTool/SkillTool.ts` | ~400 | `skillHasOnlySafeProperties` |
| Context Modifier Chain | `src/tools/SkillTool/SkillTool.ts` | ~800 | `getAppState()` closure layering |
| Filesystem Command Loader | `src/utils/plugins/loadPluginCommands.ts` | 218-412 | `createPluginCommand` factory |
| Markdown Collection | `src/utils/plugins/loadPluginCommands.ts` | 1-100 | `collectMarkdownFiles` recursive walker |
| SKILL.md Priority | `src/utils/plugins/loadPluginCommands.ts` | ~150 | `transformPluginSkillFiles` |
| Variable Substitution Chain | `src/utils/plugins/loadPluginCommands.ts` | 300-400 | 5-stage substitution in `getPromptForCommand` |
| Versioned State File | `src/utils/plugins/installedPluginsManager.ts` | 115-182 | `migrateToSinglePluginFile` |
| V1->V2 Migration | `src/utils/plugins/installedPluginsManager.ts` | ~200 | `migrateV1ToV2` all entries -> user scope |
| Dual-Layer State | `src/utils/plugins/installedPluginsManager.ts` | ~400-600 | Disk vs memory, pending updates |
| Plugin Version Fallback | `src/utils/plugins/installedPluginsManager.ts` | ~800 | manifest -> marketplace -> git SHA |
| Background Update | `src/utils/plugins/pluginAutoupdate.ts` | 227-284 | `autoUpdateMarketplacesAndPluginsInBackground` |
| Notification Buffer | `src/utils/plugins/pluginAutoupdate.ts` | 37-65 | `onPluginsAutoUpdated` with pending buffer |
| Error-Isolated Loading | `src/hooks/useManagePlugins.ts` | 70-110 | Per-subsystem try/catch |
| LSP Error Preservation | `src/hooks/useManagePlugins.ts` | ~120-140 | Merge with dedup |
| Builtin Plugin Registry | `src/plugins/builtinPlugins.ts` | 1-160 | `registerBuiltinPlugin` + settings toggle |
| Marketplace Security | `src/utils/plugins/schemas.ts` | various | `ALLOWED_OFFICIAL_MARKETPLACE_NAMES`, homograph blocking |

## Module 3: Agent Orchestration & Skill Execution

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Polymorphic Execution Router | `src/tools/AgentTool/AgentTool.tsx` | 82-138 | `inputSchema` with four modes |
| Conditional Schema Construction | `src/tools/AgentTool/AgentTool.tsx` | 110-125 | Feature-gated `.omit()` |
| Build-Time Dead Code Elimination | `src/tools/AgentTool/AgentTool.tsx` | 435 | `"external" === 'ant'` literal |
| MCP Server Polling | `src/tools/AgentTool/AgentTool.tsx` | 371-409 | 500ms poll, 30s timeout, early exit |
| Foreground-to-Background Transition | `src/tools/AgentTool/AgentTool.tsx` | 810-1053 | Race-based with iterator cleanup |
| Auto-Background Timer | `src/tools/AgentTool/AgentTool.tsx` | 72-77 | `getAutoBackgroundMs` 120s |
| Worktree Lifecycle | `src/tools/AgentTool/AgentTool.tsx` | 583-685 | Create, cleanup, change detection |
| Partial Result Recovery | `src/tools/AgentTool/AgentTool.tsx` | 1220-1234 | Finalize on error if messages exist |
| Discriminated Union Mapper | `src/tools/AgentTool/AgentTool.tsx` | 1298-1379 | `mapToolResultToToolResultBlockParam` |
| One-Shot Optimization | `src/tools/AgentTool/AgentTool.tsx` | 1351-1362 | Skip agentId/usage for Explore/Plan |
| Multi-Tier Feature Flag Cache | `src/services/analytics/growthbook.ts` | 734-775 | `getFeatureValue_CACHED_MAY_BE_STALE` |
| Empty Payload Protection | `src/services/analytics/growthbook.ts` | 335-339 | Never clear on `{}` |
| SDK API Format Workaround | `src/services/analytics/growthbook.ts` | 346-376 | `value` -> `defaultValue` transform |
| Auth Availability Race | `src/services/analytics/growthbook.ts` | 509-553 | `clientCreatedWithAuth` tracking |
| Pending Exposure Dedup | `src/services/analytics/growthbook.ts` | 82-89 | `pendingExposures` + `loggedExposures` |
| Signal-Based Refresh | `src/services/analytics/growthbook.ts` | 107-157 | `onGrowthBookRefresh` with catch-up |
| Client Replacement Guard | `src/services/analytics/growthbook.ts` | 556-578 | `client !== thisClient` before+after await |
| Safe Config Mutation | `src/services/analytics/growthbook.ts` | 245-271 | `setGrowthBookConfigOverride` |

## Module 4: Context Compaction & Retry

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Image Stripping | `src/services/compact/compact.ts` | ~200-250 | `stripImagesFromMessages` |
| Attachment Stripping | `src/services/compact/compact.ts` | ~260-300 | `stripReinjectedAttachments` |
| PTL Retry with Truncation | `src/services/compact/compact.ts` | ~350-430 | `truncateHeadForPTLRetry` |
| Post-Compact File Attachments | `src/services/compact/compact.ts` | ~600-700 | 50K budget, 5K/file, max 5 |
| Skill Attachment | `src/services/compact/compact.ts` | ~750-800 | 25K budget, 5K/skill, head-truncate |
| Boundary Marker | `src/services/compact/compact.ts` | ~900-950 | `preservedSegment` metadata |
| Full Compaction | `src/services/compact/compact.ts` | ~1000-1400 | `compactConversation` |
| Partial Compaction | `src/services/compact/compact.ts` | ~1450-1600 | `partialCompactConversation` |
| Time-Based Micro-Compact | `src/services/compact/microCompact.ts` | ~200-350 | `maybeTimeBasedMicrocompact` |
| Cache-Editing Micro-Compact | `src/services/compact/microCompact.ts` | ~400-530 | `cachedMicrocompactPath` |
| Token Estimation | `src/services/compact/microCompact.ts` | ~100-150 | `estimateMessageTokens` with 4/3 pad |
| Auto-Compact Thresholds | `src/services/compact/autoCompact.ts` | ~50-120 | `getAutoCompactThreshold` |
| Circuit Breaker | `src/services/compact/autoCompact.ts` | ~200-300 | `MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES = 3` |
| Token Warning State | `src/services/compact/autoCompact.ts` | ~130-180 | `calculateTokenWarningState` |
| Session Memory Compact | `src/services/compact/sessionMemoryCompact.ts` | ~200-400 | `trySessionMemoryCompaction` |
| API Invariant Preservation | `src/services/compact/sessionMemoryCompact.ts` | ~100-180 | `adjustIndexToPreserveAPIInvariants` |
| Scoped Cleanup | `src/services/compact/postCompactCleanup.ts` | 1-77 | `runPostCompactCleanup` |
| Time-Based Config | `src/services/compact/timeBasedMCConfig.ts` | 1-43 | 60min threshold, GrowthBook sourced |
| Classified Retry | `src/services/api/withRetry.ts` | ~100-500 | `withRetry` main loop |
| Retry Delay with Jitter | `src/services/api/withRetry.ts` | ~50-70 | `getRetryDelay` |
| Fast Mode Cooldown | `src/services/api/withRetry.ts` | ~300-350 | 429 long/unknown -> 10-30min cooldown |
| Persistent Mode | `src/services/api/withRetry.ts` | ~500-600 | Indefinite retry, 5min max backoff |
| Compact Command | `src/commands/compact/compact.ts` | 1-287 | Priority strategy chain |

## Module 6: Query Engine & Main Loop Orchestration

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Agentic Message Loop | `src/query.ts` | 307-1727 | `while(true)` main loop with context compression pipeline |
| Context Compression Pipeline | `src/query.ts` | 365-454 | snip -> microcompact -> collapse -> autocompact (order matters) |
| Streaming Tool Dispatch | `src/query.ts` | 654-863 | `StreamingToolExecutor` concurrent execution during model stream |
| Recovery State Machine | `src/query.ts` | 1062-1256 | PTL, max-output-tokens, stop hooks, token budget branches |
| Reactive Compact | `src/query.ts` | 1119 | Emergency compaction on 413, single-shot guard |
| Post-Tool Attachments | `src/query.ts` | 1580-1628 | Memory prefetch, skill discovery, queued commands |
| Session Lifecycle Wrapper | `src/QueryEngine.ts` | 209-1155 | `submitMessage()` async generator with usage tracking |
| Permission Wrapping | `src/QueryEngine.ts` | 244-271 | `wrappedCanUseTool` denial tracking |
| Compact Boundary GC | `src/QueryEngine.ts` | 919 | splice pre-boundary messages for memory release |
| Concurrent Tool Executor | `src/services/tools/StreamingToolExecutor.ts` | 1-530 | Ordered drain, concurrent-safe fanout, Bash cascade kill |
| Post-Tool Hook Lifecycle | `src/services/tools/toolHooks.ts` | 1-400 | Async generator yielding hook_cancelled/blocking/stopped/context |
| Async Hook Registry | `src/utils/hooks/AsyncHookRegistry.ts` | 1-309 | Fire-and-forget with polling drain, Promise.allSettled isolation |

## Module 7: Message Pipeline & Cost Tracking

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Message Normalization | `src/utils/messages.ts` | 1-5512 | `normalizeMessagesForAPI` pipeline |
| Message Factories | `src/utils/messages.ts` | various | `createUserMessage`, `createAssistantAPIErrorMessage` |
| Attachment Reordering | `src/utils/messages.ts` | various | `reorderAttachmentsForAPI` |
| Media Strip Map | `src/utils/messages.ts` | various | Retroactive media block removal for past errors |
| Cost Accumulation | `src/cost-tracker.ts` | 1-323 | `addToTotalSessionCost` with per-model buckets |
| Session Cost Persistence | `src/cost-tracker.ts` | various | `saveCurrentSessionCosts`/`restoreCostStateForSession` |
| Recursive Advisor Accounting | `src/cost-tracker.ts` | various | Sub-model cost attribution |
| Error Classification | `src/services/api/errors.ts` | 1-1207 | `classifyAPIError` ~20 string tags |
| Error-to-Message Conversion | `src/services/api/errors.ts` | various | `getAssistantMessageFromError` with contextual hints |
| Token Gap Parsing | `src/services/api/errors.ts` | various | `parsePromptTooLongTokenCounts` for reactive compact |

## Module 5: Self-Configuration

| Pattern | File | Lines | Evidence |
|---------|------|-------|----------|
| Settings Type Definitions | `src/utils/settings/types.ts` | various | Full settings schema |
| Settings Merge Hierarchy | `src/utils/settings/types.ts` | various | Plugin < user < project < local < policy |
| Permission Rule Validation | `src/utils/settings/permissionValidation.ts` | various | Rule syntax, parentheses matching |
| Hook Schema | `src/schemas/hooks.ts` | various | Event types, hook types, filtering |
| CLAUDE.md Discovery | `src/utils/claudemd.ts` | various | File hierarchy, @include directives |
| Config Command | `src/commands/config/config.tsx` | various | Settings UI, ConfigTool |
| Supported Settings | `src/tools/ConfigTool/supportedSettings.ts` | various | 50+ configurable settings |
