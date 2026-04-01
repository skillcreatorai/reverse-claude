# Reverse-Claude: Portability Assessment

What needs adaptation when applying these patterns to other repos/systems.

## Module 1: Permissioned Invocation & Runtime Safety

**Highly portable.** The permission cascade pattern is universal for any CLI agent.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Permission Decision Cascade | High | Replace tool-specific rules with your tool names |
| Asymmetric Stripping | High | Define your own SAFE_ENV_VARS list |
| Flag Validation Pipeline | High | Define your own CommandConfig allowlist |
| Speculative Classifier | Medium | Requires LLM classifier endpoint; can substitute with rule-based classifier |
| Git Safety Guards | Medium | Only needed if your agent runs git commands |
| $-Token Rejection | High | Universal defense against parser differentials |

**Dependencies:** tree-sitter (optional, for AST parsing), shell-quote (for command parsing)

## Module 2: Plugin/Skill Discovery & Lifecycle

**Highly portable.** Markdown-based plugin format works anywhere.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Filesystem-to-Registry Loader | High | Adapt directory structure and frontmatter fields |
| Versioned State Migration | High | Define your own V1/V2 schemas |
| Background Update with Buffer | High | Universal pattern, no dependencies |
| Error-Isolated Loading | High | Replace subsystem names |
| Builtin Registry | High | Register your own builtins |

**Dependencies:** YAML parser (for frontmatter), fs module

## Module 3: Agent Orchestration & Skill Execution

**Medium portability.** Some patterns are tightly coupled to the agent runtime.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Polymorphic Execution Router | High | Define your own execution modes |
| Foreground-to-Background Transition | Medium | Requires async iterator protocol + signal mechanism |
| Conditional Schema Construction | Medium | Requires Zod or similar runtime schema library |
| Multi-Tier Feature Flag Cache | High | Replace GrowthBook with your flag provider |
| MCP Server Polling | Low | Specific to MCP protocol; replace with your service discovery |
| Build-Time Dead Code Elimination | Medium | Requires bundler with dead code elimination |

**Dependencies:** Zod (schema), AsyncLocalStorage (context propagation), feature flag SDK

## Module 4: Context Compaction & Retry

**Highly portable.** Core patterns work for any LLM context management.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Compaction Hierarchy | High | Define your own strategy priority |
| Micro-Compact (Time-Based) | High | Adjust thresholds for your cache TTLs |
| Auto-Compact with Circuit Breaker | High | Universal pattern |
| Session Memory Compact | Medium | Requires running summary extraction system |
| API Invariant Preservation | Medium | Specific to Anthropic API message format |
| Classified Retry with Backoff | High | Universal; adjust error classification |
| PTL Retry with Truncation | Medium | Specific to prompt-too-long errors; generalize to "input too large" |

**Dependencies:** Token counter (rough estimation is sufficient), API error classification

## Module 5: Self-Configuration

**Claude Code specific.** This module is about configuring Claude Code itself.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Settings File Hierarchy | High | Universal config merge pattern |
| Permission Rules | Low | Claude Code specific syntax |
| Hooks | Low | Claude Code specific event system |
| CLAUDE.md Instructions | Low | Claude Code specific convention |
| Configuration Recipes | Low | Directly usable only in Claude Code |

**Note:** Module 5 is intentionally not portable. It's the "point it at itself" module.

## Module 6: Query Engine & Main Loop Orchestration

**Highly portable.** The agentic message loop is the universal pattern for tool-calling LLM apps.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Agentic Message Loop | High | Replace callModel with your API client |
| Context Compression Pipeline | High | Reorder layers for your context management |
| Streaming Tool Executor | High | Define your own concurrency-safe tool list |
| Recovery State Machine | Medium | Error types are Anthropic-specific |
| Session Lifecycle Wrapper | High | Universal session management pattern |
| Post-Tool Hook Lifecycle | High | Define your own hook event types |
| Async Hook Registry | High | Universal fire-and-forget pattern |

**Dependencies:** AsyncGenerator protocol, AbortController

## Module 7: Message Pipeline & Cost Tracking

**Medium portability.** Message normalization is API-specific; cost tracking is universal.

| Pattern | Portability | Adaptation Needed |
|---------|------------|-------------------|
| Message Normalization | Low | Heavily tied to Anthropic message format |
| Cost Accumulation | High | Replace pricing function for your provider |
| Error Classification | Medium | Error codes are provider-specific |
| Media Strip Map | Medium | Concept portable, implementation API-specific |

**Dependencies:** Provider pricing tables, API error format knowledge

## Summary

| Module | Overall Portability | Main Blocker |
|--------|-------------------|--------------|
| 1. Permissions | High | None |
| 2. Plugin Lifecycle | High | None |
| 3. Agent Orchestration | Medium | MCP protocol, Zod, AsyncLocalStorage |
| 4. Compact & Retry | High | API message format specifics |
| 5. Self-Configuration | Low (intentional) | Claude Code specific |
| 6. Query Engine | High | None |
| 7. Message Pipeline & Cost | Medium | Anthropic message format |

## Recommended Extraction Order for Other Repos

1. **Module 4 first** — every LLM app needs context management and retry
2. **Module 1 second** — every CLI agent needs permission gates
3. **Module 2 third** — plugin systems are universally useful
4. **Module 3 last** — most tightly coupled to specific runtime
5. **Module 5 never** — it's Claude Code's mirror, not portable
