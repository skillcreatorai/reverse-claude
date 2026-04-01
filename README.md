<div align="center">

# reverse-claude

**The reverse-engineering manual for Claude Code.**

7 modules. 43 patterns. 1,746 lines of actionable intelligence extracted from ~28,000 lines of production source.

[![Install with skills.sh](https://img.shields.io/badge/skills.sh-install-black?style=for-the-badge)](https://skills.sh)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude_Code-compatible-orange?style=for-the-badge)](https://claude.ai/code)

<br/>

[Install](#install) · [What's Inside](#whats-inside) · [Modules](#modules) · [Usage](#usage) · [References](#references)

</div>

---

## What is this?

`reverse-claude` is a Claude Code skill that encodes **how Claude Code itself works** — its permission system, plugin loader, agent orchestrator, context compactor, configuration surface, query engine, and message pipeline.

Point it at Claude Code to **understand, configure, and extend it.**

Or use the patterns to **build your own Claude Code-like system.**

```
/reverse-claude how do permissions work?
/reverse-claude set up auto-format hooks
/reverse-claude what's the compaction hierarchy?
/reverse-claude configure autonomous mode for this project
```

---

## Install

**skills.sh** (recommended)
```bash
npx skills add skillcreatorai/reverse-claude
```

**Manual**
```bash
mkdir -p ~/.claude/skills/reverse-claude
curl -fsSL https://raw.githubusercontent.com/skillcreatorai/reverse-claude/main/SKILL.md \
  -o ~/.claude/skills/reverse-claude/SKILL.md
```

**Verify**
```
/reverse-claude
```

---

## What's Inside

| Stat | Value |
|------|-------|
| Modules | 7 |
| Named patterns | 43 |
| Skill lines | 1,746 |
| Source lines analyzed | ~28,000 |
| Source files read | 35+ |
| Smoke tests | 3 |
| Anti-patterns documented | 30+ |

---

## Modules

### Module 1 — Permissioned Invocation & Runtime Safety

How Claude Code decides what's safe to run. The permission cascade that classifies every shell command through **deny > ask > allow > read-only > passthrough** layers.

**Patterns:** Permission decision cascade, asymmetric env-var stripping, declarative flag validation, compound command guards, speculative classifier (race the user), command semantics, git operation tracking.

**Key insight:** Deny rules strip ALL env vars (fixed-point iteration). Allow rules strip only safe ones. This asymmetry prevents `DOCKER_HOST=evil docker ps` from matching `allow(docker:*)`.

---

### Module 2 — Plugin/Skill Discovery & Lifecycle

How plugins are found, loaded, migrated, and updated. The pipeline: **walk directories -> parse frontmatter -> validate -> hydrate variables -> register**.

**Patterns:** Filesystem-to-registry loader, versioned state migration (V1->V2), background update with notification buffer, error-isolated subsystem loading, imperative plugin registry, MCP server lifecycle.

**Key insight:** Updates only touch disk state, never in-memory. The session sees a frozen snapshot. This prevents stale-cache bugs from partial reloads.

---

### Module 3 — Agent Orchestration & Skill Execution

How agents spawn across four execution modes through a single entry point. Feature flags control schema shape at module load time.

**Patterns:** Polymorphic execution router, foreground-to-background transition (race-based), conditional schema construction, multi-tier feature flag cache, discriminated union result mapping, cascading abort controllers, API client lifecycle.

**Key insight:** The foreground-to-background transition races `iterator.next()` against a `backgroundSignal` promise. If backgrounded mid-execution, existing messages are replayed through a fresh progress tracker.

---

### Module 4 — Context Compaction & Retry

How context stays manageable across long sessions. Four increasingly expensive strategies, with a circuit breaker that stops after 3 consecutive failures.

**Patterns:** Compaction hierarchy (micro -> session memory -> full -> reactive), tiered in-place reduction, full compaction with state preservation, PTL retry with grouped truncation, cursor-based session memory, auto-compact with circuit breaker, classified retry with adaptive backoff, scoped cache invalidation, thinking block budget, session memory persistence.

**Key insight:** The circuit breaker was added after discovering 250K+ wasted API calls/day from sessions stuck in auto-compact failure loops.

---

### Module 5 — Self-Configuration (Point It At Itself)

The actionable module. Settings hierarchy, permission rules, hooks, CLAUDE.md, and ready-to-use configuration recipes.

**Patterns:** Settings file hierarchy (6 layers), permission rule syntax, hook events and types, CLAUDE.md discovery order, configuration recipes (lockdown, auto-format, auto-lint, daily context, autonomous mode), plugin/skill installation.

**Key insight:** `settings.local.json` is always gitignored. Put personal preferences and API keys there, not in `settings.json`.

---

### Module 6 — Query Engine & Main Loop Orchestration

The core orchestration that ties all modules together. Every iteration: one API call, stream response, execute tools concurrently, recover or continue.

**Patterns:** Agentic message loop, session lifecycle wrapper, streaming tool execution (concurrent + ordered drain).

**Key insight:** Tools begin executing as soon as their `tool_use` block arrives in the stream — before the model finishes generating. This overlaps tool I/O with model generation latency.

---

### Module 7 — Message Pipeline & Cost Tracking

How messages are normalized for the API, how cost is tracked per-model, and how errors are classified for both machines and humans.

**Patterns:** Message normalization pipeline (4-phase), cost accumulation model (per-model, recursive advisor accounting), error classification (dual-function cascade), post-tool hook lifecycle.

**Key insight:** The media strip-map retroactively removes offending image/doc blocks from past user messages — so a 50MB PDF isn't re-sent on every retry.

---

## Usage

### Understanding Claude Code

```
/reverse-claude how does the permission cascade work?
/reverse-claude explain the compaction hierarchy
/reverse-claude what happens when an agent backgrounds?
```

### Configuring Claude Code

```
/reverse-claude lock down permissions for production
/reverse-claude set up PostToolUse hooks for formatting
/reverse-claude configure CLAUDE.md for a team project
```

### Building Similar Systems

```
/reverse-claude I'm building a CLI agent — how should I handle permissions?
/reverse-claude design a plugin discovery system
/reverse-claude implement retry with backoff for my API client
```

---

## References

| File | What It Contains |
|------|-----------------|
| [`SKILL.md`](SKILL.md) | The complete skill (1,746 lines) |
| [`references/evidence-map.md`](references/evidence-map.md) | File:line anchors for every pattern (80+ entries) |
| [`references/portability.md`](references/portability.md) | Per-module adaptation guide for other repos |

---

## Extracted From

This skill was reverse-engineered from Claude Code's production TypeScript source. Key files analyzed:

| File | Lines | What It Contains |
|------|-------|-----------------|
| `bashPermissions.ts` | 2,621 | Permission cascade, env-var stripping |
| `readOnlyValidation.ts` | 1,990 | Flag validation, expansion detection |
| `SkillTool.ts` | 1,108 | Skill resolution, permission layering |
| `AgentTool.tsx` | 1,397 | Agent spawning, fg/bg transitions |
| `growthbook.ts` | 1,155 | Feature flag cache, override chain |
| `compact.ts` | 1,705 | Full compaction, state preservation |
| `withRetry.ts` | 822 | Classified retry, adaptive backoff |
| `query.ts` | 1,729 | Main message loop, recovery |
| `QueryEngine.ts` | 1,295 | Session lifecycle, usage tracking |
| `messages.ts` | 5,512 | Message normalization (largest utility) |
| `cost-tracker.ts` | 323 | Per-model cost accumulation |
| `errors.ts` | 1,207 | Error classification cascade |
| `StreamingToolExecutor.ts` | 530 | Concurrent tool execution |
| + 22 more files | | |

---

## License

MIT

---

<div align="center">

Built by [SkillCreator.ai](https://skillcreator.ai)

</div>
