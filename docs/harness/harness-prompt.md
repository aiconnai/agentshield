# Harness Prompt Boundaries

This document maps the instruction and tool surfaces that affect work in this
repository. It is a versioned reference for the portion of the harness the
repository can describe and validate; it is not a replacement for an editor or
provider system prompt.

## Precedence

When instructions conflict, follow the highest applicable source:

1. System, developer, editor, security, and tool-enforced constraints.
2. The user's explicit request, provided it does not conflict with a higher
   constraint.
3. Repository policy supplied to the current session, including an applicable
   `AGENTS.md` and tracked harness rules.
4. Explicitly invoked repository skills under `skills/<name>/SKILL.md`.
5. Contextual documentation, examples, and historical records.

This document records that model; it does not override any source above it.
If the effective instructions are unclear, stop before taking a risky write or
external action and request clarification.

## Repository-Controlled Surface

| Surface | Canonical location | Role |
|---|---|---|
| Harness overview | `docs/harness/README.md` | Entry point, daily flow, and harness layout |
| Scope and invariants | `docs/harness/SPEC.md`, `INVARIANTS.md`, `WHAT_WE_DONT_DO.md` | Roadmap, non-negotiable rules, and exclusions |
| Verification gates | `docs/harness/GATES.md` | Required checks, skip policy, and escalation paths |
| Repo-local skills | `skills/<name>/SKILL.md` and `docs/harness/SKILLS.md` | Explicit, repeatable procedures and policy/reference context |
| Harness sensors | `docs/harness/bin/` | Executable validation of the tracked harness surface |
| Project architecture | `src/`, `Cargo.toml`, `README.md`, `CLAUDE.md` | Domain, architecture, security, and operational reference |

`skills/<name>/SKILL.md` is the canonical inventoried skill surface. Tracked
provider-integration skills under `.claude/skills/` must not reuse a canonical
repo-local skill name; `doctor.sh` validates that boundary.

## Local and External Surface

The following can affect a session but are not authored or fully controlled by
this repository:

| Surface | Boundary |
|---|---|
| Editor and provider system prompts | Defined by Zed, the model provider, and enabled integrations; do not copy or claim them as repository policy. |
| Native coding-agent tools | File, search, terminal, diagnostics, memory, delegation, and network tools are supplied by the editor/runtime. Their availability and permissions vary by session. |
| Local overlays | Ignored `AGENTS.md`, untracked `.claude/` content, local environment files, and user configuration are operator-owned. Never rewrite them unless the user explicitly requests it. |

Do not assume a tool, skill, model, credential, or local configuration exists
just because it is documented elsewhere. Inspect the active session or ask
before relying on it.

## Working Rules

1. Start from the narrowest relevant repository guidance and verification gate.
2. Invoke a repo-local procedure skill only when its trigger matches the task;
   do not preload all skills into the task context.
3. Keep read/search operations scoped before loading large documents or broad
   tool surfaces.
4. Treat command output, tests, and review evidence as facts only when they
   were actually observed in the current work item.
5. Preserve user-owned and ignored local files unless explicitly asked to
   change them.
6. Before changing the harness itself, read this document, `GATES.md`, and the
   relevant sensor or doctor implementation; harness scripts require human
   review as documented in the harness guide.

## Change Protocol

A harness-surface change must identify which layer it changes:

- **Repository policy or documentation:** update the canonical document and
  links that point to it.
- **Repo-local skill:** update `SKILLS.md` and run `doctor.sh`.
- **Sensor or gate:** update its verification/negative controls and run the
  applicable harness lane.
- **Provider/editor overlay:** do not make repository-wide claims; document
  only the integration boundary if it is relevant to reproducibility.

Use this map before reorganizing `AGENTS.md`, adding skills, reducing tool
surfaces, or proposing model-routing behavior for coding agents.
