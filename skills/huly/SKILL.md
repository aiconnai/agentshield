---
name: huly
description: Use when working with Huly workspaces, projects, issues, labels, components, milestones, or documents. Prefer the official Huly Platform API for token-based automation, especially when the user authenticates to Huly through GitHub/Google/OIDC and the third-party huly-cli email/password login path cannot be used.
metadata:
  short-description: Work with Huly via the Platform API
---

# Huly

Use this skill to read or write Huly project data from Codex.

## Decision path

- If a first-party Huly MCP/app connector is available, use that.
- If the user asks to use the Python `huly-cli`, use it only when email/password auth is available.
- If the user uses GitHub/Google/OIDC login, prefer the official Platform API with token auth.
- For writes, first do a non-mutating connection/project lookup to confirm workspace, token, and project.
- Make write scripts idempotent: search by title or identifier first, then create only missing records.

## Environment

Expected env vars:

```bash
HULY_URL=https://huly.app/workbench/<workspace>/
HULY_WORKSPACE=<workspace-slug>
HULY_PROJECT=<project-identifier>
HULY_API_TOKEN=<token>
```

Compatibility fallbacks:

```bash
HULY_TOKEN=<token>
HULY_APY_TOKEN=<token>
```

`HULY_APY_TOKEN` is commonly a typo. Prefer `HULY_API_TOKEN`, but support the typo if already present.

Normalize `HULY_URL` before calling the API client. Browser URLs like `https://huly.app/workbench/aiconn/` should connect to base URL `https://huly.app`.

## Python CLI caveat

The third-party Python CLI can be useful for simple local workflows:

```bash
pipx install huly-cli
huly --help
```

But the observed `huly-cli` auth flow supports:

```bash
huly auth login --email ... --password ...
```

It does not support GitHub OAuth login. If the user logs in through GitHub, use the Platform API instead.

## Platform API setup

Use a temporary Node workspace unless the project already has Huly API dependencies.

```bash
tmp=/tmp/huly-api-work
rm -rf "$tmp"
mkdir -p "$tmp"
cd "$tmp"
npm init -y >/dev/null
npm install --silent \
  @hcengineering/api-client \
  @hcengineering/core \
  @hcengineering/rank \
  @hcengineering/tracker \
  ws ts-node typescript @types/node
```

Node 26 may expose `sessionStorage`, causing the Huly client to take a browser branch and expect `window`. Add this shim before importing Huly client modules:

```ts
(globalThis as any).window = (globalThis as any).window ?? { addEventListener: () => undefined }
```

Run TypeScript scripts with:

```bash
npx ts-node --transpile-only \
  --compiler-options '{"module":"Node16","moduleResolution":"Node16"}' \
  script.ts
```

## Read-only project lookup

Always run a read-only check before creating or updating Huly data.

```ts
(globalThis as any).window = (globalThis as any).window ?? { addEventListener: () => undefined }

import { NodeWebSocketFactory, connect } from '@hcengineering/api-client'
import tracker from '@hcengineering/tracker'

function baseUrl (raw: string): string {
  const url = new URL(raw)
  return `${url.protocol}//${url.host}`
}

async function main (): Promise<void> {
  const url = baseUrl(process.env.HULY_URL ?? 'https://huly.app')
  const token = process.env.HULY_API_TOKEN ?? process.env.HULY_TOKEN ?? process.env.HULY_APY_TOKEN
  const workspace = process.env.HULY_WORKSPACE
  const projectIdentifier = process.env.HULY_PROJECT

  if (token === undefined || token === '') throw new Error('Missing HULY_API_TOKEN/HULY_TOKEN')
  if (workspace === undefined || workspace === '') throw new Error('Missing HULY_WORKSPACE')
  if (projectIdentifier === undefined || projectIdentifier === '') throw new Error('Missing HULY_PROJECT')

  const client = await connect(url, {
    token,
    workspace,
    socketFactory: NodeWebSocketFactory,
    connectionTimeout: 30000
  })

  try {
    const project = await client.findOne(tracker.class.Project, { identifier: projectIdentifier })
    if (project === undefined) {
      const projects = await client.findAll(tracker.class.Project, {}, { limit: 20 })
      console.log(JSON.stringify({
        ok: false,
        error: 'Project not found',
        knownProjects: projects.map((p: any) => ({
          identifier: p.identifier,
          name: p.name ?? p.description
        }))
      }, null, 2))
      process.exitCode = 2
      return
    }

    console.log(JSON.stringify({
      ok: true,
      project: {
        identifier: project.identifier,
        id: project._id,
        description: project.description,
        defaultIssueStatus: project.defaultIssueStatus
      }
    }, null, 2))
  } finally {
    await client.close()
  }
}

void main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err)
  process.exit(1)
})
```

## Create issues idempotently

Use this pattern for issue creation:

- Look up the project by `tracker.class.Project` and `{ identifier: HULY_PROJECT }`.
- For each issue, check `tracker.class.Issue` by `{ space: project._id, title }`.
- If it exists, skip it.
- Increment project sequence with `client.updateDoc(...)`.
- Upload Markdown with `client.uploadMarkup(...)`.
- Create the issue with `client.addCollection(...)`.

```ts
(globalThis as any).window = (globalThis as any).window ?? { addEventListener: () => undefined }

import { NodeWebSocketFactory, connect } from '@hcengineering/api-client'
import core, { SortingOrder, generateId } from '@hcengineering/core'
import { makeRank } from '@hcengineering/rank'
import tracker, { IssuePriority } from '@hcengineering/tracker'

type IssueSpec = {
  title: string
  priority: IssuePriority
  description: string
}

function baseUrl (raw: string): string {
  const url = new URL(raw)
  return `${url.protocol}//${url.host}`
}

async function createIssues (issues: IssueSpec[]): Promise<void> {
  const url = baseUrl(process.env.HULY_URL ?? 'https://huly.app')
  const token = process.env.HULY_API_TOKEN ?? process.env.HULY_TOKEN ?? process.env.HULY_APY_TOKEN
  const workspace = process.env.HULY_WORKSPACE
  const projectIdentifier = process.env.HULY_PROJECT

  if (token === undefined || token === '') throw new Error('Missing HULY_API_TOKEN/HULY_TOKEN')
  if (workspace === undefined || workspace === '') throw new Error('Missing HULY_WORKSPACE')
  if (projectIdentifier === undefined || projectIdentifier === '') throw new Error('Missing HULY_PROJECT')

  const client = await connect(url, {
    token,
    workspace,
    socketFactory: NodeWebSocketFactory,
    connectionTimeout: 30000
  })

  const results: Array<{ action: 'created' | 'skipped', identifier: string, title: string }> = []

  try {
    const project = await client.findOne(tracker.class.Project, { identifier: projectIdentifier })
    if (project === undefined) throw new Error(`Project not found: ${projectIdentifier}`)

    for (const spec of issues) {
      const existing = await client.findOne(tracker.class.Issue, {
        space: project._id,
        title: spec.title
      })

      if (existing !== undefined) {
        results.push({ action: 'skipped', identifier: existing.identifier, title: spec.title })
        continue
      }

      const issueId = generateId()
      const incResult = await client.updateDoc(
        tracker.class.Project,
        core.space.Space,
        project._id,
        { $inc: { sequence: 1 } },
        true
      )
      const sequence = (incResult as any).object.sequence
      const identifier = `${project.identifier}-${sequence}`
      const lastIssue = await client.findOne(
        tracker.class.Issue,
        { space: project._id },
        { sort: { rank: SortingOrder.Descending } }
      )
      const description = await client.uploadMarkup(
        tracker.class.Issue,
        issueId,
        'description',
        spec.description,
        'markdown'
      )

      await client.addCollection(
        tracker.class.Issue,
        project._id,
        project._id,
        project._class,
        'issues',
        {
          title: spec.title,
          description,
          status: project.defaultIssueStatus,
          number: sequence,
          kind: tracker.taskTypes.Issue,
          identifier,
          priority: spec.priority,
          assignee: null,
          component: null,
          estimation: 0,
          remainingTime: 0,
          reportedTime: 0,
          reports: 0,
          subIssues: 0,
          parents: [],
          childInfo: [],
          dueDate: null,
          rank: makeRank(lastIssue?.rank, undefined)
        },
        issueId
      )

      results.push({ action: 'created', identifier, title: spec.title })
    }

    console.log(JSON.stringify({ ok: true, project: project.identifier, results }, null, 2))
  } finally {
    await client.close()
  }
}
```

## Priorities

Use `IssuePriority` from `@hcengineering/tracker`:

```ts
IssuePriority.NoPriority // 0
IssuePriority.Urgent     // 1
IssuePriority.High       // 2
IssuePriority.Medium     // 3
IssuePriority.Low        // 4
```

## Operational rules

- Do not print tokens or full `.env` values.
- Prefer temporary scripts under `/tmp` for one-off Huly operations.
- Do not commit temporary Node workspaces or generated auth/cache files.
- Use raw API output only for identifiers, titles, and non-sensitive metadata.
- If a write fails mid-run, rerun the idempotent script rather than manually guessing sequence numbers.
- Treat Huly model-sync warnings like `no document found, failed to apply model transaction` as noise if the final API result is successful.
