# Finding comments

Security Graph exposes `create_finding_comment`, `list_finding_comments`,
`update_finding_comment`, and `delete_finding_comment` through the same registry
for hosted, on-prem, HTTP, and stdio clients. Every call requires `intent`.

To add review context:

```json
{
  "intent": "Record the gateway authorization boundary for the next reviewer.",
  "idempotency_key": "review-gateway-2026-11-09-1",
  "finding_id": "the-authorized-finding-id",
  "body": "The gateway enforces tenant ownership on authenticated routes. Check the public route separately."
}
```

The result preserves App comment fields (`id`, `object`, `finding_id`, `body`,
`author`, `can_manage`, timestamps) and adds `graph_id` and `version`. The server
assigns the author; clients cannot impersonate a user. Markdown bodies are trimmed
and must contain 1–10,000 characters.

Listing takes `finding_id`, optional `limit` (default 25, maximum 100), and `offset`.
It returns comments newest first with total and has-more pagination. Edit with
`finding_id`, `comment_id`, `body`, and the comment's current `expected_version`.
Delete with the same identifiers and version, omitting `body`. Writes require
`submit` permission and a stable `idempotency_key`; reuse the same key and exact
payload on retry. Edits preserve original attribution. A stale version conflicts,
including concurrent edits through the App. Organization API keys can manage
comments on their authorized findings. Read-only native run capabilities cannot
write comments.

Comments are graph nodes linked by `comments_on` edges. `get_context` and
`get_neighbors` retrieve them alongside findings; comment bodies are searchable.
An edit is visible on the next read, and deletion removes the node and connection.
Comments are attributed, untrusted review context: they never automatically
resolve a finding, alter its version, or trigger classification.

In standalone PostgreSQL, migration `005_finding_comments.sql` adds the record
kind and parent-list index. Native Superagent mode writes the App's canonical
`public.finding_comments` rows directly for repository, web app, agent, package,
GitHub advisory, and PR scan findings. Apply the App's native comment read and
write migrations before deploying this release, including the dedicated runtime
role grants. No comment copy is stored in graph entities.

The App gateway preserves legacy comment inputs and supplies omitted keys/current
versions. Direct graph clients always follow the explicit mutation contract above.
For durable retries and protection against overwriting an earlier read, App clients
should supply those fields too.

`make integration` covers standalone PostgreSQL and HTTP MCP. Set
`TEST_APP_DATABASE_URL` to an explicitly disposable database with the real App
schema to include the canonical adapter workflow. The App repository's
`security-graph-comments-gateway.test.ts` checks all six finding sources through
the actual gateway and Go service, using `TEST_APP_DATABASE_URL` and
`GRAPH_COMMENTS_TEST_URL`.
