# Native Superagent integration

The app and Go service share the existing PostgreSQL database. Findings and reports remain authoritative in `repository_red_team_*`, `web_app_red_team_*`, `agent_red_team_*`, `package_red_team_*`, and `protection_advisories`. Security-invoker views project their public context; graph-only assets, links, audit history, idempotency receipts, report origins, and notification intents live in the private `security_graph` schema. No native finding/report is copied into graph entities.

## Authentication and connection

Agents connect to the app's existing `https://www.superagent.sh/mcp` endpoint with an existing `sk_live_` organization API key. The app validates it using existing auth and rate limits, then forwards the same credential to the operator-configured Go service. Go independently validates its SHA-256 hash in `public.api_keys` on every request and derives the organization and API-key actor. Clients never supply an organization ID or org header. Deleting the key revokes subsequent requests on both endpoints.

Existing app keys grant the existing organization-wide access. No new per-agent scopes, asset grants, or expiry are invented for them. Standalone deployments retain their separately issued scoped `sg_` keys. Intent is mandatory but never changes authorization. Existing privacy-scoped MCP analytics bound and redact intent without recording tool arguments or finding contents.

## Deploy

1. Apply the additive `security_graph_native_integration` app migration using the app's normal migration process. Do not run standalone migrations as a substitute.
2. Run the Go service with `STORAGE_BACKEND=superagent`, `DATABASE_URL` pointing to that app database, and `LISTEN_ADDR` on a private network interface.
3. Configure app `SECURITY_GRAPH_URL` to the private service `/mcp` endpoint, using TLS across untrusted networks. Only operators control this URL.
4. Keep `CRON_SECRET` set. The app drains notification intents after writes and `/api/security-graph/effects` retries due intents every minute. Claims have fenced leases, and notification/webhook deduplication uses existing app logic.
5. Verify the real end-to-end workflow before enabling this configuration in production. Unsetting `SECURITY_GRAPH_URL` returns the app to its existing MCP implementation.

Use a dedicated server database login and a direct or session-pool connection. The role must read the five finding sources, four report sources, connected repositories, API keys, and organization memberships; insert/update the native report/finding tables; update API-key `last_used_at`; and read/write private graph metadata with sequence access. It must be allowed to operate across tenants through the app's existing server-side RLS bypass mechanism. Never expose this database credential to MCP clients. DDL belongs to the migration role. The local integration runner uses only the local Supabase database administrator.

## Domain behavior

- Existing app finding/report detail MCP tools use the app's public serializers and add an optimistic `version`. Native Go reads provide normalized context with the same lifecycle vocabulary.
- `create_report` records external work in the matching native report table, without provisioning a sandbox, starting an internal scan, or billing models. Native report origins retain the API-key actor and asset mapping. Only the originating key can finish that external execution. Existing native scans keep their execution ownership.
- `submit_finding` validates the shared repository authoring contract: policy evidence, code references, PoC, proposed patch, validation evidence, and the six Markdown sections. It writes existing advisory fields with triage `new` and no independent verification assertion. Full structured submission and actual API-key attribution remain in triage evidence and graph history.
- Manual triage updates preserve resolution clearing and the app's report triggers. Agent reports translate internal `completed`/`review_completed` into public `in_review`/`completed`. Resolving findings in a running assessment does not finish it. New findings reopen finished reports.
- Mutation, notification intent, audit history and idempotency receipt commit in one transaction. Notifications/webhooks use existing app fanout after commit, with durable retry on failure. GitHub publication and sandbox execution stay in their existing app workflows.
- List tools support kind, triage status, report type/status, asset and search filters. Stable ID cursors and bounded offsets replace newest-first paging in the native v2 surface. App list envelopes expose `pagination.next_after`; they do not claim a total count.
- The change feed currently records graph-mediated mutations, not all app-originated edits or deletions. Direct reads immediately reflect app edits. A full replication protocol remains future work.

## Integration verification

In a sibling app checkout, run `pnpm test:security-graph` with local Supabase running, its native migration applied, and local Supabase credentials in `.env.local`. Set `SECURITY_GRAPH_PROJECT` if this repo is not a sibling named `security-graph`. The runner starts isolated real Next and Go services, creates temporary organizations and existing-format local API keys, exercises real MCP and REST, then deletes its fixtures. No organization is supplied by the client and no key is printed.

Coverage includes all four report kinds, connected GitHub advisories, native source identity without imports, concurrent idempotent submissions, canonical app serialization, report reopen/review/completion, accepted-risk notifications, tenant isolation, private-schema access and revocation. Standalone PostgreSQL/MCP workflows remain covered by `make integration`.

On-prem uses the same engine/contracts against its own PostgreSQL or custom storage adapter. The hosted UI does not read an on-prem database implicitly; an explicit connector/network path is a separate milestone.

## Continuous integration access

The app native workflow checks out the pinned engine source using `SECURITY_GRAPH_DEPLOY_KEY`, a read-only engine-repository deploy key. Its reviewed commit is configured through `SECURITY_GRAPH_INTEGRATION_REF`.

This repository's pull requests and main pushes run the standalone PostgreSQL/MCP integration suite, format/vet/build checks, schema and dependency checks, and container smoke checks. Native App end-to-end verification runs separately from the app checkout; it is not a CI job in this repository.

Rotate the app workflow's credential by replacing its consuming repository secret and then removing the old deploy key from the source repository.


## Native assessment execution

The compatible App migration `20261109083236_native_security_graph_mcp_execution.sql`
adds server-only native capabilities, history-search receipts and classification
jobs. Existing organization API keys continue to work. Native runners still use
their App callbacks; those credentials are never accepted by MCP. The App mints
short-lived `sg_native_` capabilities only on its trusted server. Each capability
selects one live run, organization, asset and publishing agent, with read access
or explicit native submission authority. The App revokes it after the request;
expiry and live runner checks prevent reuse after completion or revocation.

The native-only `get_native_context`, `search_native_context`,
`save_native_finding` and `replace_native_pr_findings` tools are advertised only
for this audience. Public API keys cannot invoke them. Standard mutations and
report/disposition ownership are not granted to native capabilities. The App
still verifies peer review and normalizes modality-owned findings before calling
the native save operation. Graph writes canonical App rows and commits audit,
idempotency, notification and inference intents together. There is no second
finding store. PR replacement is atomic and preserves durable reviewer feedback.

The service records successful native history searches and rejects publication
without a receipt for that run and publishing agent. A startup snapshot or
another peer's search does not satisfy this requirement. The App's agent-facing
MCP bridge carries evidence as untrusted tool data and keeps free-form history
out of startup instructions.

Apply the migration before deploying the new service and App. Existing trusted
Graph runtime roles are granted the additional least-privilege access by the
migration's final block; newly provisioned runtime roles need those same grants.
No browser role receives access. Native capabilities stay entirely on the App
server and never enter sandbox configuration or model context.

## Finding review status and history

Apply the App's `20261110075253_finding_disposition_graph_parity` migration before
deploying the engine with native PR triage support. PR findings accept the same
manual states (`new`, `in_review`, `resolved`) and resolutions (`fixed`,
`accepted_risk`, `false_positive`, `wont_fix`) as other findings. The legacy
`dismissed` flag remains synchronized; reopening clears cached PR suppression.
PR execution results are retained rather than rerunning the assessment.

Dashboard, REST, and MCP transitions append actor-attributed before/after events
atomically with the authoritative row update. Native MCP writes use the
authenticated API-key actor and do not duplicate the database event. Context
records expose the ten most recent transitions in `data.status_history`; the
change feed includes operation and structured event details. Historical review
context remains available when a finding is reopened, with the current status
and newer transitions taking precedence. The migration grants the native runtime
only the additional PR columns and dismissal-cache access it needs.

## Agent-selected vulnerability types and compliance

Apply App migration `20261110092754_agent_selected_finding_classification.sql`.
It retires inference queue triggers, marks outstanding jobs manual, and exposes
explicit compliance IDs in authorized native context and dashboard pagination.
Historical model suggestions remain readable; they are not converted into agent
choices.

`get_classification_options` returns two selectable lists: `vulnerability_types`
and `compliance`, with the catalog version, names, descriptions, framework
releases and reference mappings. `set_finding_classification` takes current
finding/classification versions, `type_ids`, `compliance_ids`, `rationale`,
`intent` and `idempotency_key`. Both arrays are required; empty arrays are valid
when no catalog choice applies. Input schemas enumerate allowed IDs. Invalid or
duplicate IDs, stale versions, and unauthorized writes are rejected. No inference
runs. Graph edges record the chosen types and compliance entries independently;
catalog reference mappings do not silently select compliance entries.

Native agents retrieve the same choices through their scoped MCP bridge and
include `classification: {type_ids, compliance_ids, rationale}` in each finding
or PR receipt. The App preserves this metadata through normalization. The Go
engine validates it and writes the classification atomically with canonical
finding persistence; it never stores classification fields in canonical advisory
columns. Existing publishing-peer, verification and history-read guards remain.
Native publishing paths require explicit selections. Hosted, standalone and
on-prem deployments use the same agent-selection tools and schemas; there is no
model runtime or background classification worker.
