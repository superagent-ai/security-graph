# Superagent Security Graph product and implementation plan

Superagent Security Graph will make Superagent’s native security knowledge available to customer-selected agents and models through MCP. Customers can use a PR review bot, pentester, or coding agent such as Codex to retrieve context, contribute findings, and record investigation and remediation results.

The implementation will live in the private repository `superagent-ai/security-graph`. It will reuse the existing finding and report models from `superagent-ai/app`, including their lifecycle rules and report structure. Hosted and on-prem deployments run the same context engine, MCP/API surface, finding template, and versioned contracts. PostgreSQL is the default backend; a storage adapter interface supports custom database implementations. The hosted service works natively with Superagent’s existing organization identity and PostgreSQL database. Customers use an existing organization API key and connect to the existing hosted MCP endpoint; they do not provision a separate service account, database, import, or synchronization setup.

This is the proposed release and implementation baseline as of 27 October 2026. Commercial packaging, delivery dates, and named owners remain open. Repository creation and implementation are subsequent work.

# Product scope

Product and MCP display name: **Superagent Security Graph**. Private repository: `superagent-ai/security-graph`. Standalone/on-prem MCP connection name: `superagent-security-graph`. Keep the existing hosted connection name `superagent` and endpoint `https://www.superagent.sh/mcp`. Descriptor: **The security context engine for your agents**.

The product promise is: **Connect your agents to what Superagent knows about your software’s security, and retain what those agents learn.**

The core loop is:

1. Superagent products contribute findings, reports, evidence, and remediation context.

2. A customer agent retrieves context for a specific target and task.

3. The agent investigates, reviews, or patches the software.

4. It submits findings or investigation results using Superagent’s contracts.

5. Authorized actors update dispositions and report review state.

6. Later customer agents and Superagent workers reuse that context.

Both native workers and external agents must consume the context service. Completion requires a demonstrated feedback loop, not just a readable MCP endpoint.

# Outcomes and measurement

| Outcome | Mechanism | Measure |
| --- | --- | --- |
| Fewer false positives | Reuse verification evidence and decisions within their applicable scope | Precision and repeat false-positive rate |
| More true positives | Connect affected assets, historical weaknesses, and exploit prerequisites | Recall on held-out cases and independently verified new findings |
| Lower cost | Reuse investigation work and retrieve bounded context | Total cost per verified finding and verified fix |
| Agent and model sovereignty | Customer-selected clients, runners, and model providers | Successful independent-client workflows |
| Shorter finding-to-patch time | Deliver evidence, code references, proposed patches, and verification context together | Median and p90 time from finding creation to verified fix |
| Broader coverage | Connect security context across the customer’s stack | Share of in-scope assets with recent checks, by asset type |
| More frequent checking | Support incremental retrieval and reusable evidence | Checks per active asset and age of last check |

Quality and cost improvements are hypotheses to validate. Compare the same tasks, models, and budgets with and without context. Keep held-out answers out of retrieval. Include context-service cost, ingestion, model usage, and human review in cost accounting.

Accepted risk and won’t-fix decisions do not count as patches. A proposed patch or merged PR alone does not establish a verified fix.

# Release workflows

**PR review.** A customer bot requests context for a repository and revision or PR. It receives related findings, affected components, previous decisions, and remediation history. It returns new findings or evidence linked to existing findings.

**Pentest to patch.** A pentester records an application finding and reproduction evidence. A coding agent retrieves that finding and its repository relationship, prepares a patch, and submits its result. Authorized resolution and subsequent verification feed later reviews.

**Persistent security memory.** A later native scan retrieves an earlier customer-agent investigation, respects its scope and freshness, and uses it to guide verification or detect a regression.

The launch demonstration should complete the pentest-to-patch workflow and show a later PR review using the retained context.

# Existing finding contract

Use the app’s existing vocabulary and behavior as the normative baseline.

| Dimension | Values |
| --- | --- |
| Triage status | `new`, `triaging`, `in_review`, `resolved` |
| Resolution | `fixed`, `accepted_risk`, `false_positive`, `wont_fix` |
| Verification | `confirmed`, `not_reproducible`, `inconclusive`, `heuristic` |
| Normalized risk | `critical`, `high`, `medium`, `low` |

Preserve these rules:

- Resolving requires a valid resolution.

- Moving to `new` or `in_review` clears the resolution.

- `triaging` is set through an authorized triage operation, not an ordinary manual update.

- Workflow state, verification result, and resolution remain independent.

- Preserve existing automatic triage behavior through adapters and compatibility checks. An outside agent’s submitted verdict is attributed evidence; it does not gain authority to overwrite the current disposition merely by submitting a result.

- Preserve historical values and source identity during migration; use the app’s existing normalization where applicable.

The detailed finding payload is the starting point: identity, source and kind, report association, title and description, CWE, CVSS, severity and risk, affected products, triage report and evidence, remediation, and timestamps. The top-level source `status` must remain distinct from `triage.status`.

Existing list responses flatten `triage_status` and `triage_resolution`; detail responses nest them under `triage`. Preserve compatibility for current consumers and describe both representations explicitly in the shared contract.

Sources: [finding enums and types](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/protection/advisory-types.ts), [finding serializer](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/api/v1/findings.ts), and [manual transition rules](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/factory/update-triage-status.ts).

# Finding report and engagement report

Require the same existing finding template for Superagent workers and external agents. The submission schema and server-side validation must enforce these six sections:

1. Impact

2. Details

3. Policy Verification

4. Code References

5. PoC

6. Remediation

Where a section does not apply, require a short explanation rather than invented evidence. Black-box investigations may lack source-code references. Existing imported records retain their original content and provenance; ingestion must not manufacture missing sections.

Retain three distinct pieces of content:

- **Finding description:** the vulnerability narrative in the existing six-section format.

- **Triage report:** summary, recommendation, Markdown report, verification result, structured evidence, and investigation timestamps.

- **Engagement report:** the parent run or assessment, its target, execution state, and review state.

Retain remediation fields for proposed patches and code references. Add agent identity, run identity, tested revision or artifact digest, environment, and provenance as versioned extensions where the existing contract lacks them. Keep investigation attempts as history, while exposing the current finding view.

A customer-agent result should update or attach to these existing concepts. A new submission envelope may carry transport metadata, but it must not introduce a competing finding lifecycle.

Source: [existing finding template](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/repository-red-team-advisory-types.ts#L118).

## Native integration implementation status

The native adapter now uses the existing app database and `sk_live_` API-key authentication behind the existing `/mcp` endpoint. Organization identity is derived exclusively from the key: no org setting, header, or tool field is needed. Current app keys retain their existing organization-wide permissions; granular scoped agent credentials remain future work. Local end-to-end checks exercise native records, external submissions through the shared finding template, lifecycle transitions, app REST visibility, notifications, isolation and revocation. Operator rollout requires the additive app migration plus `STORAGE_BACKEND=superagent`, a server database connection and app `SECURITY_GRAPH_URL`. This does not mean production has been deployed. The remainder of this plan describes the wider product scope, including work not yet implemented.

## Finding submission schema

The submission contract must reuse the app’s structured finding authoring schema, validator, and Markdown formatter. The read API’s `description: string` is the rendered representation of that template, not the full authoring schema. Extract these contracts into `pkg/contracts` and use them for both native workers and external-agent submissions.

The new MCP submission envelope requires `intent` alongside `finding`. The finding fields come from the existing verified repository `save_finding` contract. External submissions extend that payload with explicit evidence applicability: source files, code references, policy documents, and proposed patches are optional when unavailable, allowing black-box assessments without invented evidence. This excerpt shows the envelope and required field set; complete property definitions and nested validators are published in `contracts/mcp-tools.json`.

```json
{
  "type": "object",
  "required": [
    "intent",
    "finding"
  ],
  "properties": {
    "intent": {
      "type": "string",
      "minLength": 1,
      "maxLength": 500,
      "pattern": "\\S",
      "description": "State the concrete purpose of this call and the security task it supports. Do not include secrets."
    },
    "finding": {
      "type": "object",
      "required": [
        "cwe_ids",
        "summary",
        "impact",
        "details",
        "proof",
        "exploit_preconditions",
        "reproduction_steps",
        "policy_verification",
        "false_positive_analysis",
        "remediation",
        "github_advisory"
      ]
    }
  }
}
```

The shared template maps these structured fields to the existing finding description:

| Template section | Structured content |
| --- | --- |
| Impact | `impact` |
| Details | `details`, supported by `exploit_preconditions` and `false_positive_analysis` |
| Policy Verification | `policy_verification` with reviewed documents, scope checks, intended-behavior checks, and conclusion |
| Code References | `code_references` containing file, line range, excerpt, reason, and optional symbol |
| PoC | `proof` and concrete `reproduction_steps` with observed results |
| Remediation | `remediation`, with structured `proposed_patch` and validation evidence retained alongside it |

In the existing repository authoring payload, `github_advisory.description` carries the formatted Markdown with all six headings. The public finding exposes it as `description`. The triage investigation’s `triage.report_markdown` remains a separate field.

The repository schema also requires a stable identifier through the outer or inner `id`; `title` and `severity` can be supplied directly or normalized from `github_advisory`. External submissions retain the required policy conclusion and affected-product information; supplied policy documents, code references, and patches retain their nested validation requirements. Keep any additional source-specific sections, such as an attack-flow diagram, supported by the shared formatter.

Use the same six-section template across all targets. For external attributed submissions, omit unavailable source evidence and patches and explain the limitation in the relevant sections. Missing, null, or empty `code_references` requires a nonblank `code_references_unavailable_reason` repeated in the `Code References` section. Missing, null, or empty `policy_verification.docs_reviewed` requires a nonblank `policy_verification.docs_unavailable_reason` repeated in the policy conclusion. The generated MCP contract records this applicability extension; the App's native verified repository authoring contract retains its existing requirements. Black-box sources must not fabricate repository code or patch evidence.

Submission validates both the structured content and the rendered template. Missing required sections or evidence return field-specific errors. Imported historical findings retain their original content and provenance.

Contract checks must prove that native and external submissions use the same template, required fields, nested validation, and output mapping.

Source: [existing save_finding schema and validation](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/repository-red-team/sandbox/runner-assets.ts#L1853).

# Report lifecycle

The existing report API accepts `in_progress`, `in_review`, `completed`, `done`, and `failed`. Manual review updates accept only `in_review` or `completed`.

Preserve the current semantics:

- Only successfully finished reports can change review status.

- Completing report review does not resolve its findings or establish that vulnerabilities were fixed.

- Review can be completed with unresolved findings.

- Resolving every finding completes the report automatically.

- New or reopened unresolved findings return the report to review.

- A successful scan with no findings completes automatically.

- Review changes do not launch a scan or emit a new scan-finished event.

Keep execution and review concepts distinct. Preserve `done` compatibility and the current source-specific mappings, including Agent reports mapping internal `review_completed` to public `completed`. Define any eventual normalization in a separate versioned migration.

Sources: [report review implementation](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/reports/review-status.ts), [report serializers](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/lib/api/v1/reports.ts), and [report API behavior](https://github.com/superagent-ai/app/blob/1e26923fe224443e78a20718fe029b0e61006e81/content/docs/api-reports.md#L85).

# Context model and source coverage

Findings and reports are the core records. Extend their usefulness with asset relationships, attributable evidence, historical decisions, and remediation links.

Start with explicit relationships: finding affects asset, finding belongs to report, application uses repository, deployment runs revision, package is used by asset, finding is related to finding, and patch addresses finding. Each relationship carries its source, observation time, and relevant revision or environment. Inferred relationships must be labeled and distinguishable from verified mappings.

Decisions apply to their observed scope. A false positive on one revision cannot silently suppress a finding on another. Unknown coverage and stale evidence must be visible to the consuming agent.

| Source | Integration requirement |
| --- | --- |
| Repository and application red team | Preserve existing findings, reports, evidence, and target references |
| Agent and Package red team | Include the existing internal finding models in the common external surface |
| PR security and connected advisories | Preserve source-specific origin and identifiers; map to the shared finding contract |
| Dependency updates | Link assessments and published remediation to affected assets and findings |
| Agent guardrails and infrastructure | Retain alert or incident semantics and link relevant context; do not turn every event into a vulnerability |
| Customer agents | Validate new submissions against the same finding and report contracts |

The current generic Findings API enumerates repository, application, and GitHub advisory findings, while the internal update path also supports Agent and Package findings. Closing this coverage gap is release work.

Customer-private evidence remains isolated by organization. Public research is a separately attributed enrichment source. Cross-customer learning from private records is outside this release.

# MCP and API surface

## Mandatory intent on every MCP call

Every context MCP tool requires a top-level `intent` input, including reads, searches, graph traversal, exports, submissions, and lifecycle updates. The agent states the concrete purpose of that call and the security task it supports. Intent describes the action’s purpose; it does not request private internal reasoning.

Use a string of 1 to 500 characters after trimming. Reject missing, null, non-string, empty, whitespace-only, or oversized values before executing the tool. Do not supply a default or infer intent from previous calls. Publish the requirement and useful examples in every tool’s input schema and client instructions.

For example, a `get_finding` call includes:

```json
{
  "intent": "Check the previous tenant-isolation finding before reviewing the authorization changes in this PR.",
  "finding_id": "finding_uuid"
}
```

The engine can use intent alongside explicit task and asset parameters to select relevant context. Intent cannot expand access, override scope, authorize a mutation, or replace evidence. Treat it as untrusted caller input.

Keep intent in the tool-call envelope rather than the finding/report domain model. Retain a bounded, sanitized representation in permitted invocation audit records; existing privacy controls apply to analytics and logs. Finding content, evidence, and secrets must not be copied into intent.

Apply the same requirement in hosted and on-prem deployments and with every storage adapter. Introduce it through the versioned context MCP contract and document migration for existing clients, because making a field mandatory changes the input contract. No call to the new context MCP surface may execute without intent.

Contract checks cover omission, null, wrong type, whitespace-only input, length limits, valid input, all registered tools, and hosted/on-prem parity.

Retain existing operation names and meanings where available: `list_findings`, `get_finding`, `update_finding_triage`, `list_reports`, `get_report`, and `update_report_review_status`. Each operation on the versioned context MCP surface also requires the common `intent` field.

Add operations for the following capabilities; exact names will be finalized with the contract:

| Capability | Required behavior |
| --- | --- |
| Retrieve task context | Filter by authorized assets, task, revision, environment, and time; return a bounded bundle |
| Search and traverse | Find related findings, evidence, decisions, reports, and asset relationships |
| Submit findings | Enforce the shared structured finding schema and six-section template; return stable IDs and ingestion outcome |
| Submit investigation results | Attach evidence, triage reports, patch references, and verification claims to a finding |
| Export and synchronize | Provide permission-scoped snapshots, pagination, and changes since a cursor |

Every context bundle includes provenance, freshness, scope, source IDs, and explicit truncation or missing-data indicators. Full graph export is supported; routine agent requests should retrieve the relevant subset.

Submissions require idempotency keys. Updates use a version or equivalent concurrency guard. Duplicate detection may suggest matches, but must preserve evidence and make mistaken merges reversible. Writes produce auditable actor and change records. Separate submission permissions from disposition permissions.

Reuse existing event infrastructure for notifications. Add events only where existing ones cannot represent context changes; document delivery retries, ordering, and cursor recovery.

# Repository and service boundaries

Create `superagent-ai/security-graph` as a private repository. Use Go with the official MCP Go SDK and a standalone service runtime. Generate language-neutral JSON schemas from the Go contracts for app compatibility; preserve the existing domain semantics. PostgreSQL is the reference backend in hosted and on-prem deployments, accessed through a versioned storage adapter interface. Keep evidence storage behind a separate object-storage interface. Specialized search or graph infrastructure can be added when measured workloads justify it.

Suggested layout:

```text
cmd/security-graph/        Service, migrations, and credential administration
cmd/export-schemas/        Language-neutral MCP schema export
internal/server/           Authenticated MCP and HTTP entrypoints
internal/engine/           Retrieval, relationships, and lifecycle operations
pkg/contracts/             Finding/report models and validation
pkg/storage/               Versioned storage adapter interface
pkg/postgres/              Reference PostgreSQL adapter and migrations
contracts/                 Generated tool schemas
integration/               Real database and MCP workflow tests
scripts/                   Integration and release entrypoints
docs/                      Architecture, operations, and client setup
```

Publish versioned Go contracts and generated language-neutral JSON schemas for both repositories to consume. The app may validate these schemas from TypeScript; shared integration fixtures verify domain behavior across languages. Keep domain rules independent of database clients, Next.js cache invalidation, billing, and sandbox execution. Preserve current IDs through namespaced source references and explicit mappings.

The app retains its UI, billing, scanners, and execution workflows. In hosted operation, the Context PostgreSQL adapter reuses the existing authoritative finding and report tables and adds context relationships, history, and derived indexes in the same database. External submissions enter the shared authoritative finding/report path and appear in the app. Read projections may accelerate retrieval, but hosted operation does not copy findings and reports into a second system of record. Route mutations through shared domain rules and preserve existing lifecycle side effects. Every record has one authoritative write path.

Do not expose raw app database access to customer agents or rely on independent writes to both stores.

# Storage and graph backend

PostgreSQL is the default supported backend. Customers may bring their own PostgreSQL instance or implement the storage adapter for another database. Both options use the same context engine, finding/report models, six-section finding template, lifecycle rules, and MCP/API behavior.

| Backend option | Customer supplies | Superagent supplies |
| --- | --- | --- |
| Customer PostgreSQL | Database connection, infrastructure, and operational configuration | Reference adapter, versioned schema and migrations, context engine, and compatibility checks |
| Custom database | A storage adapter and database operations for the chosen system | Versioned adapter specification, context engine, and compatibility checks |

Hosted PostgreSQL migrations extend the existing Superagent database with context relationships, history, and indexes while reusing its finding and report tables. On-prem migrations initialize the equivalent models in a dedicated customer database or schema. Store core entities and evidence references in typed tables. Store relationships with organization, source entity, relationship type, target entity, provenance, revision or environment, and observation time. Use indexed typed columns for core fields and JSONB for source-specific metadata. Implement bounded traversal through joins and recursive queries, and provide a PostgreSQL search implementation as the default. A specialized graph database is not required for the initial release.

## Building the context graph

The context engine creates relationships from explicit source identifiers, product integrations, agent submissions, and customer mappings. Examples include finding belongs to report, finding affects application, application uses repository, repository uses package version, and patch addresses finding.

Create deterministic relationships automatically. Label inferred relationships with their provenance and confidence, and support correction. A database connection alone does not establish asset relationships.

Authoritative records and asserted relationships remain durable. Derived relationships and search indexes can be rebuilt from their source records and assertions. Preserve the app integration’s existing write-ownership rules during migration.

## Storage adapter contract

The adapter exposes domain operations rather than a generic SQL interface. The service owns finding validation, lifecycle rules, authorization, relationship building, and context assembly. The adapter implements durable persistence, scoped queries, concurrency, and consistency.

| Operation | Required semantics |
| --- | --- |
| Read entities | Retrieve findings, reports, assets, and evidence references within the supplied organization and asset scope |
| Apply mutation | Check expected version and idempotency key; persist the change, audit history, and change event atomically |
| Traverse relationships | Return an authorized neighborhood with explicit depth, result, and execution limits |
| Export snapshot | Produce a consistent, permission-scoped snapshot with resumable pagination |
| Read changes | Return durable changes and deletions through a documented cursor and retention contract |

A custom backend must satisfy these semantics, including atomic writes or an equivalent implementation that passes the same contract checks. Unsupported guarantees must fail explicitly. The adapter cannot redefine statuses, bypass the shared finding template, or silently weaken isolation.

Version the adapter interface and document compatibility with context-service releases. PostgreSQL migrations ship with the reference adapter; custom adapter maintainers own their database schema migrations, backup, restore, and upgrades.

Search can use a separate adapter with indexes derived from authoritative records. This permits another search or graph engine later without changing finding/report contracts or replacing durable storage.

## Source connectors and release support

A source connector imports data from an existing system. A storage adapter replaces the context service’s persistence implementation. Customers can use either or both.

Ship the complete PostgreSQL adapter, on-prem deployment package, adapter specification, and reusable contract checks in the first release. Validate the extension interface with a minimal alternate test implementation. Production support for additional databases requires a maintained adapter that passes compatibility checks and representative workload validation.

# Ingestion and migration

1. Inventory source schemas, lifecycle behavior, evidence availability, and event coverage.

2. Extract and version the existing contracts before adding context-specific fields.

3. Initialize hosted context relationships and indexes from existing records in place, preserving IDs, timestamps, and provenance. Backfill copies of source records only when importing from another system or explicitly connecting deployments.

4. Capture authoritative changes durably for relationship maintenance, derived indexes, and explicitly configured connectors, using an outbox or equivalent mechanism tied to writes. Hosted finding/report reads use the existing authoritative tables.

5. Apply derived updates and connector events idempotently; reject stale versions and reconcile source IDs, relationships, and lifecycle state. Do not independently write competing hosted copies of findings or reports.

6. Propagate deletions and access revocation through retrieval indexes, cached bundles, exports where controllable, and evidence references.

7. Compare context responses with app responses before routing native workers through the service.

8. Enable external writes after read compatibility and ownership routing pass validation.

Use feature flags and staged organizations for cutover. App workflows remain available during context-service failures. Surface freshness for derived indexes; projection lag does not redefine authoritative hosted finding/report state. Pending synchronization applies to explicitly configured cross-deployment connectors, not to normal hosted record persistence. Rollback stops new routing without discarding submitted evidence or audit history.

# Hosted and customer-managed deployment

Run the same context engine and versioned finding/report contracts in hosted and on-prem deployments. Deployment mode changes infrastructure, configuration, and operations; a custom storage adapter changes persistence. Neither creates a separate product model or finding template.

**Hosted default:** Superagent operates the shared context service against the app’s existing PostgreSQL database, using existing finding/report tables and adding context structures. Reuse existing account and organization identity and provide scoped agent credentials through Superagent Settings. Native integration is enabled as part of the hosted release; customers only create a credential and add the MCP connection.

**Customer-managed on-prem:** provide the same service as a pinned container release with PostgreSQL configuration and migrations, evidence-storage configuration, authentication integration, health checks, backup and restore guidance, and an upgrade procedure. Customers supply database, storage, networking, and identity configuration. PostgreSQL is the default; a compatible custom storage adapter can replace it. The core service must work without access to the app’s private database or Superagent’s internal cloud credentials.

Document where records, indexes, evidence, logs, caches, and backups live. A remote database alone is not a fully customer-managed deployment. Synchronizing hosted Superagent product data to a customer deployment is an explicit, scoped connection; external-agent submissions must work without that connection.

Core retrieval and storage should not require a Superagent-selected model. Any model-assisted enrichment is optional, separately configured, and explicit about data egress. Customer agents remain responsible for their own model-provider data handling.

Permissions cover reading, evidence submission, dispositions, export, and administration, with organization and asset scope. Enforce them on the service, including evidence downloads and exports. Treat stored report text as untrusted content. Keep credentials out of evidence, telemetry, and context bundles.

# Native Superagent integration and authentication

Hosted Context must work out of the box with Superagent. Keep the hosted MCP endpoint at `https://www.superagent.sh/mcp` and route context operations to the shared engine behind that endpoint. Agent access uses existing organization data with no separate signup, manual import, database provisioning, or synchronization configuration.

## Customer connection flow

1. Sign into Superagent and select the organization.

2. Create an agent credential in Settings with selected asset access and permissions for reading context, submitting evidence/findings, and optionally changing dispositions.

3. Add the hosted MCP URL and credential to the agent’s MCP client.

4. Discover the tools and schemas, retrieve task context, and submit results. Every tool call supplies the mandatory `intent`.

Store the credential securely in the client’s supported secret or environment configuration. The agent never receives database credentials. Provide client setup instructions and a connection check that verifies access to the intended organization.

## Identity and authorization

The existing MCP implementation validates organization API keys; granular agent/asset scopes are release work. Extend the credential system to bind each agent principal to its organization, grants, allowed assets, expiry, and revocation state. Store secrets using the existing protected credential pattern. Derive organization identity from validated credentials rather than trusting an organization ID supplied in a tool argument.

The service enforces authorization for every tool, source record, relationship traversal, evidence download, export, and mutation. Submission permission does not imply permission to accept risk, mark a finding fixed, delete data, or perform billable work. Intent explains a call but never grants permissions.

App UI requests use existing user authentication and organization authorization. Where the app delegates to the Context service, use an authenticated, scoped service/delegation mechanism that preserves the initiating user or agent in the audit trail. Keep database credentials server-side and restrict service database access to the required data and operations.

Version the MCP contract and document the mandatory-intent migration for existing clients while preserving the endpoint and finding/report semantics. Scoped credential creation, rotation, revocation, and denied-access behavior must be part of hosted onboarding and integration checks.

## On-prem connection

On-prem runs the same engine and MCP tools at a customer-owned endpoint against the customer’s database, authenticated through customer-configured identity or locally issued scoped credentials. It works independently of the hosted app.

A connector to hosted Superagent is optional. An authorized organization administrator selects the assets and data permitted to cross the boundary and creates connector-specific credentials. Prefer an outbound connection from the customer environment so ingestion does not require a public inbound endpoint. Define backfill, incremental changes, retries, revocation, and source ownership explicitly.

Hosted Superagent UI access to private on-prem records requires an explicit supported network and data-access path. Enabling a connector does not implicitly upload all local records or make the hosted UI able to read the customer database.

# Implementation milestones

The sequence below is dependency-based. Set dates and named owners after estimating the source inventory and deployment requirements.

| Milestone | Deliverables | Exit gate |
| --- | --- | --- |
| 1 Contracts and ownership | Private repo, extracted schemas and transitions, source matrix, write-ownership design | App and context consume the same version; compatibility fixtures pass |
| 2 Storage and ingestion | Storage adapter contract, hosted adapter over existing app tables, on-prem initialization migrations, alternate test adapter, context indexes, durable updates, connectors | Adapter checks pass; hosted records retain their IDs and write path; on-prem models and connector retries behave correctly |
| 3 Read context | Existing hosted MCP endpoint, scoped credential validation, task bundles, search, relationships, export | An agent connects with a Superagent-issued credential and retrieves only authorized organization/asset context |
| 4 External contributions | Finding submissions, investigation results, guarded updates, audit history | An external result appears correctly in the app and influences a later native-worker task |
| 5 Deployment and onboarding | Native hosted Settings and MCP setup, existing database integration, on-prem package, optional connector, custom adapter guide, backup/restore | Hosted requires only credential creation and MCP configuration; both modes pass the same model and workflow checks |
| 6 Pilot and release | PR review and pentest-to-patch pilots, evaluations, operations guide, docs | Acceptance checks pass and measured quality/cost results support launch claims |

Contract extraction and data ownership precede write APIs. Deployment packaging begins alongside service implementation rather than waiting until the pilot.

# Validation and release acceptance

All tests must be integration tests using real services and complete workflows. Contract assertions belong inside integration tests. Do not add unit tests or mocked substitutes. Also run formatting, vet, builds, manual client verification, and outcome evaluations as appropriate.

Required acceptance scenarios:

- Finding transitions, resolution requirements, and report review behavior match the app.

- Existing REST payloads and domain semantics remain compatible. The versioned context MCP contract enforces mandatory intent for every tool, with documented migration for existing MCP clients.

- Every declared product source is either ingested or represented through an explicitly documented relationship.

- Organization and asset isolation hold for search, traversal, export, evidence access, and cached responses.

- Duplicate, reordered, delayed, and replayed ingestion events converge correctly.

- Concurrent agents cannot silently overwrite dispositions; retries do not create duplicate findings.

- Stale false-positive or accepted-risk context is scoped and visible.

- Untrusted evidence cannot alter permissions or become instructions to the service.

- Context deletion and permission changes propagate to derived stores.

- Both deployment modes pass migration, restore, and a representative upgrade.

- The PostgreSQL adapter and alternate test adapter pass the same persistence contract checks for isolation, idempotency, version conflicts, atomic audit/event writes, traversal limits, snapshots, and change cursors.

- Hosted and on-prem deployments enforce identical finding templates, report models, lifecycle rules, and MCP/API semantics.

- A hosted customer can create a scoped credential in Superagent, connect through the existing MCP endpoint, read existing findings/reports, and submit a finding visible in the app without a separate account, database, import, or synchronization setup.

- Hosted finding/report updates retain the existing IDs, lifecycle side effects, and single authoritative write path; credential revocation and organization/asset restrictions take effect across every tool.

- On-prem works independently; an optional hosted connector transfers only explicitly authorized data and does not require public inbound access for the baseline ingestion flow.

- Codex and another independent MCP client complete the primary workflows.

- A native worker uses context contributed by an outside agent.

Measure retrieval latency, context size, ingestion lag, client errors, and task-level cost under a representative workload. Set numerical service objectives after baselining; do not publish unsupported percentage improvements.

# Launch scope and open decisions

Include the shared finding/report contract, native source coverage, scoped retrieval, outside-agent submissions, lifecycle updates, export, mandatory intent, native hosted integration with the existing Superagent database and MCP endpoint, scoped credential onboarding, the reference PostgreSQL backend, the custom storage adapter interface and compatibility checks, and a documented on-prem deployment with optional hosted connector.

Defer a graph visualization UI, broad third-party scanner imports, custom workflow statuses, autonomous remediation orchestration, cross-customer private-data learning, and specialized graph-database infrastructure.

Resolve these decisions before delivery commitments:

- Assign ongoing repository ownership and release maintainers for the private `superagent-ai/security-graph` repository.

- Named owners, pilot customers, staffing, and dates.

- Supported database and object-storage versions, identity integrations, and customer-managed support policy.

- Numerical quality, freshness, latency, and cost gates after baseline measurement.

- Commercial packaging and usage limits. Assess ingestion, storage, retention, and context reads separately from customer-paid model execution.

- Whether risk-acceptance expiry and additional approval policies belong in the first version or a later compatible extension.

The first implementation work item is to extract the app’s finding and report contracts and validate them in both repositories. The first product proof is a customer agent contributing a useful result that a later Superagent worker successfully reuses.

Source issue: [Security context graph 872](https://github.com/superagent-ai/app/issues/872).
