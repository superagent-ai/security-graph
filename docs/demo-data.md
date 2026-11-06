# Seed demo data

The seeder creates clearly labeled dummy findings for MCP context retrieval and local load checks. All domain records go through the real authenticated MCP HTTP transport and engine, including validation, attribution, lifecycle transitions, idempotency, and audit events.

Use a **local development or disposable PostgreSQL database**. The seeder is additive: it does not migrate, truncate, delete, reset, or backdate data. It refuses native App storage and requires an organization beginning with `demo-`.

## Local Compose setup

Prepare the local database using the [quickstart](../README.md#run-locally), including `.env` and standalone migrations. Then run:

```sh
make seed
```

Equivalent command, usable from any directory:

```sh
/path/to/security-graph/scripts/seed-demo.sh
```

The script rebuilds the engine image and connects to the existing Compose database. It uses `--no-deps` and does not start the database or apply migrations. An already-running MCP service is not required: the seed command starts a private ephemeral HTTP MCP listener inside its own process and shuts it down afterward. No additional port is published.

Defaults:

| Data | Count |
| --- | ---: |
| Findings | 2,000 |
| Assets | 60 |
| Assessment reports | 120 |
| Submitting agent identities | 8 |
| Catalog assignments | 2,000 |
| Explicit asset relationships | 173 |
| Concurrent report workflows | 4 |

The engine also creates the normal finding/report relationships and audit/change events. The default organization is `demo-security-graph`.

For a larger dataset:

```sh
./scripts/seed-demo.sh \
  --org demo-large \
  --findings 10000 \
  --assets 200 \
  --reports 400 \
  --workers 8
```

Flags support 1–100,000 findings, 1–10,000 assets/reports, and 1–16 workers. Seeding uses normal serialized organization writes, so increasing workers does not guarantee proportional throughput. Work is bounded and does not retain the entire dataset in memory.

## Read the data through MCP

Launch a read-only stdio MCP session in the seeded organization:

```sh
docker compose run --rm --no-deps -T server stdio \
  --org demo-security-graph --actor demo-reader --scopes read
```

Use this command in your MCP client configuration. Discover the tools, then use `list_assets`, `list_findings`, `list_reports`, `get_context`, and `get_neighbors` to inspect the data. Every call requires an intent. Lists support search, status and exact `source` filters with keyset pagination; context retrieval is bounded. Original finding/report sources identify the submitting agents, while review actors remain separate in the change feed.

The seeder never prints its temporary credentials. For authenticated HTTP access, issue a read-scoped key for the same demo organization using the [agent guide](../AGENTS.md#http-credentials-and-client-configuration).

## Host-run binary

With Go and an already-prepared local database, use the same command directly:

```sh
# Set DATABASE_URL using your local development environment or secret mechanism.
go run ./cmd/security-graph seed-demo \
  --org demo-security-graph --findings 2000 --assets 60 --reports 120
```

`go run ./cmd/security-graph seed-demo --help` works without a database connection. Progress counts go to stderr; the final JSON manifest goes to stdout. Database connection errors, MCP failures, and interrupted runs return a nonzero exit code.

## Contents and attribution

Findings are submitted by eight distinct authenticated principals:

- `pr-review-bot` and `codeql-scanner` for repository assessments.
- `dependency-auditor` for package assessments.
- `web-red-teamer` and `api-red-teamer` for web application assessments.
- `agent-red-teamer` for agent assessments.
- `cloud-posture-bot` and `secrets-scanner` for repository assessments.

Every finding still follows the current shared repository evidence authoring contract, even when the report represents a web application, package, or agent run. Report types do not add new authoring models.

Generated scenarios cover tenant isolation/IDOR, SQL injection, SSRF, stored XSS, path traversal, indirect prompt injection, excessive agency, diagnostic data exposure, authentication bypass, and command injection. Every record is marked `[DEMO]` or identifies its synthetic provenance. Targets use `example.invalid`; code references are fictional. Structured policy reviews, PoCs, patches, and patch validation results explicitly say they are simulated and were not executed. No scanner or model is invoked, no network target is assessed, and findings are not marked independently verified.

The dataset includes all four severities; `new`, `in_review`, and `resolved` findings; all four resolutions; and running, failed, in-review, and completed reports. Some reports contain only resolved findings and complete automatically. Others complete their review while retaining unresolved findings, preserving the engine's existing semantics. `triaging` remains system-managed and is never assigned manually.

A coordinator registers assets and links them into a high-degree platform hub, service clusters, and a dependency ring. Agents can submit and classify their own assessment findings but do not have disposition permission. A separate demo reviewer performs the seeded triage and report review decisions, so source attribution and decision audit actors remain distinct.

## Reruns, interruption, and credentials

The dataset ID derives from the seed format version and the asset/report/finding counts. Stable idempotency keys and deterministic payloads let the **same organization and counts** resume after interruption or rerun without creating duplicate domain records or audit/change events. Changing only `--workers` preserves the dataset identity.

Changing counts creates a separate additive dataset with its own IDs and agent namespace; it does not resize or overwrite the previous dataset. Use a separate `demo-` organization when comparing scales. Replaying cached seed operations does not reset subsequent reviewer edits. As with normal MCP mutations, do not remove idempotency receipts if you intend to resume a seed. Developers changing generated payloads must bump the seed format version.

The trusted operator command issues temporary organization-scoped credentials directly through standalone credential management, then performs all domain writes through MCP. Keys remain only in process memory, expire after two hours, and are individually revoked on completion, ordinary failure, or graceful cancellation. An ungraceful kill can leave keys active until expiry, although their secrets are not persisted or printed. Reruns issue fresh temporary credentials with the same principals; the idempotent domain operations remain unchanged.

The seeder intentionally offers no destructive cleanup flag. For disposable development environments, manage database teardown separately; never run test cleanup against a production database.

## Verification

`make integration` runs the real seed CLI against disposable PostgreSQL, independently reads its output through MCP, checks all eight source identities and lifecycle varieties, verifies canonical finding templates and classification assignments, confirms temporary key revocation and organization isolation, and reruns with another worker count to ensure records and audit/change events are unchanged. `make check` covers formatting, vet, and builds.

The full default was also exercised against a fresh disposable database: 2,000 findings, 2,000 catalog assignments, 60 assets, 120 reports, and 173 explicit asset relationships completed in approximately 24 seconds on one local run. This is an observation, not a production throughput guarantee.
