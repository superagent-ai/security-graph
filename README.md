# Superagent Security Graph

Shared security context for your agents. A Go service exposing authenticated MCP tools over PostgreSQL, with the finding template and lifecycle vocabulary from `superagent-ai/app`.

## Current implementation

- Streamable HTTP MCP at `/mcp`, using the official Go MCP SDK.
- Mandatory intent on every tool, published in each JSON input schema.
- Organization and asset-scoped credentials, expiry, revocation, and distinct read, submission, disposition, graph-write, and export permissions.
- PostgreSQL transactions with optimistic versions, idempotent retries, actor attribution, and durable change cursors.
- External reports, structured findings, the six-section finding template, remediation evidence, and automatic report review transitions.
- Explicit asset relationships and bounded graph retrieval, including automatic finding/report/asset links.
- A public storage adapter interface and exported language-neutral tool schemas.
- Docker Compose for on-prem, integration CI, and tag-triggered binary/container releases.

Two storage modes use the same engine and finding template. The standalone PostgreSQL mode stores its own records for on-prem deployments. `STORAGE_BACKEND=superagent` reads and writes the app's existing finding/report tables and authenticates existing organization API keys. Its real app → MCP → PostgreSQL integration has passed locally. Production activation requires the additive app migration and the service configuration below. Non-repository authoring profiles, investigation-result history, full snapshot exports, and the optional hosted/on-prem connector remain milestones.

## Native Superagent app

Apply the app's `security_graph_native_integration` migration to its existing database. Run this service with:

```sh
STORAGE_BACKEND=superagent DATABASE_URL="$SUPERAGENT_DATABASE_URL" ./security-graph serve
```

Set `SECURITY_GRAPH_URL` in the app to the service's private `/mcp` URL. Keep the app's existing `CRON_SECRET` configured for durable notification retries. Use a direct or session-pooled PostgreSQL connection with the permissions described in [native integration](docs/superagent-integration.md).

Agents keep connecting to `https://www.superagent.sh/mcp` using their existing `SUPERAGENT_API_KEY`. The key determines the organization. No organization field, header, separate key, import, or synchronization step is needed. These existing keys retain their current organization-wide permissions; the standalone scoped-key grants below do not narrow app keys. Delete the key in Settings to revoke it.

When enabled, the app advertises MCP version 2 and requires `intent` on all tools. Graph mutations also require idempotency keys and current versions. The app retains existing scan, runtime, and incident tools. Its finding/report detail tools use the existing public app serializers.

## Why Go

This service primarily does network and database work. Go provides a compact deployable binary, straightforward concurrency, an official MCP SDK, and an approachable adapter interface. Rust is also viable, but its additional complexity does not address the expected initial bottleneck. PostgreSQL query design and bounded retrieval matter more than language-level CPU differences here.

## Run locally or on-prem

Install Docker and Compose, then:

```sh
cp .env.example .env
# Set POSTGRES_PASSWORD and the matching DATABASE_URL in .env.
docker compose up --build -d
```

Compose starts PostgreSQL, applies additive migrations, and starts the service at `http://127.0.0.1:8080/mcp`. Existing data is retained in the named volume. Use a customer-operated TLS reverse proxy for remote connections. The service also supports an existing PostgreSQL 17+ instance; run migrations against a dedicated customer schema/database and set `DATABASE_URL` accordingly.

Create an agent credential with explicit access to one asset:

```sh
docker compose run --rm server issue-key \
  --org acme --actor pr-review-agent \
  --assets acme/payments \
  --scopes read,submit,graph:write \
  --ttl 24h
```

The key is printed once; only its SHA-256 hash is stored. Put it into your MCP client's secret configuration or environment. An operator can explicitly grant `--all-assets` when organization-wide access is intended. `disposition` is required to resolve findings or change report review state; `export` is required for the change feed.

For clients supporting URL-and-header configuration:

```json
{
  "mcpServers": {
    "superagent-security-graph": {
      "url": "https://security-graph.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${env:SUPERAGENT_GRAPH_API_KEY}"
      }
    }
  }
}
```

Environment-variable interpolation varies by client; use its documented secret mechanism. The URL above is illustrative. Local development can use `http://127.0.0.1:8080/mcp`.

Revoke every credential for an agent:

```sh
docker compose run --rm server revoke-key --org acme --actor pr-review-agent
```

Standalone authentication uses deployment-issued bearer keys. Native mode uses existing app API keys. Neither mode accepts arbitrary browser session tokens; OAuth/OIDC federation is a future integration.

## Agent workflow

1. Discover tool schemas and read the server instructions.
2. Register an authorized asset with `create_asset`, using `asset_id: "acme/payments"`.
3. Retrieve existing context using `get_context` or the finding/report tools.
4. Start an external assessment with `create_report`. This records a run; it does not launch a Superagent scan.
5. Submit a structured finding with `submit_finding`. Include the existing policy review, code references, concrete PoC, and proposed patch validation evidence. New submissions are attributed claims with triage status `new`, not independently confirmed vulnerabilities.
6. Record execution completion using `finish_report`. The engine handles empty/all-resolved reports and unresolved review state.
7. Use `update_finding_triage` or `update_report_review_status` only with disposition permission and a current `expected_version`.

Every call includes `intent`, a concrete purpose of 1–500 characters. Writes also require an `idempotency_key`; use the same key and exact payload for retries. The same key with a different payload or permissions returns a conflict. These mutation results and their audit events commit atomically. Only a fingerprint of intent is retained in audit records.

Responses include the storage record's `version` and canonical domain data under `data`. The initial service envelope is versioned independently from the existing app REST response. The complete input schemas are in [contracts/mcp-tools.json](contracts/mcp-tools.json), generated directly from the live tool registry.

| Finding triage | Resolution when resolved | Verification vocabulary |
| --- | --- | --- |
| `new`, `triaging`, `in_review`, `resolved` | `fixed`, `accepted_risk`, `false_positive`, `wont_fix` | `confirmed`, `not_reproducible`, `inconclusive`, `heuristic` |

`triaging` is system-managed and cannot be assigned through the manual update tool. Reopening clears the resolution. Completing a report review does not resolve its findings. New or reopened findings return finished reports to review; resolving all findings completes them. Submitted patch validation is evidence supplied by the agent, not a claim that this service executed it.

## Development

Go 1.26+ is required.

```sh
go mod download
make check
make integration
make build
```

**All tests are integration tests.** `make integration` starts a disposable real PostgreSQL container and exercises the real HTTP MCP endpoint. Alternatively set `TEST_DATABASE_URL` to a disposable database whose name contains `test`. It covers auth, mandatory intent, template validation, concurrent retries, lifecycle transitions, graph limits, tenant/asset isolation, and revocation. No production database or mocked store is used.

Regenerate public schemas after changing a tool or contract:

```sh
go run ./cmd/export-schemas > contracts/mcp-tools.json
```

## CI and delivery

Pull requests and main run formatting, vet, build, module verification, PostgreSQL/MCP integration tests with the race detector, schema drift checks, and a container smoke check. Actions are pinned to commit SHAs. Issue and PR templates are copied unchanged from the landing/app repo.

Pushing a semantic tag such as `v0.1.0` runs the checks again, builds Linux/macOS/Windows archives and checksums, publishes an amd64/arm64 container to `ghcr.io/superagent-ai/security-graph:<tag>`, and creates a release in this private repository. GitHub's token supplies publication permissions; no production deployment credentials are needed. No release is created by pushing main. Customer deployment and upgrades remain explicit operations.

The first package publication should retain private visibility and repository access inheritance. The workflow includes container provenance and an SBOM. Deployment-specific TLS, identity, backups, and production runtime credentials are configured by the operator.

## Architecture and plan

- [Storage adapter contract](docs/storage-adapters.md)
- [Native Superagent integration](docs/superagent-integration.md)
- [Product and implementation plan](docs/product-and-implementation-plan.md)
- [Source compatibility](docs/source-compatibility.md)
