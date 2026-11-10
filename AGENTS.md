# Security Graph

Build the shared security context engine in Go. Preserve the finding/report models and lifecycle semantics documented in `docs/product-and-implementation-plan.md` and sourced from `superagent-ai/app`.

## Verification

- All tests must be integration tests. Do not add unit tests, mocks masquerading as integration tests, or tests that merely mirror implementation details.
- Exercise real PostgreSQL, real MCP transport, and complete workflows. Contract assertions belong inside these integration checks.
- Run `make check` and `make integration` before publishing changes. Integration checks require Docker or `TEST_DATABASE_URL` pointing to a disposable PostgreSQL database.
- Never run destructive test setup or migrations against a production database.

## Architecture

- PostgreSQL is the reference backend. Custom backends implement the public storage contract.
- Hosted and on-prem use the same engine, contracts, and MCP tool schemas.
- Every MCP tool call requires a nonempty `intent`; intent never grants authorization.
- Scope every operation by authenticated organization and asset access. Keep credentials and untrusted finding contents out of logs.
- Do not claim native hosted app integration is complete until the app adapter and app-side integration pass an end-to-end check.
- Keep all GitHub Actions pinned to full commit SHAs. Preserve the issue and PR templates copied from the app repository.

## Using Security Graph

Start with the [local quickstart](README.md#run-locally). This guide covers local access, HTTP credentials, finding requirements, and report transitions.

### Local stdio access

`security-graph stdio` uses the same tool registry and storage engine over stdin/stdout. The agent launches it as a subprocess; stdout contains MCP messages only, and diagnostics use stderr. Closing stdin shuts it down. Configure `DATABASE_URL` and apply standalone migrations before launching it.

The process defaults to organization `local`, actor `local-agent`, all assets within that organization, and scopes `read,submit,graph:write`. No API key is created or exchanged. Trust comes from the operator launching the process with database access; MCP arguments and client metadata cannot select its organization or expand its permissions.

Operators can set `--org`, `--actor`, `--assets`, and `--scopes` on the `stdio` command. For example, a review process can explicitly opt into `--scopes read,disposition`. These are trusted launch settings, not MCP tool arguments. Only standalone storage supports stdio; `STORAGE_BACKEND=superagent` must use authenticated HTTP.

The README's Docker configuration uses `-T` to preserve stdio framing and `--no-deps` because the database has already been prepared. It publishes no MCP port. Database credentials remain in the gitignored `.env` file.

### HTTP credentials and client configuration

Use `docker compose up --build -d` to start the HTTP service at `http://127.0.0.1:8080/mcp`. HTTP always requires a bearer key, including on localhost. For standalone HTTP, issue a scoped assessment key:

```sh
docker compose run --rm server issue-key \
  --org acme --actor local-agent \
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
docker compose run --rm server revoke-key --org acme --actor local-agent
```

Standalone HTTP authentication uses deployment-issued bearer keys. Native mode uses existing app API keys for customer clients. The App server can also mint five-minute, run/asset-scoped `sg_native_` capabilities for guarded native execution; runner credentials themselves remain invalid MCP credentials. Neither mode accepts arbitrary browser session tokens; OAuth/OIDC federation is a future integration.

### Agent workflow

Finding submissions currently use the repository assessment profile. Include the six sections `Impact`, `Details`, `Policy Verification`, `Code References`, `PoC`, and `Remediation`, with the structured evidence required by the tools. See [source compatibility](docs/source-compatibility.md) for the current authoring scope.

1. Discover tool schemas and read the server instructions.
2. Register an authorized asset with `create_asset`, using `asset_id: "acme/payments"`.
3. Retrieve existing context using `get_context` or the finding/report tools.
4. Start an external assessment with `create_report`. This records a run; it does not launch a Superagent scan.
5. Submit a structured finding with `submit_finding`. Include the existing policy review, code references, concrete PoC, and proposed patch validation evidence. New submissions are attributed claims with triage status `new`, not independently confirmed vulnerabilities.
6. Read `get_classification_options` and call `set_finding_classification` with agent-selected `type_ids`, `compliance_ids`, rationale, and current versions. Native App tools save the same object atomically. Empty arrays explicitly mean no applicable choice. Hosted deployments do not run Julia inference.
7. Record execution completion using `finish_report`. The engine handles empty/all-resolved reports and unresolved review state.
8. Use `update_finding_triage` or `update_report_review_status` only with disposition permission and a current `expected_version`.

Every call includes `intent`, a concrete purpose of 1–500 characters. Writes also require an `idempotency_key`; use the same key and exact payload for retries. The same key with a different payload or permissions returns a conflict. These mutation results and their audit events commit atomically. Only a fingerprint of intent is retained in audit records.

Responses include the storage record's `version` and canonical domain data under `data`. The initial service envelope is versioned independently from the existing app REST response. The complete input schemas are in [contracts/mcp-tools.json](contracts/mcp-tools.json), generated directly from the live tool registry.

| Finding triage | Resolution when resolved | Verification vocabulary |
| --- | --- | --- |
| `new`, `triaging`, `in_review`, `resolved` | `fixed`, `accepted_risk`, `false_positive`, `wont_fix` | `confirmed`, `not_reproducible`, `inconclusive`, `heuristic` |

`triaging` is system-managed and cannot be assigned through the manual update tool. Reopening clears the resolution. Completing a report review does not resolve its findings. New or reopened findings return finished reports to review; resolving all findings completes them. Submitted patch validation is evidence supplied by the agent, not a claim that this service executed it.
