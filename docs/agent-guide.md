# Agent guide

Start with the [local quickstart](../README.md#run-locally). This guide covers credentials, finding requirements, and report transitions.

## Credentials and client configuration

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

Standalone authentication uses deployment-issued bearer keys. Native mode uses existing app API keys. Neither mode accepts arbitrary browser session tokens; OAuth/OIDC federation is a future integration.

## Agent workflow

Finding submissions currently use the repository assessment profile. Include the six sections `Impact`, `Details`, `Policy Verification`, `Code References`, `PoC`, and `Remediation`, with the structured evidence required by the tools. See [source compatibility](source-compatibility.md) for the current authoring scope.

1. Discover tool schemas and read the server instructions.
2. Register an authorized asset with `create_asset`, using `asset_id: "acme/payments"`.
3. Retrieve existing context using `get_context` or the finding/report tools.
4. Start an external assessment with `create_report`. This records a run; it does not launch a Superagent scan.
5. Submit a structured finding with `submit_finding`. Include the existing policy review, code references, concrete PoC, and proposed patch validation evidence. New submissions are attributed claims with triage status `new`, not independently confirmed vulnerabilities.
6. Record execution completion using `finish_report`. The engine handles empty/all-resolved reports and unresolved review state.
7. Use `update_finding_triage` or `update_report_review_status` only with disposition permission and a current `expected_version`.

Every call includes `intent`, a concrete purpose of 1–500 characters. Writes also require an `idempotency_key`; use the same key and exact payload for retries. The same key with a different payload or permissions returns a conflict. These mutation results and their audit events commit atomically. Only a fingerprint of intent is retained in audit records.

Responses include the storage record's `version` and canonical domain data under `data`. The initial service envelope is versioned independently from the existing app REST response. The complete input schemas are in [contracts/mcp-tools.json](../contracts/mcp-tools.json), generated directly from the live tool registry.

| Finding triage | Resolution when resolved | Verification vocabulary |
| --- | --- | --- |
| `new`, `triaging`, `in_review`, `resolved` | `fixed`, `accepted_risk`, `false_positive`, `wont_fix` | `confirmed`, `not_reproducible`, `inconclusive`, `heuristic` |

`triaging` is system-managed and cannot be assigned through the manual update tool. Reopening clears the resolution. Completing a report review does not resolve its findings. New or reopened findings return finished reports to review; resolving all findings completes them. Submitted patch validation is evidence supplied by the agent, not a claim that this service executed it.
