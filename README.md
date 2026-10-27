# Superagent Security Graph

Shared security context for the agents you already use.

## Why Security Graph?

Pentesters and PR review agents need more than the code in front of them. They need to know which assets are connected, what previous assessments found, and which findings have already been fixed or dismissed.

Security Graph gives your agents that context through MCP. They can read findings and reports, follow relationships between assets, and record their own assessment results using Superagent's finding template and report lifecycle.

- Reduce repeated investigation and give agents the context to distinguish false positives from real issues.
- Carry knowledge between assessments to shorten the path from finding to fix and make frequent checks less expensive.
- Use your own agents and models, with data stored in your infrastructure or the existing Superagent app database.

Your agent performs the security assessment. Security Graph stores and shares the context.

## Run locally

You'll need Docker with Compose and a checkout of this repository.

### 1. Prepare the local database

Copy the example configuration:

```sh
cp .env.example .env
```

Set a long password in `.env`, using the same password for `POSTGRES_PASSWORD` and `DATABASE_URL` (URL-encoded in the URL if needed). Then build the service and prepare PostgreSQL:

```sh
docker compose build
docker compose run --rm migrate
```

The database starts empty and retains data across restarts. You only need to prepare it once; rebuild and rerun migrations when upgrading.

### 2. Connect your agent

Add this **stdio MCP server** to your agent's configuration, replacing both paths with your checkout location:

```json
{
  "mcpServers": {
    "security-graph": {
      "command": "docker",
      "args": [
        "compose", "--project-directory", "/absolute/path/to/security-graph",
        "--env-file", "/absolute/path/to/security-graph/.env",
        "run", "--rm", "--no-deps", "-T", "server", "stdio"
      ]
    }
  }
}
```

Your agent launches the Go process and communicates through its input/output streams. No MCP API key, login, or HTTP endpoint is needed. The process has assessment permissions in a local workspace; advanced access settings are in [AGENTS.md](AGENTS.md#using-security-graph).

Ask your agent to register `acme/payments`, read its context, and record an assessment. The usual tool sequence is:

```text
create_asset → get_context → create_report → submit_finding → finish_report
```

Every tool call requires an `intent` describing its purpose. The agent discovers the required inputs through MCP. Finding submissions currently require repository evidence, including code references, a PoC, and patch validation; see the [agent guide](AGENTS.md#using-security-graph).

The MCP process exits when your agent disconnects. To stop PostgreSQL while keeping its data, run `docker compose down`.

## Use it with your infrastructure

**Standalone / on-prem:** Run the same service against your own PostgreSQL database. For shared remote access, use authenticated HTTP behind HTTPS; see [HTTP credentials](AGENTS.md#http-credentials-and-client-configuration). Other databases can be supported through the [storage adapter interface](docs/storage-adapters.md).

**Native Superagent:** Run the service against the existing App database and configure App to forward MCP calls to it. Agents use their existing Superagent API keys; organization access comes from the key. This requires the App migration and service configuration described in the [native integration guide](docs/superagent-integration.md).

## More

- [Agent guide: credentials, findings, and report lifecycle](AGENTS.md#using-security-graph)
- [Development, integration tests, and releases](docs/development.md)
- [Product and implementation plan](docs/product-and-implementation-plan.md)
- [Finding/report compatibility](docs/source-compatibility.md)
