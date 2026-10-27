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

### 1. Start the service

Copy the example configuration:

```sh
cp .env.example .env
```

Set a long password in `.env`, using the same password for `POSTGRES_PASSWORD` and `DATABASE_URL` (URL-encoded in the URL if needed). Then start:

```sh
docker compose up --build -d
```

This starts PostgreSQL, applies migrations, and serves MCP at **http://127.0.0.1:8080/mcp**. The graph starts empty; data persists across restarts.

### 2. Create an agent key

This example grants access to one asset, `acme/payments`, for 24 hours:

```sh
docker compose run --rm server issue-key \
  --org acme --actor local-agent \
  --assets acme/payments \
  --scopes read,submit,graph:write,disposition \
  --ttl 24h
```

Save the printed key in your agent's secret configuration.

### 3. Connect your agent

Add an HTTP MCP server in your agent's settings:

| Setting | Value |
| --- | --- |
| URL | `http://127.0.0.1:8080/mcp` |
| Authorization header | `Bearer <your-agent-key>` |

Ask your agent to register `acme/payments`, read its context, and record an assessment. The usual tool sequence is:

```text
create_asset → get_context → create_report → submit_finding → finish_report
```

Every tool call requires an `intent` describing its purpose. The agent discovers the required inputs through MCP. Finding submissions currently require repository evidence, including code references, a PoC, and patch validation; see the [agent guide](AGENTS.md#using-security-graph).

To stop the local service while keeping its data, run `docker compose down`.

## Use it with your infrastructure

**Standalone / on-prem:** Run the same service against your own PostgreSQL database. Put it behind HTTPS for remote access. Other databases can be supported through the [storage adapter interface](docs/storage-adapters.md).

**Native Superagent:** Run the service against the existing App database and configure App to forward MCP calls to it. Agents use their existing Superagent API keys; organization access comes from the key. This requires the App migration and service configuration described in the [native integration guide](docs/superagent-integration.md).

## More

- [Agent guide: credentials, findings, and report lifecycle](AGENTS.md#using-security-graph)
- [Development, integration tests, and releases](docs/development.md)
- [Product and implementation plan](docs/product-and-implementation-plan.md)
- [Finding/report compatibility](docs/source-compatibility.md)
