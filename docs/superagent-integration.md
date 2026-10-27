# Native Superagent integration

The hosted release must reuse the existing app database, organization identity, finding/report records, and `https://www.superagent.sh/mcp` connection. Customers should only issue a scoped agent credential and connect their MCP client. On-prem runs the same engine against customer infrastructure.

## Initial implementation boundary

This repository currently provides a working standalone PostgreSQL/MCP service. Its additive migrations create only the `security_graph` schema. Native hosted wiring is not enabled by this commit, and the existing app is not changed.

The next native integration must implement an adapter over the app's authoritative records rather than backfilling a second copy:

- Read repository, application, Agent, Package, and connected advisory findings through their existing organization/asset ownership paths.
- Normalize public finding/report payloads with the existing serializers, including Agent report review mappings and source status versus triage status.
- Route submissions and mutations through the authoritative app domain logic, preserving notifications, report-completion behavior, durable publication, and other existing side effects.
- Place graph relationships and derived indexes alongside existing records in the same PostgreSQL database.
- Bind app credentials to organization, agent identity, scopes, assets, expiry, and revocation. Current organization keys alone do not provide those granular grants.
- Preserve the initiating user or agent when the app delegates an operation to this service. Use audience-bound service credentials; do not pass database secrets or arbitrary browser cookies to agents.
- Keep the hosted MCP URL and provide an explicit versioned migration for required intent.

The app currently uses `repository_red_team_advisories`, `web_app_red_team_advisories`, `agent_red_team_advisories`, `package_red_team_advisories`, and `protection_advisories` for finding persistence. Ownership follows the associated report or connected repository. A generic findings listing currently covers fewer kinds than the internal updater, so native integration must close that coverage gap.

The public storage interface deliberately leaves physical tables and credential validation behind adapters. Existing app records retain a single authoritative write path; sharing a database does not permit bypassing domain rules with independent writes.

## Completion gate

A real app + service + PostgreSQL integration must show that an existing organization can connect, read its existing findings/reports, submit an external finding visible in the app, and exercise permitted lifecycle changes without a separate account, database, import, or synchronization setup. Denied scopes, expired/revoked credentials, asset boundaries, and report side effects must be checked through that workflow before hosted cutover.

For on-prem, hosted data transfer is an optional scoped outbound connector, not an implicit synchronization dependency. The hosted UI cannot read private on-prem records without an explicitly supported network/data-access path.
