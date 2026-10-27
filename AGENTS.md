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
