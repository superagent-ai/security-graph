# Development and releases

Go 1.26+ is required.

```sh
go mod download
make check
make integration
make build
```

**All tests are integration tests.** `make integration` starts a disposable real PostgreSQL container and exercises the real HTTP MCP endpoint. Alternatively set `TEST_DATABASE_URL` to a disposable database whose name contains `test`. It covers authenticated HTTP and real CLI subprocesses over stdio, including mandatory intent, template validation, idempotent retries, lifecycle transitions, persistence across restarts, tenant/asset/scope isolation, and shutdown. No production database or mocked store is used.

Regenerate public schemas after changing a tool or contract:

```sh
go run ./cmd/export-schemas > contracts/mcp-tools.json
```

## CI and delivery

Pull requests and main run formatting, vet, build, module verification, PostgreSQL/MCP integration tests with the race detector, schema drift checks, and a container smoke check. Actions are pinned to commit SHAs. Issue and PR templates are copied unchanged from the landing/app repo.

Pushing a semantic tag such as `v0.1.0` runs the checks again, builds Linux/macOS/Windows archives and checksums, publishes an amd64/arm64 container to `ghcr.io/superagent-ai/security-graph:<tag>`, and creates a release in this private repository. GitHub's token supplies publication permissions; no production deployment credentials are needed. No release is created by pushing main. Customer deployment and upgrades remain explicit operations.

The first package publication should retain private visibility and repository access inheritance. The workflow includes container provenance and an SBOM. Deployment-specific TLS, identity, backups, and production runtime credentials are configured by the operator.

## Standalone hosting

Compose retains database data in its named volume. For an existing PostgreSQL 17+ instance, use a dedicated customer database/schema, set `DATABASE_URL`, and run the binary's `migrate` command before `serve`. Standalone deployments use the default `postgres` storage backend. Use certificate verification for remote database connections and a TLS reverse proxy for remote MCP access.

Native App deployments use their own migration and credentials; follow the [native integration guide](superagent-integration.md).

## Why Go

This service primarily does network and database work. Go provides a compact deployable binary, straightforward concurrency, an official MCP SDK, and an approachable adapter interface. Rust is also viable, but its additional complexity does not address the expected initial bottleneck. PostgreSQL query design and bounded retrieval matter more than language-level CPU differences here.
