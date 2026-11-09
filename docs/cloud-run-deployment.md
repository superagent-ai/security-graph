# Cloud Run with native Superagent storage and Julia-1

The hosted service uses `Dockerfile.julia`, the App's existing PostgreSQL database,
and `STORAGE_BACKEND=superagent`. The image includes the manifest-pinned Julia-1
weights, hash-locked CPU wheels and Python runtime. Inference runs offline in the
resident worker. Its files are read-only and the image runs as a non-root user.
The default `Dockerfile` remains the smaller Go-only distribution.

## Prerequisites

- Apply the native App migration through the App's normal migration process.
  Never run standalone migrations against the production App database.
- Use a dedicated database login with the native adapter's required table and
  column grants, server-side RLS bypass, no DDL or role administration, and a
  bounded connection limit. Do not use the App's administrator password.
- Use a direct or **session-pool** PostgreSQL connection with certificate
  verification. Native reads use repeatable-read transactions. Keep the pool
  capacity in mind: each Go instance opens at most 10 database connections.
  The image includes the public Supabase Root 2021 CA at
  `/etc/security-graph/supabase-ca.crt`; set `sslmode=verify-full` and
  `sslrootcert=/etc/security-graph/supabase-ca.crt` in the connection URL. Its
  SHA-256 fingerprint is
  `807025AD50D4ED219D2C9C7D299C004F824EB00CF7F65AFEF607D07B72E6CAFA`.
  Source: `https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt`.
- Store the connection URL in Secret Manager as `security-graph-database-url`.
  Grant `roles/secretmanager.secretAccessor` on this secret only to the dedicated
  `security-graph` runtime service account. Pin a numeric secret version.
- Enable Cloud Run, Artifact Registry and Secret Manager in the chosen project.
  Keep container images and the service close to the existing App database.

## Build, test and deploy

```sh
make check
JULIA_PYTHON=/absolute/path/julia-venv/bin/python \
JULIA_MODEL_DIR=/absolute/path/julia-model REQUIRE_JULIA=1 make integration

docker buildx build --platform linux/amd64 -f Dockerfile.julia \
  --build-arg VERSION=<release> -t <registry-image>:<release> --load .
./scripts/container-integration.sh <registry-image>:<release>
docker push <registry-image>:<release>

GCP_PROJECT=<project> GCP_REGION=<region> \
GRAPH_IMAGE=<registry-image>@sha256:<digest> DATABASE_SECRET_VERSION=1 \
bash scripts/deploy-gcp.sh
```

The deployment starts with 2 vCPUs, 2 GiB RAM, one warm instance and a maximum
of two instances. Julia admits one inference per process, without a waiting
queue; other MCP requests may execute concurrently. Measure production memory
and latency before increasing replica counts or reducing memory. Request-based
billing is used; the warm instance incurs idle charges. The earlier Go-only
512 MiB cost estimate does not apply to this model-enabled deployment.

For automatic native-finding classification, deploy the compatible native MCP
execution build and apply the App's native execution migration. Set
`AUTO_CLASSIFY_FINDINGS=1` and use `--no-cpu-throttling` on Cloud Run: the durable
classification worker runs after the save request has returned and needs CPU
between requests. Keep one warm instance. This uses instance-based CPU billing;
manual-only deployments can retain request-based CPU allocation. Julia runs in
the deployed Graph container, including when its database is reached through a
local-development tunnel; it does not run on the App developer's computer.

Cloud Run allows requests through its platform IAM layer so the existing App can
forward MCP without a second authentication protocol. The Go service still
requires a valid existing Superagent bearer key on every MCP request. Missing,
invalid and revoked keys are rejected; `/healthz` and `/readyz` are public probes.

## Verification and App routing

Run the App's native integration workflow against **local disposable services**
with the same engine and actual Julia configured before production cutover.
See [native integration](superagent-integration.md). The deployed service also
needs real HTTPS checks: readiness, unauthorized requests, MCP discovery,
intent enforcement, and classification through the native storage adapter.
Use explicitly isolated smoke-test records; do not run the integration test
runner or its schema setup against production.

Set the App's `SECURITY_GRAPH_URL` to the deployed HTTPS `/mcp` endpoint after
verification. Keep the App's existing `CRON_SECRET` and effect retry schedule.
Verify the App's public MCP endpoint using an existing organization key. A
healthy Go endpoint alone does not establish complete hosted App integration.
Unsetting `SECURITY_GRAPH_URL` rolls App routing back. Keep the previous Cloud
Run image digest/revision and secret version for service rollback.
