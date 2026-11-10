# Cloud Run with native Superagent storage

The hosted service uses the Go-only `Dockerfile` and agent-selected vulnerability
types and compliance mappings. No Julia weights, Python runtime, or inference
worker are included. Keep `AUTO_CLASSIFY_FINDINGS=0`; remove legacy classifier
environment overrides when upgrading. Apply the App agent-selection migration
before enabling the updated App.
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

Run `make check` and `make integration` against a disposable PostgreSQL database.
Use `deploy/gcp/cloudbuild.yaml` to build the Go-only `Dockerfile`; provide an
immutable `_VERSION` and Artifact Registry `_IMAGE` tag. The image contains the
binary, CA certificates and the public Supabase CA, with no inference runtime.

Deploy the resulting image digest to the existing Cloud Run service using its
existing runtime service account, dedicated database secret and ingress/auth
settings. Retain `STORAGE_BACKEND=superagent`, set `AUTO_CLASSIFY_FINDINGS=0`, and
remove `CLASSIFIER_COMMAND`, `CLASSIFIER_ARGS`, `CLASSIFIER_MODE`,
`CLASSIFIER_TIMEOUT`, `CLASSIFICATION_THRESHOLD` and `JULIA_CPU_THREADS` overrides.
Update any existing test traffic tag to the new revision when moving traffic.

Verify `/readyz`, authenticated `tools/list`, `get_classification_options`, and a
real `set_finding_classification` save/read/retry before announcing completion.
The registry should advertise `set_finding_classification` and omit
`classify_finding`. Test native App saves against its connected local database,
including invalid-choice rollback, both ID lists in run context, and graph edges.
No model loading or capacity retry is part of classification.
