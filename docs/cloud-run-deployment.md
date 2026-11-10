# Cloud Run with native Superagent storage

The hosted service uses the Go-only `Dockerfile` and agent-selected vulnerability
types and compliance mappings. No Julia weights, Python runtime, or inference
worker are included. Remove retired classifier environment overrides when
upgrading. Apply the App agent-selection migration
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
settings. Retain `STORAGE_BACKEND=superagent` and remove `AUTO_CLASSIFY_FINDINGS`,
`CLASSIFIER_COMMAND`, `CLASSIFIER_ARGS`, `CLASSIFIER_MODE`,
`CLASSIFIER_TIMEOUT`, `CLASSIFICATION_THRESHOLD` and `JULIA_CPU_THREADS` overrides.
Update any existing test traffic tag to the new revision when moving traffic.

Verify `/readyz`, authenticated `tools/list`, `get_classification_options`, and a
real `set_finding_classification` save/read/retry before announcing completion.
The registry should advertise `set_finding_classification` and omit
`classify_finding` and `set_finding_types`. Test native App saves against its connected local database,
including invalid-choice rollback, both ID lists in run context, and graph edges.
No model loading or capacity retry is part of classification.

## Continuous deployment from main

The `Deploy to GCP` workflow runs the reusable `Checks` workflow on pushes to
`main`, including PR merges, and deploys only after every check, PostgreSQL/MCP
integration check, and container integration check passes. PR and release-tag runs cannot deploy. Main runs are serialized without
cancelling an active deployment; rerunning an older commit cannot roll back a
newer main commit. GitHub can replace a pending run with a newer pending run.

The container job saves the exact tested image as a one-day GitHub artifact.
The deployment job loads that artifact, authenticates through Google Workload
Identity Federation, pushes it to Artifact Registry with a commit/run/attempt
tag, and deploys its immutable digest. No Google service-account key or database
credential is stored in GitHub. The generated `gha-creds-*.json` authentication
file is excluded from Git, Docker, and Cloud Build uploads.

`scripts/deploy-gcp.sh` updates an **existing** service's image without changing
its database secret, environment, runtime identity, network, scaling, probes, or
IAM policy. This matters because the live service's database secret can differ
from the initial provisioning example above. It creates a revision with no
traffic and a `ci-candidate` tag, checks that revision's `/readyz` (which pings
the configured database) and verifies that unauthenticated MCP requests return
401. Only then does it route 100% of service traffic to that exact revision.
Failure before promotion leaves the current service traffic in place.
Other existing traffic tags continue to point to their previous revisions;
clients should use the canonical service URL.

These deployment checks are read-only. They do not establish that authenticated
native App workflows pass end to end; the App-side checks described above remain
required when changing the adapter or its contracts. CI does not run migrations
or seed any data against the live database.

### One-time identity and GitHub configuration

The target service, Artifact Registry repository, runtime service account, and
numeric database secret reference must already exist. An administrator configures
a dedicated deployment identity with the following grants:

| Resource | Deployment identity role |
| --- | --- |
| Target Artifact Registry repository | `roles/artifactregistry.writer` |
| Existing Cloud Run service | `roles/run.developer` |
| Existing runtime service account | `roles/iam.serviceAccountUser` |

The deployment identity has no Secret Manager access or database credentials.
Use a dedicated workload identity pool so another provider in a shared pool
cannot impersonate this repository. Restrict its provider to the numeric GitHub
organization and repository IDs, `refs/heads/main`, `push` events, and this
workflow. For this repository, the setup is:

```sh
project=superagent-410019
region=europe-west1
project_number=408394858807
repository=superagent-ai/security-graph
pool=security-graph-github
deployer="security-graph-deploy@${project}.iam.gserviceaccount.com"
runtime="security-graph@${project}.iam.gserviceaccount.com"

# Enable federation APIs in addition to the runtime prerequisites above.
gcloud services enable iamcredentials.googleapis.com sts.googleapis.com \
  --project="$project"
gcloud iam service-accounts create security-graph-deploy \
  --project="$project" --display-name='Security Graph GitHub deployment'
gcloud iam workload-identity-pools create "$pool" \
  --project="$project" --location=global --display-name='Security Graph GitHub'
gcloud iam workload-identity-pools providers create-oidc github \
  --project="$project" --location=global --workload-identity-pool="$pool" \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id' \
  --attribute-condition="assertion.repository_owner_id == '152537519' && assertion.repository_id == '1435951143' && assertion.ref == 'refs/heads/main' && assertion.event_name == 'push' && assertion.workflow_ref == '${repository}/.github/workflows/deploy.yml@refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding "$deployer" \
  --project="$project" --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${project_number}/locations/global/workloadIdentityPools/${pool}/attribute.repository_id/1435951143"
gcloud artifacts repositories add-iam-policy-binding security-graph \
  --project="$project" --location="$region" \
  --member="serviceAccount:$deployer" --role=roles/artifactregistry.writer
gcloud run services add-iam-policy-binding security-graph \
  --project="$project" --region="$region" \
  --member="serviceAccount:$deployer" --role=roles/run.developer
gcloud iam service-accounts add-iam-policy-binding "$runtime" \
  --project="$project" --member="serviceAccount:$deployer" \
  --role=roles/iam.serviceAccountUser

# Limit the environment to main, without a manual approval gate.
gh api --method PUT "repos/$repository/environments/gcp" \
  --input - <<'JSON'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api --method POST "repos/$repository/environments/gcp/deployment-branch-policies" \
  -f name=main -f type=branch
gh variable set GCP_PROJECT --repo="$repository" --env=gcp --body="$project"
gh variable set GCP_REGION --repo="$repository" --env=gcp --body="$region"
gh variable set GCP_SERVICE --repo="$repository" --env=gcp --body=security-graph
gh variable set GCP_IMAGE_REPOSITORY --repo="$repository" --env=gcp \
  --body="${region}-docker.pkg.dev/${project}/security-graph/service"
gh variable set GCP_DEPLOY_SERVICE_ACCOUNT --repo="$repository" --env=gcp --body="$deployer"
gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --repo="$repository" --env=gcp \
  --body="projects/${project_number}/locations/global/workloadIdentityPools/${pool}/providers/github"
```

Do not recreate existing identities when repeating setup; inspect and update
their policies instead. The deploy job needs `contents: read` and `id-token:
write`; other jobs retain only their existing permissions. See Google's
[authentication action](https://github.com/google-github-actions/auth) and
[deployment federation guide](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
for the identity configuration.

### Rollback

Use an operator account to route traffic to a known healthy revision:

```sh
gcloud run services update-traffic security-graph \
  --project=superagent-410019 --region=europe-west1 \
  --to-revisions=KNOWN_HEALTHY_REVISION=100
```

The next successful main deployment promotes its new revision. To keep a
rollback in place while investigating, disable the `Deploy to GCP` workflow in GitHub
before additional pushes to main. Existing tagged releases remain separate from
this deployment workflow.
