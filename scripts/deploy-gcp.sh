#!/usr/bin/env bash
# Deploy a verified Go image; database migrations stay in the App workflow.
set -euo pipefail
: "${GCP_PROJECT:?Set GCP_PROJECT}"
: "${GCP_REGION:?Set GCP_REGION near the existing App database}"
: "${GRAPH_IMAGE:?Set GRAPH_IMAGE to the tested Artifact Registry image digest}"
: "${DATABASE_SECRET_VERSION:?Set the numeric Secret Manager database URL version}"
[[ "$GRAPH_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'GRAPH_IMAGE must be pinned by digest.' >&2; exit 1; }
[[ "$DATABASE_SECRET_VERSION" =~ ^[1-9][0-9]*$ ]] || { echo 'Pin a numeric secret version.' >&2; exit 1; }
gcloud run deploy security-graph \
  --project="$GCP_PROJECT" --region="$GCP_REGION" \
  --image="$GRAPH_IMAGE" \
  --service-account="security-graph@${GCP_PROJECT}.iam.gserviceaccount.com" \
  --execution-environment=gen2 \
  --port=8080 --cpu=2 --memory=2Gi \
  --min=1 --max=2 --concurrency=16 --timeout=60s \
  --cpu-throttling --cpu-boost \
  --set-env-vars=STORAGE_BACKEND=superagent \
  --set-secrets="DATABASE_URL=security-graph-database-url:${DATABASE_SECRET_VERSION}" \
  --startup-probe=httpGet.path=/readyz,httpGet.port=8080,initialDelaySeconds=0,timeoutSeconds=5,periodSeconds=10,failureThreshold=12 \
  --liveness-probe=httpGet.path=/healthz,httpGet.port=8080,initialDelaySeconds=10,timeoutSeconds=5,periodSeconds=30,failureThreshold=3 \
  --allow-unauthenticated --quiet
