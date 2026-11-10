#!/usr/bin/env bash
# Update an existing service with a verified image; migrations stay in the App workflow.
set -euo pipefail
: "${GCP_PROJECT:?Set GCP_PROJECT}"
: "${GCP_REGION:?Set GCP_REGION near the existing App database}"
: "${GRAPH_IMAGE:?Set GRAPH_IMAGE to the tested Artifact Registry image digest}"
GCP_SERVICE="${GCP_SERVICE:-security-graph}"
[[ "$GRAPH_IMAGE" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'GRAPH_IMAGE must be pinned by digest.' >&2; exit 1; }

# Only change the image. Keep the existing database secret, service account,
# network, scaling, probes, and authentication settings. Fail if the service is absent.
revision="$(gcloud run services update "$GCP_SERVICE" \
  --project="$GCP_PROJECT" --region="$GCP_REGION" \
  --image="$GRAPH_IMAGE" --no-traffic --tag=ci-candidate \
  --format='value(status.latestCreatedRevisionName)' --quiet)"
: "${revision:?Cloud Run did not return a candidate revision}"
status="$(gcloud run services describe "$GCP_SERVICE" \
  --project="$GCP_PROJECT" --region="$GCP_REGION" --format='json(status)')"
candidate_url="$(jq -er --arg revision "$revision" \
  '.status.traffic[] | select(.tag == "ci-candidate" and .revisionName == $revision) | .url' <<< "$status")"

# These are read-only checks against the actual candidate, before traffic moves.
curl --fail --silent --show-error --retry 5 --retry-all-errors --retry-delay 5 \
  --connect-timeout 5 --max-time 10 --output /dev/null "$candidate_url/readyz"
http_status="$(curl --silent --show-error --connect-timeout 5 --max-time 10 \
  --output /dev/null --write-out '%{http_code}' "$candidate_url/mcp" \
  -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')"
[[ "$http_status" == 401 ]] || { echo 'Candidate MCP endpoint did not require authentication.' >&2; exit 1; }

gcloud run services update-traffic "$GCP_SERVICE" \
  --project="$GCP_PROJECT" --region="$GCP_REGION" \
  --to-revisions="$revision=100" --quiet
url="$(jq -er '.status.url' <<< "$status")"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "url=$url" >> "$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "Deployed revision \`$revision\` to [$GCP_SERVICE]($url/mcp)."
    echo
    echo "Image: \`$GRAPH_IMAGE\`"
    echo
    echo 'Candidate database readiness and MCP authentication checks passed before routing traffic.'
  } >> "$GITHUB_STEP_SUMMARY"
fi
echo "Deployed $revision to $url/mcp"
