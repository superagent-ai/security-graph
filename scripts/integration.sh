#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${TEST_DATABASE_URL:-}" ]]; then
  exec go test -race -count=1 -v ./integration/...
fi
container="security-graph-integration-${RANDOM}-${RANDOM}"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run --detach --name "$container" \
  -e POSTGRES_PASSWORD=integration-only \
  -e POSTGRES_DB=security_graph_test \
  -p 127.0.0.1::5432 postgres:17-alpine >/dev/null
for attempt in {1..60}; do
  if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d security_graph_test >/dev/null 2>&1; then
    port="$(docker port "$container" 5432/tcp | awk -F: '{print $NF}')"
    export TEST_DATABASE_URL="postgres://postgres:integration-only@127.0.0.1:${port}/security_graph_test?sslmode=disable"
    go test -race -count=1 -v ./integration/...
    exit
  fi
  sleep 1
done
echo "PostgreSQL did not become ready" >&2
exit 1
