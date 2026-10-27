#!/usr/bin/env bash
# Exercise the shipped container, CLI migrations, credentials, and MCP endpoint.
set -euo pipefail
image="${1:-security-graph:check}"
suffix="${RANDOM}-${RANDOM}"
network="security-graph-test-$suffix"
database="security-graph-db-$suffix"
service="security-graph-service-$suffix"
cleanup() {
  docker rm -f "$service" "$database" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$network" >/dev/null
docker run --detach --name "$database" --network "$network" \
  -e POSTGRES_PASSWORD=integration-only -e POSTGRES_DB=security_graph_test postgres:17-alpine >/dev/null
for attempt in {1..60}; do
  if docker exec "$database" pg_isready -h 127.0.0.1 -U postgres -d security_graph_test >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 60 ]]; then echo 'PostgreSQL did not start' >&2; exit 1; fi
  sleep 1
done
database_url="postgres://postgres:integration-only@${database}:5432/security_graph_test?sslmode=disable"
docker run --rm --network "$network" -e DATABASE_URL="$database_url" "$image" migrate
graph_token="$(docker run --rm --network "$network" -e DATABASE_URL="$database_url" "$image" issue-key --org container-test --actor integration-agent --all-assets --scopes read --ttl 1h)"
docker run --detach --name "$service" --network "$network" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1::8080 -e DATABASE_URL="$database_url" "$image" serve >/dev/null
port="$(docker port "$service" 8080/tcp | awk -F: '{print $NF}')"
for attempt in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null; then break; fi
  if [[ "$attempt" == 30 ]]; then echo 'Container did not become ready' >&2; exit 1; fi
  sleep 1
done
curl --fail --silent --show-error "http://127.0.0.1:$port/mcp" \
  -H "Authorization: Bearer $graph_token" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' |
  python3 -c 'import json,sys; tools=json.load(sys.stdin)["result"]["tools"]; assert len(tools)>=10; assert all("intent" in t["inputSchema"]["required"] for t in tools)'
docker run --rm --network "$network" -e DATABASE_URL="$database_url" "$image" revoke-key --org container-test --actor integration-agent >/dev/null
status="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$port/mcp" -H "Authorization: Bearer $graph_token" -H 'Content-Type: application/json' --data '{}')"
if [[ "$status" != 401 ]]; then echo 'Revoked key was accepted by the container' >&2; exit 1; fi
echo 'Container PostgreSQL, migration, authentication, MCP discovery, and revocation integration passed.'
