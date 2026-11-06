#!/usr/bin/env bash
set -euo pipefail
# Use the existing local Compose database. Preparation/migrations are explicit;
# this script never starts dependencies, truncates tables, or resets a database.
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec docker compose --project-directory "$project_root" run --build --rm --no-deps -T server seed-demo "$@"
