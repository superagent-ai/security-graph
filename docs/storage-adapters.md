# Storage adapters

`pkg/storage` defines a Go interface without PostgreSQL-specific types. Provide an implementation and construct `engine.Engine{Store: adapter}`. The MCP handlers and finding/report models remain the same. The initial executable selects PostgreSQL; custom adapter maintainers provide a composition root or add a reviewed backend selector. The service does not load arbitrary uploaded plugins.

`View` supplies an organization/asset-scoped consistent read snapshot. `Update` supplies a scoped transaction callback and must atomically commit entity changes, change/audit records, and the idempotency response. Failed callbacks commit nothing. A mutation's expected version must match; organization/actor/key identifies a retry, and the request digest binds its operation, input, and permission context.

The reference adapter serializes writes per organization using a PostgreSQL transaction advisory lock, then checks idempotency before running the callback. This favors correctness during the initial release; measure contention before replacing it with finer-grained locks. Never perform external side effects inside transaction callbacks.

Every read filters by authenticated organization and asset grants. Relationship records are visible only when both endpoints are visible. Record kind and asset identity are immutable. Graph traversal applies the same restrictions with a maximum depth of three and 100 returned records; truncation is explicit. Runtime queries have a statement timeout and requests have a total deadline.

Changes use monotonically increasing cursors and retain actor, operation, version, and an intent fingerprint. Sequence values need not be contiguous, including across organizations. The current feed reports metadata; clients fetch authorized current records afterward. Immutable event bodies, deletion/tombstone propagation, retention negotiation, and consistent multi-page full snapshots are still required before claiming a full replication protocol.

Search currently uses a bounded result query over JSON content. It is correct but not optimized for a large corpus. Indexed full-text retrieval and a separate search adapter are planned. Core record storage uses typed identity, kind, asset, report, version, and timestamp columns plus JSONB domain payloads. Further typed projections can be added without changing the public model.

A second backend must pass the same real database and MCP workflow integration checks. A fake in-memory adapter is not evidence of production compatibility. PostgreSQL schema migration, credential issuance and revocation live in the reference adapter; other implementations own equivalent persistence and operational guarantees.

The classification extension adds a scoped `classification` record kind.
`Query.ConnectedTo` must also match classification `data.target_ids` arrays.
Catalog definitions and assignment edges are immutable/static and current-state
projections assembled by the shared engine; adapters persist classification
records with their usual concurrency, audit and idempotency guarantees. See
[vulnerability classifications](vulnerability-catalog.md).


`Query.Source` filters exact canonical `data.source` attribution. Apply it together with the existing organization, target, kind, status, search and keyset constraints; do not implement it as a substring search or allow it to expand access.

Finding discussions add the `comment` record kind and the optional
`storage.CommentReader` / `storage.CommentDeleter` interfaces. Implement listing
with exact parent finding scope, newest-first pagination and total, and atomic
version-fenced deletion. `Put` must persist comments and create their
`comments_on` graph connection in the same transaction. Deletion removes live
comment nodes/connections and records an audit event. Native adapters project
canonical App rows and edges instead of copying them. Custom backends without
these interfaces retain their existing tools but do not support comment listing
or deletion. See [finding comments](finding-comments.md).
