CREATE SCHEMA IF NOT EXISTS security_graph;
CREATE TABLE IF NOT EXISTS security_graph.entities (
  organization_id text NOT NULL,
  id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('asset','report','finding','relationship')),
  asset_id text NOT NULL,
  report_id text NOT NULL DEFAULT '',
  version bigint NOT NULL CHECK (version > 0),
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id,id)
);
CREATE INDEX IF NOT EXISTS entities_asset_kind ON security_graph.entities(organization_id,asset_id,kind,id);
CREATE INDEX IF NOT EXISTS entities_report ON security_graph.entities(organization_id,report_id,id);
CREATE INDEX IF NOT EXISTS relationships_source ON security_graph.entities(organization_id,(data->>'source_id')) WHERE kind='relationship';
CREATE INDEX IF NOT EXISTS relationships_target ON security_graph.entities(organization_id,(data->>'target_id')) WHERE kind='relationship';
CREATE TABLE IF NOT EXISTS security_graph.changes (
  cursor bigserial PRIMARY KEY,
  organization_id text NOT NULL,
  asset_id text NOT NULL,
  entity_id text NOT NULL,
  kind text NOT NULL,
  version bigint NOT NULL,
  actor_id text NOT NULL,
  operation text NOT NULL,
  intent_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS changes_scope ON security_graph.changes(organization_id,cursor);
CREATE TABLE IF NOT EXISTS security_graph.idempotency (
  organization_id text NOT NULL,
  actor_id text NOT NULL,
  key text NOT NULL,
  digest text NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(organization_id,actor_id,key)
);
CREATE TABLE IF NOT EXISTS security_graph.credentials (
  key_hash text PRIMARY KEY,
  organization_id text NOT NULL,
  actor_id text NOT NULL,
  scopes text[] NOT NULL,
  asset_ids text[] NOT NULL DEFAULT '{}',
  all_assets boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
