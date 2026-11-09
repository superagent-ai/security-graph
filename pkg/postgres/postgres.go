// Package postgres implements the reference storage adapter. It uses a separate
// schema and never creates or modifies the existing app's public tables.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Pool   *pgxpool.Pool
	Native Native
}

func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Store{Pool: p}
	if err = s.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close()                         { s.Pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.Pool.Ping(ctx) }
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(183810027)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS security_graph; CREATE TABLE IF NOT EXISTS security_graph.schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		return err
	}
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, f := range files {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM security_graph.schema_migrations WHERE version=$1)", f.Name()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, e := migrations.ReadFile("migrations/" + f.Name())
		if e != nil {
			return e
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO security_graph.schema_migrations(version) VALUES($1)", f.Name()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type transaction struct {
	native Native
	tx     pgx.Tx
	p      storage.Principal
	call   storage.Call
}

func (s *Store) View(ctx context.Context, p storage.Principal, f func(storage.Reader) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = f(&transaction{tx: tx, p: p, native: s.Native}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Update(ctx context.Context, p storage.Principal, c storage.Call, f func(storage.Transaction) (any, error)) (json.RawMessage, error) {
	if c.Key == "" || len(c.Key) > 200 {
		return nil, fmt.Errorf("idempotency_key must contain 1 to 200 characters")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", p.OrganizationID); err != nil {
		return nil, err
	}
	var digest string
	var response json.RawMessage
	err = tx.QueryRow(ctx, "SELECT digest,response FROM security_graph.idempotency WHERE organization_id=$1 AND actor_id=$2 AND key=$3", p.OrganizationID, p.ActorID, c.Key).Scan(&digest, &response)
	if err == nil {
		if digest != c.Digest {
			return nil, storage.ErrConflict
		}
		return response, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	result, err := f(&transaction{tx: tx, p: p, call: c, native: s.Native})
	if err != nil {
		return nil, err
	}
	response, err = json.Marshal(result)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO security_graph.idempotency(organization_id,actor_id,key,digest,response) VALUES($1,$2,$3,$4,$5)", p.OrganizationID, p.ActorID, c.Key, c.Digest, response)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return response, nil
}

const cols = "id,kind,asset_id,report_id,version,data,created_at,updated_at"

// Relationship visibility requires access to both endpoints, including reads
// outside graph traversal. Hiding only the target payload would leak its ID.
const visible = ` AND (entities.kind <> 'relationship' OR
  (EXISTS(SELECT 1 FROM security_graph.entities src WHERE src.organization_id=entities.organization_id AND src.id=entities.data->>'source_id' AND ($VIS OR src.asset_id=ANY($ASSETS::text[])))
   AND EXISTS(SELECT 1 FROM security_graph.entities dst WHERE dst.organization_id=entities.organization_id AND dst.id=entities.data->>'target_id' AND ($VIS OR dst.asset_id=ANY($ASSETS::text[])))))`

func (t *transaction) visibility(all, assets string) string {
	v := visible
	if t.native != nil {
		v = strings.ReplaceAll(v, "security_graph.entities src", "(SELECT organization_id,id,asset_id FROM security_graph.entities UNION ALL SELECT organization_id,id,asset_id FROM security_graph.app_records) src")
		v = strings.ReplaceAll(v, "security_graph.entities dst", "(SELECT organization_id,id,asset_id FROM security_graph.entities UNION ALL SELECT organization_id,id,asset_id FROM security_graph.app_records) dst")
	}
	return strings.NewReplacer("$VIS", all, "$ASSETS", assets).Replace(v)
}

func scan(row pgx.Row) (r storage.Record, err error) {
	err = row.Scan(&r.ID, &r.Kind, &r.AssetID, &r.ReportID, &r.Version, &r.Data, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = storage.ErrNotFound
	}
	return
}
func (t *transaction) Get(ctx context.Context, id string) (storage.Record, error) {
	if t.native != nil {
		r, err := t.native.Get(ctx, t.tx, t.p, id)
		if !errors.Is(err, storage.ErrNotFound) {
			return r, err
		}
	}
	return scan(t.tx.QueryRow(ctx, "SELECT "+cols+" FROM security_graph.entities WHERE organization_id=$1 AND id=$2 AND ($3 OR asset_id=ANY($4::text[]))"+t.visibility("$3", "$4"), t.p.OrganizationID, id, t.p.AllAssets, t.p.AssetIDs))
}
func (t *transaction) List(ctx context.Context, q storage.Query) ([]storage.Record, error) {
	if q.Limit < 1 || q.Limit > 201 {
		return nil, fmt.Errorf("limit must be between 1 and 201")
	}
	if t.native != nil {
		return t.native.List(ctx, t.tx, t.p, q)
	}
	rows, err := t.tx.Query(ctx, "SELECT "+cols+" FROM security_graph.entities WHERE organization_id=$1 AND ($2 OR asset_id=ANY($3::text[])) AND ($4='' OR kind=$4) AND ($5='' OR report_id=$5) AND ($6='' OR asset_id=$6) AND id>$7 AND ($8='' OR strpos(lower(data::text),lower($8))>0) AND ($10::text[] IS NULL OR data->>'source_id'=ANY($10::text[]) OR data->>'target_id'=ANY($10::text[]) OR (kind='classification' AND (data->'target_ids') ?| $10::text[]))"+t.visibility("$2", "$3")+" AND ($11='' OR data->>'kind'=$11) AND ($12='' OR data->'triage'->>'status'=$12) AND ($13='' OR data->>'type'=$13) AND ($14='' OR data->>'status'=$14) AND ($16='' OR data->>'source'=$16) ORDER BY id LIMIT $9 OFFSET $15", t.p.OrganizationID, t.p.AllAssets, t.p.AssetIDs, q.Kind, q.ReportID, q.AssetID, q.After, q.Search, q.Limit, q.ConnectedTo, q.FindingKind, q.TriageStatus, q.ReportType, q.Status, q.Offset, q.Source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storage.Record{}
	for rows.Next() {
		r, e := scan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (t *transaction) Put(ctx context.Context, r storage.Record, expected int64) (storage.Record, error) {
	if !t.p.AllowsAsset(r.AssetID) {
		return r, storage.ErrForbidden
	}
	if r.ID == "" || r.AssetID == "" {
		return r, fmt.Errorf("id and asset_id required")
	}
	if t.native != nil && (r.Kind == "finding" || r.Kind == "report") {
		saved, err := t.native.Put(ctx, t.tx, t.p, r, expected)
		if err != nil {
			return r, err
		}
		return saved, t.audit(ctx, saved)
	}
	old, err := t.Get(ctx, r.ID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return r, err
	}
	if err == nil && (old.Version != expected || old.AssetID != r.AssetID || old.Kind != r.Kind) {
		return r, storage.ErrConflict
	}
	if errors.Is(err, storage.ErrNotFound) && expected != 0 {
		return r, storage.ErrConflict
	}
	if expected == 0 {
		r, err = scan(t.tx.QueryRow(ctx, "INSERT INTO security_graph.entities(organization_id,id,kind,asset_id,report_id,version,data) VALUES($1,$2,$3,$4,$5,1,$6) ON CONFLICT DO NOTHING RETURNING "+cols, t.p.OrganizationID, r.ID, r.Kind, r.AssetID, r.ReportID, r.Data))
	} else {
		r, err = scan(t.tx.QueryRow(ctx, "UPDATE security_graph.entities SET data=$1,report_id=$2,version=version+1,updated_at=now() WHERE organization_id=$3 AND id=$4 AND version=$5 RETURNING "+cols, r.Data, r.ReportID, t.p.OrganizationID, r.ID, expected))
	}
	if errors.Is(err, storage.ErrNotFound) {
		return r, storage.ErrConflict
	}
	if err != nil {
		return r, err
	}
	return r, t.audit(ctx, r)
}

func (t *transaction) audit(ctx context.Context, r storage.Record) error {
	h := sha256.Sum256([]byte(t.call.Intent))
	_, err := t.tx.Exec(ctx, "INSERT INTO security_graph.changes(organization_id,asset_id,entity_id,kind,version,actor_id,operation,intent_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", t.p.OrganizationID, r.AssetID, r.ID, r.Kind, r.Version, t.p.ActorID, t.call.Operation, hex.EncodeToString(h[:]))
	return err
}
func (t *transaction) Changes(ctx context.Context, after int64, limit int) ([]storage.Change, error) {
	if limit < 1 || limit > 200 {
		return nil, fmt.Errorf("invalid limit")
	}
	source := "security_graph.entities"
	if t.native != nil {
		source = "(SELECT organization_id,id,asset_id,kind,data FROM security_graph.app_records UNION ALL SELECT organization_id,id,asset_id,kind,data FROM security_graph.entities e WHERE NOT EXISTS(SELECT 1 FROM security_graph.app_records n WHERE n.organization_id=e.organization_id AND n.id=e.id))"
	}
	rows, err := t.tx.Query(ctx, "SELECT c.cursor,c.entity_id,c.kind,c.version,c.actor_id,c.created_at FROM security_graph.changes c JOIN "+source+" entities ON entities.organization_id=c.organization_id AND entities.id=c.entity_id WHERE c.organization_id=$1 AND ($2 OR c.asset_id=ANY($3::text[])) AND c.cursor>$4"+t.visibility("$2", "$3")+" ORDER BY c.cursor LIMIT $5", t.p.OrganizationID, t.p.AllAssets, t.p.AssetIDs, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storage.Change{}
	for rows.Next() {
		var c storage.Change
		if err = rows.Scan(&c.Cursor, &c.EntityID, &c.Kind, &c.Version, &c.ActorID, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Authenticate(ctx context.Context, token string) (storage.Principal, error) {
	if s.Native != nil {
		return s.Native.Authenticate(ctx, s, token)
	}
	var p storage.Principal
	h := sha256.Sum256([]byte(token))
	err := s.Pool.QueryRow(ctx, "SELECT organization_id,actor_id,scopes,asset_ids,all_assets FROM security_graph.credentials WHERE key_hash=$1 AND revoked_at IS NULL AND expires_at>now()", hex.EncodeToString(h[:])).Scan(&p.OrganizationID, &p.ActorID, &p.Scopes, &p.AssetIDs, &p.AllAssets)
	if err != nil {
		return p, storage.ErrForbidden
	}
	return p, nil
}
func (s *Store) IssueKey(ctx context.Context, token string, p storage.Principal, expires time.Time) error {
	if p.AssetIDs == nil {
		p.AssetIDs = []string{}
	}
	if p.OrganizationID == "" || p.ActorID == "" || len(p.Scopes) == 0 || (!p.AllAssets && len(p.AssetIDs) == 0) {
		return fmt.Errorf("organization, actor, scopes and asset access are required")
	}
	for _, scope := range p.Scopes {
		if scope != "read" && scope != "submit" && scope != "disposition" && scope != "graph:write" && scope != "export" {
			return fmt.Errorf("unknown scope %q", scope)
		}
	}
	h := sha256.Sum256([]byte(token))
	_, err := s.Pool.Exec(ctx, "INSERT INTO security_graph.credentials(key_hash,organization_id,actor_id,scopes,asset_ids,all_assets,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)", hex.EncodeToString(h[:]), p.OrganizationID, p.ActorID, p.Scopes, p.AssetIDs, p.AllAssets, expires)
	return err
}

var _ storage.Store = (*Store)(nil)

func (s *Store) NativeContext(ctx context.Context, p storage.Principal, q *storage.NativeQuery) (json.RawMessage, error) {
	n, ok := s.Native.(NativeExecution)
	if !ok {
		return nil, storage.ErrForbidden
	}
	return n.NativeContext(ctx, s, p, q)
}
func (t *transaction) SaveNativeFinding(ctx context.Context, payload json.RawMessage) (storage.Record, error) {
	n, ok := t.native.(NativeExecution)
	if !ok {
		return storage.Record{}, storage.ErrForbidden
	}
	r, err := n.SaveNativeFinding(ctx, t.tx, t.p, payload)
	if err != nil {
		return r, err
	}
	return r, t.audit(ctx, r)
}
func (t *transaction) ReplaceNativePRFindings(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	n, ok := t.native.(NativeExecution)
	if !ok {
		return nil, storage.ErrForbidden
	}
	result, err := n.ReplaceNativePRFindings(ctx, t.tx, t.p, payload)
	if err != nil {
		return nil, err
	}
	var ids []string
	if err = json.Unmarshal(result, &ids); err != nil {
		return nil, err
	}
	for _, id := range ids {
		r, e := t.native.Get(ctx, t.tx, t.p, id)
		if e != nil {
			return nil, e
		}
		if e = t.audit(ctx, r); e != nil {
			return nil, e
		}
	}
	return result, nil
}
