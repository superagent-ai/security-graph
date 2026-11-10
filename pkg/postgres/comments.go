package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type nativeComments interface {
	FindingComments(context.Context, pgx.Tx, storage.Principal, string, int, int) ([]storage.Record, int64, error)
	DeleteComment(context.Context, pgx.Tx, storage.Principal, storage.Record, int64) error
}

func (t *transaction) FindingComments(ctx context.Context, findingID string, limit, offset int) ([]storage.Record, int64, error) {
	if n, ok := t.native.(nativeComments); ok {
		return n.FindingComments(ctx, t.tx, t.p, findingID, limit, offset)
	}
	if t.native != nil {
		return nil, 0, storage.ErrForbidden
	}
	var total int64
	err := t.tx.QueryRow(ctx, `SELECT count(*) FROM security_graph.entities WHERE organization_id=$1 AND kind='comment' AND data->>'finding_id'=$2 AND ($3 OR asset_id=ANY($4::text[]))`, t.p.OrganizationID, findingID, t.p.AllAssets, t.p.AssetIDs).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := t.tx.Query(ctx, `SELECT `+cols+` FROM security_graph.entities WHERE organization_id=$1 AND kind='comment' AND data->>'finding_id'=$2 AND ($3 OR asset_id=ANY($4::text[])) ORDER BY created_at DESC,id DESC LIMIT $5 OFFSET $6`, t.p.OrganizationID, findingID, t.p.AllAssets, t.p.AssetIDs, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []storage.Record{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, r)
	}
	return result, total, rows.Err()
}
func (t *transaction) DeleteComment(ctx context.Context, r storage.Record, expected int64) error {
	if r.Kind != "comment" || !t.p.AllowsAsset(r.AssetID) {
		return storage.ErrForbidden
	}
	if n, ok := t.native.(nativeComments); ok {
		if err := n.DeleteComment(ctx, t.tx, t.p, r, expected); err != nil {
			return err
		}
	} else {
		if t.native != nil {
			return storage.ErrForbidden
		}
		deleted, err := t.tx.Exec(ctx, `DELETE FROM security_graph.entities WHERE organization_id=$1 AND id=$2 AND kind='comment' AND version=$3 AND ($4 OR asset_id=ANY($5::text[]))`, t.p.OrganizationID, r.ID, expected, t.p.AllAssets, t.p.AssetIDs)
		if err != nil {
			return err
		}
		if deleted.RowsAffected() != 1 {
			return storage.ErrConflict
		}
		_, err = t.tx.Exec(ctx, `DELETE FROM security_graph.entities WHERE organization_id=$1 AND kind='relationship' AND (data->>'source_id'=$2 OR data->>'target_id'=$2)`, t.p.OrganizationID, r.ID)
		if err != nil {
			return err
		}
	}
	r.Version++
	return t.audit(ctx, r)
}
func (t *transaction) commentEdge(ctx context.Context, r storage.Record) error {
	var c struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(r.Data, &c); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"source_id": r.ID, "target_id": c.FindingID, "type": "comments_on", "provenance": "Attributed finding discussion; not independent verification."})
	_, err := t.Put(ctx, storage.Record{ID: "link:" + r.ID + ":comments_on", Kind: "relationship", AssetID: r.AssetID, ReportID: r.ReportID, Data: body}, 0)
	return err
}
