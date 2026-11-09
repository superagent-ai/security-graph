package superagent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

var commentParents = map[string]string{
	"github_advisory": "protection_advisory_id", "repository_red_team": "repository_advisory_id",
	"web_app_red_team": "web_app_advisory_id", "agent_red_team": "agent_advisory_id",
	"package_red_team": "package_advisory_id", "pr_scan": "pr_scan_finding_id",
}

func (a *Adapter) commentParent(ctx context.Context, tx pgx.Tx, p storage.Principal, findingID string) (string, error) {
	parent, err := a.Get(ctx, tx, p, findingID)
	if err != nil {
		return "", err
	}
	var f struct {
		Kind string `json:"kind"`
	}
	if parent.Kind != "finding" {
		return "", storage.ErrNotFound
	}
	if err = json.Unmarshal(parent.Data, &f); err != nil {
		return "", err
	}
	column, ok := commentParents[f.Kind]
	if !ok {
		return "", contracts.ErrInvalid
	}
	return column, nil
}
func (a *Adapter) comment(ctx context.Context, tx pgx.Tx, p storage.Principal, r storage.Record, expected int64) error {
	var c struct {
		FindingID string `json:"finding_id"`
		Body      string `json:"body"`
	}
	if err := json.Unmarshal(r.Data, &c); err != nil {
		return err
	}
	column, err := a.commentParent(ctx, tx, p, c.FindingID)
	if err != nil {
		return err
	}
	id := strings.TrimPrefix(r.ID, "comment:")
	if expected == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO public.finding_comments(id,`+column+`,body,author_type,author_name) VALUES($1,$2,$3,'api_key','API key')`, id, c.FindingID, c.Body)
		return err
	}
	// The version predicate also fences edits made through the App concurrently.
	updated, err := tx.Exec(ctx, `UPDATE public.finding_comments SET body=$1 WHERE id=$2 AND `+column+`=$3 AND (extract(epoch FROM updated_at)*1000000)::bigint=$4`, c.Body, id, c.FindingID, expected)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return storage.ErrConflict
	}
	return nil
}
func (a *Adapter) FindingComments(ctx context.Context, tx pgx.Tx, p storage.Principal, findingID string, limit, offset int) ([]storage.Record, int64, error) {
	column, err := a.commentParent(ctx, tx, p, findingID)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM public.finding_comments WHERE `+column+`=$1`, findingID).Scan(&total); err != nil {
		return nil, 0, err
	}
	// Page the indexed canonical parent column before building graph JSON.
	rows, err := tx.Query(ctx, `WITH page AS MATERIALIZED (
 SELECT 'comment:'||id::text AS id FROM public.finding_comments WHERE `+column+`=$2
 ORDER BY created_at DESC,id DESC LIMIT $5 OFFSET $6
) SELECT c.`+strings.ReplaceAll(fields, ",", ",c.")+` FROM security_graph.app_comments c JOIN page USING(id)
 WHERE organization_id=$1 AND ($3 OR asset_id=ANY($4::text[])) ORDER BY created_at DESC,id DESC`, p.OrganizationID, findingID, p.AllAssets, p.AssetIDs, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []storage.Record{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
func (a *Adapter) DeleteComment(ctx context.Context, tx pgx.Tx, p storage.Principal, r storage.Record, expected int64) error {
	var c struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(r.Data, &c); err != nil {
		return err
	}
	column, err := a.commentParent(ctx, tx, p, c.FindingID)
	if err != nil {
		return err
	}
	deleted, err := tx.Exec(ctx, `DELETE FROM public.finding_comments WHERE id=$1 AND `+column+`=$2 AND (extract(epoch FROM updated_at)*1000000)::bigint=$3`, strings.TrimPrefix(r.ID, "comment:"), c.FindingID, expected)
	if err != nil {
		return err
	}
	if deleted.RowsAffected() != 1 {
		return storage.ErrConflict
	}
	return nil
}
