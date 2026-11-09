package superagent

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"math"
)

type ClassificationQueue struct{ Store *postgres.Store }

func (q ClassificationQueue) Claim(ctx context.Context) (*engine.ClassificationJob, error) {
	// Recover only expired leases. The fenced completion cannot acknowledge a
	// job reclaimed by another instance after cancellation or process death.
	_, err := q.Store.Pool.Exec(ctx, `UPDATE security_graph.classification_jobs SET status='pending',lease_token=NULL,lease_until=NULL WHERE status='processing' AND lease_until<now()`)
	if err != nil {
		return nil, err
	}
	j := &engine.ClassificationJob{Lease: uuid.NewString()}
	err = q.Store.Pool.QueryRow(ctx, `WITH candidate AS (
 SELECT j.id FROM security_graph.classification_jobs j WHERE j.status='pending' AND j.retry_at<=now()
 AND NOT EXISTS(SELECT 1 FROM security_graph.classification_jobs active WHERE active.organization_id=j.organization_id AND active.status='processing' AND active.lease_until>now())
 ORDER BY j.retry_at,j.created_at FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE security_graph.classification_jobs j SET status='processing',attempts=attempts+1,error_code=NULL,lease_token=$1,lease_until=now()+interval '3 minutes',updated_at=now()
 FROM candidate c WHERE j.id=c.id RETURNING j.id::text,j.organization_id::text,j.finding_id,j.asset_id,j.finding_version`, j.Lease).Scan(&j.ID, &j.OrganizationID, &j.FindingID, &j.AssetID, &j.FindingVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return j, err
}
func (q ClassificationQueue) Finish(ctx context.Context, j *engine.ClassificationJob, status, code string) error {
	capacitySeconds := math.Ceil(j.RetryAfter.Seconds())
	if capacitySeconds < 1 {
		capacitySeconds = 2
	}
	if capacitySeconds > 60 {
		capacitySeconds = 60
	}
	tx, err := q.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE security_graph.classification_jobs SET status=$1,error_code=nullif($2,''),lease_token=NULL,lease_until=NULL,
 attempts=CASE WHEN $1='pending' AND $2='classifier_capacity' THEN greatest(attempts-1,0) ELSE attempts END,
 retry_at=CASE WHEN $1='pending' AND $2='classifier_capacity' THEN now()+make_interval(secs=>$5::double precision)
 WHEN $1='pending' THEN now()+make_interval(secs=>least(1800,60*power(2,least(attempts-1,5)))::integer) ELSE retry_at END,updated_at=now()
 WHERE id=$3 AND lease_token=$4 AND status='processing'`, status, code, j.ID, j.Lease, capacitySeconds)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 && j.NextVersion > 0 {
		_, err = tx.Exec(ctx, `INSERT INTO security_graph.classification_jobs(organization_id,finding_id,asset_id,finding_version) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, j.OrganizationID, j.FindingID, j.AssetID, j.NextVersion)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
