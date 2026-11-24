package superagent

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// Script Guard findings are projected from host-validated immutable assessments.
// Only disposition metadata is writable; publication and scan execution remain
// App-owned. The SQL operation shares Graph's audit/idempotency transaction.
func (a *Adapter) scriptGuardFinding(ctx context.Context, tx pgx.Tx, p storage.Principal, f contracts.Finding, expected int64) error {
	if expected == 0 {
		return storage.ErrForbidden
	}
	var saved bool
	err := tx.QueryRow(ctx, "SELECT security_graph.update_script_guard_finding($1,$2::uuid,$3,$4,$5)",
		p.OrganizationID, f.ID, expected, f.Triage.Status, f.Triage.Resolution).Scan(&saved)
	if err != nil {
		return err
	}
	if !saved {
		return storage.ErrConflict
	}
	return nil
}
