package superagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
	"strings"
)

func (a *Adapter) authenticateNative(ctx context.Context, s *postgres.Store, token string) (storage.Principal, error) {
	var p storage.Principal
	if len(token) != len("sg_native_")+64 {
		return p, storage.ErrForbidden
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(token, "sg_native_")); err != nil {
		return p, storage.ErrForbidden
	}
	h := sha256.Sum256([]byte(token))
	var submit bool
	var asset string
	err := s.Pool.QueryRow(ctx, `SELECT c.organization_id::text,c.run_id::text,c.modality,c.asset_id,c.agent_id,c.source_token_hash,c.can_submit
 FROM security_graph.native_access_tokens c WHERE c.token_hash=$1 AND c.expires_at>now()
 AND EXISTS(SELECT 1 FROM security_graph.app_native_run_scopes r WHERE r.token_hash=c.source_token_hash AND r.run_id=c.run_id::text AND r.organization_id=c.organization_id::text AND r.asset_id=c.asset_id AND r.modality=c.modality)`, hex.EncodeToString(h[:])).Scan(&p.OrganizationID, &p.NativeRunID, &p.NativeModality, &asset, &p.NativeAgentID, &p.NativeTokenHash, &submit)
	if err != nil {
		return storage.Principal{}, storage.ErrForbidden
	}
	p.ActorID = "native:" + p.NativeModality + ":" + p.NativeRunID + ":" + p.NativeAgentID
	p.AssetIDs = []string{asset}
	p.Scopes = []string{"read"}
	if submit {
		p.Scopes = append(p.Scopes, "native:submit")
	}
	return p, nil
}
func (a *Adapter) NativeContext(ctx context.Context, s *postgres.Store, p storage.Principal, q *storage.NativeQuery) ([]byte, error) {
	if p.NativeRunID == "" || p.NativeTokenHash == "" {
		return nil, storage.ErrForbidden
	}
	var query any
	if q != nil {
		if len(q.Query) > 200 || len(q.RecordID) > 2048 || len(q.After) > 2048 || q.Limit < 1 || q.Limit > 20 {
			return nil, contracts.ErrInvalid
		}
		b, _ := json.Marshal(q)
		query = b
	}
	var result []byte
	err := s.Pool.QueryRow(ctx, "SELECT public.security_graph_native_context($1,$2)", p.NativeTokenHash, query).Scan(&result)
	if err == nil && len(result) == 0 {
		return nil, storage.ErrForbidden
	}
	return result, err
}
func (a *Adapter) SaveNativeFinding(ctx context.Context, tx pgx.Tx, p storage.Principal, payload []byte) (storage.Record, error) {
	if !p.Allows("native:submit") || p.NativeRunID == "" || p.NativeModality == "pr_scan" {
		return storage.Record{}, storage.ErrForbidden
	}
	var id string
	err := tx.QueryRow(ctx, "SELECT public.security_graph_save_native_finding($1,$2,$3,$4,$5)::text", p.OrganizationID, p.NativeRunID, p.NativeModality, p.NativeAgentID, payload).Scan(&id)
	if err != nil {
		return storage.Record{}, nativeError(err)
	}
	return a.Get(ctx, tx, p, id)
}
func (a *Adapter) ReplaceNativePRFindings(ctx context.Context, tx pgx.Tx, p storage.Principal, payload []byte) ([]byte, error) {
	if !p.Allows("native:submit") || p.NativeRunID == "" || p.NativeModality != "pr_scan" {
		return nil, storage.ErrForbidden
	}
	var result []byte
	err := tx.QueryRow(ctx, "SELECT public.security_graph_replace_native_pr_findings($1,$2,$3)", p.OrganizationID, p.NativeRunID, payload).Scan(&result)
	return result, nativeError(err)
}
func nativeError(err error) error {
	if err != nil && strings.Contains(err.Error(), "native_context_read_required") {
		return contracts.ErrNativeContextReadRequired
	}
	return err
}
