package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type Engine struct {
	Store storage.Store
}
type Call struct {
	Intent string `json:"intent" jsonschema:"Required: explain the concrete purpose of this call and the security task it supports. 1 to 500 characters; exclude secrets."`
}
type WriteCall struct {
	Intent         string `json:"intent" jsonschema:"Required purpose of this action; 1 to 500 nonblank characters. Never include secrets."`
	IdempotencyKey string `json:"idempotency_key" jsonschema:"Stable key for retrying exactly this mutation."`
}

func authorize(p storage.Principal, intent, scope string) error {
	if err := contracts.ValidateIntent(intent); err != nil {
		return err
	}
	if !p.Allows(scope) {
		return storage.ErrForbidden
	}
	return nil
}
func data(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func decode[T any](r storage.Record, kind string) (v T, err error) {
	if r.Kind != kind {
		return v, storage.ErrNotFound
	}
	err = json.Unmarshal(r.Data, &v)
	return
}
func (e *Engine) write(ctx context.Context, p storage.Principal, op, scope string, c WriteCall, args any, f func(storage.Transaction) (any, error)) (json.RawMessage, error) {
	if err := authorize(p, c.Intent, scope); err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.IdempotencyKey) == "" || len(c.IdempotencyKey) > 200 {
		return nil, fmt.Errorf("%w: idempotency_key must contain 1 to 200 characters", contracts.ErrInvalid)
	}
	// Grants are part of the digest so a replay cannot restore a result after
	// a credential's organization/asset permissions have changed.
	h := sha256.Sum256(data(struct {
		Operation string
		Principal storage.Principal
		Args      any
	}{op, p, args}))
	return e.Store.Update(ctx, p, storage.Call{Intent: c.Intent, Operation: op, Key: c.IdempotencyKey, Digest: hex.EncodeToString(h[:])}, f)
}
func (e *Engine) Get(ctx context.Context, p storage.Principal, intent, id, kind string) (r storage.Record, err error) {
	if err = authorize(p, intent, "read"); err != nil {
		return
	}
	err = e.Store.View(ctx, p, func(tx storage.Reader) error {
		var er error
		r, er = tx.Get(ctx, id)
		if er == nil && kind != "" && r.Kind != kind {
			return storage.ErrNotFound
		}
		return er
	})
	return
}
func (e *Engine) List(ctx context.Context, p storage.Principal, intent string, q storage.Query) (out []storage.Record, err error) {
	if err = authorize(p, intent, "read"); err != nil {
		return
	}
	if q.Limit == 0 {
		q.Limit = 25
	}
	if q.Limit < 1 || q.Limit > 100 || len(q.Search) > 500 || len(q.Source) > 500 || q.Offset < 0 || q.Offset > 10000 || (q.After != "" && q.Offset != 0) {
		return nil, fmt.Errorf("%w: limit must be 1 to 100; search and source at most 500 characters", contracts.ErrInvalid)
	}
	err = e.Store.View(ctx, p, func(tx storage.Reader) error { var er error; out, er = tx.List(ctx, q); return er })
	return
}

type CreateAssetInput struct {
	WriteCall
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Locator string `json:"locator"`
}

func (e *Engine) CreateAsset(ctx context.Context, p storage.Principal, a CreateAssetInput) (json.RawMessage, error) {
	return e.write(ctx, p, "create_asset", "graph:write", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		if strings.HasPrefix(a.AssetID, "catalog:") || strings.HasPrefix(a.AssetID, "classification-edge:") {
			return nil, fmt.Errorf("%w: reserved graph namespace", contracts.ErrInvalid)
		}
		if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Type) == "" || strings.TrimSpace(a.Locator) == "" {
			return nil, fmt.Errorf("%w: asset name, type and locator required", contracts.ErrInvalid)
		}
		return tx.Put(ctx, storage.Record{ID: a.AssetID, Kind: "asset", AssetID: a.AssetID, Data: data(contracts.Asset{Name: a.Name, Type: a.Type, Locator: a.Locator})}, 0)
	})
}

type CreateReportInput struct {
	WriteCall
	AssetID string `json:"asset_id"`
	Type    string `json:"type"`
	Target  string `json:"target"`
}

func (e *Engine) CreateReport(ctx context.Context, p storage.Principal, a CreateReportInput) (json.RawMessage, error) {
	return e.write(ctx, p, "create_report", "submit", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		if !contracts.ValidReportType(a.Type) || strings.TrimSpace(a.Target) == "" {
			return nil, fmt.Errorf("%w: valid report type and target required", contracts.ErrInvalid)
		}
		asset, err := tx.Get(ctx, a.AssetID)
		if err != nil {
			return nil, err
		}
		if asset.Kind != "asset" {
			return nil, storage.ErrNotFound
		}
		id := uuid.NewString()
		saved, err := tx.Put(ctx, storage.Record{ID: id, Kind: "report", AssetID: a.AssetID, Data: data(contracts.Report{ID: id, Object: "report", Type: a.Type, Target: a.Target, Source: p.ActorID, Status: "in_progress", AgentStatus: "running"})}, 0)
		if err != nil {
			return nil, err
		}
		if err = link(ctx, tx, a.AssetID, id, "targets", a.AssetID); err != nil {
			return nil, err
		}
		return saved, nil
	})
}

type SubmitFindingInput struct {
	WriteCall
	ReportID string               `json:"report_id"`
	Finding  contracts.Submission `json:"finding"`
}

func (e *Engine) SubmitFinding(ctx context.Context, p storage.Principal, a SubmitFindingInput) (json.RawMessage, error) {
	if err := a.Finding.Validate(); err != nil {
		return nil, err
	}
	return e.write(ctx, p, "submit_finding", "submit", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		r, err := tx.Get(ctx, a.ReportID)
		if err != nil {
			return nil, err
		}
		report, err := decode[contracts.Report](r, "report")
		if err != nil {
			return nil, err
		}
		if report.Status == "failed" {
			return nil, storage.ErrConflict
		}
		id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.OrganizationID+"\x00"+r.ID+"\x00"+p.ActorID+"\x00"+a.Finding.ID)).String()
		f := contracts.Finding{ID: id, Object: "finding", Kind: report.Type + "_red_team", ReportID: r.ID, Title: a.Finding.Title, Description: a.Finding.GitHubAdvisory.Description, Severity: a.Finding.Severity, CWEIDs: a.Finding.CWEIDs, Source: p.ActorID, Triage: contracts.Triage{Status: contracts.New}, Submission: a.Finding}
		saved, err := tx.Put(ctx, storage.Record{ID: id, Kind: "finding", AssetID: r.AssetID, ReportID: r.ID, Data: data(f)}, 0)
		if err != nil {
			return nil, err
		}
		if err = link(ctx, tx, r.AssetID, id, "belongs_to", r.ID); err != nil {
			return nil, err
		}
		if report.Status == "completed" || report.Status == "done" {
			// Native database triggers may already have reopened this report.
			r, err = tx.Get(ctx, r.ID)
			if err != nil {
				return nil, err
			}
			report, err = decode[contracts.Report](r, "report")
			if err != nil {
				return nil, err
			}
			if report.Status == "in_review" {
				return saved, nil
			}
			report.Status = "in_review"
			r.Data = data(report)
			if _, err = tx.Put(ctx, r, r.Version); err != nil {
				return nil, err
			}
		}
		return saved, nil
	})
}

type UpdateFindingInput struct {
	WriteCall
	FindingID        string  `json:"finding_id"`
	ExpectedVersion  int64   `json:"expected_version"`
	TriageStatus     string  `json:"triage_status"`
	TriageResolution *string `json:"triage_resolution,omitempty"`
}

func (e *Engine) UpdateFinding(ctx context.Context, p storage.Principal, a UpdateFindingInput) (json.RawMessage, error) {
	if err := contracts.ValidateResolution(a.TriageStatus, a.TriageResolution); err != nil {
		return nil, err
	}
	return e.write(ctx, p, "update_finding_triage", "disposition", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		r, err := tx.Get(ctx, a.FindingID)
		if err != nil {
			return nil, err
		}
		f, err := decode[contracts.Finding](r, "finding")
		if err != nil {
			return nil, err
		}
		if r.Version != a.ExpectedVersion {
			return nil, storage.ErrConflict
		}
		f.Triage.Status = a.TriageStatus
		f.Triage.Resolution = nil
		if a.TriageStatus == contracts.Resolved {
			f.Triage.Resolution = a.TriageResolution
		}
		r.Data = data(f)
		saved, err := tx.Put(ctx, r, a.ExpectedVersion)
		if err != nil {
			return nil, err
		}
		if f.Kind == "github_advisory" || f.Kind == "pr_scan" {
			return saved, nil
		}
		if err = e.syncReport(ctx, tx, f.ReportID); err != nil {
			return nil, err
		}
		return saved, nil
	})
}
func (e *Engine) syncReport(ctx context.Context, tx storage.Transaction, id string) error {
	r, err := tx.Get(ctx, id)
	if err != nil {
		return err
	}
	report, err := decode[contracts.Report](r, "report")
	if err != nil {
		return err
	}
	if (report.Status != "in_review" && report.Status != "completed" && report.Status != "done") || (report.AgentStatus != "completed" && report.AgentStatus != "review" && report.EngagementMode != "manual") {
		return nil
	}
	status := "completed"
	after := ""
	for {
		rows, er := tx.List(ctx, storage.Query{Kind: "finding", ReportID: id, Limit: 201, After: after})
		if er != nil {
			return er
		}
		for _, row := range rows {
			f, er := decode[contracts.Finding](row, "finding")
			if er != nil {
				return er
			}
			if f.Triage.Status != "resolved" {
				status = "in_review"
				break
			}
		}
		if status == "in_review" || len(rows) < 201 {
			break
		}
		after = rows[len(rows)-1].ID
	}
	if report.Status != status {
		report.Status = status
		r.Data = data(report)
		_, err = tx.Put(ctx, r, r.Version)
	}
	return err
}

type ReportStatusInput struct {
	WriteCall
	ReportID        string `json:"report_id"`
	ExpectedVersion int64  `json:"expected_version"`
	Status          string `json:"status"`
}

func (e *Engine) ReportStatus(ctx context.Context, p storage.Principal, a ReportStatusInput, finish bool) (json.RawMessage, error) {
	op, scope := "update_report_review_status", "disposition"
	if finish {
		op, scope = "finish_report", "submit"
	}
	return e.write(ctx, p, op, scope, a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		r, err := tx.Get(ctx, a.ReportID)
		if err != nil {
			return nil, err
		}
		report, err := decode[contracts.Report](r, "report")
		if err != nil {
			return nil, err
		}
		if r.Version != a.ExpectedVersion {
			return nil, storage.ErrConflict
		}
		if finish {
			if report.Status != "in_progress" || (a.Status != "succeeded" && a.Status != "failed") {
				return nil, storage.ErrConflict
			}
			if a.Status == "failed" {
				report.Status = "failed"
				report.AgentStatus = "failed"
			} else {
				report.Status = "in_review"
				report.AgentStatus = "completed"
			}
		} else {
			if (report.Status != "completed" && report.Status != "in_review" && report.Status != "done") || (report.AgentStatus != "completed" && report.AgentStatus != "review" && report.EngagementMode != "manual") || (a.Status != "completed" && a.Status != "in_review") {
				return nil, storage.ErrConflict
			}
			report.Status = a.Status
		}
		r.Data = data(report)
		saved, err := tx.Put(ctx, r, r.Version)
		if err != nil {
			return nil, err
		}
		if finish && a.Status == "succeeded" {
			if err = e.syncReport(ctx, tx, r.ID); err != nil {
				return nil, err
			}
			return tx.Get(ctx, r.ID)
		}
		return saved, nil
	})
}

type RelationshipInput struct {
	WriteCall
	Relationship contracts.Relationship `json:"relationship"`
}

func (e *Engine) AddRelationship(ctx context.Context, p storage.Principal, a RelationshipInput) (json.RawMessage, error) {
	return e.write(ctx, p, "add_relationship", "graph:write", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		rel := a.Relationship
		if strings.TrimSpace(rel.Type) == "" || strings.TrimSpace(rel.Provenance) == "" {
			return nil, fmt.Errorf("%w: relationship type and provenance required", contracts.ErrInvalid)
		}
		source, err := tx.Get(ctx, rel.SourceID)
		if err != nil {
			return nil, err
		}
		target, err := tx.Get(ctx, rel.TargetID)
		if err != nil {
			return nil, err
		}
		if source.Kind == "relationship" || target.Kind == "relationship" {
			return nil, fmt.Errorf("%w: relationship endpoints must be entities", contracts.ErrInvalid)
		}
		return tx.Put(ctx, storage.Record{ID: uuid.NewString(), Kind: "relationship", AssetID: source.AssetID, Data: data(rel)}, 0)
	})
}

type ContextResult struct {
	Records    []storage.Record `json:"records"`
	Truncated  bool             `json:"truncated"`
	MaxDepth   int              `json:"max_depth"`
	Provenance string           `json:"provenance"`
}

func (e *Engine) Context(ctx context.Context, p storage.Principal, intent, id string, depth, limit int) (result ContextResult, err error) {
	if err = authorize(p, intent, "read"); err != nil {
		return
	}
	if depth < 0 || depth > 3 || limit < 1 || limit > 100 {
		return result, fmt.Errorf("%w: depth 0 to 3 and limit 1 to 100 required", contracts.ErrInvalid)
	}
	result = ContextResult{Records: []storage.Record{}, MaxDepth: depth, Provenance: "persisted records, curated catalog and attributed classification projections"}
	err = e.Store.View(ctx, p, func(tx storage.Reader) error {
		root, er := graphGet(ctx, tx, id)
		if er != nil {
			return er
		}
		seen := map[string]bool{id: true}
		result.Records = append(result.Records, root)
		front := []string{id}
		for d := 0; d < depth && len(front) > 0; d++ {
			next := []string{}
			stop := fmt.Errorf("context_limit")
			er = graphEdges(ctx, tx, front, func(edge storage.Record) error {
				var rel contracts.Relationship
				if err := json.Unmarshal(edge.Data, &rel); err != nil {
					return err
				}
				for _, node := range front {
					neighbor := ""
					if rel.SourceID == node {
						neighbor = rel.TargetID
					} else if rel.TargetID == node {
						neighbor = rel.SourceID
					}
					if neighbor == "" {
						continue
					}
					r, err := graphGet(ctx, tx, neighbor)
					if err == storage.ErrNotFound {
						continue
					}
					if err != nil {
						return err
					}
					if !seen[edge.ID] {
						if len(result.Records) >= limit {
							return stop
						}
						seen[edge.ID] = true
						result.Records = append(result.Records, edge)
					}
					if !seen[neighbor] {
						if len(result.Records) >= limit {
							return stop
						}
						seen[neighbor] = true
						result.Records = append(result.Records, r)
						next = append(next, neighbor)
					}
				}
				return nil
			})
			if er == stop {
				result.Truncated = true
				return nil
			}
			if er != nil {
				return er
			}
			front = next
		}
		return nil
	})
	return
}

func link(ctx context.Context, tx storage.Transaction, asset, source, kind, target string) error {
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(source+"\x00"+kind+"\x00"+target)).String()
	_, err := tx.Put(ctx, storage.Record{ID: id, Kind: "relationship", AssetID: asset, Data: data(contracts.Relationship{SourceID: source, Type: kind, TargetID: target, Provenance: "Superagent structured identifiers"})}, 0)
	return err
}
func (e *Engine) Changes(ctx context.Context, p storage.Principal, intent string, after int64, limit int) (out []storage.Change, err error) {
	if err = authorize(p, intent, "export"); err != nil {
		return
	}
	if after < 0 || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: invalid cursor or limit", contracts.ErrInvalid)
	}
	err = e.Store.View(ctx, p, func(tx storage.Reader) error { var er error; out, er = tx.Changes(ctx, after, limit); return er })
	return
}
