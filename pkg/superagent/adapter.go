// Package superagent maps the engine directly onto the app's authoritative
// PostgreSQL records. No findings or reports are copied into graph entities.
package superagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type Adapter struct{}

func Enable(ctx context.Context, s *postgres.Store) error {
	var ok bool
	if err := s.Pool.QueryRow(ctx, "SELECT to_regclass('security_graph.app_records') IS NOT NULL").Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errors.New("apply the app security_graph_native_integration migration before selecting the superagent backend")
	}
	s.Native = &Adapter{}
	return nil
}
func (a *Adapter) Authenticate(ctx context.Context, s *postgres.Store, token string) (storage.Principal, error) {
	var p storage.Principal
	h := sha256.Sum256([]byte(token))
	if !strings.HasPrefix(token, "sk_live_") {
		// Optional app migration: existing runner credentials confer read-only
		// access to one asset for an active run. Re-evaluated on every request,
		// so native revocation, expiry and execution completion take effect.
		var enabled bool
		if err := s.Pool.QueryRow(ctx, "SELECT to_regclass('security_graph.app_runner_principals') IS NOT NULL").Scan(&enabled); err != nil || !enabled {
			return p, storage.ErrForbidden
		}
		var asset string
		err := s.Pool.QueryRow(ctx, "SELECT organization_id,actor_id,asset_id FROM security_graph.app_runner_principals WHERE token_hash=$1", hex.EncodeToString(h[:])).Scan(&p.OrganizationID, &p.ActorID, &asset)
		if err != nil {
			return storage.Principal{}, storage.ErrForbidden
		}
		p.Scopes = []string{"read"}
		p.AssetIDs = []string{asset}
		return p, nil
	}
	var id string
	err := s.Pool.QueryRow(ctx, "SELECT id::text,organization_id::text FROM public.api_keys WHERE key_hash=$1", hex.EncodeToString(h[:])).Scan(&id, &p.OrganizationID)
	if err != nil {
		return p, storage.ErrForbidden
	}
	p.ActorID = "api_key:" + id
	p.AllAssets = true
	p.Scopes = []string{"read", "submit", "disposition", "graph:write", "export"}
	p.AssetIDs = []string{}
	_, err = s.Pool.Exec(ctx, "UPDATE public.api_keys SET last_used_at=now() WHERE id=$1", id)
	if err != nil {
		return storage.Principal{}, err
	}
	return p, nil
}

const fields = "id,kind,asset_id,report_id,version,data,created_at,updated_at"

func scan(row pgx.Row) (r storage.Record, err error) {
	err = row.Scan(&r.ID, &r.Kind, &r.AssetID, &r.ReportID, &r.Version, &r.Data, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = storage.ErrNotFound
	}
	return
}
func (a *Adapter) Get(ctx context.Context, tx pgx.Tx, p storage.Principal, id string) (storage.Record, error) {
	return scan(tx.QueryRow(ctx, "SELECT "+fields+" FROM security_graph.app_records WHERE organization_id=$1 AND id=$2 AND ($3 OR asset_id=ANY($4::text[]))", p.OrganizationID, id, p.AllAssets, p.AssetIDs))
}
func (a *Adapter) List(ctx context.Context, tx pgx.Tx, p storage.Principal, q storage.Query) ([]storage.Record, error) {
	if q.Limit < 1 || q.Limit > 201 {
		return nil, contracts.ErrInvalid
	}
	// Graph-only assets and explicit relationships live beside native records;
	// the union never duplicates an app finding/report into graph persistence.
	rows, err := tx.Query(ctx, `WITH records AS NOT MATERIALIZED (
 SELECT organization_id,`+fields+` FROM security_graph.app_records
 UNION ALL SELECT organization_id,`+fields+` FROM security_graph.entities e WHERE kind IN ('asset','relationship') AND NOT EXISTS(SELECT 1 FROM security_graph.app_records n WHERE n.organization_id=e.organization_id AND n.id=e.id)
 ) SELECT `+fields+` FROM records r WHERE organization_id=$1 AND ($2 OR asset_id=ANY($3::text[])) AND ($4='' OR kind=$4) AND ($5='' OR report_id=$5) AND ($6='' OR asset_id=$6) AND id>$7 AND ($8='' OR strpos(lower(data::text),lower($8))>0) AND ($10::text[] IS NULL OR data->>'source_id'=ANY($10::text[]) OR data->>'target_id'=ANY($10::text[])) AND (kind<>'relationship' OR (EXISTS(SELECT 1 FROM records n WHERE n.organization_id=r.organization_id AND n.id=r.data->>'source_id' AND ($2 OR n.asset_id=ANY($3::text[]))) AND EXISTS(SELECT 1 FROM records n WHERE n.organization_id=r.organization_id AND n.id=r.data->>'target_id' AND ($2 OR n.asset_id=ANY($3::text[]))))) AND ($11='' OR data->>'kind'=$11) AND ($12='' OR data->'triage'->>'status'=$12) AND ($13='' OR data->>'type'=$13) AND ($14='' OR data->>'status'=$14) ORDER BY id LIMIT $9 OFFSET $15`, p.OrganizationID, p.AllAssets, p.AssetIDs, q.Kind, q.ReportID, q.AssetID, q.After, q.Search, q.Limit, q.ConnectedTo, q.FindingKind, q.TriageStatus, q.ReportType, q.Status, q.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storage.Record{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type source struct{ report, finding, fk string }

var sources = map[string]source{
	"repository": {"repository_red_team_reports", "repository_red_team_advisories", "report_id"},
	"web_app":    {"web_app_red_team_reports", "web_app_red_team_advisories", "report_id"},
	"agent":      {"agent_red_team_projects", "agent_red_team_advisories", "project_id"},
	"package":    {"package_red_team_reports", "package_red_team_advisories", "report_id"},
}

func (a *Adapter) Put(ctx context.Context, tx pgx.Tx, p storage.Principal, r storage.Record, expected int64) (storage.Record, error) {
	if !p.AllowsAsset(r.AssetID) {
		return r, storage.ErrForbidden
	}
	old, err := a.Get(ctx, tx, p, r.ID)
	if expected != 0 {
		if err != nil {
			return r, err
		}
		if old.Version != expected || old.Kind != r.Kind || old.AssetID != r.AssetID {
			return r, storage.ErrConflict
		}
	} else if err == nil {
		return r, storage.ErrConflict
	} else if !errors.Is(err, storage.ErrNotFound) {
		return r, err
	}
	if r.Kind == "report" {
		err = a.report(ctx, tx, p, r, old, expected)
	} else if r.Kind == "finding" {
		err = a.finding(ctx, tx, p, r, old, expected)
	} else {
		return r, contracts.ErrInvalid
	}
	if err != nil {
		return r, err
	}
	return a.Get(ctx, tx, p, r.ID)
}
func (a *Adapter) report(ctx context.Context, tx pgx.Tx, p storage.Principal, r, old storage.Record, expected int64) error {
	var report contracts.Report
	if err := json.Unmarshal(r.Data, &report); err != nil {
		return err
	}
	s, ok := sources[report.Type]
	if !ok {
		return contracts.ErrInvalid
	}
	if expected == 0 {
		if report.Status != "in_progress" || report.AgentStatus != "running" {
			return storage.ErrConflict
		}
		switch report.Type {
		case "repository":
			_, err := tx.Exec(ctx, "INSERT INTO public.repository_red_team_reports(id,organization_id,repo,agent_status) VALUES($1,$2,$3,'running')", r.ID, p.OrganizationID, report.Target)
			if err != nil {
				return err
			}
		case "web_app":
			_, err := tx.Exec(ctx, "INSERT INTO public.web_app_red_team_reports(id,organization_id,target_url,allowed_host,agent_status) VALUES($1,$2,$3,$4,'running')", r.ID, p.OrganizationID, report.Target, "")
			if err != nil {
				return err
			}
		case "agent":
			_, err := tx.Exec(ctx, "INSERT INTO public.agent_red_team_projects(id,organization_id,description,agent_type,engagement_mode,status,agent_status) VALUES($1,$2,$3,'chatbot','manual','running','running')", r.ID, p.OrganizationID, report.Target)
			if err != nil {
				return err
			}
		case "package":
			_, err := tx.Exec(ctx, "INSERT INTO public.package_red_team_reports(id,organization_id,installation_instructions,agent_status) VALUES($1,$2,$3,'running')", r.ID, p.OrganizationID, report.Target)
			if err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, "INSERT INTO security_graph.native_report_origins(organization_id,report_id,asset_id,actor_id) VALUES($1,$2,$3,$4)", p.OrganizationID, r.ID, r.AssetID, p.ActorID)
		return err
	}
	var previous contracts.Report
	_ = json.Unmarshal(old.Data, &previous)
	if report.AgentStatus != previous.AgentStatus {
		var own bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM security_graph.native_report_origins WHERE organization_id=$1 AND report_id=$2 AND actor_id=$3)", p.OrganizationID, r.ID, p.ActorID).Scan(&own); err != nil {
			return err
		}
		if !own {
			return storage.ErrForbidden
		}
	}
	status := report.Status
	if report.Type == "agent" {
		if status == "completed" {
			status = "review_completed"
		} else if status == "in_review" {
			status = "completed"
		}
	}
	tag, err := tx.Exec(ctx, "UPDATE public."+s.report+" SET status=$1,agent_status=$2,updated_at=clock_timestamp() WHERE id=$3 AND organization_id=$4 AND updated_at=$5", status, report.AgentStatus, r.ID, p.OrganizationID, old.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return storage.ErrConflict
	}
	return nil
}
func (a *Adapter) finding(ctx context.Context, tx pgx.Tx, p storage.Principal, r, old storage.Record, expected int64) error {
	var f contracts.Finding
	if err := json.Unmarshal(r.Data, &f); err != nil {
		return err
	}
	typ := strings.TrimSuffix(f.Kind, "_red_team")
	s, ok := sources[typ]
	if !ok && f.Kind != "github_advisory" {
		return contracts.ErrInvalid
	}
	if expected == 0 {
		if !ok {
			return storage.ErrForbidden
		}
		parent, err := a.Get(ctx, tx, p, f.ReportID)
		if err != nil {
			return err
		}
		if parent.Kind != "report" || parent.AssetID != r.AssetID {
			return storage.ErrForbidden
		}
		var rep contracts.Report
		_ = json.Unmarshal(parent.Data, &rep)
		if rep.Type != typ {
			return storage.ErrConflict
		}
		// The legacy required user FK is attribution to the key creator, or an org
		// owner when the key predates creator attribution. Actual actor is retained
		// separately in transactional graph history and the submission evidence.
		var creator string
		err = tx.QueryRow(ctx, "SELECT coalesce((SELECT created_by FROM public.api_keys WHERE id::text=$1 AND organization_id=$2),(SELECT user_id FROM public.organization_members WHERE organization_id=$2 AND role='owner' ORDER BY created_at LIMIT 1))::text", strings.TrimPrefix(p.ActorID, "api_key:"), p.OrganizationID).Scan(&creator)
		if err != nil {
			return fmt.Errorf("%w: organization needs an owner for legacy finding attribution", contracts.ErrInvalid)
		}
		products := []map[string]string{}
		for _, v := range f.Submission.GitHubAdvisory.Vulnerabilities {
			products = append(products, map[string]string{"ecosystem": v.Package.Ecosystem, "package_name": v.Package.Name, "affected_versions": v.VulnerableVersionRange})
		}
		productJSON, _ := json.Marshal(products)
		evidence, _ := json.Marshal(map[string]any{"security_graph_submission": f.Submission, "submitted_by_api_key": strings.TrimPrefix(p.ActorID, "api_key:"), "proposed_patch": f.Submission.ProposedPatch, "code_references": f.Submission.CodeReferences})
		_, err = tx.Exec(ctx, "INSERT INTO public."+s.finding+"(id,"+s.fk+",title,description,affected_products,cvss_vector,weakness,created_by,source,source_attempt_id,triage_status,triage_risk,triage_evidence) VALUES($1,$2,$3,$4,$5,'',$6,$7,'agent',$8,'new',$9,$10)", r.ID, f.ReportID, f.Title, f.Description, productJSON, strings.Join(f.CWEIDs, ", "), creator, "security-graph:"+p.ActorID+":"+f.Submission.ID, f.Severity, evidence)
		if err != nil {
			return err
		}
		return enqueue(ctx, tx, p, f, "finding_created", rep.Target)
	}
	var before contracts.Finding
	_ = json.Unmarshal(old.Data, &before)
	table := s.finding
	if f.Kind == "github_advisory" {
		table = "protection_advisories"
	}
	tag, err := tx.Exec(ctx, "UPDATE public."+table+" SET triage_status=$1,triage_resolution=$2,triaged_at=$3,updated_at=clock_timestamp() WHERE id=$4 AND updated_at=$5", f.Triage.Status, f.Triage.Resolution, triagedAt(f.Triage.Status), r.ID, old.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return storage.ErrConflict
	}
	if f.Triage.Status == "resolved" && f.Triage.Resolution != nil && *f.Triage.Resolution == "accepted_risk" && (before.Triage.Resolution == nil || *before.Triage.Resolution != "accepted_risk") && typ != "web_app" && typ != "package" {
		return enqueue(ctx, tx, p, f, "finding_accepted", "")
	}
	return nil
}
func triagedAt(status string) any {
	if status == "new" {
		return nil
	}
	return time.Now().UTC()
}
func enqueue(ctx context.Context, tx pgx.Tx, p storage.Principal, f contracts.Finding, event, target string) error {
	if f.Kind == "package_red_team" {
		return nil
	}
	var report any = f.ReportID
	if f.Kind == "github_advisory" {
		report = nil
	}
	_, err := tx.Exec(ctx, "INSERT INTO security_graph.app_effects(organization_id,event_type,finding_id,finding_kind,report_id,title,repository) VALUES($1,$2,$3,$4,$5,$6,$7)", p.OrganizationID, event, f.ID, f.Kind, report, f.Title, target)
	return err
}

var _ postgres.Native = (*Adapter)(nil)
