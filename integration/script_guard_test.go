package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/superagent"
)

// Real MCP and the actual App schema. The App suite additionally exercises
// source validation, completion fencing and the forwarding Next MCP endpoint.
func TestScriptGuardNativeReview(t *testing.T) {
	address := os.Getenv("TEST_APP_DATABASE_URL")
	if address == "" {
		t.Skip("requires disposable local App database with script_guard_security_graph migration")
	}
	cfg, err := pgxpool.ParseConfig(address)
	if err != nil || !strings.Contains(cfg.ConnConfig.Database, "test") || (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") {
		t.Fatal("requires explicitly disposable local test database")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var installed bool
	if err = admin.QueryRow(ctx, "SELECT to_regclass('security_graph.script_guard_finding_records') IS NOT NULL").Scan(&installed); err != nil || !installed {
		t.Fatal("apply App Script Guard graph migration first", err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, other, site, version := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	token, otherToken := "sk_live_"+uuid.NewString(), "sk_live_"+uuid.NewString()
	exec("INSERT INTO public.organizations(id,name,slug) VALUES($1::uuid,'Script Graph test',$1::text),($2::uuid,'Foreign Script Graph test',$2::text)", org, other)
	defer exec("DELETE FROM public.organizations WHERE id=ANY($1::uuid[])", []string{org, other})
	for organization, key := range map[string]string{org: token, other: otherToken} {
		h := sha256.Sum256([]byte(key))
		exec("INSERT INTO public.api_keys(organization_id,key_hash,key_prefix) VALUES($1,$2,$3)", organization, hex.EncodeToString(h[:]), key[:12])
	}
	exec("INSERT INTO public.dns_sites(id,organization_id,hostname,zone_id,zone_name,monitoring_enabled) VALUES($1,$2,'graph-script.example.org',$3,'example.org',true)", site, org, strings.Repeat("a", 32))
	exec("INSERT INTO public.dns_script_versions(id,site_id,organization_id,script_url,sha256,byte_size,storage_path,content_type) VALUES($1,$2,$3,'https://cdn.example.org/widget.js',$4,50,'fixture-only','application/javascript')", version, site, org, strings.Repeat("a", 64))
	evidence := `[{"title":"Form input collection","severity":"high","explanation":"Source review found form input sent to a collection endpoint.","independently_reviewed":true,"evidence":[{"start_line":1,"end_line":1,"excerpt":"collect(input.value)"}]}]`
	exec("UPDATE public.dns_script_scans SET status='completed',verdict='suspicious',findings=$2,summary='Source-only script assessment',limitations='[\"Runtime not executed\"]',completed_at=clock_timestamp() WHERE version_id=$1", version, evidence)
	var findingID, scanID string
	if err := admin.QueryRow(ctx, "SELECT id::text,scan_id::text FROM security_graph.script_guard_findings WHERE organization_id=$1", org).Scan(&findingID, &scanID); err != nil {
		t.Fatal(err)
	}
	store, err := postgres.Open(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = superagent.Enable(ctx, store); err != nil {
		t.Fatal(err)
	}
	eng := &engine.Engine{Store: store}
	principal, err := store.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	neighborhood, err := eng.Context(ctx, principal, "Read the affected site and captured version.", findingID, 2, 100)
	if err != nil {
		t.Fatal("script neighborhood", err)
	}
	if len(neighborhood.Records) < 5 {
		t.Fatal("missing site or script relationships", neighborhood)
	}
	http := httptest.NewServer(server.Handler(eng, store, "script-guard-test"))
	defer http.Close()
	c, foreign := client{http.URL, token}, client{http.URL, otherToken}
	get := func() contracts.Finding {
		t.Helper()
		r := c.record(t, "get_finding", map[string]any{"intent": "Read source evidence.", "finding_id": findingID})
		var f contracts.Finding
		if err := json.Unmarshal(r.Data, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	initial := c.record(t, "get_finding", map[string]any{"intent": "Read source evidence.", "finding_id": findingID})
	if get().Kind != "script_guard" || get().Triage.VerificationStatus == nil || *get().Triage.VerificationStatus != "heuristic" {
		t.Fatal("source review was promoted to runtime verification")
	}
	failure(t, foreign.call(t, "get_finding", map[string]any{"intent": "Check isolation.", "finding_id": findingID}))
	update := writeArgs()
	update["finding_id"], update["expected_version"], update["triage_status"], update["triage_resolution"] = findingID, initial.Version, "resolved", "accepted_risk"
	resolved := c.record(t, "update_finding_triage", update)
	if resolved.Version <= initial.Version || get().Triage.Resolution == nil || *get().Triage.Resolution != "accepted_risk" {
		t.Fatal("resolution not persisted")
	}
	if c.record(t, "update_finding_triage", update).Version != resolved.Version {
		t.Fatal("replay changed version")
	}
	stale := writeArgs()
	stale["finding_id"], stale["expected_version"], stale["triage_status"] = findingID, initial.Version, "new"
	failure(t, c.call(t, "update_finding_triage", stale))
	report := c.record(t, "get_report", map[string]any{"intent": "Read derived review completion.", "report_id": scanID})
	var rep contracts.Report
	_ = json.Unmarshal(report.Data, &rep)
	if rep.Type != "script_guard" || rep.Status != "completed" {
		t.Fatal("finding resolution did not complete review")
	}
	forbidden := writeArgs()
	forbidden["report_id"], forbidden["expected_version"], forbidden["status"] = scanID, report.Version, "in_review"
	failure(t, c.call(t, "update_report_review_status", forbidden))
	reopen := writeArgs()
	reopen["finding_id"], reopen["expected_version"], reopen["triage_status"] = findingID, resolved.Version, "in_review"
	c.record(t, "update_finding_triage", reopen)
	if get().Triage.Resolution != nil {
		t.Fatal("reopening retained accepted risk")
	}
	report = c.record(t, "get_report", map[string]any{"intent": "Read reopened review.", "report_id": scanID})
	_ = json.Unmarshal(report.Data, &rep)
	if rep.Status != "in_review" {
		t.Fatal("report did not reopen")
	}
	var source string
	if err := admin.QueryRow(ctx, "SELECT findings::text FROM public.dns_script_scans WHERE id=$1", scanID).Scan(&source); err != nil {
		t.Fatal(err)
	}
	var before, after any
	_ = json.Unmarshal([]byte(evidence), &before)
	_ = json.Unmarshal([]byte(source), &after)
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(after)
	if string(left) != string(right) {
		t.Fatal("disposition changed immutable evidence")
	}
	var copied, changes int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM security_graph.entities WHERE organization_id=$1 AND kind IN ('finding','report')", org).Scan(&copied); err != nil || copied != 0 {
		t.Fatal("native source was duplicated", err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM security_graph.changes WHERE organization_id=$1 AND entity_id=$2 AND operation='update_finding_triage'", org, findingID).Scan(&changes); err != nil || changes != 2 {
		t.Fatal("audit or idempotency lost", changes, err)
	}
	exec("DELETE FROM public.dns_sites WHERE id=$1", site)
	failure(t, c.call(t, "get_finding", map[string]any{"intent": "Verify deleted capture is unavailable.", "finding_id": findingID}))
}
