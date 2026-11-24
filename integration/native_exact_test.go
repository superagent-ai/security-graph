package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/superagent"
)

// Compare real HTTP responses from schema-discovered typed and legacy adapters
// against the same authoritative App data, including mutation readbacks. The
// legacy adapter is initialized while the optional loader is genuinely absent.
func TestNativeExactRecordMCPParity(t *testing.T) {
	address := os.Getenv("TEST_APP_DATABASE_URL")
	if address == "" {
		t.Skip("requires disposable PostgreSQL with the App exact-record migration")
	}
	cfg, err := pgxpool.ParseConfig(address)
	if err != nil || !strings.Contains(cfg.ConnConfig.Database, "test") || (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") {
		t.Fatal("requires an explicitly disposable local test database")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const signature = "security_graph.app_record(text,text,boolean,text[],text[])"
	var installed bool
	if err := admin.QueryRow(ctx, "SELECT to_regprocedure($1) IS NOT NULL", signature).Scan(&installed); err != nil || !installed {
		t.Fatal("apply the App typed_native_graph_record_reads migration first", err)
	}
	// Prefer the existing dedicated Graph runtime for the real HTTP operations.
	// App service_role intentionally lacks Graph's general mutation metadata
	// grants. Minimal App-only test stacks can use their configured administrator.
	runtime := cfg.ConnConfig.User
	var dedicated string
	err = admin.QueryRow(ctx, `SELECT rolname FROM pg_roles WHERE rolbypassrls AND NOT rolsuper
 AND rolname NOT IN ('postgres','service_role','supabase_read_only_user')
 AND has_table_privilege(oid,'security_graph.entities','INSERT')
 AND has_table_privilege(oid,'security_graph.entities','UPDATE')
 AND has_table_privilege(oid,'security_graph.idempotency','SELECT')
 AND has_column_privilege(oid,'public.api_keys','key_hash','SELECT') ORDER BY rolname LIMIT 1`).Scan(&dedicated)
	if err == nil {
		runtime = dedicated
	} else if err != pgx.ErrNoRows {
		t.Fatal(err)
	}
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("role", runtime)
	q.Set("sslmode", "disable")
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	open := func() *postgres.Store {
		t.Helper()
		s, err := postgres.Open(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	legacy, fast := open(), open()
	exec("ALTER FUNCTION " + signature + " RENAME TO app_record_temporarily_unavailable")
	func() {
		defer exec("ALTER FUNCTION security_graph.app_record_temporarily_unavailable(text,text,boolean,text[],text[]) RENAME TO app_record")
		if err := superagent.Enable(ctx, legacy); err != nil {
			t.Fatal(err)
		}
	}()
	if err := superagent.Enable(ctx, fast); err != nil {
		t.Fatal(err)
	}
	org, other, installation, repo, scan, findingID, report, advisory := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	token, otherToken := "sk_live_"+uuid.NewString(), "sk_live_"+uuid.NewString()
	exec("INSERT INTO public.organizations(id,name,slug) VALUES($1::uuid,'Exact read fixture',$1::text),($2::uuid,'Other exact tenant',$2::text)", org, other)
	t.Cleanup(func() {
		for _, table := range []string{"changes", "entities", "idempotency", "app_effects", "native_report_origins"} {
			exec("DELETE FROM security_graph."+table+" WHERE organization_id::text=ANY($1::text[])", []string{org, other})
		}
		exec("DELETE FROM public.protection_installations WHERE installation_id=$1", installation)
		exec("DELETE FROM public.organizations WHERE id=ANY($1::uuid[])", []string{org, other})
	})
	for organization, key := range map[string]string{org: token, other: otherToken} {
		h := sha256.Sum256([]byte(key))
		exec("INSERT INTO public.api_keys(organization_id,key_hash,key_prefix) VALUES($1,$2,$3)", organization, hex.EncodeToString(h[:]), key[:12])
	}
	exec("INSERT INTO public.protection_installations(installation_id,organization_id,account_id,account_login,account_type) VALUES($1,$2,$1,'exact','Organization')", installation, org)
	exec("INSERT INTO public.protection_repositories(repository_id,organization_id,installation_id,owner,name,full_name) VALUES($1,$2,$3,'exact',$1,'exact/'||$1)", repo, org, installation)
	exec("INSERT INTO public.protection_scans(id,repository_id,installation_id,pull_number,head_sha,base_sha,scan_type,status,check_name) VALUES($1,$2,$3,1,'head','base','pr_scan','completed','Exact fixture')", scan, repo, installation)
	exec("INSERT INTO public.protection_findings(id,scan_id,repository_id,pull_number,head_sha,category,severity,title,evidence,recommendation,fingerprint) VALUES($1::uuid,$2,$3,1,'head','security','high','Exact PR fixture','Evidence','Fix',$1::text)", findingID, scan, repo)
	exec("INSERT INTO public.repository_red_team_reports(id,organization_id,repo,status,agent_status) VALUES($1,$2,$3,'in_review','completed')", report, org, "exact/"+repo)
	exec("INSERT INTO public.repository_red_team_advisories(id,report_id,title,description,cvss_vector,weakness) VALUES($1,$2,'Exact repository fixture','Evidence','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','CWE-862')", advisory, report)
	exec("INSERT INTO public.protection_finding_feedback(repository_id,pull_number,finding_fingerprint,finding_body,replies,dismissed_by) VALUES($1,1,$2,'Review context','[{\"body\":\"Preserve feedback\"}]','maintainer')", repo, findingID)
	external := uuid.NewString()
	exec("INSERT INTO security_graph.entities(organization_id,id,kind,asset_id,version,data) VALUES($1,$2,'asset',$2,1,'{\"name\":\"External asset\",\"type\":\"repository\"}')", org, external)
	oldServer := httptest.NewServer(server.Handler(&engine.Engine{Store: legacy}, legacy, "legacy-schema"))
	defer oldServer.Close()
	newServer := httptest.NewServer(server.Handler(&engine.Engine{Store: fast}, fast, "typed-schema"))
	defer newServer.Close()
	oldClient, newClient := client{oldServer.URL, token}, client{newServer.URL, token}
	compare := func(tool string, args map[string]any) {
		t.Helper()
		if _, ok := args["intent"]; !ok {
			args["intent"] = "Verify exact native record and mutation parity over real HTTP."
		}
		a, b := oldClient.call(t, tool, args), newClient.call(t, tool, args)
		if a.Result.IsError || b.Result.IsError || len(a.Error) > 0 || len(b.Error) > 0 {
			t.Fatalf("%s %v: legacy=%s typed=%s", tool, args, a.Result.Content, b.Result.Content)
		}
		var av, bv any
		if err := json.Unmarshal(a.Result.Structured, &av); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b.Result.Structured, &bv); err != nil || !reflect.DeepEqual(av, bv) {
			t.Fatalf("%s response changed: %s vs %s (%v)", tool, a.Result.Structured, b.Result.Structured, err)
		}
	}
	compare("get_report", map[string]any{"report_id": report})
	compare("get_report", map[string]any{"report_id": scan})
	for _, id := range []string{findingID, advisory, "pr-feedback:" + repo + ":1:" + findingID} {
		compare("get_finding", map[string]any{"finding_id": id})
	}
	compare("get_context", map[string]any{"entity_id": findingID, "depth": 2, "limit": 100})
	commentArgs := writeArgs()
	commentArgs["finding_id"], commentArgs["body"] = findingID, "Preserve discussion on exact read."
	comment := newClient.record(t, "create_finding_comment", commentArgs)
	for _, id := range []string{findingID, "comment:" + comment.ID, "link:" + scan + ":targets", "repository:exact/" + repo, external} {
		compare("get_context", map[string]any{"entity_id": id, "depth": 0, "limit": 1})
	}
	current := newClient.record(t, "get_finding", map[string]any{"intent": "Read current version before disposition.", "finding_id": findingID})
	update := writeArgs()
	update["finding_id"], update["expected_version"], update["triage_status"] = findingID, current.Version, "in_review"
	// Removing only the legacy projection grant proves the actual HTTP path
	// uses the typed loader, including the PR optimistic-version comparison.
	runtimeIdentifier := pgx.Identifier{runtime}.Sanitize()
	if dedicated != "" {
		exec("REVOKE SELECT ON security_graph.app_records FROM " + runtimeIdentifier)
	}
	func() {
		if dedicated != "" {
			defer exec("GRANT SELECT ON security_graph.app_records TO " + runtimeIdentifier)
		}
		newClient.record(t, "update_finding_triage", update)
		if dedicated != "" {
			failure(t, oldClient.call(t, "get_finding", map[string]any{"intent": "Exercise old schema fallback.", "finding_id": findingID}))
		}
	}()
	compare("get_finding", map[string]any{"finding_id": findingID})
	compare("get_context", map[string]any{"entity_id": findingID, "depth": 0, "limit": 1})
	// Idempotent replay works across adapter versions, while a distinct stale
	// write retains the existing optimistic-version rejection.
	compare("update_finding_triage", update)
	stale := writeArgs()
	stale["finding_id"], stale["expected_version"], stale["triage_status"] = findingID, current.Version, "new"
	failure(t, newClient.call(t, "update_finding_triage", stale))
	for _, id := range []string{uuid.NewString(), "not-a-uuid", strings.ToUpper(findingID), strings.ReplaceAll(findingID, "-", "")} {
		failure(t, newClient.call(t, "get_finding", map[string]any{"intent": "Check unknown ID behavior.", "finding_id": id}))
	}
	failure(t, (client{newServer.URL, otherToken}).call(t, "get_finding", map[string]any{"intent": "Check organization isolation.", "finding_id": findingID}))
}
