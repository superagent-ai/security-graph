package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/demoseed"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// The real CLI starts its own authenticated HTTP MCP server, writes complete
// workflows to real PostgreSQL, and is then verified through another MCP server.
func TestDemoSeedPostgresWorkflow(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("run make integration to start real PostgreSQL")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || !strings.Contains(config.ConnConfig.Database, "test") {
		t.Fatal("TEST_DATABASE_URL must name an explicitly disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "security-graph")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/security-graph")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build seed CLI: %v: %s", err, output)
	}
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "DATABASE_URL=") && !strings.HasPrefix(v, "STORAGE_BACKEND=") {
			env = append(env, v)
		}
	}
	env = append(env, "DATABASE_URL="+databaseURL, "STORAGE_BACKEND=postgres")
	org := "demo-test-" + uuid.NewString()
	run := func(workers string) demoseed.Summary {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, "seed-demo", "--org", org, "--findings", "72", "--assets", "12", "--reports", "16", "--workers", workers)
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("seed CLI: %v: %s", err, stderr.String())
		}
		var summary demoseed.Summary
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("seed result: %v", err)
		}
		if bytes.Contains(stdout.Bytes(), []byte("sg_")) || bytes.Contains(stderr.Bytes(), []byte("sg_")) {
			t.Fatal("seed logged a credential")
		}
		return summary
	}
	first := run("4")
	if first.Organization != org || first.Findings != 72 || first.Assets != 12 || first.Reports != 16 || first.Agents != 8 || first.Classifications != 72 || first.AssetRelationships < 20 {
		t.Fatalf("unexpected seed manifest: %+v", first)
	}
	token := "sg_" + uuid.NewString()
	reader := storage.Principal{OrganizationID: org, ActorID: "independent-demo-reader", AllAssets: true, Scopes: []string{"read", "export"}}
	if err = db.IssueKey(ctx, token, reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "seed-integration"))
	defer api.Close()
	c := client{url: api.URL, token: token}
	listAll := func(kind string) []storage.Record {
		t.Helper()
		result := []storage.Record{}
		after := ""
		for {
			out := c.call(t, "list_"+kind, map[string]any{"intent": "Independently inspect synthetic seed records through authenticated MCP.", "limit": 100, "after": after})
			if out.Result.IsError || len(out.Error) > 0 {
				t.Fatalf("seed read rejected: %s", out.Result.Content)
			}
			var page []storage.Record
			if json.Unmarshal(out.Result.Structured, &page) != nil {
				t.Fatal("invalid seed list response")
			}
			result = append(result, page...)
			if len(page) < 100 {
				return result
			}
			after = page[len(page)-1].ID
		}
	}
	findings := listAll("findings")
	assets := listAll("assets")
	reports := listAll("reports")
	if len(findings) != 72 || len(assets) != 12 || len(reports) != 16 {
		t.Fatalf("seed records: findings=%d assets=%d reports=%d", len(findings), len(assets), len(reports))
	}
	agents := map[string]bool{}
	severities := map[string]bool{}
	triage := map[string]bool{}
	resolutions := map[string]bool{}
	reportStates := map[string]bool{}
	reportKinds := map[string]bool{}
	classifications := 0
	for _, r := range findings {
		var f contracts.Finding
		if err = json.Unmarshal(r.Data, &f); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(f.Title, "[DEMO]") || !strings.Contains(f.Source, "demo-seed/") || !strings.Contains(f.Submission.Details, "SYNTHETIC") || !strings.Contains(f.Submission.ProposedPatch.Validation.Tests[0].Result, "not executed") {
			t.Fatal("demo data is not clearly attributed and labeled")
		}
		if err = f.Submission.Validate(); err != nil {
			t.Fatalf("seed violated finding contract: %v", err)
		}
		if f.Triage.VerificationStatus != nil {
			t.Fatal("synthetic claims were presented as verified findings")
		}
		agents[f.Source] = true
		severities[f.Severity] = true
		triage[f.Triage.Status] = true
		if f.Triage.Resolution != nil {
			resolutions[*f.Triage.Resolution] = true
		}
		classified := c.record(t, "get_finding_classification", map[string]any{"intent": "Verify a real seeded catalog assignment.", "finding_id": r.ID})
		if classified.Kind != "classification" {
			t.Fatal("missing seeded classification")
		}
		classifications++
	}
	for _, r := range reports {
		var report contracts.Report
		_ = json.Unmarshal(r.Data, &report)
		reportStates[report.Status] = true
		reportKinds[report.Type] = true
	}
	if len(agents) != 8 || len(severities) != 4 || len(triage) != 3 || len(resolutions) != 4 || len(reportStates) != 4 || len(reportKinds) != 4 || classifications != 72 {
		t.Fatalf("seed did not exercise varied agent and lifecycle data: agents=%d severity=%d triage=%d resolutions=%d reports=%d report types=%d", len(agents), len(severities), len(triage), len(resolutions), len(reportStates), len(reportKinds))
	}
	var active int
	if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.credentials WHERE organization_id=$1 AND actor_id LIKE 'demo-seed/%' AND revoked_at IS NULL", org).Scan(&active); err != nil || active != 0 {
		t.Fatal("temporary seed keys remained active")
	}
	var entitiesBefore, changesBefore int
	if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.entities WHERE organization_id=$1", org).Scan(&entitiesBefore); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.changes WHERE organization_id=$1", org).Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	second := run("1")
	if first != second {
		t.Fatal("worker count changed retry identity")
	}
	var entitiesAfter, changesAfter int
	_ = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.entities WHERE organization_id=$1", org).Scan(&entitiesAfter)
	_ = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.changes WHERE organization_id=$1", org).Scan(&changesAfter)
	if entitiesBefore != entitiesAfter || changesBefore != changesAfter {
		t.Fatal("rerun duplicated records, mutations, or audit events")
	}
	// A separate principal cannot see the dummy records or traverse their assets.
	otherToken := "sg_" + uuid.NewString()
	other := reader
	other.OrganizationID = "other-" + uuid.NewString()
	if err = db.IssueKey(ctx, otherToken, other, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	failure(t, (client{url: api.URL, token: otherToken}).call(t, "get_context", map[string]any{"intent": "Confirm seeded data stays in its demo organization.", "entity_id": assets[0].ID, "depth": 1, "limit": 100}))
	for _, args := range [][]string{{"--org", "production"}, {"--findings", "0"}, {"--workers", "17"}} {
		cmd := exec.CommandContext(ctx, binary, append([]string{"seed-demo"}, args...)...)
		cmd.Env = env
		if err := cmd.Run(); err == nil {
			t.Fatal("seed accepted unsafe organization or invalid limits")
		}
	}
	cmd := exec.CommandContext(ctx, binary, "seed-demo")
	cmd.Env = append(env, "STORAGE_BACKEND=superagent")
	if err := cmd.Run(); err == nil {
		t.Fatal("seed accepted native app storage")
	}
}
