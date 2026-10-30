package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// Real CLI subprocesses communicate with the official MCP client over pipes and
// persist complete workflows to PostgreSQL. No in-memory transport or mock store.
func TestStdioPostgresWorkflow(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("run make integration to start real PostgreSQL")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil || !strings.Contains(cfg.ConnConfig.Database, "test") {
		t.Fatal("TEST_DATABASE_URL must name an explicitly disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var originalCredentials int
	if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.credentials WHERE organization_id='local'").Scan(&originalCredentials); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "security-graph")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/security-graph")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "DATABASE_URL=") && !strings.HasPrefix(entry, "STORAGE_BACKEND=") {
			env = append(env, entry)
		}
	}
	env = append(env, "DATABASE_URL="+url, "STORAGE_BACKEND=postgres")
	connect := func(t *testing.T, protocol string, args ...string) (*mcp.ClientSession, func()) {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, append([]string{"stdio"}, args...)...)
		cmd.Env = env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		c := mcp.NewClient(&mcp.Implementation{Name: "stdio-integration", Version: "test"}, nil)
		session, err := c.Connect(ctx, &mcp.CommandTransport{Command: cmd}, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
		if err != nil {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
			t.Fatalf("connect CLI over stdio: %v", err)
		}
		closed := false
		close := func() {
			t.Helper()
			if closed {
				return
			}
			closed = true
			start := time.Now()
			if err := session.Close(); err != nil {
				t.Errorf("close stdio: %v", err)
			}
			if cmd.ProcessState == nil || !cmd.ProcessState.Success() || time.Since(start) > 3*time.Second {
				t.Errorf("stdio did not exit cleanly on EOF: %s", stderr.String())
			}
		}
		t.Cleanup(close)
		return session, close
	}
	session, close := connect(t, "2026-07-28")
	t.Run("discovery and mandatory intent", func(t *testing.T) {
		tools, err := session.ListTools(ctx, nil)
		if err != nil || len(tools.Tools) < 10 {
			t.Fatalf("discover tools: %v", err)
		}
		for _, tool := range tools.Tools {
			encoded, _ := json.Marshal(tool.InputSchema)
			var schema struct{ Required []string }
			if err := json.Unmarshal(encoded, &schema); err != nil || !slices.Contains(schema.Required, "intent") {
				t.Errorf("%s does not require intent", tool.Name)
			}
		}
		for _, intent := range []any{nil, "", "   ", strings.Repeat("a", 501), 42} {
			stdioRejected(t, ctx, session, "list_findings", map[string]any{"intent": intent})
		}
		stdioRejected(t, ctx, session, "list_findings", map[string]any{})
		stdioRejected(t, ctx, session, "list_findings", map[string]any{"intent": "Attempt to choose a tenant through tool arguments.", "organization_id": "another-organization"})
	})
	assetArgs := writeArgs()
	assetArgs["asset_id"] = "stdio/" + uuid.NewString()
	assetArgs["name"], assetArgs["type"], assetArgs["locator"] = "Local payments", "repository", "https://github.com/example/payments"
	asset := stdioRecord(t, ctx, session, "create_asset", assetArgs)
	t.Run("empty list is readable by legacy clients", func(t *testing.T) {
		legacy, _ := connect(t, "2025-11-25", "--org", "empty-list-"+uuid.NewString())
		result, err := legacy.CallTool(ctx, &mcp.CallToolParams{Name: "list_assets", Arguments: map[string]any{"intent": "Discover assets in an empty standalone workspace."}})
		if err != nil || result.IsError || result.StructuredContent != nil || len(result.Content) != 1 {
			t.Fatalf("legacy empty asset discovery returned an invalid result: %v", err)
		}
		content, ok := result.Content[0].(*mcp.TextContent)
		var rows []storage.Record
		if !ok || json.Unmarshal([]byte(content.Text), &rows) != nil || len(rows) != 0 {
			t.Fatal("legacy empty asset list must contain a JSON array text fallback")
		}
	})
	reportArgs := writeArgs()
	reportArgs["asset_id"], reportArgs["type"], reportArgs["target"] = asset.ID, "repository", "example/payments@fixture"
	report := stdioRecord(t, ctx, session, "create_report", reportArgs)
	submit := writeArgs()
	submit["report_id"], submit["finding"] = report.ID, finding("stdio-tenant-isolation")
	saved := stdioRecord(t, ctx, session, "submit_finding", submit)
	if retry := stdioRecord(t, ctx, session, "submit_finding", submit); retry.ID != saved.ID {
		t.Fatal("idempotent retry produced a different finding")
	}
	t.Run("shared finding template and assessment completion", func(t *testing.T) {
		bad := finding("invalid-stdio-template")
		bad.GitHubAdvisory.Description = "Unstructured text"
		invalid := writeArgs()
		invalid["report_id"], invalid["finding"] = report.ID, bad
		stdioRejected(t, ctx, session, "submit_finding", invalid)
		finish := writeArgs()
		finish["report_id"], finish["expected_version"], finish["status"] = report.ID, report.Version, "succeeded"
		report = stdioRecord(t, ctx, session, "finish_report", finish)
		var data contracts.Report
		if err := json.Unmarshal(report.Data, &data); err != nil || data.Status != "in_review" {
			t.Fatalf("unresolved assessment must enter review: %v", err)
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_context", Arguments: map[string]any{
			"intent": "Follow the persisted asset, assessment and finding.", "entity_id": asset.ID, "depth": 3, "limit": 100,
		}})
		if err != nil || result.IsError {
			t.Fatalf("get context: %v", err)
		}
		encoded, _ := json.Marshal(result.StructuredContent)
		if !bytes.Contains(encoded, []byte(saved.ID)) {
			t.Fatal("stdio context omitted the persisted finding")
		}
	})
	t.Run("list results across protocol versions", func(t *testing.T) {
		for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
			reader, _ := connect(t, protocol, "--scopes", "read,export")
			for _, entry := range []struct{ tool, id string }{{"list_assets", asset.ID}, {"list_reports", report.ID}, {"list_findings", saved.ID}, {"list_changes", saved.ID}} {
				args := map[string]any{"intent": "Reuse persisted assessment context from a new client session."}
				if entry.tool == "list_changes" {
					args["after"], args["limit"] = 0, 100
				}
				result, err := reader.CallTool(ctx, &mcp.CallToolParams{Name: entry.tool, Arguments: args})
				if err != nil || result.IsError || len(result.Content) != 1 {
					t.Fatalf("%s %s: %v", protocol, entry.tool, err)
				}
				content, ok := result.Content[0].(*mcp.TextContent)
				var rows []json.RawMessage
				if !ok || json.Unmarshal([]byte(content.Text), &rows) != nil || !strings.Contains(content.Text, entry.id) {
					t.Fatalf("%s %s lost persisted context", protocol, entry.tool)
				}
				if protocol == "2025-11-25" && result.StructuredContent != nil {
					t.Fatalf("%s returned a non-object structuredContent to a legacy client", entry.tool)
				}
				if protocol == "2026-07-28" {
					encoded, _ := json.Marshal(result.StructuredContent)
					var structured, text any
					if json.Unmarshal(encoded, &structured) != nil || json.Unmarshal([]byte(content.Text), &text) != nil || !reflect.DeepEqual(structured, text) {
						t.Fatalf("%s modern structured and text results differ", entry.tool)
					}
				}
			}
		}
	})
	t.Run("least privilege and fixed local identity", func(t *testing.T) {
		update := writeArgs()
		update["finding_id"], update["expected_version"] = saved.ID, saved.Version
		update["triage_status"], update["triage_resolution"] = "resolved", "fixed"
		stdioRejected(t, ctx, session, "update_finding_triage", update)
		review := writeArgs()
		review["report_id"], review["expected_version"], review["status"] = report.ID, report.Version, "completed"
		stdioRejected(t, ctx, session, "update_report_review_status", review)
		stdioRejected(t, ctx, session, "list_changes", map[string]any{"intent": "Attempt export without a grant.", "after": 0, "limit": 100})
		var org, actor string
		if err := db.Pool.QueryRow(ctx, "SELECT organization_id,actor_id FROM security_graph.changes WHERE entity_id=$1 LIMIT 1", saved.ID).Scan(&org, &actor); err != nil || org != "local" || actor != "local-agent" {
			t.Fatalf("local identity not retained in audit: %v", err)
		}
		other, _ := connect(t, "2026-07-28", "--org", "stdio-other-"+uuid.NewString())
		stdioRejected(t, ctx, other, "get_finding", map[string]any{"intent": "Attempt cross-organization access.", "finding_id": saved.ID})
		limited, _ := connect(t, "2026-07-28", "--assets", "different-asset", "--scopes", "read")
		stdioRejected(t, ctx, limited, "get_finding", map[string]any{"intent": "Attempt access outside configured assets.", "finding_id": saved.ID})
		stdioRejected(t, ctx, limited, "create_report", reportArgs)
	})
	close()
	t.Run("persistence and legacy clients across process restarts", func(t *testing.T) {
		restarted, _ := connect(t, "2025-11-25")
		if got := stdioRecord(t, ctx, restarted, "get_finding", map[string]any{"intent": "Read the finding after restarting the local process.", "finding_id": saved.ID}); got.ID != saved.ID {
			t.Fatal("finding did not survive process restart")
		}
		if got := stdioRecord(t, ctx, restarted, "submit_finding", submit); got.ID != saved.ID {
			t.Fatal("idempotency did not survive process restart")
		}
	})
	t.Run("explicit reviewer grant completes the report", func(t *testing.T) {
		reviewer, _ := connect(t, "2026-07-28", "--actor", "local-reviewer", "--assets", asset.ID, "--scopes", "read,disposition")
		update := writeArgs()
		update["finding_id"], update["expected_version"] = saved.ID, saved.Version
		update["triage_status"], update["triage_resolution"] = "resolved", "fixed"
		stdioRecord(t, ctx, reviewer, "update_finding_triage", update)
		got := stdioRecord(t, ctx, reviewer, "get_report", map[string]any{"intent": "Verify completion after resolving the last finding.", "report_id": report.ID})
		var data contracts.Report
		if err := json.Unmarshal(got.Data, &data); err != nil || data.Status != "completed" {
			t.Fatal("resolving the last finding did not complete the report")
		}
	})
	t.Run("stdio creates no credential and HTTP still requires authentication", func(t *testing.T) {
		var count int
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.credentials WHERE organization_id='local'").Scan(&count); err != nil || count != originalCredentials {
			t.Fatalf("stdio created credentials: count=%d err=%v", count, err)
		}
		api := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "integration"))
		defer api.Close()
		if _, err := (client{url: api.URL}).rpc("tools/list", map[string]any{}); err == nil {
			t.Fatal("keyless stdio enabled unauthenticated HTTP")
		}
	})
	t.Run("invalid startup configuration and native mode fail closed", func(t *testing.T) {
		for _, timeout := range []string{"invalid", "0", "500ms", "121s"} {
			cmd := exec.CommandContext(ctx, binary, "stdio")
			cmd.Env = append(append([]string{}, env...), "CLASSIFIER_COMMAND=python", "CLASSIFIER_TIMEOUT="+timeout)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if output, err := cmd.Output(); err == nil || len(output) != 0 || !strings.Contains(stderr.String(), "CLASSIFIER_TIMEOUT must be") {
				t.Fatalf("invalid classifier timeout accepted or misdiagnosed: %s", timeout)
			}
		}
		for _, args := range [][]string{{"--scopes", "admin"}, {"--org", " "}, {"--assets", ","}, {"unexpected-argument"}} {
			cmd := exec.CommandContext(ctx, binary, append([]string{"stdio"}, args...)...)
			cmd.Env = env
			if output, err := cmd.Output(); err == nil || len(output) != 0 {
				t.Fatalf("invalid stdio configuration succeeded or wrote to stdout: %v", args)
			}
		}
		cmd := exec.CommandContext(ctx, binary, "stdio")
		cmd.Env = []string{"STORAGE_BACKEND=superagent"}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if output, err := cmd.Output(); err == nil || len(output) != 0 || !strings.Contains(stderr.String(), "standalone storage only") {
			t.Fatal("native mode did not refuse keyless stdio before database access")
		}
	})
}

func stdioRejected(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, args any) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err == nil && !result.IsError {
		t.Fatalf("%s unexpectedly accepted unauthorized or invalid input", name)
	}
}

func stdioRecord(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, args any) storage.Record {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || result.IsError {
		t.Fatalf("%s failed: %v", name, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var record storage.Record
	if err := json.Unmarshal(encoded, &record); err != nil || record.ID == "" {
		t.Fatalf("%s did not return a record: %v", name, err)
	}
	return record
}
