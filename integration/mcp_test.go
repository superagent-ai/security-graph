// These checks use real PostgreSQL and a real HTTP MCP transport. No mocks.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type rpcResult struct {
	Result struct {
		IsError    bool            `json:"isError"`
		Content    json.RawMessage `json:"content"`
		Structured json.RawMessage `json:"structuredContent"`
		Tools      []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required []string `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	} `json:"result"`
	Error json.RawMessage `json:"error"`
}
type client struct{ url, token string }

func (c client) rpc(method string, params any) (rpcResult, error) {
	return c.rpcVersion(context.Background(), method, params, "2025-11-25")
}

func (c client) rpcContext(ctx context.Context, method string, params any) (rpcResult, error) {
	// HTTP disconnect cancellation is defined by the modern protocol.
	return c.rpcVersion(ctx, method, params, "2026-07-28")
}

func (c client) rpcVersion(ctx context.Context, method string, params any, protocol string) (rpcResult, error) {
	if protocol >= "2026-07-28" {
		fields := map[string]any{}
		for key, value := range params.(map[string]any) {
			fields[key] = value
		}
		fields["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    protocol,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "resident-integration", "version": "1"},
		}
		params = fields
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/mcp", bytes.NewReader(body))
	if err != nil {
		return rpcResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", protocol)
	if protocol >= "2026-07-28" {
		req.Header.Set("Mcp-Method", method)
		if name, ok := params.(map[string]any)["name"].(string); ok {
			req.Header.Set("Mcp-Name", name)
		}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	timeout := 35 * time.Second
	if call, ok := params.(map[string]any); method == "tools/call" && ok && call["name"] == "classify_finding" {
		timeout = 140 * time.Second
	}
	res, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return rpcResult{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return rpcResult{}, err
	}
	if res.StatusCode != 200 {
		return rpcResult{}, fmt.Errorf("HTTP %d: %s", res.StatusCode, b)
	}
	var out rpcResult
	err = json.Unmarshal(b, &out)
	// Legacy clients recover non-object results from their JSON text fallback.
	if err == nil && len(out.Result.Structured) == 0 {
		var content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(out.Result.Content, &content) == nil && len(content) == 1 && content[0].Type == "text" && json.Valid([]byte(content[0].Text)) {
			out.Result.Structured = json.RawMessage(content[0].Text)
		}
	}
	return out, err
}
func (c client) call(t *testing.T, name string, args any) rpcResult {
	t.Helper()
	out, err := c.rpc("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func (c client) record(t *testing.T, name string, args any) storage.Record {
	t.Helper()
	out := c.call(t, name, args)
	if out.Result.IsError || len(out.Error) > 0 {
		t.Fatalf("%s failed: error=%s content=%s", name, out.Error, out.Result.Content)
	}
	var r storage.Record
	if err := json.Unmarshal(out.Result.Structured, &r); err != nil {
		t.Fatalf("%s decode: %v; %s", name, err, out.Result.Structured)
	}
	if r.ID == "" {
		t.Fatalf("%s returned no record: %s", name, out.Result.Structured)
	}
	return r
}
func failure(t *testing.T, r rpcResult) {
	t.Helper()
	if !r.Result.IsError && len(r.Error) == 0 {
		t.Fatalf("expected rejection, got %s", r.Result.Structured)
	}
}
func writeArgs() map[string]any {
	return map[string]any{"intent": "Investigate the integration fixture authorization vulnerability.", "idempotency_key": uuid.NewString()}
}
func finding(id string) contracts.Submission {
	return contracts.Submission{ID: id, Title: "Missing tenant check", Severity: "high", CWEIDs: []string{"CWE-862"}, AffectedFiles: []string{"handler.go"}, Summary: "A tenant can read another tenant's records.", Impact: "Cross-tenant record disclosure.", Details: "The handler does not compare tenant identifiers.", Proof: "A request from tenant A returned tenant B's fixture record.", ExploitPreconditions: []string{"Authenticated tenant account."}, ReproductionSteps: []string{"Request tenant B fixture record as A; observed HTTP 200 and B's record."}, PolicyVerification: contracts.PolicyVerification{DocsReviewed: []contracts.PolicyDocument{{File: "POLICY.md", RelevantExcerpt: "Tenants must be isolated.", Interpretation: "Cross-tenant access is forbidden."}}, InScope: true, Conclusion: "This violates tenant isolation."}, FalsePositiveAnalysis: "No documented cross-tenant sharing exists.", CodeReferences: []contracts.CodeReference{{File: "handler.go", LineStart: 10, LineEnd: 12, Excerpt: "store.Get(id)", Reason: "No tenant predicate."}}, Remediation: "Apply a tenant predicate.", ProposedPatch: contracts.ProposedPatch{Summary: "Check tenant membership.", Diff: "--- a/handler.go\n+++ b/handler.go\n@@ -1 +1 @@\n-store.Get(id)\n+store.GetForTenant(id, tenant)\n", Files: []string{"handler.go"}, Validation: contracts.PatchValidation{Tests: []contracts.ValidationCommand{{Command: "integration tenant-isolation scenario", Result: "Cross-tenant request returns 404."}}}}, GitHubAdvisory: contracts.Advisory{Summary: "Missing tenant check", Severity: "high", CWEIDs: []string{"CWE-862"}, Vulnerabilities: []contracts.Vulnerability{{Package: contracts.Package{Ecosystem: "Go", Name: "example.com/app"}, VulnerableVersionRange: "1.0.0"}}, Description: "## Impact\nCross-tenant disclosure.\n\n## Details\nMissing tenant predicate.\n\n## Policy Verification\nTenant isolation is required.\n\n## Code References\nhandler.go:10-12.\n\n## PoC\nRequest as A returned B's record with HTTP 200.\n\n## Remediation\nUse a tenant predicate."}}
}

func TestMCPPostgresWorkflow(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("run make integration to start real PostgreSQL")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.ConnConfig.Database, "test") {
		t.Fatal("TEST_DATABASE_URL must name an explicitly disposable test database")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx); err != nil {
		t.Fatalf("migration replay: %v", err)
	}
	org := "test-" + uuid.NewString()
	token := "sg_" + uuid.NewString()
	p := storage.Principal{OrganizationID: org, ActorID: "integration-agent", Scopes: []string{"read", "submit", "disposition", "graph:write", "export"}, AllAssets: true}
	if err = db.IssueKey(ctx, token, p, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "integration"))
	defer api.Close()
	c := client{url: api.URL, token: token}
	t.Run("authentication and tool contract", func(t *testing.T) {
		if _, err := (client{url: api.URL, token: "invalid"}).rpc("tools/list", map[string]any{}); err == nil {
			t.Fatal("invalid token accepted")
		}
		out, err := c.rpc("tools/list", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Result.Tools) < 10 {
			t.Fatalf("missing tools: %+v", out)
		}
		for _, tool := range out.Result.Tools {
			found := false
			for _, name := range tool.InputSchema.Required {
				if name == "intent" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s does not require intent", tool.Name)
			}
		}
		for _, intent := range []any{nil, "", "   ", strings.Repeat("a", 501), 42} {
			failure(t, c.call(t, "list_findings", map[string]any{"intent": intent}))
		}
		failure(t, c.call(t, "list_findings", map[string]any{}))
	})
	assetArgs := writeArgs()
	assetArgs["asset_id"] = "asset-" + uuid.NewString()
	assetArgs["name"] = "Payments"
	assetArgs["type"] = "repository"
	assetArgs["locator"] = "https://github.com/example/payments"
	asset := c.record(t, "create_asset", assetArgs)
	reportArgs := writeArgs()
	reportArgs["asset_id"] = asset.ID
	reportArgs["type"] = "repository"
	reportArgs["target"] = "example/payments@fixture"
	report := c.record(t, "create_report", reportArgs)
	submit := writeArgs()
	submit["report_id"] = report.ID
	submit["finding"] = finding("tenant-isolation")
	var saved storage.Record
	t.Run("durable idempotency under concurrent retries", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 6)
		ids := make(chan string, 6)
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := c.rpc("tools/call", map[string]any{"name": "submit_finding", "arguments": submit})
				if err != nil {
					errs <- err
					return
				}
				if r.Result.IsError || len(r.Error) > 0 {
					errs <- fmt.Errorf("submission failed: %s %s", r.Error, r.Result.Content)
					return
				}
				var record storage.Record
				if err = json.Unmarshal(r.Result.Structured, &record); err != nil {
					errs <- err
					return
				}
				ids <- record.ID
			}()
		}
		wg.Wait()
		close(errs)
		close(ids)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
		first := ""
		for id := range ids {
			if first == "" {
				first = id
			}
			if id != first {
				t.Error("retry created different finding")
			}
		}
		saved = c.record(t, "get_finding", map[string]any{"intent": "Read the saved fixture finding.", "finding_id": first})
		var count int
		if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.entities WHERE organization_id=$1 AND kind='finding'", org).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expected one finding, got %d: %v", count, err)
		}
		changed := map[string]any{}
		for k, v := range submit {
			changed[k] = v
		}
		changed["finding"] = finding("different-finding")
		failure(t, c.call(t, "submit_finding", changed))
	})
	if saved.ID == "" {
		t.Fatal("submission did not produce a finding")
	}
	t.Run("template validation rolls back", func(t *testing.T) {
		a := writeArgs()
		a["report_id"] = report.ID
		bad := finding("invalid-template")
		bad.GitHubAdvisory.Description = "Unstructured text"
		a["finding"] = bad
		failure(t, c.call(t, "submit_finding", a))
		var n int
		_ = db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.entities WHERE organization_id=$1 AND kind='finding'", org).Scan(&n)
		if n != 1 {
			t.Fatal("invalid finding persisted")
		}
	})
	t.Run("finding and report lifecycle", func(t *testing.T) {
		a := writeArgs()
		a["report_id"] = report.ID
		a["expected_version"] = report.Version
		a["status"] = "completed"
		failure(t, c.call(t, "update_report_review_status", a))
		a["idempotency_key"] = uuid.NewString()
		a["status"] = "succeeded"
		report = c.record(t, "finish_report", a)
		var parent contracts.Report
		_ = json.Unmarshal(report.Data, &parent)
		if parent.Status != "in_review" {
			t.Fatalf("unresolved report status %s", parent.Status)
		}
		a = writeArgs()
		a["report_id"] = report.ID
		a["expected_version"] = report.Version
		a["status"] = "completed"
		report = c.record(t, "update_report_review_status", a)
		u := writeArgs()
		u["finding_id"] = saved.ID
		u["expected_version"] = saved.Version
		u["triage_status"] = "resolved"
		failure(t, c.call(t, "update_finding_triage", u))
		u["triage_resolution"] = "accepted_risk"
		saved = c.record(t, "update_finding_triage", u)
		var f contracts.Finding
		_ = json.Unmarshal(saved.Data, &f)
		if f.Triage.Status != "resolved" || f.Triage.Resolution == nil || *f.Triage.Resolution != "accepted_risk" {
			t.Fatal("resolution not retained")
		}
		u["idempotency_key"] = uuid.NewString()
		u["triage_status"] = "new"
		failure(t, c.call(t, "update_finding_triage", u))
		u["expected_version"] = saved.Version
		u["idempotency_key"] = uuid.NewString()
		saved = c.record(t, "update_finding_triage", u)
		_ = json.Unmarshal(saved.Data, &f)
		if f.Triage.Resolution != nil {
			t.Fatal("reopen retained resolution")
		}
		report = c.record(t, "get_report", map[string]any{"intent": "Check report reopened after a finding reopened.", "report_id": report.ID})
		_ = json.Unmarshal(report.Data, &parent)
		if parent.Status != "in_review" {
			t.Fatal("parent did not reopen")
		}
		u["idempotency_key"] = uuid.NewString()
		u["expected_version"] = saved.Version
		u["triage_status"] = "resolved"
		u["triage_resolution"] = "fixed"
		saved = c.record(t, "update_finding_triage", u)
		report = c.record(t, "get_report", map[string]any{"intent": "Check automatic review completion.", "report_id": report.ID})
		_ = json.Unmarshal(report.Data, &parent)
		if parent.Status != "completed" {
			t.Fatal("resolved report did not complete")
		}
	})
	t.Run("graph retrieval and truncation", func(t *testing.T) {
		r := c.call(t, "get_context", map[string]any{"intent": "Follow evidence from application to report and finding.", "entity_id": asset.ID, "depth": 3, "limit": 100})
		if r.Result.IsError || len(r.Error) > 0 {
			t.Fatalf("graph failed: %s %s", r.Error, r.Result.Content)
		}
		var graph engine.ContextResult
		_ = json.Unmarshal(r.Result.Structured, &graph)
		found := false
		for _, r := range graph.Records {
			if r.ID == saved.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("automatic relationships missing: %s", r.Result.Structured)
		}
		r = c.call(t, "get_context", map[string]any{"intent": "Request a deliberately bounded context bundle.", "entity_id": asset.ID, "depth": 3, "limit": 1})
		_ = json.Unmarshal(r.Result.Structured, &graph)
		if !graph.Truncated || len(graph.Records) != 1 {
			t.Fatal("truncation was not explicit")
		}
	})
	t.Run("tenant asset and scope isolation plus revocation", func(t *testing.T) {
		otherToken := "sg_" + uuid.NewString()
		other := p
		other.OrganizationID = "test-other-" + uuid.NewString()
		if err = db.IssueKey(ctx, otherToken, other, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		otherClient := client{url: api.URL, token: otherToken}
		failure(t, otherClient.call(t, "get_finding", map[string]any{"intent": "Probe a finding outside this organization.", "finding_id": saved.ID}))
		a := writeArgs()
		a["asset_id"] = "private-" + uuid.NewString()
		a["name"] = "Private service"
		a["type"] = "application"
		a["locator"] = "https://private.example"
		private := c.record(t, "create_asset", a)
		rel := writeArgs()
		rel["relationship"] = contracts.Relationship{SourceID: asset.ID, TargetID: private.ID, Type: "calls", Provenance: "integration fixture"}
		edge := c.record(t, "add_relationship", rel)
		limitedToken := "sg_" + uuid.NewString()
		limited := p
		limited.ActorID = "limited"
		limited.Scopes = []string{"read", "export"}
		limited.AllAssets = false
		limited.AssetIDs = []string{asset.ID}
		if err = db.IssueKey(ctx, limitedToken, limited, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		lc := client{url: api.URL, token: limitedToken}
		failure(t, lc.call(t, "create_report", reportArgs))
		r := lc.call(t, "get_context", map[string]any{"intent": "Read only the authorized asset context.", "entity_id": asset.ID, "depth": 3, "limit": 100})
		if bytes.Contains(r.Result.Structured, []byte(private.ID)) || bytes.Contains(r.Result.Structured, []byte(edge.ID)) {
			t.Fatal("graph leaked hidden relationship endpoint")
		}
		r = lc.call(t, "list_changes", map[string]any{"intent": "Read authorized changes only.", "after": 0, "limit": 100})
		if bytes.Contains(r.Result.Structured, []byte(edge.ID)) {
			t.Fatal("change feed leaked hidden edge")
		}
		if _, err = db.Pool.Exec(ctx, "UPDATE security_graph.credentials SET revoked_at=now() WHERE organization_id=$1 AND actor_id='limited'", org); err != nil {
			t.Fatal(err)
		}
		if _, err = lc.rpc("tools/list", map[string]any{}); err == nil {
			t.Fatal("revoked credential remained usable")
		}
	})
	t.Run("audit is attributable and does not retain raw intent", func(t *testing.T) {
		var actor, hash string
		if err = db.Pool.QueryRow(ctx, "SELECT actor_id,intent_hash FROM security_graph.changes WHERE organization_id=$1 LIMIT 1", org).Scan(&actor, &hash); err != nil {
			t.Fatal(err)
		}
		if actor != "integration-agent" || len(hash) != 64 {
			t.Fatal("missing actor or privacy-preserving intent fingerprint")
		}
		r := c.call(t, "list_changes", map[string]any{"intent": "Read the durable ingestion cursor.", "after": 0, "limit": 100})
		if r.Result.IsError || len(r.Error) > 0 {
			t.Fatal("change feed failed")
		}
		var changes []storage.Change
		if err = json.Unmarshal(r.Result.Structured, &changes); err != nil || len(changes) == 0 {
			t.Fatal("empty change feed")
		}
	})
}
