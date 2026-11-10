// Real PostgreSQL and authenticated MCP workflows for paged context and provenance.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
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

func TestMCPContextAttributionAndPaging(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("run make integration to start real PostgreSQL")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.ConnConfig.Database, "test") {
		t.Fatal("TEST_DATABASE_URL must name an explicitly disposable test database")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	org := "context-" + uuid.NewString()
	principal := storage.Principal{OrganizationID: org, ActorID: "origin-agent", AllAssets: true, Scopes: []string{"read", "submit", "graph:write", "disposition", "export"}}
	token := "sg_" + uuid.NewString()
	if err = db.IssueKey(ctx, token, principal, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	mcpAPI := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "context-integration"))
	defer mcpAPI.Close()
	writer := client{url: mcpAPI.URL, token: token}
	createAsset := func(id string) storage.Record {
		args := writeArgs()
		args["asset_id"] = id
		args["name"] = id
		args["type"] = "repository"
		args["locator"] = "https://github.com/example/" + id
		return writer.record(t, "create_asset", args)
	}
	asset := createAsset("payments-" + uuid.NewString())
	hidden := createAsset("private-" + uuid.NewString())
	reportArgs := writeArgs()
	reportArgs["asset_id"] = asset.ID
	reportArgs["type"] = "repository"
	reportArgs["target"] = "example/payments@context"
	report := writer.record(t, "create_report", reportArgs)
	submit := writeArgs()
	submit["report_id"] = report.ID
	submit["finding"] = finding("context-finding")
	saved := writer.record(t, "submit_finding", submit)
	finish := writeArgs()
	finish["report_id"] = report.ID
	finish["expected_version"] = report.Version
	finish["status"] = "succeeded"
	report = writer.record(t, "finish_report", finish)

	call := func(name string, args any) rpcResult { t.Helper(); return writer.call(t, name, args) }
	record := func(name string, args any) storage.Record { t.Helper(); return writer.record(t, name, args) }
	t.Run("high degree adjacency has bounded resumable pages", func(t *testing.T) {
		for i := 0; i < 125; i++ {
			leaf := createAsset(fmt.Sprintf("scale-%03d-%s", i, org))
			args := writeArgs()
			args["relationship"] = contracts.Relationship{SourceID: asset.ID, TargetID: leaf.ID, Type: "depends_on", Provenance: "High-degree graph integration fixture over authenticated MCP."}
			writer.record(t, "add_relationship", args)
		}
		pageAt := func(cursor string) engine.NeighborsResult {
			t.Helper()
			r := call("get_neighbors", map[string]any{"intent": "Page a high-degree graph through authenticated MCP.", "entity_id": asset.ID, "cursor": cursor, "limit": 25})
			if r.Result.IsError || len(r.Error) > 0 {
				t.Fatalf("get_neighbors failed: %s %s", r.Error, r.Result.Content)
			}
			var page engine.NeighborsResult
			if json.Unmarshal(r.Result.Structured, &page) != nil {
				t.Fatal("bad neighborhood page")
			}
			return page
		}
		cursor := ""
		seen := map[string]bool{}
		pages := 0
		for {
			page := pageAt(cursor)
			pages++
			if page.Edges > 25 || len(page.Records) > 51 {
				t.Fatal("unbounded neighborhood response")
			}
			if len(page.Records) == 0 || page.Records[0].ID != asset.ID {
				t.Fatal("missing authorized page root")
			}
			for _, r := range page.Records {
				if r.Kind == "relationship" {
					if seen[r.ID] {
						t.Fatal("duplicate relationship across stable pages")
					}
					seen[r.ID] = true
				}
			}
			if page.NextCursor == "" {
				break
			}
			if page.NextCursor == cursor || pages > 12 {
				t.Fatal("cursor did not progress")
			}
			cursor = page.NextCursor
		}
		if pages < 6 || len(seen) < 126 {
			t.Fatalf("high-degree neighbors were hidden: pages=%d edges=%d", pages, len(seen))
		}
		first := pageAt("")
		a := pageAt(first.NextCursor)
		b := pageAt(first.NextCursor)
		if !bytes.Equal(dataForTest(a), dataForTest(b)) {
			t.Fatal("stable cursor replay returned a different page")
		}
		failure(t, call("get_neighbors", map[string]any{"intent": "Reject a cursor used for a different root.", "entity_id": hidden.ID, "cursor": first.NextCursor, "limit": 25}))
		failure(t, call("get_neighbors", map[string]any{"intent": "Reject an unbounded adjacency page.", "entity_id": asset.ID, "limit": 26}))
		// Catalog and classification phases must survive the same cursor pagination.
		current := record("get_finding", map[string]any{"intent": "Read current version before classification.", "finding_id": saved.ID})
		assign := writeArgs()
		assign["finding_id"] = current.ID
		assign["expected_version"] = current.Version
		assign["expected_classification_version"] = 0
		assign["type_ids"] = []string{"missing_authorization", "idor"}
		assign["compliance_ids"] = []string{}
		assign["rationale"] = "Classify the real tenant-isolation integration finding."
		writer.record(t, "set_finding_classification", assign)
		cursor = ""
		types := map[string]bool{}
		for i := 0; i < 10; i++ {
			result := call("get_neighbors", map[string]any{"intent": "Continue projected classification adjacency pages.", "entity_id": saved.ID, "cursor": cursor, "limit": 1})
			if result.Result.IsError {
				t.Fatalf("classification neighbors: %s", result.Result.Content)
			}
			var page engine.NeighborsResult
			_ = json.Unmarshal(result.Result.Structured, &page)
			for _, r := range page.Records {
				if r.Kind == "relationship" {
					var rel contracts.Relationship
					_ = json.Unmarshal(r.Data, &rel)
					if rel.Type == "instance_of" {
						types[rel.TargetID] = true
					}
				}
			}
			cursor = page.NextCursor
			if cursor == "" {
				break
			}
		}
		if len(types) != 2 {
			t.Fatal("partial classification cursor lost assignments")
		}
	})

	t.Run("paged adjacency enforces endpoint scope", func(t *testing.T) {
		p := storage.Principal{OrganizationID: org, ActorID: "restricted-reader", AssetIDs: []string{asset.ID}, Scopes: []string{"read"}}
		key := "sg_" + uuid.NewString()
		if err := db.IssueKey(ctx, key, p, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		reader := client{url: mcpAPI.URL, token: key}
		result := reader.call(t, "get_neighbors", map[string]any{"intent": "Only read graph endpoints within the credential's asset grants.", "entity_id": asset.ID, "limit": 25})
		if result.Result.IsError || bytes.Contains(result.Result.Structured, []byte("scale-")) {
			t.Fatal("scoped neighbor page leaked private endpoints")
		}
		failure(t, reader.call(t, "get_neighbors", map[string]any{"intent": "Reject access to a private root.", "entity_id": hidden.ID, "limit": 25}))
	})
	t.Run("exact submitter filters and reviewer attribution", func(t *testing.T) {
		other := principal
		other.ActorID = principal.ActorID + "-extra"
		key := "sg_" + uuid.NewString()
		if err := db.IssueKey(ctx, key, other, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		scanner := client{url: mcpAPI.URL, token: key}
		args := writeArgs()
		args["asset_id"], args["type"], args["target"] = asset.ID, "repository", "source-filter-fixture"
		run := scanner.record(t, "create_report", args)
		for i := 0; i < 8; i++ {
			submission := finding(fmt.Sprintf("other-agent-%d", i))
			submission.Title = "Evidence mentioning " + principal.ActorID
			args = writeArgs()
			args["report_id"], args["finding"] = run.ID, submission
			scanner.record(t, "submit_finding", args)
		}
		exact := call("list_findings", map[string]any{"intent": "Select the authenticated submitter rather than mentions in evidence.", "source": principal.ActorID, "limit": 100})
		var own []storage.Record
		if exact.Result.IsError || json.Unmarshal(exact.Result.Structured, &own) != nil || len(own) != 1 || own[0].ID != saved.ID {
			t.Fatal("creator filter matched another agent's content")
		}
		first := call("list_findings", map[string]any{"intent": "Read a bounded source-specific finding page.", "source": other.ActorID, "report_id": run.ID, "limit": 5})
		var page []storage.Record
		if first.Result.IsError || json.Unmarshal(first.Result.Structured, &page) != nil || len(page) != 5 {
			t.Fatal("source-specific page failed")
		}
		next := call("list_findings", map[string]any{"intent": "Continue the same source and assessment.", "source": other.ActorID, "report_id": run.ID, "after": page[3].ID, "limit": 5})
		var rest []storage.Record
		if next.Result.IsError || json.Unmarshal(next.Result.Structured, &rest) != nil || len(rest) != 4 || rest[0].ID != page[4].ID {
			t.Fatal("source pagination skipped or repeated findings")
		}
		reports := call("list_reports", map[string]any{"intent": "Read assessments contributed by one exact source.", "source": other.ActorID, "limit": 100})
		var runs []storage.Record
		if reports.Result.IsError || json.Unmarshal(reports.Result.Structured, &runs) != nil || len(runs) != 1 || runs[0].ID != run.ID {
			t.Fatal("source-specific assessment history failed")
		}
		current := record("get_finding", map[string]any{"intent": "Read the current creator-attributed record before review.", "finding_id": saved.ID})
		args = writeArgs()
		args["finding_id"], args["expected_version"], args["triage_status"], args["triage_resolution"] = current.ID, current.Version, "resolved", "fixed"
		reviewed := scanner.record(t, "update_finding_triage", args)
		var domain contracts.Finding
		if json.Unmarshal(reviewed.Data, &domain) != nil || domain.Source != principal.ActorID {
			t.Fatal("reviewer replaced the original submitter")
		}
		restricted := other
		restricted.ActorID = "private-target-reader"
		restricted.AllAssets = false
		restricted.AssetIDs = []string{hidden.ID}
		restricted.Scopes = []string{"read"}
		scopedKey := "sg_" + uuid.NewString()
		if err := db.IssueKey(ctx, scopedKey, restricted, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		scoped := client{url: mcpAPI.URL, token: scopedKey}
		denied := scoped.call(t, "list_findings", map[string]any{"intent": "A source filter must never expand target authorization.", "source": other.ActorID, "limit": 100})
		var inaccessible []storage.Record
		if denied.Result.IsError || json.Unmarshal(denied.Result.Structured, &inaccessible) != nil || len(inaccessible) != 0 {
			t.Fatal("source filter expanded credential scope")
		}
	})
}
func dataForTest(v any) []byte { b, _ := json.Marshal(v); return b }
