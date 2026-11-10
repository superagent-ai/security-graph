package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
	"github.com/superagent-ai/security-graph/pkg/superagent"
)

// Both backends use real PostgreSQL and authenticated HTTP MCP. Native mode
// requires an explicitly disposable database with the real App schema applied.
func TestFindingCommentMCPWorkflow(t *testing.T) {
	for _, mode := range []string{"standalone", "superagent"} {
		t.Run(mode, func(t *testing.T) {
			url := os.Getenv("TEST_DATABASE_URL")
			if mode == "superagent" {
				url = os.Getenv("TEST_APP_DATABASE_URL")
			}
			if url == "" {
				t.Skip("requires disposable PostgreSQL")
			}
			cfg, err := pgxpool.ParseConfig(url)
			if err != nil || !strings.Contains(cfg.ConnConfig.Database, "test") {
				t.Fatal("requires explicitly disposable test database")
			}
			ctx := context.Background()
			db, err := postgres.Open(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if mode == "standalone" {
				err = db.Migrate(ctx)
			} else {
				err = superagent.Enable(ctx, db)
			}
			if err != nil {
				t.Fatal(err)
			}
			org, token := uuid.NewString(), "sg_"+uuid.NewString()
			principal := storage.Principal{OrganizationID: org, ActorID: "comments-integration", AllAssets: true, Scopes: []string{"read", "submit", "graph:write", "export"}}
			findingID := ""
			if mode == "superagent" {
				token = "sk_live_" + uuid.NewString()
				hash := sha256.Sum256([]byte(token))
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.organizations(id,name,slug) VALUES($1,'Native comment fixture',$2)`, org, org)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.api_keys(organization_id,key_hash,key_prefix) VALUES($1,$2,$3)`, org, hex.EncodeToString(hash[:]), token[:12])
				if err != nil {
					t.Fatal(err)
				}
				report := uuid.NewString()
				findingID = uuid.NewString()
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.repository_red_team_reports(id,organization_id,repo) VALUES($1,$2,$3)`, report, org, "https://github.com/example/"+org)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.repository_red_team_advisories(id,report_id,title,description,cvss_vector,weakness) VALUES($1,$2,'Comment fixture','Native discussion','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','CWE-78')`, findingID, report)
				if err != nil {
					t.Fatal(err)
				}
			} else if err = db.IssueKey(ctx, token, principal, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			api := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "comments-integration"))
			defer api.Close()
			c := client{api.URL, token}
			if mode == "standalone" {
				a := writeArgs()
				a["asset_id"], a["name"], a["type"], a["locator"] = org, "Comment fixture", "repository", "https://example.test/comments"
				asset := c.record(t, "create_asset", a)
				a = writeArgs()
				a["asset_id"], a["type"], a["target"] = asset.ID, "repository", "https://example.test/comments"
				report := c.record(t, "create_report", a)
				a = writeArgs()
				a["report_id"], a["finding"] = report.ID, finding(uuid.NewString())
				findingID = c.record(t, "submit_finding", a).ID
			}
			parent := c.record(t, "get_finding", map[string]any{"intent": "Read finding before discussion.", "finding_id": findingID})
			call := func(name string, args map[string]any) map[string]any {
				t.Helper()
				out := c.call(t, name, args)
				if out.Result.IsError || len(out.Error) > 0 {
					t.Fatalf("%s: %s %s", name, out.Error, out.Result.Content)
				}
				var value map[string]any
				if err := json.Unmarshal(out.Result.Structured, &value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			create := writeArgs()
			create["finding_id"], create["body"] = findingID, "  Gateway already enforces this boundary.  "
			comment := call("create_finding_comment", create)
			id := comment["id"].(string)
			graphID := comment["graph_id"].(string)
			version := int64(comment["version"].(float64))
			if comment["body"] != "Gateway already enforces this boundary." || comment["can_manage"] != true {
				t.Fatal(comment)
			}
			if replay := call("create_finding_comment", create); replay["id"] != id {
				t.Fatal("duplicate retry created another comment")
			}
			create["body"] = "Different retry payload"
			failure(t, c.call(t, "create_finding_comment", create))
			listArgs := map[string]any{"intent": "Read reviewer discussion.", "finding_id": findingID, "limit": 1}
			listed := call("list_finding_comments", listArgs)
			if listed["pagination"].(map[string]any)["total"] != float64(1) {
				t.Fatal(listed)
			}
			contextArgs := map[string]any{"intent": "Use finding discussion during investigation.", "entity_id": findingID, "depth": 1, "limit": 100}
			graph := call("get_context", contextArgs)
			if !strings.Contains(fmt.Sprint(graph), graphID) || !strings.Contains(fmt.Sprint(graph), "comments_on") {
				t.Fatal("comment missing from graph", graph)
			}
			bad := writeArgs()
			bad["finding_id"], bad["body"] = findingID, "   "
			failure(t, c.call(t, "create_finding_comment", bad))
			bad = writeArgs()
			bad["finding_id"], bad["body"] = findingID, strings.Repeat("x", 10001)
			failure(t, c.call(t, "create_finding_comment", bad))
			update := writeArgs()
			update["finding_id"], update["comment_id"], update["body"], update["expected_version"] = findingID, id, "Verified the gateway only covers authenticated routes.", version
			edited := call("update_finding_comment", update)
			newVersion := int64(edited["version"].(float64))
			if newVersion <= version {
				t.Fatal("version did not advance")
			}
			if fmt.Sprint(edited["author"]) != fmt.Sprint(comment["author"]) {
				t.Fatal("edit changed attribution")
			}
			stale := writeArgs()
			stale["finding_id"], stale["comment_id"], stale["body"], stale["expected_version"] = findingID, id, "Stale edit", version
			failure(t, c.call(t, "update_finding_comment", stale))
			mismatch := writeArgs()
			mismatch["finding_id"], mismatch["comment_id"], mismatch["expected_version"] = uuid.NewString(), id, newVersion
			failure(t, c.call(t, "delete_finding_comment", mismatch))
			// Reader-only credentials cannot write or learn comments from another org/asset.
			if mode == "standalone" {
				for _, p := range []storage.Principal{
					{OrganizationID: org, ActorID: "reader", AllAssets: true, Scopes: []string{"read"}},
					{OrganizationID: uuid.NewString(), ActorID: "outsider", AllAssets: true, Scopes: principal.Scopes},
					{OrganizationID: org, ActorID: "wrong-asset", AssetIDs: []string{"private"}, Scopes: principal.Scopes},
				} {
					key := "sg_" + uuid.NewString()
					if err := db.IssueKey(ctx, key, p, time.Now().Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
					restricted := client{api.URL, key}
					a := writeArgs()
					a["finding_id"], a["body"] = findingID, "Unauthorized discussion"
					failure(t, restricted.call(t, "create_finding_comment", a))
					if p.ActorID != "reader" {
						failure(t, restricted.call(t, "list_finding_comments", listArgs))
					}
				}
			} else {
				otherOrg, otherKey := uuid.NewString(), "sk_live_"+uuid.NewString()
				h := sha256.Sum256([]byte(otherKey))
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.organizations(id,name,slug) VALUES($1,'Other fixture',$2)`, otherOrg, otherOrg)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Pool.Exec(ctx, `INSERT INTO public.api_keys(organization_id,key_hash,key_prefix) VALUES($1,$2,$3)`, otherOrg, hex.EncodeToString(h[:]), otherKey[:12])
				if err != nil {
					t.Fatal(err)
				}
				other := client{api.URL, otherKey}
				failure(t, other.call(t, "list_finding_comments", listArgs))
				a := writeArgs()
				a["finding_id"], a["body"] = findingID, "Other tenant"
				failure(t, other.call(t, "create_finding_comment", a))
				// An App edit must fence an MCP write carrying the old version too.
				_, err = db.Pool.Exec(ctx, `UPDATE public.finding_comments SET body='Concurrent App edit' WHERE id=$1`, id)
				if err != nil {
					t.Fatal(err)
				}
				a = writeArgs()
				a["finding_id"], a["comment_id"], a["body"], a["expected_version"] = findingID, id, "Overwrite App edit", newVersion
				failure(t, c.call(t, "update_finding_comment", a))
				current := call("list_finding_comments", listArgs)
				newVersion = int64(current["data"].([]any)[0].(map[string]any)["version"].(float64))
			}
			remove := writeArgs()
			remove["finding_id"], remove["comment_id"], remove["expected_version"] = findingID, id, newVersion
			call("delete_finding_comment", remove)
			call("delete_finding_comment", remove)
			remaining := call("list_finding_comments", listArgs)
			if len(remaining["data"].([]any)) != 0 {
				t.Fatal("deleted comment still listed")
			}
			graph = call("get_context", contextArgs)
			if strings.Contains(fmt.Sprint(graph), graphID) {
				t.Fatal("deleted comment still in graph")
			}
			after := c.record(t, "get_finding", map[string]any{"intent": "Verify discussion does not change finding lifecycle.", "finding_id": findingID})
			if after.Version != parent.Version {
				t.Fatal("comment changed finding version/classification")
			}
			var audit int
			if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM security_graph.changes WHERE organization_id=$1 AND kind='comment'`, org).Scan(&audit); err != nil || audit != 3 {
				t.Fatalf("expected three audited mutations, got %d: %v", audit, err)
			}
		})
	}
}
