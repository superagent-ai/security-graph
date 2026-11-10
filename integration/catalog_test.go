package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/catalog"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

func TestCatalogClassificationWorkflow(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("run make integration")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.ConnConfig.Database, "test") {
		t.Fatal("requires a disposable test database")
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
	eng := &engine.Engine{Store: db}
	api := httptest.NewServer(server.Handler(eng, db, "catalog-integration"))
	defer api.Close()
	org := "catalog-test-" + uuid.NewString()
	issue := func(org, asset string, all bool, scopes ...string) client {
		token := "sg_" + uuid.NewString()
		p := storage.Principal{OrganizationID: org, ActorID: uuid.NewString(), AllAssets: all, AssetIDs: []string{asset}, Scopes: scopes}
		if err := db.IssueKey(ctx, token, p, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		return client{url: api.URL, token: token}
	}
	c := issue(org, "", true, "read", "submit", "graph:write", "export")
	out := c.call(t, "get_vulnerability_catalog", map[string]any{"intent": "Discover curated vulnerability types and framework mappings."})
	var cat catalog.Catalog
	if err = json.Unmarshal(out.Result.Structured, &cat); err != nil {
		t.Fatal(err)
	}
	if err = cat.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cat.Types) < 15 || len(cat.Frameworks) < 3 || len(cat.Mappings) < 10 {
		t.Fatal("catalog missing expected coverage")
	}
	failure(t, c.call(t, "get_vulnerability_catalog", map[string]any{"intent": " "}))
	assetArgs := writeArgs()
	assetArgs["asset_id"] = "catalog:v1:type:fake"
	assetArgs["name"] = "fake"
	assetArgs["type"] = "type"
	assetArgs["locator"] = "fixture"
	failure(t, c.call(t, "create_asset", assetArgs))
	create := func(c client, label string) (storage.Record, storage.Record) {
		a := writeArgs()
		a["asset_id"] = label + uuid.NewString()
		a["name"] = label
		a["type"] = "repository"
		a["locator"] = "https://example.com/" + label
		asset := c.record(t, "create_asset", a)
		r := writeArgs()
		r["asset_id"] = asset.ID
		r["type"] = "repository"
		r["target"] = "https://example.com/" + label
		report := c.record(t, "create_report", r)
		f := writeArgs()
		f["report_id"] = report.ID
		f["finding"] = finding(uuid.NewString())
		return asset, c.record(t, "submit_finding", f)
	}
	asset, f := create(c, "payments")
	_, private := create(c, "private")
	args := func(f storage.Record, version int64, ids []string) map[string]any {
		a := writeArgs()
		a["finding_id"] = f.ID
		a["expected_version"] = f.Version
		a["expected_classification_version"] = version
		a["type_ids"] = ids
		a["compliance_ids"] = []string{}
		a["rationale"] = "The fixture omits authorization before reading a tenant record."
		return a
	}
	t.Run("agent selects both catalog lists without a classifier", func(t *testing.T) {
		_, f := create(c, "agent-selected")
		options := c.call(t, "get_classification_options", map[string]any{"intent": "Choose explicit evidence-backed category and compliance IDs."})
		var lists struct {
			Types      []catalog.Type  `json:"vulnerability_types"`
			Compliance []catalog.Entry `json:"compliance"`
		}
		if err := json.Unmarshal(options.Result.Structured, &lists); err != nil || len(lists.Types) != 16 || len(lists.Compliance) < 10 {
			t.Fatal("missing selectable lists", err)
		}
		tools, err := c.rpc("tools/list", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range tools.Result.Tools {
			if tool.Name == "classify_finding" || tool.Name == "set_finding_types" {
				t.Fatal("retired classification tool exposed")
			}
			if tool.Name == "set_finding_classification" {
				for _, name := range []string{"type_ids", "compliance_ids"} {
					if string(tool.InputSchema.Properties[name].Type) != `"array"` {
						t.Fatalf("%s must be a non-null array", name)
					}
				}
			}
		}
		for _, name := range []string{"type_ids", "compliance_ids"} {
			omitted := args(f, 0, []string{})
			delete(omitted, name)
			failure(t, c.call(t, "set_finding_classification", omitted))
			null := args(f, 0, []string{})
			null[name] = nil
			failure(t, c.call(t, "set_finding_classification", null))
		}
		a := args(f, 0, []string{"command_injection"})
		a["compliance_ids"] = []string{"owasp-web:A05"}
		selected := c.record(t, "set_finding_classification", a)
		replay := c.record(t, "set_finding_classification", a)
		if !bytes.Equal(selected.Data, replay.Data) {
			t.Fatal("selection replay changed")
		}
		var cl engine.Classification
		if json.Unmarshal(selected.Data, &cl) != nil || cl.Method != "agent_asserted" || len(cl.ComplianceIDs) != 1 || cl.ComplianceIDs[0] != "owasp-web:A05" {
			t.Fatal("agent choices not retained")
		}
		neighborhood := c.call(t, "get_context", map[string]any{"intent": "Verify selected compliance relationship.", "entity_id": f.ID, "depth": 1, "limit": 100})
		if !bytes.Contains(neighborhood.Result.Structured, []byte("catalog:v1:entry:owasp-web:A05")) {
			t.Fatal("missing compliance edge")
		}
		reverse := c.call(t, "get_neighbors", map[string]any{"intent": "Verify reverse compliance selection traversal.", "entity_id": "catalog:v1:entry:owasp-web:A05", "limit": 25})
		if !bytes.Contains(reverse.Result.Structured, []byte(f.ID)) {
			t.Fatal("missing reverse selection")
		}
		bad := args(f, selected.Version, []string{"command_injection"})
		bad["compliance_ids"] = []string{"invented"}
		failure(t, c.call(t, "set_finding_classification", bad))
		stale := args(f, 0, []string{"command_injection"})
		stale["compliance_ids"] = []string{}
		failure(t, c.call(t, "set_finding_classification", stale))
		empty := args(f, selected.Version, []string{})
		empty["compliance_ids"] = []string{}
		cleared := c.record(t, "set_finding_classification", empty)
		if !bytes.Contains(cleared.Data, []byte(`"status":"unclassified"`)) {
			t.Fatal("empty choice must remain unclassified")
		}
	})
	for _, ids := range [][]string{{"invented_type"}, {"injection"}, {"missing_authorization", "missing_authorization"}} {
		failure(t, c.call(t, "set_finding_classification", args(f, 0, ids)))
	}
	a := args(f, 0, []string{"missing_authorization"})
	assigned := c.record(t, "set_finding_classification", a)
	replay := c.record(t, "set_finding_classification", a)
	if !bytes.Equal(assigned.Data, replay.Data) || replay.Version != 1 {
		t.Fatal("classification replay changed")
	}
	conflict := args(f, 0, []string{"idor"})
	failure(t, c.call(t, "set_finding_classification", conflict))
	a["type_ids"] = []string{"ssrf"}
	failure(t, c.call(t, "set_finding_classification", a))
	privateClass := c.record(t, "set_finding_classification", args(private, 0, []string{"missing_authorization"}))
	// Reverse traversal through shared definitions must enforce both asset and org boundaries.
	scoped := issue(org, asset.ID, false, "read", "graph:write", "export")
	other := issue("other-"+uuid.NewString(), "", true, "read", "export")
	contextAt := func(c client, id string, depth int) engine.ContextResult {
		r := c.call(t, "get_context", map[string]any{"intent": "Follow authorized vulnerability classifications and framework mappings.", "entity_id": id, "depth": depth, "limit": 100})
		if r.Result.IsError || len(r.Error) > 0 {
			t.Fatalf("context failed: %s", r.Result.Content)
		}
		var g engine.ContextResult
		if json.Unmarshal(r.Result.Structured, &g) != nil {
			t.Fatal("invalid graph")
		}
		return g
	}
	node := cat.TypeNode("missing_authorization")
	for _, tc := range []struct {
		c       client
		allowed bool
	}{{scoped, true}, {other, false}} {
		g := contextAt(tc.c, node, 1)
		b, _ := json.Marshal(g)
		if bytes.Contains(b, []byte(private.ID)) || bytes.Contains(b, []byte(privateClass.ID)) {
			t.Fatal("catalog traversal leaked private assignment")
		}
		if bytes.Contains(b, []byte(f.ID)) != tc.allowed {
			t.Fatal("wrong assignment visibility")
		}
	}
	g := contextAt(scoped, f.ID, 3)
	b, _ := json.Marshal(g)
	for _, r := range g.Records {
		if strings.HasPrefix(r.ID, "classification-edge:") {
			edgeGraph := contextAt(scoped, r.ID, 0)
			if len(edgeGraph.Records) != 1 || edgeGraph.Records[0].ID != r.ID {
				t.Fatal("projected edge is not addressable")
			}
		}
	}
	if !bytes.Contains(b, []byte("instance_of")) || !bytes.Contains(b, []byte("framework_entry")) {
		t.Fatal("finding did not connect to framework entries")
	}
	if len(contextAt(scoped, node, 0).Records) != 1 {
		t.Fatal("depth zero traversed")
	}
	bounded := scoped.call(t, "get_context", map[string]any{"intent": "Bound catalog traversal.", "entity_id": node, "depth": 3, "limit": 1})
	var limited engine.ContextResult
	_ = json.Unmarshal(bounded.Result.Structured, &limited)
	if !limited.Truncated || len(limited.Records) != 1 {
		t.Fatal("catalog traversal did not truncate")
	}
	failure(t, scoped.call(t, "get_finding_classification", map[string]any{"intent": "Check unauthorized assignment.", "finding_id": private.ID}))
	failure(t, scoped.call(t, "set_finding_classification", args(private, 1, []string{"idor"})))
	readonly := issue(org, asset.ID, false, "read")
	failure(t, readonly.call(t, "set_finding_classification", args(f, 1, []string{"idor"})))
	// Reclassification replaces graph edges; it does not leave stale assignments.
	cleared := c.record(t, "set_finding_classification", args(f, 1, []string{}))
	if cleared.Version != 2 {
		t.Fatal("classification version not incremented")
	}
	g = contextAt(scoped, node, 1)
	b, _ = json.Marshal(g)
	if bytes.Contains(b, []byte(f.ID)) {
		t.Fatal("cleared classification left stale edges")
	}
	after := c.record(t, "get_finding", map[string]any{"intent": "Ensure classification preserves the original finding.", "finding_id": f.ID})
	if f.Version != after.Version || !bytes.Equal(f.Data, after.Data) {
		t.Fatal("classification changed finding evidence or lifecycle")
	}
	audit := scoped.call(t, "list_changes", map[string]any{"intent": "Inspect classification history.", "after": 0, "limit": 100})
	if bytes.Contains(audit.Result.Structured, []byte(privateClass.ID)) || !bytes.Contains(audit.Result.Structured, []byte(assigned.ID)) {
		t.Fatal("classification change visibility incorrect")
	}
	t.Run("legacy graph namespace collisions preserve persisted identity", func(t *testing.T) {
		ids := []string{cat.TypeNode("ssrf"), "classification-edge:legacy-asset:ssrf"}
		for _, id := range ids {
			p := storage.Principal{OrganizationID: org, ActorID: "legacy-import", AllAssets: true, Scopes: []string{"read", "graph:write"}}
			_, err := db.Update(ctx, p, storage.Call{Key: uuid.NewString(), Digest: uuid.NewString(), Intent: "Import an asset created before catalog namespaces existed.", Operation: "legacy_fixture_import"}, func(tx storage.Transaction) (any, error) {
				b, _ := json.Marshal(contracts.Asset{Name: "Legacy private asset", Type: "repository", Locator: "https://example.com/legacy"})
				return tx.Put(ctx, storage.Record{ID: id, Kind: "asset", AssetID: id, Data: b}, 0)
			})
			if err != nil {
				t.Fatal(err)
			}
			reportArgs := writeArgs()
			reportArgs["asset_id"] = id
			reportArgs["type"] = "repository"
			reportArgs["target"] = "https://example.com/legacy"
			report := c.record(t, "create_report", reportArgs)
			root := contextAt(c, id, 1)
			if root.Records[0].Kind != "asset" || !bytes.Contains(root.Records[0].Data, []byte("Legacy private asset")) {
				t.Fatal("legacy asset was reinterpreted")
			}
			linked := false
			for _, r := range root.Records {
				if r.ID == report.ID {
					linked = true
				}
				if r.Kind == "framework_entry" || r.Kind == "vulnerability_type" {
					t.Fatal("legacy asset gained catalog relationships")
				}
			}
			if !linked {
				t.Fatal("legacy asset lost persisted relationships")
			}
			aroundReport := contextAt(c, report.ID, 1)
			for _, r := range aroundReport.Records {
				if r.ID == id && r.Kind != "asset" {
					t.Fatal("persisted relationship endpoint was reinterpreted")
				}
			}
		}
		// A caller without access to the colliding asset still sees only the
		// public catalog definition, with no private data or relationships.
		hidden := contextAt(scoped, cat.TypeNode("ssrf"), 1)
		hiddenJSON, _ := json.Marshal(hidden)
		if hidden.Records[0].Kind != "vulnerability_type" || bytes.Contains(hiddenJSON, []byte("Legacy private asset")) {
			t.Fatal("catalog lookup leaked an inaccessible legacy asset")
		}
		_, f := create(c, "collision-classification")
		cl := c.record(t, "set_finding_classification", args(f, 0, []string{"ssrf"}))
		graph := contextAt(c, f.ID, 1)
		for _, r := range graph.Records {
			if strings.HasPrefix(r.ID, "classification-edge:") {
				t.Fatal("assignment was projected onto the legacy asset")
			}
		}
		failure(t, c.call(t, "get_context", map[string]any{"intent": "Do not reinterpret a colliding assignment target.", "entity_id": "classification-edge:" + cl.ID + ":ssrf", "depth": 0, "limit": 10}))
	})
}
