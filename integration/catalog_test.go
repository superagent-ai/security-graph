package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/catalog"
	"github.com/superagent-ai/security-graph/pkg/classifier"
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
	create := func(label string) (storage.Record, storage.Record) {
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
	asset, f := create("payments")
	_, private := create("private")
	args := func(f storage.Record, version int64, ids []string) map[string]any {
		a := writeArgs()
		a["finding_id"] = f.ID
		a["expected_version"] = f.Version
		a["expected_classification_version"] = version
		a["type_ids"] = ids
		a["rationale"] = "The fixture omits authorization before reading a tenant record."
		return a
	}
	for _, ids := range [][]string{{"invented_type"}, {"injection"}, {"missing_authorization", "missing_authorization"}} {
		failure(t, c.call(t, "set_finding_types", args(f, 0, ids)))
	}
	a := args(f, 0, []string{"missing_authorization"})
	assigned := c.record(t, "set_finding_types", a)
	replay := c.record(t, "set_finding_types", a)
	if !bytes.Equal(assigned.Data, replay.Data) || replay.Version != 1 {
		t.Fatal("classification replay changed")
	}
	conflict := args(f, 0, []string{"idor"})
	failure(t, c.call(t, "set_finding_types", conflict))
	a["type_ids"] = []string{"ssrf"}
	failure(t, c.call(t, "set_finding_types", a))
	privateClass := c.record(t, "set_finding_types", args(private, 0, []string{"missing_authorization"}))
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
	failure(t, scoped.call(t, "set_finding_types", args(private, 1, []string{"idor"})))
	readonly := issue(org, asset.ID, false, "read")
	failure(t, readonly.call(t, "set_finding_types", args(f, 1, []string{"idor"})))
	failure(t, readonly.call(t, "classify_finding", args(f, 1, nil)))
	// Reclassification replaces graph edges; it does not leave stale assignments.
	cleared := c.record(t, "set_finding_types", args(f, 1, []string{}))
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
	// The default deployment remains usable without a model.
	modelArgs := writeArgs()
	modelArgs["finding_id"] = f.ID
	modelArgs["expected_version"] = f.Version
	modelArgs["expected_classification_version"] = 2
	failure(t, c.call(t, "classify_finding", modelArgs))
	t.Run("real Julia local decisions and durable retry", func(t *testing.T) {
		python, model := os.Getenv("JULIA_PYTHON"), os.Getenv("JULIA_MODEL_DIR")
		if python == "" || model == "" {
			if os.Getenv("REQUIRE_JULIA") == "1" {
				t.Fatal("Julia integration requires JULIA_PYTHON and JULIA_MODEL_DIR")
			}
			t.Skip("set JULIA_PYTHON and JULIA_MODEL_DIR to exercise actual Julia weights")
		}
		script, err := filepath.Abs("../scripts/julia/classify.py")
		if err != nil {
			t.Fatal(err)
		}
		eng.Classifier = classifier.Command{Path: python, Args: []string{script, "--model-dir", model}}
		assigned = c.record(t, "classify_finding", modelArgs)
		var cl engine.Classification
		if json.Unmarshal(assigned.Data, &cl) != nil || cl.Model == nil {
			t.Fatal("model provenance missing")
		}
		if cl.Model.Model != "SupersonicLabs/Julia-1" || cl.Model.Revision != "a85b127321d580d65176c89ced8273f305745d85" || len(cl.Model.Scores) != len(cat.Types)-1 {
			t.Fatal("model did not score catalog")
		}
		for _, v := range cl.Model.Scores {
			if v < 0 || v > 1 {
				t.Fatal("invalid model score")
			}
		}
		if cl.Method != "model_suggested" || (cl.Status != "suggested" && cl.Status != "unclassified") {
			t.Fatal("model result treated as accepted classification")
		}
		graph := contextAt(scoped, f.ID, 1)
		for _, record := range graph.Records {
			if record.Kind != "relationship" {
				continue
			}
			var rel contracts.Relationship
			_ = json.Unmarshal(record.Data, &rel)
			if rel.Type == "instance_of" {
				t.Fatal("model created canonical assignment")
			}
		}
		t.Logf("Julia authorization fixture: score=%f, assignments=%v", cl.Model.Scores["missing_authorization"], cl.TypeIDs)
		eng.Classifier = nil
		replay = c.record(t, "classify_finding", modelArgs)
		if replay.Version != assigned.Version || !bytes.Equal(replay.Data, assigned.Data) {
			t.Fatal("offline retry did not recover original result")
		}
		invalid := args(f, assigned.Version, []string{})
		invalid["expected_version"] = f.Version + 1
		failure(t, c.call(t, "set_finding_types", invalid))
		final := c.record(t, "get_finding_classification", map[string]any{"intent": "Read persisted local model decisions.", "finding_id": f.ID})
		eng.Classifier = classifier.Command{Path: python, Args: []string{script, "--model-dir", filepath.Join(t.TempDir(), "missing-model")}}
		failing := writeArgs()
		failing["finding_id"] = f.ID
		failing["expected_version"] = f.Version
		failing["expected_classification_version"] = assigned.Version
		failure(t, c.call(t, "classify_finding", failing))
		unchanged := c.record(t, "get_finding_classification", map[string]any{"intent": "Ensure runtime failure commits no assignment.", "finding_id": f.ID})
		if unchanged.Version != assigned.Version {
			t.Fatal("runtime failure committed")
		}
		if final.Version != assigned.Version {
			t.Fatal("stale mutation changed classification")
		}
		current := c.record(t, "get_finding", map[string]any{"intent": "Check model did not confirm the finding.", "finding_id": f.ID})
		var domain contracts.Finding
		_ = json.Unmarshal(current.Data, &domain)
		if domain.Triage.Status != "new" {
			t.Fatal("model changed triage")
		}
	})
}
