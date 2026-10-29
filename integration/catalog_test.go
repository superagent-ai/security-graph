package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		failureClient := issue("failure-"+uuid.NewString(), "", true, "read", "submit", "graph:write")
		_, failureFinding := create(failureClient, "runtime-failure")
		failing := writeArgs()
		failing["finding_id"] = failureFinding.ID
		failing["expected_version"] = failureFinding.Version
		failing["expected_classification_version"] = 0
		failed := failureClient.call(t, "classify_finding", failing)
		failure(t, failed)
		if !bytes.Contains(failed.Result.Content, []byte("local_classifier_unavailable")) {
			t.Fatal("runtime failure was not exercised")
		}
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
	t.Run("real Julia process-wide capacity and tenant cooldowns", func(t *testing.T) {
		python, model := os.Getenv("JULIA_PYTHON"), os.Getenv("JULIA_MODEL_DIR")
		if python == "" || model == "" {
			if os.Getenv("REQUIRE_JULIA") == "1" {
				t.Fatal("Julia configuration required")
			}
			t.Skip("requires actual Julia weights")
		}
		script, err := filepath.Abs("../scripts/julia/classify.py")
		if err != nil {
			t.Fatal(err)
		}
		command := classifier.Command{Path: python, Args: []string{script, "--model-dir", model}}
		eng.Classifier = command
		// Separate Engine instances must share the same process-wide budget.
		secondEngine := &engine.Engine{Store: db, Classifier: command}
		secondAPI := httptest.NewServer(server.Handler(secondEngine, db, "capacity-integration"))
		defer secondAPI.Close()
		type tenant struct {
			org     string
			c       client
			finding storage.Record
		}
		tenants := []tenant{}
		for i := 0; i < 3; i++ {
			org := "capacity-" + uuid.NewString()
			c := issue(org, "", true, "read", "submit", "graph:write")
			if i%2 == 1 {
				c.url = secondAPI.URL
			}
			_, f := create(c, "capacity")
			tenants = append(tenants, tenant{org, c, f})
		}
		sibling := issue(tenants[0].org, "", true, "read", "graph:write")
		sibling.url = secondAPI.URL
		tenants = append(tenants, tenant{tenants[0].org, sibling, tenants[0].finding})
		type attempt struct {
			who  int
			args map[string]any
			out  rpcResult
			err  error
		}
		start := make(chan struct{})
		results := make(chan attempt, 24)
		var workers sync.WaitGroup
		keys := []string{}
		for i := 0; i < 24; i++ {
			who := i % len(tenants)
			a := writeArgs()
			a["finding_id"] = tenants[who].finding.ID
			a["expected_version"] = tenants[who].finding.Version
			a["expected_classification_version"] = 0
			keys = append(keys, a["idempotency_key"].(string))
			workers.Add(1)
			go func(who int, args map[string]any) {
				defer workers.Done()
				<-start
				out, err := tenants[who].c.rpc("tools/call", map[string]any{"name": "classify_finding", "arguments": args})
				results <- attempt{who, args, out, err}
			}(who, a)
		}
		close(start)
		workers.Wait()
		close(results)
		successful, busy := 0, 0
		var winner attempt
		var assignment storage.Record
		for r := range results {
			if r.err != nil {
				t.Fatal(r.err)
			}
			if r.out.Result.IsError || len(r.out.Error) > 0 {
				if !bytes.Contains(r.out.Result.Content, []byte("classifier_capacity_exceeded")) {
					t.Fatalf("unexpected rejection: %s", r.out.Result.Content)
				}
				busy++
				continue
			}
			successful++
			winner = r
			if json.Unmarshal(r.out.Result.Structured, &assignment) != nil || assignment.Kind != "classification" {
				t.Fatal("invalid classification receipt")
			}
		}
		if successful != 1 || busy != 23 {
			t.Fatalf("admission allowed %d and rejected %d; wanted one process", successful, busy)
		}
		var receipts int
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.idempotency WHERE key=ANY($1::text[])", keys).Scan(&receipts); err != nil || receipts != 1 {
			t.Fatalf("capacity rejections committed receipts: count=%d err=%v", receipts, err)
		}
		// Cached retries bypass admission, even with the model disconnected.
		eng.Classifier = nil
		secondEngine.Classifier = nil
		recovered := tenants[winner.who].c.record(t, "classify_finding", winner.args)
		if recovered.ID != assignment.ID || recovered.Version != assignment.Version {
			t.Fatal("capacity limits blocked durable retry")
		}
		eng.Classifier = command
		secondEngine.Classifier = command
		currentArgs := func(f storage.Record, version int64) map[string]any {
			a := writeArgs()
			a["finding_id"] = f.ID
			a["expected_version"] = f.Version
			a["expected_classification_version"] = version
			return a
		}
		for _, c := range []client{tenants[winner.who].c, issue(tenants[winner.who].org, "", true, "read", "graph:write")} {
			r := c.call(t, "classify_finding", currentArgs(tenants[winner.who].finding, assignment.Version))
			failure(t, r)
			if !bytes.Contains(r.Result.Content, []byte("classifier_capacity_exceeded")) {
				t.Fatal("actor/organization cooldown bypassed")
			}
		}
		// Two other organizations can each reach the actual worker after the
		// prior request terminates. A real missing-model failure frees the slot.
		broken := classifier.Command{Path: python, Args: []string{script, "--model-dir", filepath.Join(t.TempDir(), "missing")}}
		eng.Classifier = broken
		secondEngine.Classifier = broken
		for _, tenant := range tenants[:3] {
			if tenant.org == tenants[winner.who].org {
				continue
			}
			r := tenant.c.call(t, "classify_finding", currentArgs(tenant.finding, 0))
			failure(t, r)
			if !bytes.Contains(r.Result.Content, []byte("local_classifier_unavailable")) {
				t.Fatal("worker slot not released or rejected tenant consumed cooldown")
			}
		}
	})

}
