package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
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
			if tool.Name == "classify_finding" {
				t.Fatal("unconfigured inference tool exposed")
			}
		}
		a := args(f, 0, []string{"command_injection"})
		a["compliance_ids"] = []string{"owasp-web:A05"}
		selected := c.record(t, "set_finding_classification", a)
		replay := c.record(t, "set_finding_classification", a)
		if !bytes.Equal(selected.Data, replay.Data) {
			t.Fatal("selection replay changed")
		}
		var cl engine.Classification
		if json.Unmarshal(selected.Data, &cl) != nil || cl.Method != "agent_asserted" || cl.Model != nil || len(cl.ComplianceIDs) != 1 || cl.ComplianceIDs[0] != "owasp-web:A05" {
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
		cl := c.record(t, "set_finding_types", args(f, 0, []string{"ssrf"}))
		graph := contextAt(c, f.ID, 1)
		for _, r := range graph.Records {
			if strings.HasPrefix(r.ID, "classification-edge:") {
				t.Fatal("assignment was projected onto the legacy asset")
			}
		}
		failure(t, c.call(t, "get_context", map[string]any{"intent": "Do not reinterpret a colliding assignment target.", "entity_id": "classification-edge:" + cl.ID + ":ssrf", "depth": 0, "limit": 10}))
	})
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
		// Exercise the real installer and model without an editable package.
		install, err := filepath.Abs("../scripts/julia/install.py")
		if err != nil {
			t.Fatal(err)
		}
		manifestPath, err := filepath.Abs("../scripts/julia/manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		manifestBody, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Files map[string]string `json:"files"`
		}
		if json.Unmarshal(manifestBody, &manifest) != nil {
			t.Fatal("invalid manifest")
		}
		source := t.TempDir()
		for name := range manifest.Files {
			target := filepath.Join(source, name)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(model, name)
			if err := os.Link(original, target); err != nil {
				src, err := os.Open(original)
				if err != nil {
					t.Fatal(err)
				}
				dst, err := os.Create(target)
				if err != nil {
					_ = src.Close()
					t.Fatal(err)
				}
				_, copyErr := io.Copy(dst, src)
				_ = src.Close()
				closeErr := dst.Close()
				if copyErr != nil || closeErr != nil {
					t.Fatal("copy model fixture failed")
				}
			}
		}
		buildMarker := filepath.Join(t.TempDir(), "build-executed")
		backend := fmt.Sprintf("from pathlib import Path\nPath(%q).write_text('unexpected build')\nraise RuntimeError('remote build executed')\n", buildMarker)
		if err := os.WriteFile(filepath.Join(source, "evil_backend.py"), []byte(backend), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "pyproject.toml"), []byte("[build-system]\nrequires=[]\nbuild-backend='evil_backend'\nbackend-path=['.']\n"), 0600); err != nil {
			t.Fatal(err)
		}
		prepared := filepath.Join(t.TempDir(), "verified-model")
		if out, err := exec.Command(python, install, "--source-dir", source, "--model-dir", prepared).CombinedOutput(); err != nil {
			t.Fatalf("verified setup failed: %v %s", err, out)
		}
		if _, err := os.Stat(buildMarker); !os.IsNotExist(err) {
			t.Fatal("installer executed remote packaging code")
		}
		if _, err := os.Stat(filepath.Join(prepared, "pyproject.toml")); !os.IsNotExist(err) {
			t.Fatal("packaging code entered runtime bundle")
		}
		codePath := filepath.Join(source, "julia", "__init__.py")
		originalCode, err := os.ReadFile(codePath)
		if err != nil {
			t.Fatal(err)
		}
		// Break the fixture hardlink before altering it; never modify the source checkpoint.
		if err := os.Remove(codePath); err != nil {
			t.Fatal(err)
		}
		tampered := append(append([]byte{}, originalCode...), []byte(backend)...)
		if err := os.WriteFile(codePath, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		rejected := filepath.Join(t.TempDir(), "rejected-model")
		out, err := exec.Command(python, install, "--source-dir", source, "--model-dir", rejected).CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("integrity mismatch")) {
			t.Fatal("altered runtime source was not rejected")
		}
		if _, err := os.Stat(rejected); !os.IsNotExist(err) {
			t.Fatal("installer published a partial invalid bundle")
		}
		auditMarker := filepath.Join(t.TempDir(), "environment-audited")
		poisonDir := t.TempDir()
		startupMarker := filepath.Join(t.TempDir(), "startup-executed")
		poison := fmt.Sprintf("from pathlib import Path\nPath(%q).write_text('inherited Python import hook')\n", startupMarker)
		if err := os.WriteFile(filepath.Join(poisonDir, "sitecustomize.py"), []byte(poison), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DATABASE_URL", "integration-only-secret")
		t.Setenv("CUSTOM_SERVICE_SECRET", "integration-only-secret")
		t.Setenv("HF_TOKEN", "integration-only-token")
		t.Setenv("PYTHONPATH", poisonDir)
		wrapper := filepath.Join(t.TempDir(), "audit-real-classifier.py")
		code := fmt.Sprintf(`import os, runpy, sys, time
from pathlib import Path
for name in ['DATABASE_URL','TEST_DATABASE_URL','CUSTOM_SERVICE_SECRET','HF_TOKEN','PYTHONPATH','PYTHONSTARTUP']:
    assert name not in os.environ, 'service environment leaked'
assert Path.cwd().resolve() == Path(os.environ['HOME']).resolve() == Path(os.environ['TMPDIR']).resolve()
assert os.environ['HF_HUB_OFFLINE'] == os.environ['TRANSFORMERS_OFFLINE'] == '1'
Path(%q).write_text('isolated')
# Exercise real inference after a cold start beyond the old HTTP/tool budget.
time.sleep(31)
sys.path.insert(0, %q)
runpy.run_path(%q, run_name='__main__')
`, auditMarker, filepath.Dir(script), script)
		if err := os.WriteFile(wrapper, []byte(code), 0600); err != nil {
			t.Fatal(err)
		}
		// Expire a real model invocation before startup, through authenticated MCP.
		timeoutClient := issue("timeout-"+uuid.NewString(), "", true, "read", "submit", "graph:write")
		_, timeoutFinding := create(timeoutClient, "timeout")
		timeoutArgs := writeArgs()
		timeoutArgs["finding_id"] = timeoutFinding.ID
		timeoutArgs["expected_version"] = timeoutFinding.Version
		timeoutArgs["expected_classification_version"] = 0
		eng.Classifier = classifier.Command{Path: python, Args: []string{script, "--model-dir", prepared}, Timeout: time.Nanosecond}
		expired := timeoutClient.call(t, "classify_finding", timeoutArgs)
		failure(t, expired)
		if !bytes.Contains(expired.Result.Content, []byte("local_classifier_timeout")) {
			t.Fatal("deadline was not distinguished from startup failure")
		}
		failure(t, timeoutClient.call(t, "get_finding_classification", map[string]any{"intent": "Ensure timeout persisted no classification.", "finding_id": timeoutFinding.ID}))
		model = prepared
		eng.Classifier = classifier.Command{Path: python, Args: []string{wrapper, "--model-dir", model}, Timeout: 90 * time.Second}

		assigned = c.record(t, "classify_finding", modelArgs)
		if _, err := os.Stat(auditMarker); err != nil {
			t.Fatal("actual model did not pass environment audit")
		}
		if _, err := os.Stat(startupMarker); !os.IsNotExist(err) {
			t.Fatal("inherited Python import hook ran")
		}
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
		if cl.Method != "model_suggested" || cl.Status != "suggested" || len(cl.TypeIDs) != 1 || cl.SelectionPolicy != engine.PrimaryTypeSelectionPolicy {
			t.Fatal("model result treated as accepted classification")
		}
		if cl.Confidence != cl.Model.Scores[cl.TypeIDs[0]] || cl.BelowThreshold != (cl.Confidence < cl.Threshold) {
			t.Fatal("best-match confidence metadata is inconsistent")
		}
		for _, score := range cl.Model.Scores {
			if score > cl.Confidence {
				t.Fatal("model suggestion did not select the highest-scoring category")
			}
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
		if err := os.WriteFile(filepath.Join(prepared, "julia", "__init__.py"), tampered, 0600); err != nil {
			t.Fatal(err)
		}
		eng.Classifier = classifier.Command{Path: python, Args: []string{script, "--model-dir", prepared}}
		failureClient := issue("failure-"+uuid.NewString(), "", true, "read", "submit", "graph:write")
		_, failureFinding := create(failureClient, "runtime-failure")
		failing := writeArgs()
		failing["finding_id"] = failureFinding.ID
		failing["expected_version"] = failureFinding.Version
		failing["expected_classification_version"] = 0
		failed := failureClient.call(t, "classify_finding", failing)
		failure(t, failed)
		if !bytes.Contains(failed.Result.Content, []byte("local_classifier_unavailable")) {
			t.Fatal("runtime integrity failure was not exercised")
		}
		if _, err := os.Stat(buildMarker); !os.IsNotExist(err) {
			t.Fatal("unverified model source executed")
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
