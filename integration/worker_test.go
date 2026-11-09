package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/classifier"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// Real model processes, authenticated HTTP MCP, and PostgreSQL throughout.
// The trusted wrapper records process loads and injects transport failures only
// after real inference, so no synthetic model substitutes for Julia.
func TestResidentJuliaMCPWorkflow(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	python, model := os.Getenv("JULIA_PYTHON"), os.Getenv("JULIA_MODEL_DIR")
	if url == "" || python == "" || model == "" {
		if os.Getenv("REQUIRE_JULIA") == "1" {
			t.Fatal("resident integration requires PostgreSQL and Julia")
		}
		t.Skip("run make integration with Julia configured")
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
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../scripts/julia/classify.py")
	if err != nil {
		t.Fatal(err)
	}
	audit, mode := filepath.Join(t.TempDir(), "events"), filepath.Join(t.TempDir(), "mode")
	wrapper := filepath.Join(t.TempDir(), "audited-worker.py")
	code := fmt.Sprintf(`import json, os, runpy, sys, time
from pathlib import Path
for name in ['DATABASE_URL','TEST_DATABASE_URL','HF_TOKEN','CUSTOM_SERVICE_SECRET','PYTHONPATH']:
    assert name not in os.environ
assert Path.cwd().resolve() == Path(os.environ['HOME']).resolve() == Path(os.environ['TMPDIR']).resolve()
sys.path.insert(0, %q)
from bundle import verify_bundle
verify_bundle(Path(%q))
sys.path.insert(0, %q)
import julia
def event(kind):
    with open(%q, 'a') as log:
        log.write(json.dumps({'event':kind,'pid':os.getpid(),'dir':str(Path.cwd())})+'\n')
load = julia.load_model
def audited_load(*args, **kwargs):
    assert kwargs['encoding_cache'] == kwargs['token_cache'] == 0
    model = load(*args, **kwargs)
    clear = model.clear_cache
    def audited_clear():
        clear()
        assert not model._encoded and not model._tokens.cache
        event('cleared')
    model.clear_cache = audited_clear
    event('loaded')
    return model
julia.load_model = audited_load
import classify
respond = classify.respond
def audited_respond(value):
    if 'result' in value:
        action = Path(%q).read_text() if Path(%q).exists() else ''
        event('reply')
        if action == 'delay': time.sleep(30)
        if action == 'wrong-id': value['id'] += 1
        if action == 'oversize': value['extra'] = 'x' * 70000
        if action == 'oversize':
            sys.stdout.write(json.dumps(value)+'\n'); sys.stdout.flush(); return
    respond(value)
classify.respond = audited_respond
classify.main()
`, filepath.Dir(script), model, model, audit, mode, mode)
	if err := os.WriteFile(wrapper, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTOM_SERVICE_SECRET", "integration-only-secret")
	worker := classifier.NewWorker(ctx, classifier.Command{Path: python, Args: []string{wrapper, "--model-dir", model, "--worker"}, Timeout: 90 * time.Second})
	eng := &engine.Engine{Store: db, Classifier: worker}
	api := httptest.NewServer(server.Handler(eng, db, "resident-integration"))
	defer func() { _ = worker.Close(); api.Close() }()
	type event struct {
		Event string `json:"event"`
		PID   int    `json:"pid"`
		Dir   string `json:"dir"`
	}
	events := func(kind string) []event {
		b, _ := os.ReadFile(audit)
		var rows []event
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var e event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatal(err)
			}
			if e.Event == kind {
				rows = append(rows, e)
			}
		}
		return rows
	}
	wait := func(timeout time.Duration, label string, predicate func() bool) {
		deadline := time.Now().Add(timeout)
		for !predicate() {
			if time.Now().After(deadline) {
				t.Fatal("worker lifecycle did not settle: " + label)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	fixture := func(reservedMarker ...bool) (client, storage.Record, map[string]any) {
		org, token := "resident-"+uuid.NewString(), "sg_"+uuid.NewString()
		if err := db.IssueKey(ctx, token, storage.Principal{OrganizationID: org, ActorID: uuid.NewString(), AllAssets: true, Scopes: []string{"read", "submit", "graph:write"}}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		c := client{api.URL, token}
		a := writeArgs()
		a["asset_id"], a["name"], a["type"], a["locator"] = org, "Resident fixture", "repository", "https://example.test/resident"
		asset := c.record(t, "create_asset", a)
		r := writeArgs()
		r["asset_id"], r["type"], r["target"] = asset.ID, "repository", "https://example.test/resident"
		report := c.record(t, "create_report", r)
		f := writeArgs()
		submission := finding(uuid.NewString())
		if len(reservedMarker) > 0 {
			submission.Details += " <mask>"
		}
		f["report_id"], f["finding"] = report.ID, submission
		stored := c.record(t, "submit_finding", f)
		args := writeArgs()
		args["finding_id"], args["expected_version"], args["expected_classification_version"] = stored.ID, stored.Version, 0
		return c, stored, args
	}
	classify := func(c client, args map[string]any) storage.Record {
		start := time.Now()
		r := c.record(t, "classify_finding", args)
		var assignment engine.Classification
		if json.Unmarshal(r.Data, &assignment) != nil || assignment.Model == nil || len(assignment.Model.Scores) != 16 || assignment.Method != "model_suggested" || len(assignment.TypeIDs) != 1 || assignment.SelectionPolicy != engine.PrimaryTypeSelectionPolicy {
			t.Fatal("missing real model scores/provenance")
		}
		t.Logf("Resident Julia MCP request: %s", time.Since(start))
		return r
	}

	first, _, firstArgs := fixture()
	assigned := classify(first, firstArgs)
	second, _, secondArgs := fixture()
	classify(second, secondArgs)
	loads := events("loaded")
	if len(loads) != 1 || len(events("cleared")) != 2 {
		t.Fatal("model reloaded or request caches not cleared")
	}
	// Strict evidence rejection clears caches but keeps the healthy model loaded.
	rejected, rejectedFinding, rejectedArgs := fixture(true)
	failure(t, rejected.call(t, "classify_finding", rejectedArgs))
	failure(t, rejected.call(t, "get_finding_classification", map[string]any{"intent": "Check rejected evidence saved no assignment.", "finding_id": rejectedFinding.ID}))
	healthy, _, healthyArgs := fixture()
	classify(healthy, healthyArgs)
	if len(events("loaded")) != 1 {
		t.Fatal("rejected evidence forced model reload")
	}
	// A durable idempotent replay must work even with the optional model offline.
	eng.Classifier = nil
	if replay := first.record(t, "classify_finding", firstArgs); replay.Version != assigned.Version || string(replay.Data) != string(assigned.Data) {
		t.Fatal("offline replay lost original result")
	}
	eng.Classifier = worker

	// Reap an idle crashed child and recover on the next real tenant request.
	process, _ := os.FindProcess(loads[0].PID)
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	wait(10*time.Second, "idle crash", func() bool { return syscall.Kill(loads[0].PID, 0) != nil })
	third, _, thirdArgs := fixture()
	classify(third, thirdArgs)
	if len(events("loaded")) != 2 {
		t.Fatal("crashed worker not replaced")
	}

	// Cancel after real inference but before its delayed response. The cancelled
	// assignment must never commit, and the late frame must never reach a tenant.
	if err := os.WriteFile(mode, []byte("delay"), 0600); err != nil {
		t.Fatal(err)
	}
	cancelClient, cancelFinding, cancelArgs := fixture()
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	before := len(events("reply"))
	pending := make(chan error, 1)
	go func() {
		r, err := cancelClient.rpcContext(requestCtx, "tools/call", map[string]any{"name": "classify_finding", "arguments": cancelArgs})
		if err == nil {
			err = fmt.Errorf("request completed before cancellation: error=%s result=%s content=%s", r.Error, r.Result.Structured, r.Result.Content)
		}
		pending <- err
	}()
	wait(90*time.Second, "real inference response", func() bool {
		select {
		case err := <-pending:
			t.Fatal(err)
		default:
		}
		return len(events("reply")) > before
	})
	cancel()
	if err := <-pending; err == nil {
		t.Fatal("cancelled HTTP call succeeded")
	}
	last := events("loaded")[1]
	wait(10*time.Second, "cancelled process exit", func() bool { return syscall.Kill(last.PID, 0) != nil })
	_ = os.Remove(mode)
	failure(t, cancelClient.call(t, "get_finding_classification", map[string]any{"intent": "Check cancelled inference saved no assignment.", "finding_id": cancelFinding.ID}))
	fourth, _, fourthArgs := fixture()
	classify(fourth, fourthArgs)
	if len(events("loaded")) != 3 {
		t.Fatal("cancelled process was reused")
	}

	for _, fault := range []string{"wrong-id", "oversize"} {
		if err := os.WriteFile(mode, []byte(fault), 0600); err != nil {
			t.Fatal(err)
		}
		c, f, args := fixture()
		failure(t, c.call(t, "classify_finding", args))
		failure(t, c.call(t, "get_finding_classification", map[string]any{"intent": "Check invalid model frame saved no assignment.", "finding_id": f.ID}))
		_ = os.Remove(mode)
		c, _, args = fixture()
		classify(c, args)
	}
	// Service shutdown interrupts an active real inference response, too.
	if err := os.WriteFile(mode, []byte("delay"), 0600); err != nil {
		t.Fatal(err)
	}
	closingClient, closingFinding, closingArgs := fixture()
	before = len(events("reply"))
	type finished struct {
		result rpcResult
		err    error
	}
	closing := make(chan finished, 1)
	go func() {
		r, err := closingClient.rpc("tools/call", map[string]any{"name": "classify_finding", "arguments": closingArgs})
		closing <- finished{r, err}
	}()
	wait(90*time.Second, "real inference response", func() bool { return len(events("reply")) > before })
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	completed := <-closing
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	failure(t, completed.result)
	failure(t, closingClient.call(t, "get_finding_classification", map[string]any{"intent": "Check shutdown saved no assignment.", "finding_id": closingFinding.ID}))
	for _, loaded := range events("loaded") {
		if syscall.Kill(loaded.PID, 0) == nil {
			t.Fatal("worker child survived Close")
		}
		if _, err := os.Stat(loaded.Dir); !os.IsNotExist(err) {
			t.Fatal("worker private home survived Close")
		}
	}
	if _, err := worker.Classify(ctx, classifier.Request{}); err == nil {
		t.Fatal("closed worker restarted")
	}
}
