package integration_test

import (
	"context"
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

// Exercise the native intent queue against real PostgreSQL, with canonical
// findings created through authenticated HTTP MCP. Model admission is verified
// separately with real Julia; no classifier or queue implementation is mocked.
func TestClassificationQueuePostgresWorkflow(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("run make integration")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil || !strings.Contains(cfg.ConnConfig.Database, "test") {
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
	// The intent table is installed by the App migration in native deployments.
	// Install that storage contract in this disposable standalone test database.
	_, err = db.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS security_graph.classification_jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL,
 finding_id text NOT NULL,asset_id text NOT NULL,finding_version bigint NOT NULL,
 status text NOT NULL DEFAULT 'pending',attempts integer NOT NULL DEFAULT 0,
 retry_at timestamptz NOT NULL DEFAULT now(),lease_token uuid,lease_until timestamptz,error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,finding_id,finding_version));
 CREATE UNIQUE INDEX IF NOT EXISTS classification_jobs_one_active_org ON security_graph.classification_jobs(organization_id) WHERE status='processing'`)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(server.Handler(&engine.Engine{Store: db}, db, "queue-integration"))
	defer api.Close()
	q := superagent.ClassificationQueue{Store: db}
	fixture := func(t *testing.T) string {
		t.Helper()
		org, token := uuid.NewString(), "sg_"+uuid.NewString()
		if err := db.IssueKey(ctx, token, storage.Principal{OrganizationID: org, ActorID: "queue-integration", AllAssets: true, Scopes: []string{"read", "submit", "graph:write"}}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.Pool.Exec(ctx, "DELETE FROM security_graph.classification_jobs WHERE organization_id=$1", org)
		})
		c := client{api.URL, token}
		a := writeArgs()
		a["asset_id"], a["name"], a["type"], a["locator"] = org, "Queue fixture", "repository", "https://example.test/queue"
		asset := c.record(t, "create_asset", a)
		r := writeArgs()
		r["asset_id"], r["type"], r["target"] = asset.ID, "repository", "https://example.test/queue"
		report := c.record(t, "create_report", r)
		f := writeArgs()
		f["report_id"], f["finding"] = report.ID, finding(uuid.NewString())
		record := c.record(t, "submit_finding", f)
		if _, err := db.Pool.Exec(ctx, "INSERT INTO security_graph.classification_jobs(organization_id,finding_id,asset_id,finding_version) VALUES($1,$2,$3,$4)", org, record.ID, asset.ID, record.Version); err != nil {
			t.Fatal(err)
		}
		return record.ID
	}
	claim := func(t *testing.T, id string) *engine.ClassificationJob {
		t.Helper()
		j, err := q.Claim(ctx)
		if err != nil || j == nil || j.FindingID != id {
			t.Fatalf("claim: job=%+v err=%v", j, err)
		}
		var code *string
		if err := db.Pool.QueryRow(ctx, "SELECT error_code FROM security_graph.classification_jobs WHERE id=$1", j.ID).Scan(&code); err != nil || code != nil {
			t.Fatal("claim retained an old error", err)
		}
		return j
	}
	ready := func(t *testing.T, id string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, "UPDATE security_graph.classification_jobs SET retry_at=now() WHERE finding_id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	state := func(t *testing.T, id string, attempts int, seconds float64) {
		t.Helper()
		var got int
		var delay float64
		if err := db.Pool.QueryRow(ctx, "SELECT attempts,extract(epoch FROM retry_at-updated_at)::float8 FROM security_graph.classification_jobs WHERE finding_id=$1", id).Scan(&got, &delay); err != nil {
			t.Fatal(err)
		}
		if got != attempts || delay != seconds {
			t.Fatalf("attempts=%d delay=%f; want attempts=%d delay=%f", got, delay, attempts, seconds)
		}
	}
	t.Run("capacity deferrals preserve failure budget and use actual availability", func(t *testing.T) {
		id := fixture(t)
		j := claim(t, id)
		for range 3 {
			j.RetryAfter = 1500 * time.Millisecond
			if err := q.Finish(ctx, j, "pending", "classifier_capacity"); err != nil {
				t.Fatal(err)
			}
			state(t, id, 0, 2)
			ready(t, id)
			j = claim(t, id)
		}
		if err := q.Finish(ctx, j, "pending", "classifier_timeout"); err != nil {
			t.Fatal(err)
		}
		state(t, id, 1, 60)
		ready(t, id)
		j = claim(t, id)
		j.RetryAfter = 37 * time.Second
		if err := q.Finish(ctx, j, "pending", "classifier_capacity"); err != nil {
			t.Fatal(err)
		}
		state(t, id, 1, 37)
		ready(t, id)
		j = claim(t, id)
		if err := q.Finish(ctx, j, "pending", "classifier_unavailable"); err != nil {
			t.Fatal(err)
		}
		state(t, id, 2, 120)
	})
	t.Run("expired leases are recovered and stale completion stays fenced", func(t *testing.T) {
		id := fixture(t)
		old := claim(t, id)
		if _, err := db.Pool.Exec(ctx, "UPDATE security_graph.classification_jobs SET lease_until=now()-interval '1 second' WHERE id=$1", old.ID); err != nil {
			t.Fatal(err)
		}
		current := claim(t, id)
		if old.Lease == current.Lease {
			t.Fatal("lease was not replaced")
		}
		old.NextVersion = old.FindingVersion + 1
		if err := q.Finish(ctx, old, "completed", ""); err != nil {
			t.Fatal(err)
		}
		var active bool
		var rows int
		if err := db.Pool.QueryRow(ctx, "SELECT status='processing' AND lease_token=$2 FROM security_graph.classification_jobs WHERE id=$1", current.ID, current.Lease).Scan(&active); err != nil || !active {
			t.Fatal("stale completion changed current claim", err)
		}
		if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM security_graph.classification_jobs WHERE finding_id=$1", id).Scan(&rows); err != nil || rows != 1 {
			t.Fatal("stale lease enqueued a new source version", err)
		}
		if err := q.Finish(ctx, current, "completed", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("deferred tenant leaves another tenant runnable", func(t *testing.T) {
		id := fixture(t)
		j := claim(t, id)
		j.RetryAfter = 45 * time.Second
		if err := q.Finish(ctx, j, "pending", "classifier_capacity"); err != nil {
			t.Fatal(err)
		}
		other := fixture(t)
		next := claim(t, other)
		if err := q.Finish(ctx, next, "completed", ""); err != nil {
			t.Fatal(err)
		}
		state(t, id, 0, 45)
	})
}
