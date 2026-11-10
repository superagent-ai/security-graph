// Package demoseed creates additive synthetic data using real authenticated MCP
// workflows. Direct database writes are limited to issuing/revoking seed keys.
package demoseed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type Config struct {
	Organization                       string
	Findings, Assets, Reports, Workers int
}
type Summary struct {
	Organization       string `json:"organization"`
	Dataset            string `json:"dataset"`
	Assets             int    `json:"assets"`
	Reports            int    `json:"reports"`
	Findings           int    `json:"findings"`
	Agents             int    `json:"agents"`
	Classifications    int    `json:"classifications"`
	AssetRelationships int    `json:"asset_relationships"`
}

func (c Config) Validate() error {
	if !regexp.MustCompile(`^demo-[a-z0-9][a-z0-9-]{0,62}$`).MatchString(c.Organization) {
		return errors.New("seed organization must start with demo- and contain only lowercase letters, digits, or hyphens (maximum 68 characters)")
	}
	if c.Findings < 1 || c.Findings > 100000 || c.Assets < 1 || c.Assets > 10000 || c.Reports < 1 || c.Reports > 10000 || c.Workers < 1 || c.Workers > 16 {
		return errors.New("seed limits: findings 1..100000, assets/reports 1..10000, workers 1..16")
	}
	return nil
}
func (c Config) dataset() string {
	// Worker count does not affect fixture content or retry identity.
	raw, _ := json.Marshal(struct{ Version, Findings, Assets, Reports int }{1, c.Findings, c.Assets, c.Reports})
	sum := sha256.Sum256(raw)
	return "v1-" + hex.EncodeToString(sum[:8])
}
func Run(ctx context.Context, db *postgres.Store, c Config, progress io.Writer) (out Summary, err error) {
	if err = c.Validate(); err != nil {
		return
	}
	if db.Native != nil {
		return out, errors.New("demo seed supports standalone storage only")
	}
	dataset := c.dataset()
	prefix := "demo-seed/" + dataset
	out = Summary{Organization: c.Organization, Dataset: dataset, Assets: c.Assets, Reports: c.Reports, Findings: c.Findings, Agents: min(len(agents), c.Reports), Classifications: c.Findings}
	if progress == nil {
		progress = io.Discard
	}
	var progressMu sync.Mutex
	logProgress := func(format string, values ...any) {
		progressMu.Lock()
		defer progressMu.Unlock()
		fmt.Fprintf(progress, format, values...)
	}
	// The server is private to this command; all principals use the normal bearer
	// authenticator and shared tool registry rather than bypassing the engine.
	listener, er := net.Listen("tcp", "127.0.0.1:0")
	if er != nil {
		return out, errors.New("start private seed MCP listener")
	}
	api := &http.Server{Handler: server.Handler(&engine.Engine{Store: db}, db, "demo-seed"), ReadHeaderTimeout: 5 * time.Second}
	defer api.Close()
	go func() { _ = api.Serve(listener) }()
	defer listener.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Timeout: 35 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hashes := []string{}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if len(hashes) > 0 {
			if _, cleanupErr := db.Pool.Exec(cleanup, "UPDATE security_graph.credentials SET revoked_at=now() WHERE organization_id=$1 AND key_hash=ANY($2::text[]) AND revoked_at IS NULL", c.Organization, hashes); cleanupErr != nil {
				err = errors.Join(err, errors.New("could not revoke temporary seed keys; they expire after two hours"))
			}
		}
	}()
	issue := func(actor string, scopes []string) (client, error) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return client{}, errors.New("generate temporary seed credential")
		}
		token := "sg_" + base64.RawURLEncoding.EncodeToString(raw)
		principal := storage.Principal{OrganizationID: c.Organization, ActorID: prefix + "/" + actor, Scopes: scopes, AllAssets: true}
		if err := db.IssueKey(ctx, token, principal, time.Now().Add(2*time.Hour)); err != nil {
			return client{}, errors.New("issue demo credential; apply standalone migrations before seeding")
		}
		hash := sha256.Sum256([]byte(token))
		hashes = append(hashes, hex.EncodeToString(hash[:]))
		return client{endpoint: "http://" + listener.Addr().String() + "/mcp", token: token, http: httpClient}, nil
	}
	coordinator, er := issue("coordinator", []string{"read", "graph:write"})
	if er != nil {
		return out, er
	}
	reviewer, er := issue("reviewer", []string{"read", "disposition"})
	if er != nil {
		return out, er
	}
	clients := make([]client, len(agents))
	for i, a := range agents {
		clients[i], er = issue(a.name, []string{"read", "submit", "graph:write"})
		if er != nil {
			return out, er
		}
	}
	args := func(stage string, index int) map[string]any {
		// Keep the original purpose stable for existing seed idempotency receipts.
		return map[string]any{"intent": "Populate clearly labeled synthetic demo data for control panel and graph exploration.", "idempotency_key": prefix + "/" + stage + fmt.Sprintf("/%06d", index)}
	}
	assetID := func(i int) string { return "demo/" + dataset + "/" + assetSlug(i) }
	for i := 0; i < c.Assets; i++ {
		a := args("asset", i)
		a["asset_id"] = assetID(i)
		a["name"] = "[DEMO] " + assetSlug(i)
		a["type"] = []string{"repository", "web_app", "service", "agent", "package", "datastore"}[i%6]
		a["locator"] = "https://example.invalid/demo/" + assetSlug(i)
		if _, er = coordinator.record(ctx, "create_asset", a); er != nil {
			return out, er
		}
	}
	edgeIndex := 0
	seenEdges := map[string]bool{}
	link := func(source, target int, kind string) error {
		key := fmt.Sprintf("%d/%s/%d", source, kind, target)
		if source == target || seenEdges[key] {
			return nil
		}
		seenEdges[key] = true
		a := args("relationship", edgeIndex)
		a["relationship"] = contracts.Relationship{SourceID: assetID(source), TargetID: assetID(target), Type: kind, Provenance: "SYNTHETIC DEMO: fictional platform architecture, not an observed dependency."}
		if _, er := coordinator.record(ctx, "add_relationship", a); er != nil {
			return er
		}
		edgeIndex++
		return nil
	}
	for i := 0; i < c.Assets; i++ {
		// A high-degree platform node, service clusters, and a dependency ring allow
		// both paged hub exploration and multi-hop traversal at larger scales.
		if er = link(0, i, "depends_on"); er != nil {
			return out, er
		}
		if er = link(i, (i+1)%c.Assets, "calls"); er != nil {
			return out, er
		}
		if er = link((i/10)*10, i, "contains_service"); er != nil {
			return out, er
		}
	}
	out.AssetRelationships = edgeIndex
	logProgress("Demo assets and %d explicit relationships ready. Seeding %d findings across %d reports and %d agents.\n", edgeIndex, c.Findings, c.Reports, out.Agents)
	var completed atomic.Int64
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	failures := make(chan error, 1)
	workflow := func(index int) error {
		agentIndex := index % len(agents)
		producer := clients[agentIndex]
		a := args("report", index)
		a["asset_id"] = assetID(index % c.Assets)
		a["type"] = agents[agentIndex].reportType
		a["target"] = fmt.Sprintf("DEMO %s / %s / run-%04d", agents[agentIndex].name, assetSlug(index%c.Assets), index)
		report, er := producer.record(workerCtx, "create_report", a)
		if er != nil {
			return er
		}
		for i := index; i < c.Findings; i += c.Reports {
			fixture, typeID := syntheticFinding(i, assetID(index%c.Assets))
			a = args("finding", i)
			a["report_id"] = report.ID
			a["finding"] = fixture
			saved, er := producer.record(workerCtx, "submit_finding", a)
			if er != nil {
				return er
			}
			a = args("classification", i)
			a["finding_id"] = saved.ID
			a["expected_version"] = saved.Version
			a["expected_classification_version"] = 0
			a["type_ids"] = []string{typeID}
			a["compliance_ids"] = []string{}
			a["rationale"] = "SYNTHETIC DEMO: illustrative catalog assignment, not verified vulnerability or compliance evidence."
			if _, er = producer.record(workerCtx, "set_finding_classification", a); er != nil {
				return er
			}
			bucket := (i/c.Reports + index*7) % 10
			if index%10 <= 1 {
				bucket = 6 + i%4
			}
			if bucket >= 4 {
				a = args("triage", i)
				a["finding_id"] = saved.ID
				a["expected_version"] = saved.Version
				if bucket < 6 {
					a["triage_status"] = "in_review"
				} else {
					a["triage_status"] = "resolved"
					a["triage_resolution"] = []string{"fixed", "accepted_risk", "false_positive", "wont_fix"}[bucket-6]
				}
				if _, er = reviewer.record(workerCtx, "update_finding_triage", a); er != nil {
					return er
				}
			}
			if count := completed.Add(1); count%250 == 0 || count == int64(c.Findings) {
				logProgress("Demo findings processed: %d/%d\n", count, c.Findings)
			}
		}
		// Leave some assessments running, fail others, and finish the rest using
		// normal lifecycle transitions. Do not assign system-managed triaging.
		if index%10 == 9 {
			return nil
		}
		a = args("finish", index)
		a["report_id"] = report.ID
		a["expected_version"] = report.Version
		a["status"] = "succeeded"
		if index%10 == 8 {
			a["status"] = "failed"
		}
		finished, er := producer.record(workerCtx, "finish_report", a)
		if er != nil {
			return er
		}
		if index%10 == 7 {
			a = args("review", index)
			a["report_id"] = report.ID
			a["expected_version"] = finished.Version
			a["status"] = "completed"
			if _, er = reviewer.record(workerCtx, "update_report_review_status", a); er != nil {
				return er
			}
		}
		return nil
	}
	var group sync.WaitGroup
	for i := 0; i < c.Workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				if er := workflow(index); er != nil {
					select {
					case failures <- er:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
feed:
	for i := 0; i < c.Reports; i++ {
		select {
		case <-workerCtx.Done():
			break feed
		case jobs <- i:
		}
	}
	close(jobs)
	group.Wait()
	select {
	case er := <-failures:
		return out, er
	default:
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}
