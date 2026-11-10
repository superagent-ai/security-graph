package integration_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// Runs within the authenticated PostgreSQL/HTTP MCP workflow.
func blackBoxWorkflow(t *testing.T, c client) {
	t.Helper()
	tools, err := c.rpc("tools/list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Result.Tools {
		if tool.Name != "submit_finding" {
			continue
		}
		found = true
		schema := tool.InputSchema.Properties["finding"]
		for _, name := range []string{"affected_files", "code_references", "proposed_patch"} {
			if _, ok := schema.Properties[name]; !ok || slices.Contains(schema.Required, name) {
				t.Fatalf("%s must be supported but optional", name)
			}
		}
		if slices.Contains(schema.Properties["policy_verification"].Required, "docs_reviewed") {
			t.Fatal("black-box findings must not require policy documents")
		}
		if _, ok := schema.Properties["code_references_unavailable_reason"]; !ok {
			t.Fatal("missing source evidence explanation schema")
		}
		if _, ok := schema.Properties["policy_verification"].Properties["docs_unavailable_reason"]; !ok {
			t.Fatal("missing policy evidence explanation schema")
		}
	}
	if !found {
		t.Fatal("submit_finding schema missing")
	}
	for _, reportType := range []string{"web_app", "agent", "package", "repository"} {
		t.Run(reportType, func(t *testing.T) {
			a := writeArgs()
			a["asset_id"], a["name"], a["type"], a["locator"] = uuid.NewString(), "Black-box target", reportType, "https://fixture.example.test"
			asset := c.record(t, "create_asset", a)
			a = writeArgs()
			a["asset_id"], a["type"], a["target"] = asset.ID, reportType, "https://fixture.example.test"
			report := c.record(t, "create_report", a)

			blackBox := finding("black-box-tenant-isolation")
			blackBox.AffectedFiles, blackBox.CodeReferences = nil, nil
			blackBox.ProposedPatch = nil
			blackBox.CodeReferencesUnavailableReason = "Unavailable: this assessment had no source-code access."
			blackBox.PolicyVerification.DocsReviewed = nil
			blackBox.PolicyVerification.DocsUnavailableReason = "No policy documents were available."
			blackBox.PolicyVerification.Conclusion = "No policy documents were available. Tenant A accessed tenant B's private fixture record; intended sharing could not be independently checked."
			blackBox.Details = "GET /records/tenant-b-fixture returned another tenant's private record to tenant A. Source code was unavailable."
			blackBox.GitHubAdvisory.Description = strings.ReplaceAll(blackBox.GitHubAdvisory.Description, "Missing tenant predicate.", blackBox.Details)
			blackBox.GitHubAdvisory.Description = strings.ReplaceAll(blackBox.GitHubAdvisory.Description, "Tenant isolation is required.", blackBox.PolicyVerification.Conclusion)
			blackBox.GitHubAdvisory.Description = strings.ReplaceAll(blackBox.GitHubAdvisory.Description, "handler.go:10-12.", blackBox.CodeReferencesUnavailableReason)
			blackBox.GitHubAdvisory.Vulnerabilities = []contracts.Vulnerability{{Package: contracts.Package{Ecosystem: "Other", Name: "https://fixture.example.test"}, VulnerableVersionRange: "Deployed instance at assessment time; version unknown."}}
			payload := func() map[string]any {
				b, err := json.Marshal(blackBox)
				if err != nil {
					t.Fatal(err)
				}
				var f map[string]any
				if err := json.Unmarshal(b, &f); err != nil {
					t.Fatal(err)
				}
				return f
			}
			f := payload()
			for _, name := range []string{"affected_files", "code_references", "proposed_patch"} {
				if _, ok := f[name]; ok {
					t.Fatalf("black-box request unexpectedly supplies %s", name)
				}
			}
			a = writeArgs()
			a["report_id"], a["finding"] = report.ID, f
			saved := c.record(t, "submit_finding", a)
			retry := c.record(t, "submit_finding", a)
			if retry.ID != saved.ID || retry.Version != saved.Version {
				t.Fatal("black-box retry was not idempotent")
			}
			read := c.record(t, "get_finding", map[string]any{"intent": "Retrieve observed black-box evidence.", "finding_id": saved.ID})
			var persisted contracts.Finding
			if err := json.Unmarshal(read.Data, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.Triage.Status != contracts.New || persisted.Triage.VerificationStatus != nil || persisted.Submission.Proof != blackBox.Proof || len(persisted.Submission.CodeReferences) != 0 || len(persisted.Submission.AffectedFiles) != 0 || persisted.Submission.ProposedPatch != nil || len(persisted.Submission.PolicyVerification.DocsReviewed) != 0 {
				t.Fatal("black-box evidence or claim attribution changed on persistence")
			}
			if persisted.Submission.CodeReferencesUnavailableReason != blackBox.CodeReferencesUnavailableReason || persisted.Submission.PolicyVerification.DocsUnavailableReason != blackBox.PolicyVerification.DocsUnavailableReason {
				t.Fatal("unavailable evidence explanations were not persisted")
			}
			for name, mutate := range map[string]func(map[string]any){
				"missing source explanation": func(f map[string]any) { delete(f, "code_references_unavailable_reason") },
				"blank source explanation":   func(f map[string]any) { f["code_references_unavailable_reason"] = " \t" },
				"empty references without explanation": func(f map[string]any) {
					f["code_references"] = []contracts.CodeReference{}
					delete(f, "code_references_unavailable_reason")
				},
				"null references without explanation": func(f map[string]any) {
					f["code_references"] = nil
					delete(f, "code_references_unavailable_reason")
				},
				"empty code references section": func(f map[string]any) {
					f["github_advisory"].(map[string]any)["description"] = strings.ReplaceAll(blackBox.GitHubAdvisory.Description, blackBox.CodeReferencesUnavailableReason, " \t")
				},
				"source explanation outside references section": func(f map[string]any) {
					f["github_advisory"].(map[string]any)["description"] = strings.ReplaceAll(blackBox.GitHubAdvisory.Description, blackBox.CodeReferencesUnavailableReason, "") + "\n" + blackBox.CodeReferencesUnavailableReason
				},
				"policy assertion without availability explanation": func(f map[string]any) {
					p := f["policy_verification"].(map[string]any)
					p["conclusion"] = "This violates policy"
					delete(p, "docs_unavailable_reason")
				},
				"blank policy explanation": func(f map[string]any) { f["policy_verification"].(map[string]any)["docs_unavailable_reason"] = " \t" },
				"empty policy documents without explanation": func(f map[string]any) {
					p := f["policy_verification"].(map[string]any)
					p["docs_reviewed"] = []contracts.PolicyDocument{}
					delete(p, "docs_unavailable_reason")
				},
				"null policy documents without explanation": func(f map[string]any) {
					p := f["policy_verification"].(map[string]any)
					p["docs_reviewed"] = nil
					delete(p, "docs_unavailable_reason")
				},
				"policy explanation missing from conclusion": func(f map[string]any) {
					f["policy_verification"].(map[string]any)["conclusion"] = "This violates policy"
				},
				"invalid source reference": func(f map[string]any) {
					f["code_references"] = []contracts.CodeReference{{File: "handler.go", LineStart: 0, LineEnd: 1, Excerpt: "fixture", Reason: "fixture"}}
				},
				"blank affected file": func(f map[string]any) { f["affected_files"] = []string{" "} },
				"unvalidated patch": func(f map[string]any) {
					f["proposed_patch"] = contracts.ProposedPatch{Summary: "Fixture fix", Diff: "fixture diff", Files: []string{"handler.go"}}
				},
				"empty supplied patch": func(f map[string]any) { f["proposed_patch"] = contracts.ProposedPatch{} },
				"incomplete policy document": func(f map[string]any) {
					f["policy_verification"].(map[string]any)["docs_reviewed"] = []contracts.PolicyDocument{{File: "POLICY.md"}}
				},
				"missing policy conclusion": func(f map[string]any) { f["policy_verification"].(map[string]any)["conclusion"] = " " },
				"missing proof":             func(f map[string]any) { delete(f, "proof") },
				"empty reproduction steps":  func(f map[string]any) { f["reproduction_steps"] = []string{} },
				"missing template section":  func(f map[string]any) { f["github_advisory"].(map[string]any)["description"] = "Unstructured finding" },
			} {
				t.Run(name, func(t *testing.T) {
					bad := payload()
					bad["id"] = uuid.NewString()
					mutate(bad)
					a := writeArgs()
					a["report_id"], a["finding"] = report.ID, bad
					failure(t, c.call(t, "submit_finding", a))
				})
			}
			listed := c.call(t, "list_findings", map[string]any{"intent": "Ensure invalid evidence was not persisted.", "report_id": report.ID})
			var records []storage.Record
			if err := json.Unmarshal(listed.Result.Structured, &records); err != nil || len(records) != 1 || records[0].ID != saved.ID {
				t.Fatalf("unexpected persisted findings: %s", listed.Result.Structured)
			}
			graph := c.call(t, "get_context", map[string]any{"intent": "Retrieve black-box findings through the graph.", "entity_id": asset.ID, "depth": 3, "limit": 100})
			var context engine.ContextResult
			if err := json.Unmarshal(graph.Result.Structured, &context); err != nil || !slices.ContainsFunc(context.Records, func(r storage.Record) bool { return r.ID == saved.ID }) {
				t.Fatal("black-box finding missing from graph")
			}
			a = writeArgs()
			a["report_id"], a["expected_version"], a["status"] = report.ID, report.Version, "succeeded"
			report = c.record(t, "finish_report", a)
			var parent contracts.Report
			if err := json.Unmarshal(report.Data, &parent); err != nil || parent.Status != "in_review" {
				t.Fatal("black-box finding must remain open for review")
			}
			a = writeArgs()
			a["finding_id"], a["expected_version"], a["triage_status"], a["triage_resolution"] = saved.ID, saved.Version, "resolved", "accepted_risk"
			c.record(t, "update_finding_triage", a)
			report = c.record(t, "get_report", map[string]any{"intent": "Check report completion after disposition.", "report_id": report.ID})
			if err := json.Unmarshal(report.Data, &parent); err != nil || parent.Status != "completed" {
				t.Fatal("black-box report lifecycle differs from source-backed reports")
			}
		})
	}
}
