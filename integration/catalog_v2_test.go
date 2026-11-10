package integration_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/superagent-ai/security-graph/pkg/catalog"
)

// Called inside the real authenticated HTTP/PostgreSQL workflow, so discovery,
// selection and graph readback exercise the same public contract as agents.
func catalogV2Discovery(t *testing.T, c client, findingID string) {
	read := func(query map[string]any) catalog.Options {
		t.Helper()
		query["intent"] = "Search the reviewed security vocabulary before assigning a finding."
		r := c.call(t, "get_classification_options", query)
		var page catalog.Options
		if r.Result.IsError || json.Unmarshal(r.Result.Structured, &page) != nil {
			t.Fatalf("invalid catalog options: %s", r.Result.Content)
		}
		return page
	}
	t.Run("bounded complete discovery and filter-bound cursors", func(t *testing.T) {
		types, entries := map[string]bool{}, map[string]bool{}
		cursor := ""
		for page := 0; page < 100; page++ {
			out := read(map[string]any{"limit": 100, "cursor": cursor})
			if out.CatalogVersion != "2" || len(out.Types) > 100 || len(out.Compliance) > 100 || len(out.Frameworks) != 15 {
				t.Fatal("unbounded or incomplete options contract")
			}
			for _, v := range out.Types {
				if types[v.ID] || v.Deprecated || !v.Classifiable {
					t.Fatal("duplicate or unavailable type")
				}
				types[v.ID] = true
			}
			for _, v := range out.Compliance {
				if entries[v.ID] || v.Deprecated {
					t.Fatal("duplicate or retired compliance entry")
				}
				entries[v.ID] = true
			}
			if out.NextCursor == "" {
				if len(types) != out.TypeTotal || len(entries) != out.ComplianceTotal || len(types) != 958 || len(entries) < 3000 {
					t.Fatal("pagination omitted choices")
				}
				break
			}
			if page == 99 {
				t.Fatal("pagination did not terminate")
			}
			if cursor == "" {
				failure(t, c.call(t, "get_classification_options", map[string]any{"intent": "Reject cursor reuse with changed filters.", "query": "SQL", "limit": 100, "cursor": out.NextCursor}))
			}
			cursor = out.NextCursor
		}
		for _, q := range []map[string]any{{"limit": 101}, {"limit": -1}, {"query": strings.Repeat("x", 201)}, {"framework_id": "invented"}, {"cursor": "invalid"}} {
			q["intent"] = "Reject invalid catalog discovery requests."
			failure(t, c.call(t, "get_classification_options", q))
		}
	})
	t.Run("new black-box weaknesses and complete compliance indexes", func(t *testing.T) {
		for query, id := range map[string]string{"clickjacking": "clickjacking", "CWE-770": "unbounded_resource_consumption", "rate limiting": "missing_rate_limiting", "consent": "consent_enforcement_failure", "stale CNAME": "dangling_dns_record"} {
			out := read(map[string]any{"query": query, "limit": 100})
			found := false
			for _, v := range out.Types {
				found = found || v.ID == id
			}
			if !found {
				t.Fatalf("missing %s", id)
			}
		}
		out := read(map[string]any{"query": "nist-800-53:AC-2", "framework_id": "nist-800-53", "limit": 100})
		found := false
		for _, e := range out.Compliance {
			if e.Framework != "nist-800-53" {
				t.Fatal("framework filter leaked unrelated choices")
			}
			found = found || e.ID == "nist-800-53:AC-2"
		}
		if !found {
			t.Fatal("missing NIST control")
		}
		a := writeArgs()
		a["finding_id"] = findingID
		a["expected_version"] = 1
		a["expected_classification_version"] = 0
		a["type_ids"] = []string{"clickjacking"}
		a["compliance_ids"] = []string{"cwe:CWE-1021", "owasp-web:A02", "owasp-asvs:V3.4.6"}
		a["rationale"] = "Demonstrate explicit independent selections and graph persistence; the controls require anti-framing policy; this test does not assert certification."
		saved := c.record(t, "set_finding_classification", a)
		if !bytes.Contains(saved.Data, []byte(`"catalog_version":"2"`)) {
			t.Fatal("new selections saved under historical definitions")
		}
		graph := c.call(t, "get_context", map[string]any{"intent": "Read back selected type and compliance edges.", "entity_id": findingID, "depth": 1, "limit": 100})
		for _, id := range []string{"catalog:v2:type:clickjacking", "catalog:v2:entry:cwe:CWE-1021", "catalog:v2:entry:owasp-web:A02", "catalog:v2:entry:owasp-asvs:V3.4.6"} {
			if !bytes.Contains(graph.Result.Structured, []byte(id)) {
				t.Fatalf("missing assigned node %s", id)
			}
		}
		current, _ := catalog.Load()
		for _, e := range current.Entries {
			if e.Deprecated {
				a = writeArgs()
				a["finding_id"] = findingID
				a["expected_version"] = 1
				a["expected_classification_version"] = saved.Version
				a["type_ids"] = []string{}
				a["compliance_ids"] = []string{e.ID}
				a["rationale"] = "Retired controls must remain unavailable for new assignments."
				failure(t, c.call(t, "set_finding_classification", a))
				break
			}
		}
	})
	t.Run("published releases retain different LLM numbering", func(t *testing.T) {
		for id, name := range map[string]string{"catalog:v1:entry:owasp-llm:LLM06": "Excessive Agency", "catalog:v2:entry:owasp-llm:LLM06": "Unbounded Consumption"} {
			r := c.call(t, "get_context", map[string]any{"intent": "Follow versioned historical framework references.", "entity_id": id, "depth": 1, "limit": 100})
			if r.Result.IsError || !bytes.Contains(r.Result.Structured, []byte(name)) {
				t.Fatalf("release meaning lost: %s", id)
			}
		}
	})
}
