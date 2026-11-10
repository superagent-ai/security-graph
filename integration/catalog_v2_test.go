package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
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
	t.Run("public versioned definitions and conditional cache contract", func(t *testing.T) {
		for _, version := range []string{"", "1", "2"} {
			url := c.url + "/catalog"
			if version != "" {
				url += "?version=" + version
			}
			r, err := http.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			var release catalog.Catalog
			if r.StatusCode != 200 || json.Unmarshal(raw, &release) != nil || release.Validate() != nil {
				t.Fatal("invalid public definitions")
			}
			if (version != "" && release.Version != version) || bytes.Contains(raw, []byte(findingID)) {
				t.Fatal("public catalog mixed versions or tenant content")
			}
			if r.Header.Get("ETag") == "" {
				t.Fatal("missing catalog validator")
			}
			request, _ := http.NewRequest("GET", url, nil)
			request.Header.Set("If-None-Match", r.Header.Get("ETag"))
			cached, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = cached.Body.Close()
			if cached.StatusCode != 304 {
				t.Fatal("immutable cache validation failed")
			}
		}
		r, err := http.Get(c.url + "/catalog?version=missing")
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatal("unknown release must not fall back to current")
		}
	})
	t.Run("legacy full lists and selections retain the original edition", func(t *testing.T) {
		out := read(map[string]any{})
		if out.CatalogVersion != "1" || len(out.Types) != 16 || out.NextCursor != "" {
			t.Fatal("legacy agents received truncated or changed choices")
		}
		a := writeArgs()
		a["finding_id"] = findingID
		a["expected_version"] = 1
		a["expected_classification_version"] = 0
		a["type_ids"] = []string{"excessive_agency"}
		a["compliance_ids"] = []string{"owasp-llm:LLM06"}
		a["rationale"] = "An in-flight legacy agent keeps the exact edition it read."
		saved := c.record(t, "set_finding_classification", a)
		if !bytes.Contains(saved.Data, []byte(`"catalog_version":"1"`)) {
			t.Fatal("legacy save was reinterpreted as the current edition")
		}
		// Explicit releases remain valid even after a newer catalog is current.
		a = writeArgs()
		a["finding_id"] = findingID
		a["expected_version"] = 1
		a["expected_classification_version"] = saved.Version
		a["catalog_version"] = "1"
		a["type_ids"] = []string{"excessive_agency"}
		a["compliance_ids"] = []string{"owasp-llm:LLM06"}
		a["rationale"] = "A versioned agent also keeps the edition it used."
		saved = c.record(t, "set_finding_classification", a)
		if !bytes.Contains(saved.Data, []byte(`"catalog_version":"1"`)) {
			t.Fatal("explicit historical selection changed meaning")
		}
	})
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
		prior := c.record(t, "get_finding_classification", map[string]any{"intent": "Read prior classification version.", "finding_id": findingID})
		a["expected_classification_version"] = prior.Version
		a["type_ids"] = []string{"clickjacking"}
		a["catalog_version"] = "2"
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
		v2, err := catalog.LoadVersion("2")
		if err != nil {
			t.Fatal(err)
		}
		foundDeprecated := false
		for _, e := range v2.Entries {
			if e.Deprecated {
				foundDeprecated = true
				a = writeArgs()
				a["catalog_version"] = v2.Version
				a["finding_id"] = findingID
				a["expected_version"] = 1
				a["expected_classification_version"] = saved.Version
				a["type_ids"] = []string{}
				a["compliance_ids"] = []string{e.ID}
				a["rationale"] = "Retired controls must remain unavailable for new assignments."
				failure(t, c.call(t, "set_finding_classification", a))
				after := c.record(t, "get_finding_classification", map[string]any{"intent": "Verify rejected retired choice preserved the prior assignment.", "finding_id": findingID})
				if after.Version != saved.Version || !bytes.Equal(after.Data, saved.Data) {
					t.Fatal("rejected deprecated entry changed the saved classification")
				}
				break
			}
		}
		if !foundDeprecated {
			t.Fatal("v2 fixture must contain a deprecated entry")
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
