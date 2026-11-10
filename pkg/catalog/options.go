package catalog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// OptionsQuery bounds each independent selection list. Cursors apply to the
// immutable release and exact normalized filters, never to tenant records.
type OptionsQuery struct {
	CatalogVersion string `json:"catalog_version,omitempty" jsonschema:"Optional immutable catalog version; omit to search the current release. Copy the returned catalog_version into every selection."`
	Query          string `json:"query,omitempty" jsonschema:"Search IDs, names, descriptions and aliases (for example clickjacking, CWE-770, SQL injection). Maximum 200 bytes. Refine searches rather than reading the entire catalog."`
	FrameworkID    string `json:"framework_id,omitempty" jsonschema:"Optional framework ID from frameworks; filter compliance and types with relevance links to that framework."`
	Limit          int    `json:"limit,omitempty" jsonschema:"Maximum choices per list, default 25, maximum 100."`
	Cursor         string `json:"cursor,omitempty" jsonschema:"Resume next_cursor with the same query, framework_id and limit."`
}
type Options struct {
	CatalogVersion  string      `json:"catalog_version"`
	Types           []Type      `json:"vulnerability_types"`
	Compliance      []Entry     `json:"compliance"`
	Frameworks      []Framework `json:"frameworks"`
	Mappings        []Mapping   `json:"mappings"`
	TypeTotal       int         `json:"vulnerability_type_total"`
	ComplianceTotal int         `json:"compliance_total"`
	NextCursor      string      `json:"next_cursor,omitempty"`
}
type optionsCursor struct {
	Version, Filter string
	Offset          int
}

// A continuation stays on the release its first page read, even if the service
// is upgraded between requests. Explicit conflicting versions still fail below.
func OptionsCatalog(q OptionsQuery) (Catalog, error) {
	version := q.CatalogVersion
	if version == "" && q.Cursor != "" {
		if len(q.Cursor) > 512 {
			return Catalog{}, fmt.Errorf("invalid catalog cursor")
		}
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var cursor optionsCursor
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Version == "" {
			return Catalog{}, fmt.Errorf("invalid catalog cursor")
		}
		version = cursor.Version
	}
	if version == "" {
		return Load()
	}
	return LoadVersion(version)
}

func (c Catalog) Options(q OptionsQuery) (Options, error) {
	out := Options{CatalogVersion: c.Version, Types: []Type{}, Compliance: []Entry{}, Frameworks: c.Frameworks, Mappings: []Mapping{}}
	q.Query = strings.ToLower(strings.TrimSpace(q.Query))
	if q.Limit == 0 {
		q.Limit = 25
	}
	if q.Limit < 1 || q.Limit > 100 || len(q.Query) > 200 || len(q.Cursor) > 512 {
		return out, fmt.Errorf("invalid catalog query bounds")
	}
	if q.FrameworkID != "" {
		found := false
		for _, f := range c.Frameworks {
			if f.ID == q.FrameworkID {
				found = true
			}
		}
		if !found {
			return out, fmt.Errorf("unknown framework_id")
		}
	}
	filter := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", q.Query, q.FrameworkID, q.Limit))))
	offset := 0
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var cur optionsCursor
		if err != nil || json.Unmarshal(raw, &cur) != nil || cur.Version != c.Version || cur.Filter != filter || cur.Offset < 0 {
			return out, fmt.Errorf("invalid catalog cursor or changed filters")
		}
		offset = cur.Offset
	}
	match := func(text string) bool {
		text = strings.ToLower(text)
		for _, word := range strings.Fields(q.Query) {
			if !strings.Contains(text, word) {
				return false
			}
		}
		return true
	}
	linkedTypes := map[string]bool{}
	for _, m := range c.Mappings {
		if q.FrameworkID == "" || strings.HasPrefix(m.Target, q.FrameworkID+":") {
			linkedTypes[m.Source] = true
		}
	}
	types := []Type{}
	typeIDs := map[string]bool{}
	for _, t := range c.Types {
		if t.Classifiable && !t.Deprecated && (q.FrameworkID == "" || linkedTypes[t.ID]) && match(t.ID+" "+t.Name+" "+t.Description+" "+t.CWEID+" "+strings.Join(t.Aliases, " ")) {
			types = append(types, t)
			typeIDs[t.ID] = true
		}
	}
	linkedEntries := map[string]bool{}
	// A vulnerability search also returns its reference mappings. With no query,
	// the compliance inventory is independent of the type inventory.
	if q.Query != "" {
		for _, m := range c.Mappings {
			if typeIDs[m.Source] {
				linkedEntries[m.Target] = true
			}
		}
	}
	entries := []Entry{}
	for _, e := range c.Entries {
		if !e.Deprecated && (q.FrameworkID == "" || e.Framework == q.FrameworkID) && (match(e.ID+" "+e.Name+" "+e.Description) || linkedEntries[e.ID]) {
			entries = append(entries, e)
		}
	}
	// Put exact names/IDs before description-only matches; default discovery
	// prioritizes the small OWASP taxonomies over large control indexes.
	rank := func(id, name string) int {
		if q.Query != "" && (strings.EqualFold(id, q.Query) || strings.EqualFold(name, q.Query)) {
			return 0
		}
		return 1
	}
	sort.SliceStable(types, func(i, j int) bool {
		a, b := rank(types[i].ID, types[i].Name), rank(types[j].ID, types[j].Name)
		if a != b {
			return a < b
		}
		return types[i].ID < types[j].ID
	})
	priority := func(e Entry) int {
		switch e.Framework {
		case "owasp-web":
			return 0
		case "owasp-api":
			return 1
		case "owasp-llm":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := rank(entries[i].ID, entries[i].Name), rank(entries[j].ID, entries[j].Name)
		if a != b {
			return a < b
		}
		if priority(entries[i]) != priority(entries[j]) {
			return priority(entries[i]) < priority(entries[j])
		}
		return entries[i].ID < entries[j].ID
	})
	out.TypeTotal, out.ComplianceTotal = len(types), len(entries)
	total := max(len(types), len(entries))
	if offset > total {
		return out, fmt.Errorf("catalog cursor outside result")
	}
	if offset < len(types) {
		out.Types = types[offset:min(offset+q.Limit, len(types))]
	}
	if offset < len(entries) {
		out.Compliance = entries[offset:min(offset+q.Limit, len(entries))]
	}
	visibleTypes, visibleEntries := map[string]bool{}, map[string]bool{}
	for _, t := range out.Types {
		visibleTypes[t.ID] = true
	}
	for _, e := range out.Compliance {
		visibleEntries[e.ID] = true
	}
	for _, m := range c.Mappings {
		if visibleTypes[m.Source] && visibleEntries[m.Target] {
			out.Mappings = append(out.Mappings, m)
		}
	}
	if offset+q.Limit < total {
		raw, _ := json.Marshal(optionsCursor{Version: c.Version, Filter: filter, Offset: offset + q.Limit})
		out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, nil
}
