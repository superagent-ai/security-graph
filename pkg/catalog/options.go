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
	Query          string `json:"query,omitempty" jsonschema:"Rank IDs, names, descriptions and aliases by relevance. Natural-language keywords need not all match. Exact IDs/names rank first; prefer a specific CWE or short root-cause phrase when refining. Maximum 200 bytes."`
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
	filter := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", optionsSearchVersion, q.Query, q.FrameworkID, q.Limit))))
	offset := 0
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var cur optionsCursor
		if err != nil || json.Unmarshal(raw, &cur) != nil || cur.Version != c.Version || cur.Filter != filter || cur.Offset < 0 {
			return out, fmt.Errorf("invalid catalog cursor or changed filters")
		}
		offset = cur.Offset
	}
	search := newCatalogSearch(c, q.Query)
	linkedTypes := map[string]bool{}
	for _, m := range c.Mappings {
		if q.FrameworkID == "" || strings.HasPrefix(m.Target, q.FrameworkID+":") {
			linkedTypes[m.Source] = true
		}
	}
	types := []Type{}
	typeScores := map[string]float64{}
	for _, t := range c.Types {
		score := search.score(search.types[t.ID])
		if t.Classifiable && !t.Deprecated && (q.FrameworkID == "" || linkedTypes[t.ID]) && score > 0 {
			types = append(types, t)
			typeScores[t.ID] = score
		}
	}
	linkedEntries := map[string]float64{}
	// A vulnerability search also returns its reference mappings. With no query,
	// the compliance inventory is independent of the type inventory.
	if q.Query != "" {
		for _, m := range c.Mappings {
			if score := typeScores[m.Source] * 0.8; score > linkedEntries[m.Target] {
				linkedEntries[m.Target] = score
			}
		}
	}
	entries := []Entry{}
	entryScores := map[string]float64{}
	for _, e := range c.Entries {
		score := max(search.score(search.entries[e.ID]), linkedEntries[e.ID])
		if !e.Deprecated && (q.FrameworkID == "" || e.Framework == q.FrameworkID) && score > 0 {
			entries = append(entries, e)
			entryScores[e.ID] = score
		}
	}
	// Put exact names/IDs before description-only matches; default discovery
	// prioritizes the small OWASP taxonomies over large control indexes.
	sort.SliceStable(types, func(i, j int) bool {
		a, b := typeScores[types[i].ID], typeScores[types[j].ID]
		if a != b {
			return a > b
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
		a, b := entryScores[entries[i].ID], entryScores[entries[j].ID]
		if a != b {
			return a > b
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
