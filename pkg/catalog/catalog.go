// Package catalog owns the immutable, reviewed classification vocabulary.
// Catalog records are public definitions, never a second store of tenant data.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

//go:embed v*.json
var files embed.FS

type Type struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Aliases         []string `json:"aliases"`
	Parents         []string `json:"parents"`
	Classifiable    bool     `json:"classifiable"`
	Deprecated      bool     `json:"deprecated"`
	CWEID           string   `json:"cwe_id,omitempty"`
	SourceURL       string   `json:"source_url,omitempty"`
	MappingGuidance string   `json:"mapping_guidance,omitempty"`
}
type Framework struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Release    string `json:"release"`
	SourceURL  string `json:"source_url"`
	Kind       string `json:"kind,omitempty"`
	Coverage   string `json:"coverage,omitempty"`
	LicenseURL string `json:"license_url,omitempty"`
	EntryCount int    `json:"entry_count,omitempty"`
}
type Entry struct {
	ID          string   `json:"id"`
	Framework   string   `json:"framework"`
	ExternalID  string   `json:"external_id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	SourceURL   string   `json:"source_url"`
	Description string   `json:"description,omitempty"`
	Deprecated  bool     `json:"deprecated,omitempty"`
	Parents     []string `json:"parents,omitempty"`
}
type Mapping struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Type      string `json:"type"`
	SourceURL string `json:"source_url"`
	Rationale string `json:"rationale"`
}
type Catalog struct {
	Notices    []Notice    `json:"notices,omitempty"`
	Version    string      `json:"version"`
	ReleasedAt time.Time   `json:"released_at"`
	Types      []Type      `json:"types"`
	Frameworks []Framework `json:"frameworks"`
	Entries    []Entry     `json:"entries"`
	Mappings   []Mapping   `json:"mappings"`
}
type Notice struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

var releases = sync.OnceValue(func() map[string]Catalog {
	out := map[string]Catalog{}
	names, err := fs.Glob(files, "v*.json")
	if err != nil {
		panic(err)
	}
	for _, name := range names {
		raw, err := files.ReadFile(name)
		if err != nil {
			panic(err)
		}
		var c Catalog
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(err)
		}
		if err := c.Validate(); err != nil {
			panic(err)
		}
		if name != "v"+c.Version+".json" {
			panic("catalog filename/version mismatch")
		}
		out[c.Version] = c
	}
	return out
})

func Load() (Catalog, error) {
	var latest Catalog
	for _, c := range releases() {
		if c.ReleasedAt.After(latest.ReleasedAt) || (c.ReleasedAt.Equal(latest.ReleasedAt) && c.Version > latest.Version) {
			latest = c
		}
	}
	if latest.Version == "" {
		return latest, fmt.Errorf("no published catalog")
	}
	return latest, nil
}

// LoadVersion resolves immutable published releases without filesystem input.
func LoadVersion(version string) (Catalog, error) {
	if c, ok := releases()[version]; ok {
		return c, nil
	}
	return Catalog{}, fmt.Errorf("unknown catalog version")
}

func (c Catalog) Type(id string) (Type, bool) {
	for _, t := range c.Types {
		if t.ID == id {
			return t, true
		}
	}
	return Type{}, false
}
func (c Catalog) TypeNode(id string) string { return "catalog:v" + c.Version + ":type:" + id }
func (c Catalog) Validate() error {
	ids := map[string]bool{}
	for _, t := range c.Types {
		if t.ID == "" || t.Name == "" || t.Description == "" || ids[t.ID] {
			return fmt.Errorf("invalid catalog type")
		}
		ids[t.ID] = true
	}
	var visit func(string, map[string]bool) error
	visit = func(id string, path map[string]bool) error {
		if path[id] {
			return fmt.Errorf("catalog hierarchy cycle")
		}
		t, ok := c.Type(id)
		if !ok {
			return fmt.Errorf("unknown catalog parent")
		}
		path[id] = true
		defer delete(path, id)
		for _, p := range t.Parents {
			if err := visit(p, path); err != nil {
				return err
			}
		}
		return nil
	}
	for id := range ids {
		if err := visit(id, map[string]bool{}); err != nil {
			return err
		}
	}
	frameworks := map[string]bool{}
	for _, f := range c.Frameworks {
		if f.ID == "" || f.Release == "" || !strings.HasPrefix(f.SourceURL, "https://") || frameworks[f.ID] {
			return fmt.Errorf("invalid framework")
		}
		frameworks[f.ID] = true
	}
	entries := map[string]Entry{}
	counts := map[string]int{}
	for _, e := range c.Entries {
		if !frameworks[e.Framework] || e.ID != e.Framework+":"+e.ExternalID || e.ExternalID == "" || entries[e.ID].ID != "" || e.Name == "" || !strings.HasPrefix(e.SourceURL, "https://") {
			return fmt.Errorf("invalid framework entry")
		}
		entries[e.ID] = e
		counts[e.Framework]++
	}
	for _, f := range c.Frameworks {
		if f.EntryCount != 0 && f.EntryCount != counts[f.ID] {
			return fmt.Errorf("incorrect framework entry count")
		}
	}
	var visitEntry func(string, map[string]bool) error
	visitEntry = func(id string, path map[string]bool) error {
		if path[id] {
			return fmt.Errorf("framework hierarchy cycle")
		}
		path[id] = true
		defer delete(path, id)
		for _, parent := range entries[id].Parents {
			if entries[parent].ID == "" || entries[parent].Framework != entries[id].Framework {
				return fmt.Errorf("unknown or cross-framework parent")
			}
			if err := visitEntry(parent, path); err != nil {
				return err
			}
		}
		return nil
	}
	for id := range entries {
		if err := visitEntry(id, map[string]bool{}); err != nil {
			return err
		}
	}
	for _, m := range c.Mappings {
		if !ids[m.Source] || entries[m.Target].ID == "" || m.Rationale == "" || !strings.HasPrefix(m.SourceURL, "https://") || (m.Type != "maps_to" && m.Type != "addressed_by" && m.Type != "exploited_by") {
			return fmt.Errorf("invalid mapping")
		}
	}
	if c.Version == "" || c.ReleasedAt.IsZero() {
		return fmt.Errorf("invalid catalog release")
	}
	return nil
}
func (c Catalog) record(id, kind string, v any) storage.Record {
	b, _ := json.Marshal(v)
	return storage.Record{ID: id, Kind: kind, Version: 1, Data: b, CreatedAt: c.ReleasedAt, UpdatedAt: c.ReleasedAt}
}
func (c Catalog) Records() []storage.Record {
	out := []storage.Record{}
	for _, t := range c.Types {
		out = append(out, c.record(c.TypeNode(t.ID), "vulnerability_type", t))
	}
	prefix := "catalog:v" + c.Version + ":"
	for _, f := range c.Frameworks {
		out = append(out, c.record(prefix+"framework:"+f.ID, "framework_release", f))
	}
	for _, e := range c.Entries {
		out = append(out, c.record(prefix+"entry:"+e.ID, "framework_entry", e))
	}
	edge := func(src, typ, dst, provenance string) {
		r := contracts.Relationship{SourceID: src, Type: typ, TargetID: dst, Provenance: provenance}
		out = append(out, c.record(prefix+"edge:"+uuid.NewSHA1(uuid.NameSpaceURL, []byte(src+"\x00"+typ+"\x00"+dst)).String(), "relationship", r))
	}
	for _, t := range c.Types {
		for _, p := range t.Parents {
			edge(c.TypeNode(t.ID), "subtype_of", c.TypeNode(p), "Security Graph catalog v"+c.Version)
		}
	}
	for _, e := range c.Entries {
		edge(prefix+"entry:"+e.ID, "part_of", prefix+"framework:"+e.Framework, e.SourceURL)
		for _, parent := range e.Parents {
			edge(prefix+"entry:"+e.ID, "part_of", prefix+"entry:"+parent, e.SourceURL)
		}
	}
	for _, m := range c.Mappings {
		edge(c.TypeNode(m.Source), m.Type, prefix+"entry:"+m.Target, m.SourceURL+"; "+m.Rationale)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type recordArchive struct {
	records   []storage.Record
	byID      map[string]storage.Record
	adjacency map[string][]storage.Record
}

var archive = sync.OnceValue(func() recordArchive {
	result := recordArchive{byID: map[string]storage.Record{}, adjacency: map[string][]storage.Record{}}
	for _, c := range releases() {
		for _, r := range c.Records() {
			result.records = append(result.records, r)
			result.byID[r.ID] = r
			if r.Kind == "relationship" {
				var edge contracts.Relationship
				if err := json.Unmarshal(r.Data, &edge); err != nil {
					panic(err)
				}
				result.adjacency[edge.SourceID] = append(result.adjacency[edge.SourceID], r)
				if edge.TargetID != edge.SourceID {
					result.adjacency[edge.TargetID] = append(result.adjacency[edge.TargetID], r)
				}
			}
		}
	}
	sort.Slice(result.records, func(i, j int) bool { return result.records[i].ID < result.records[j].ID })
	return result
})

// Records returns every published release, not just the current selectable one.
func Records() []storage.Record            { return append([]storage.Record{}, archive().records...) }
func Get(id string) (storage.Record, bool) { r, ok := archive().byID[id]; return r, ok }

// Adjacent uses the immutable release index. Tenant graph reads should not
// decode or scan thousands of unrelated public definitions on every request.
func Adjacent(ids ...string) []storage.Record {
	seen := map[string]bool{}
	out := []storage.Record{}
	for _, id := range ids {
		for _, r := range archive().adjacency[id] {
			if !seen[r.ID] {
				seen[r.ID] = true
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (c Catalog) Get(id string) (storage.Record, bool) {
	for _, r := range c.Records() {
		if r.ID == id {
			return r, true
		}
	}
	return storage.Record{}, false
}
