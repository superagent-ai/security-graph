// Package catalog owns the immutable, reviewed classification vocabulary.
// Catalog records are public definitions, never a second store of tenant data.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

//go:embed v1.json
var files embed.FS

type Type struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Aliases      []string `json:"aliases"`
	Parents      []string `json:"parents"`
	Classifiable bool     `json:"classifiable"`
	Deprecated   bool     `json:"deprecated"`
}
type Framework struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Release   string `json:"release"`
	SourceURL string `json:"source_url"`
}
type Entry struct {
	ID         string `json:"id"`
	Framework  string `json:"framework"`
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	SourceURL  string `json:"source_url"`
}
type Mapping struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Type      string `json:"type"`
	SourceURL string `json:"source_url"`
	Rationale string `json:"rationale"`
}
type Catalog struct {
	Version    string      `json:"version"`
	ReleasedAt time.Time   `json:"released_at"`
	Types      []Type      `json:"types"`
	Frameworks []Framework `json:"frameworks"`
	Entries    []Entry     `json:"entries"`
	Mappings   []Mapping   `json:"mappings"`
}

func Load() (Catalog, error) {
	var c Catalog
	b, err := files.ReadFile("v1.json")
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
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
	entries := map[string]bool{}
	for _, e := range c.Entries {
		if !frameworks[e.Framework] || e.ExternalID == "" || entries[e.ID] || !strings.HasPrefix(e.SourceURL, "https://") {
			return fmt.Errorf("invalid framework entry")
		}
		entries[e.ID] = true
	}
	for _, m := range c.Mappings {
		if !ids[m.Source] || !entries[m.Target] || m.Rationale == "" || !strings.HasPrefix(m.SourceURL, "https://") || (m.Type != "maps_to" && m.Type != "addressed_by" && m.Type != "exploited_by") {
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
	}
	for _, m := range c.Mappings {
		edge(c.TypeNode(m.Source), m.Type, prefix+"entry:"+m.Target, m.SourceURL+"; "+m.Rationale)
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
