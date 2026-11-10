package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/catalog"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// The reviewed catalog is immutable and contains no tenant data. Decode and
// validate it once instead of repeating that work for each projected neighbor.
var immutableCatalog = sync.OnceValue(func() catalog.Catalog {
	c, err := catalog.Load()
	if err != nil {
		panic(err)
	}
	return c
})

func currentCatalog() catalog.Catalog { return immutableCatalog() }
func (e *Engine) Catalog(p storage.Principal, intent string) (catalog.Catalog, error) {
	if err := authorize(p, intent, "read"); err != nil {
		return catalog.Catalog{}, err
	}
	return catalog.Load()
}

func (e *Engine) ClassificationOptions(p storage.Principal, intent string) (any, error) {
	if err := authorize(p, intent, "read"); err != nil {
		return nil, err
	}
	c := currentCatalog()
	types := []catalog.Type{}
	for _, t := range c.Types {
		if t.Classifiable && !t.Deprecated {
			types = append(types, t)
		}
	}
	return map[string]any{"catalog_version": c.Version, "vulnerability_types": types, "compliance": c.Entries, "frameworks": c.Frameworks, "mappings": c.Mappings}, nil
}

type ClassificationVersionInput struct {
	WriteCall
	FindingID                     string `json:"finding_id"`
	ExpectedVersion               int64  `json:"expected_version" jsonschema:"Current finding version; classification does not change it."`
	ExpectedClassificationVersion int64  `json:"expected_classification_version" jsonschema:"0 for first classification; otherwise the current classification record version."`
}
type ClassificationSelection struct {
	TypeIDs       []string `json:"type_ids" jsonschema:"Select zero or more vulnerability type IDs from get_classification_options. Never invent IDs."`
	ComplianceIDs []string `json:"compliance_ids" jsonschema:"Select zero or more compliance/framework entry IDs from get_classification_options. Empty means no applicable mapping; mappings are not proof of compliance."`
	Rationale     string   `json:"rationale" jsonschema:"Explain how the evidence supports these selections, or why no catalog choice applies."`
}
type SetClassificationInput struct {
	ClassificationVersionInput
	ClassificationSelection
}
type Classification struct {
	SourceID        string   `json:"source_id"`
	FindingVersion  int64    `json:"finding_version"`
	CatalogVersion  string   `json:"catalog_version"`
	TypeIDs         []string `json:"type_ids"`
	ComplianceIDs   []string `json:"compliance_ids"`
	TargetIDs       []string `json:"target_ids"`
	Method          string   `json:"method"`
	Status          string   `json:"status"`
	Rationale       string   `json:"rationale,omitempty"`
	SelectionPolicy string   `json:"selection_policy,omitempty"`
}

func classificationID(org, finding string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("classification\x00"+org+"\x00"+finding)).String()
}
func (e *Engine) GetClassification(ctx context.Context, p storage.Principal, intent, id string) (storage.Record, error) {
	if _, err := e.Get(ctx, p, intent, id, "finding"); err != nil {
		return storage.Record{}, err
	}
	return e.Get(ctx, p, intent, classificationID(p.OrganizationID, id), "classification")
}
func validateTypes(c catalog.Catalog, ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		t, ok := c.Type(id)
		if !ok || !t.Classifiable || t.Deprecated || seen[id] {
			return fmt.Errorf("%w: unknown, duplicate or unavailable vulnerability type", contracts.ErrInvalid)
		}
		seen[id] = true
	}
	return nil
}
func validateSelection(c catalog.Catalog, selection ClassificationSelection) error {
	if selection.TypeIDs == nil || selection.ComplianceIDs == nil || strings.TrimSpace(selection.Rationale) == "" || len(selection.Rationale) > 2000 {
		return fmt.Errorf("%w: select both lists and supply rationale (1–2000 bytes)", contracts.ErrInvalid)
	}
	if err := validateTypes(c, selection.TypeIDs); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, entry := range c.Entries {
		allowed[entry.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range selection.ComplianceIDs {
		if !allowed[id] || seen[id] {
			return fmt.Errorf("%w: unknown or duplicate compliance entry", contracts.ErrInvalid)
		}
		seen[id] = true
	}
	return nil
}
func (e *Engine) SetFindingClassification(ctx context.Context, p storage.Principal, in SetClassificationInput) (json.RawMessage, error) {
	if err := authorize(p, in.Intent, "read"); err != nil {
		return nil, err
	}
	if err := validateSelection(currentCatalog(), in.ClassificationSelection); err != nil {
		return nil, err
	}
	return e.write(ctx, p, "set_finding_classification", "graph:write", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
		f, err := tx.Get(ctx, in.FindingID)
		if err != nil {
			return nil, err
		}
		if f.Kind != "finding" {
			return nil, storage.ErrNotFound
		}
		if f.Version != in.ExpectedVersion {
			return nil, storage.ErrConflict
		}
		return saveAgentClassification(ctx, tx, p, f, in.ExpectedClassificationVersion, in.ClassificationSelection)
	})
}
func saveAgentClassification(ctx context.Context, tx storage.Transaction, p storage.Principal, f storage.Record, expected int64, selection ClassificationSelection) (storage.Record, error) {
	ids := append([]string{}, selection.TypeIDs...)
	sort.Strings(ids)
	entries := append([]string{}, selection.ComplianceIDs...)
	sort.Strings(entries)
	return saveClassification(ctx, tx, p, f, expected, Classification{SourceID: f.ID, FindingVersion: f.Version, CatalogVersion: currentCatalog().Version, TypeIDs: ids, ComplianceIDs: entries, Method: "agent_asserted", SelectionPolicy: "agent_selected_v1", Rationale: selection.Rationale})
}

func saveClassification(ctx context.Context, tx storage.Transaction, p storage.Principal, f storage.Record, expected int64, c Classification) (storage.Record, error) {
	if expected < 0 {
		return storage.Record{}, fmt.Errorf("%w: negative classification version", contracts.ErrInvalid)
	}
	c.TargetIDs = []string{}
	for _, id := range c.TypeIDs {
		c.TargetIDs = append(c.TargetIDs, "catalog:v"+c.CatalogVersion+":type:"+id)
	}
	for _, id := range c.ComplianceIDs {
		c.TargetIDs = append(c.TargetIDs, "catalog:v"+c.CatalogVersion+":entry:"+id)
	}
	c.Status = "classified"
	if len(c.TypeIDs) == 0 && len(c.ComplianceIDs) == 0 {
		c.Status = "unclassified"
	}
	return tx.Put(ctx, storage.Record{ID: classificationID(p.OrganizationID, f.ID), Kind: "classification", AssetID: f.AssetID, ReportID: f.ReportID, Data: data(c)}, expected)
}
func graphGet(ctx context.Context, tx storage.Reader, id string) (storage.Record, error) {
	// Asset IDs were unrestricted before catalogs existed. Never reinterpret an
	// authorized legacy record as a public definition or a projected edge.
	if r, err := tx.Get(ctx, id); err != storage.ErrNotFound {
		return r, err
	}
	if r, ok := currentCatalog().Get(id); ok {
		if r.Kind == "relationship" {
			var rel contracts.Relationship
			_ = json.Unmarshal(r.Data, &rel)
			for _, endpoint := range []string{rel.SourceID, rel.TargetID} {
				if _, err := tx.Get(ctx, endpoint); err == nil {
					return storage.Record{}, storage.ErrNotFound
				} else if err != storage.ErrNotFound {
					return storage.Record{}, err
				}
			}
		}
		return r, nil
	}
	if strings.HasPrefix(id, "classification-edge:") {
		parts := strings.SplitN(strings.TrimPrefix(id, "classification-edge:"), ":", 2)
		if len(parts) != 2 {
			return storage.Record{}, storage.ErrNotFound
		}
		r, err := tx.Get(ctx, parts[0])
		if err != nil {
			return storage.Record{}, err
		}
		cl, err := decode[Classification](r, "classification")
		if err != nil {
			return storage.Record{}, err
		}
		f, err := tx.Get(ctx, cl.SourceID)
		if err != nil {
			return storage.Record{}, err
		}
		if f.Kind != "finding" {
			return storage.Record{}, storage.ErrNotFound
		}
		for _, typeID := range classificationTargets(cl) {
			if typeID == parts[1] {
				target := classificationTarget(cl, typeID)
				if _, err := tx.Get(ctx, target); err == nil {
					return storage.Record{}, storage.ErrNotFound
				} else if err != storage.ErrNotFound {
					return storage.Record{}, err
				}
				return classificationEdge(r, cl, typeID), nil
			}
		}
		return storage.Record{}, storage.ErrNotFound
	}
	return storage.Record{}, storage.ErrNotFound
}
func classificationTargets(cl Classification) []string {
	ids := append([]string{}, cl.TypeIDs...)
	for _, id := range cl.ComplianceIDs {
		ids = append(ids, "entry/"+id)
	}
	return ids
}
func classificationTarget(cl Classification, id string) string {
	if strings.HasPrefix(id, "entry/") {
		return "catalog:v" + cl.CatalogVersion + ":entry:" + strings.TrimPrefix(id, "entry/")
	}
	return "catalog:v" + cl.CatalogVersion + ":type:" + id
}
func classificationEdge(r storage.Record, cl Classification, id string) storage.Record {
	edgeType := "instance_of"
	if strings.HasPrefix(id, "entry/") {
		edgeType = "mapped_to"
	}
	return storage.Record{ID: "classification-edge:" + r.ID + ":" + id, Kind: "relationship", AssetID: r.AssetID, ReportID: r.ReportID, Version: r.Version, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Data: data(contracts.Relationship{SourceID: cl.SourceID, Type: edgeType, TargetID: classificationTarget(cl, id), Provenance: cl.Method + "; classification=" + r.ID})}
}

// graphEdges projects current classification assignments into instance_of edges.
// All finding lookups and classification queries use the authenticated snapshot.
func graphEdges(ctx context.Context, tx storage.Reader, front []string, emit func(storage.Record) error) error {
	c := currentCatalog()
	collisions := map[string]bool{}
	virtualAvailable := func(ids ...string) (bool, error) {
		for _, id := range ids {
			exists, known := collisions[id]
			if !known {
				_, err := tx.Get(ctx, id)
				if err != nil && err != storage.ErrNotFound {
					return false, err
				}
				exists = err == nil
				collisions[id] = exists
			}
			if exists {
				return false, nil
			}
		}
		return true, nil
	}
	connected := map[string]bool{}
	for _, id := range front {
		connected[id] = true
	}
	for _, r := range c.Records() {
		if r.Kind != "relationship" {
			continue
		}
		var rel contracts.Relationship
		_ = json.Unmarshal(r.Data, &rel)
		if connected[rel.SourceID] || connected[rel.TargetID] {
			available, err := virtualAvailable(r.ID, rel.SourceID, rel.TargetID)
			if err != nil {
				return err
			}
			if !available {
				continue
			}
			if err := emit(r); err != nil {
				return err
			}
		}
	}
	for _, kind := range []string{"relationship", "classification"} {
		after := ""
		for {
			rows, err := tx.List(ctx, storage.Query{Kind: kind, Limit: 201, After: after, ConnectedTo: front})
			if err != nil {
				return err
			}
			for _, r := range rows {
				if kind == "relationship" {
					if err = emit(r); err != nil {
						return err
					}
					continue
				}
				var cl Classification
				if err = json.Unmarshal(r.Data, &cl); err != nil {
					return err
				}
				// Never traverse assignments whose finding is no longer visible.
				f, er := tx.Get(ctx, cl.SourceID)
				if er == storage.ErrNotFound {
					continue
				}
				if er != nil {
					return er
				}
				if f.Kind != "finding" {
					continue
				}
				for _, id := range classificationTargets(cl) {
					target := classificationTarget(cl, id)
					if !connected[cl.SourceID] && !connected[target] {
						continue
					}
					edge := classificationEdge(r, cl, id)
					available, er := virtualAvailable(edge.ID, target)
					if er != nil {
						return er
					}
					if !available {
						continue
					}
					if err = emit(edge); err != nil {
						return err
					}
				}
			}
			if len(rows) < 201 {
				break
			}
			after = rows[len(rows)-1].ID
		}
	}
	return nil
}
