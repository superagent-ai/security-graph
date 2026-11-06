package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/catalog"
	"github.com/superagent-ai/security-graph/pkg/classifier"
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

type ClassifyInput struct {
	WriteCall
	FindingID                     string `json:"finding_id"`
	ExpectedVersion               int64  `json:"expected_version" jsonschema:"Current finding version; classification does not change it."`
	ExpectedClassificationVersion int64  `json:"expected_classification_version" jsonschema:"0 for first classification; otherwise the current classification record version."`
}
type SetTypesInput struct {
	ClassifyInput
	TypeIDs   []string `json:"type_ids" jsonschema:"Existing classifiable catalog IDs. Empty records an unclassified finding."`
	Rationale string   `json:"rationale"`
}
type Classification struct {
	SourceID       string             `json:"source_id"`
	FindingVersion int64              `json:"finding_version"`
	CatalogVersion string             `json:"catalog_version"`
	TypeIDs        []string           `json:"type_ids"`
	TargetIDs      []string           `json:"target_ids"`
	Method         string             `json:"method"`
	Status         string             `json:"status"`
	Rationale      string             `json:"rationale,omitempty"`
	Model          *classifier.Result `json:"model,omitempty"`
	Threshold      float64            `json:"threshold,omitempty"`
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
func (e *Engine) SetFindingTypes(ctx context.Context, p storage.Principal, in SetTypesInput) (json.RawMessage, error) {
	if err := authorize(p, in.Intent, "read"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Rationale) == "" || len(in.Rationale) > 2000 {
		return nil, fmt.Errorf("%w: rationale requires 1 to 2000 bytes", contracts.ErrInvalid)
	}
	c := currentCatalog()
	if err := validateTypes(c, in.TypeIDs); err != nil {
		return nil, err
	}
	ids := append([]string{}, in.TypeIDs...)
	sort.Strings(ids)
	return e.write(ctx, p, "set_finding_types", "graph:write", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
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
		return saveClassification(ctx, tx, p, f, in.ExpectedClassificationVersion, Classification{SourceID: f.ID, FindingVersion: f.Version, CatalogVersion: c.Version, TypeIDs: ids, Method: "agent_asserted", Rationale: in.Rationale})
	})
}
func saveClassification(ctx context.Context, tx storage.Transaction, p storage.Principal, f storage.Record, expected int64, c Classification) (storage.Record, error) {
	if expected < 0 {
		return storage.Record{}, fmt.Errorf("%w: negative classification version", contracts.ErrInvalid)
	}
	c.TargetIDs = []string{}
	for _, id := range c.TypeIDs {
		c.TargetIDs = append(c.TargetIDs, "catalog:v"+c.CatalogVersion+":type:"+id)
	}
	c.Status = "classified"
	if c.Method == "model_suggested" {
		c.Status = "suggested"
	}
	if len(c.TypeIDs) == 0 {
		c.Status = "unclassified"
	}
	return tx.Put(ctx, storage.Record{ID: classificationID(p.OrganizationID, f.ID), Kind: "classification", AssetID: f.AssetID, ReportID: f.ReportID, Data: data(c)}, expected)
}
func (e *Engine) ClassifyFinding(ctx context.Context, p storage.Principal, in ClassifyInput) (json.RawMessage, error) {
	if err := authorize(p, in.Intent, "read"); err != nil {
		return nil, err
	}
	// Inference runs lazily after the idempotency receipt lookup, but outside any
	// database transaction. Replay therefore works even if the model is offline.
	var infer bool
	var f storage.Record
	result, err := e.write(ctx, p, "classify_finding", "graph:write", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
		var err error
		f, err = tx.Get(ctx, in.FindingID)
		if err != nil {
			return nil, err
		}
		if f.Kind != "finding" {
			return nil, storage.ErrNotFound
		}
		if in.ExpectedVersion < 1 || in.ExpectedClassificationVersion < 0 {
			return nil, fmt.Errorf("%w: invalid expected versions", contracts.ErrInvalid)
		}
		if f.Version != in.ExpectedVersion {
			return nil, storage.ErrConflict
		}
		old, err := tx.Get(ctx, classificationID(p.OrganizationID, f.ID))
		if err == nil {
			if old.Kind != "classification" || old.Version != in.ExpectedClassificationVersion {
				return nil, storage.ErrConflict
			}
		} else if err != storage.ErrNotFound {
			return nil, err
		} else if in.ExpectedClassificationVersion != 0 {
			return nil, storage.ErrConflict
		}
		infer = true
		return nil, errInferenceRequired
	})
	if !infer || err != errInferenceRequired {
		return result, err
	}
	if e.Classifier == nil {
		return nil, classifier.ErrUnavailable
	}
	var finding contracts.Finding
	if err = json.Unmarshal(f.Data, &finding); err != nil {
		return nil, err
	}
	// Supply authored evidence, not intent, credentials, or a claimed CWE label.
	state := data(struct {
		Title, Description, Summary, Details, Impact, Proof string
		References                                          []contracts.CodeReference
	}{finding.Title, finding.Description, finding.Submission.Summary, finding.Submission.Details, finding.Submission.Impact, finding.Submission.Proof, finding.Submission.CodeReferences})
	if len(state) > 16384 {
		return nil, fmt.Errorf("%w: classifier evidence exceeds 16 KiB", contracts.ErrInvalid)
	}
	c := currentCatalog()
	req := classifier.Request{State: state, Candidates: []catalog.Type{}}
	for _, t := range c.Types {
		if t.Classifiable && !t.Deprecated {
			req.Candidates = append(req.Candidates, t)
		}
	}
	decision, err := e.classifyLocally(ctx, p, req)
	if err != nil {
		return nil, err
	}
	if err = classifier.Validate(req, decision); err != nil {
		return nil, err
	}
	threshold := e.ClassificationThreshold
	if threshold == 0 {
		threshold = 0.95
	}
	if math.IsNaN(threshold) || threshold <= 0 || threshold > 1 {
		return nil, fmt.Errorf("invalid classifier threshold")
	}
	ids := []string{}
	for id, score := range decision.Scores {
		if score >= threshold {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return e.write(ctx, p, "classify_finding", "graph:write", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
		latest, err := tx.Get(ctx, in.FindingID)
		if err != nil {
			return nil, err
		}
		if latest.Kind != "finding" || latest.Version != f.Version {
			return nil, storage.ErrConflict
		}
		return saveClassification(ctx, tx, p, latest, in.ExpectedClassificationVersion, Classification{SourceID: f.ID, FindingVersion: f.Version, CatalogVersion: c.Version, TypeIDs: ids, Method: "model_suggested", Model: &decision, Threshold: threshold})
	})
}

var errInferenceRequired = fmt.Errorf("inference_required")

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
		for _, typeID := range cl.TypeIDs {
			if typeID == parts[1] {
				target := "catalog:v" + cl.CatalogVersion + ":type:" + typeID
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
func classificationEdge(r storage.Record, cl Classification, id string) storage.Record {
	edgeType := "instance_of"
	if cl.Method == "model_suggested" {
		edgeType = "suggested_instance_of"
	}
	return storage.Record{ID: "classification-edge:" + r.ID + ":" + id, Kind: "relationship", AssetID: r.AssetID, ReportID: r.ReportID, Version: r.Version, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		Data: data(contracts.Relationship{SourceID: cl.SourceID, Type: edgeType, TargetID: "catalog:v" + cl.CatalogVersion + ":type:" + id, Provenance: cl.Method + "; classification=" + r.ID})}
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
				for _, id := range cl.TypeIDs {
					target := "catalog:v" + cl.CatalogVersion + ":type:" + id
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
