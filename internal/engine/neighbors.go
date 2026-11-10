package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// NeighborsInput pages a single authorized adjacency list without changing the
// existing bounded get_context contract or requiring a backend-specific API.
type NeighborsInput struct {
	Call
	EntityID string `json:"entity_id"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Edges per page; default 25, maximum 25. Nodes are deduplicated within each page."`
}
type NeighborsResult struct {
	Records    []storage.Record `json:"records"`
	NextCursor string           `json:"next_cursor,omitempty"`
	Edges      int              `json:"edges"`
	Provenance string           `json:"provenance"`
}
type neighborCursor struct {
	Version      int    `json:"v"`
	Organization string `json:"org"`
	Entity       string `json:"entity"`
	Phase        int    `json:"phase"`
	After        string `json:"after,omitempty"`
	PartialID    string `json:"partial_id,omitempty"`
	TypeAfter    string `json:"type_after,omitempty"`
}

func (e *Engine) Neighbors(ctx context.Context, p storage.Principal, in NeighborsInput) (out NeighborsResult, err error) {
	if err = authorize(p, in.Intent, "read"); err != nil {
		return
	}
	if in.Limit == 0 {
		in.Limit = 25
	}
	if in.EntityID == "" || in.Limit < 1 || in.Limit > 25 || len(in.Cursor) > 4096 {
		return out, fmt.Errorf("%w: entity_id and limit 1 to 25 required", contracts.ErrInvalid)
	}
	cursor := neighborCursor{Version: 1, Organization: p.OrganizationID, Entity: in.EntityID}
	if in.Cursor != "" {
		var decoded neighborCursor
		raw, er := base64.RawURLEncoding.DecodeString(in.Cursor)
		if er != nil || json.Unmarshal(raw, &decoded) != nil || decoded.Version != 1 || decoded.Organization != p.OrganizationID || decoded.Entity != in.EntityID || decoded.Phase < 0 || decoded.Phase > 2 {
			return out, fmt.Errorf("%w: invalid neighborhood cursor", contracts.ErrInvalid)
		}
		cursor = decoded
	}
	out = NeighborsResult{Records: []storage.Record{}, Provenance: "Live authorized adjacency pages; persisted relationships, curated catalog and attributed classifications. Concurrent edits may require refreshing from the first page."}
	err = e.Store.View(ctx, p, func(tx storage.Reader) error {
		root, er := graphGet(ctx, tx, in.EntityID)
		if er != nil {
			return er
		}
		if root.Kind == "relationship" || root.Kind == "classification" {
			return fmt.Errorf("%w: choose a graph entity", contracts.ErrInvalid)
		}
		out.Records = append(out.Records, root)
		seen := map[string]bool{root.ID: true}
		available := func(ids ...string) (bool, error) {
			for _, id := range ids {
				_, er := tx.Get(ctx, id)
				if er == nil {
					return false, nil
				}
				if er != storage.ErrNotFound {
					return false, er
				}
			}
			return true, nil
		}
		emit := func(edge storage.Record) (bool, error) {
			var rel contracts.Relationship
			if er := json.Unmarshal(edge.Data, &rel); er != nil {
				return false, er
			}
			neighbor := ""
			if rel.SourceID == root.ID {
				neighbor = rel.TargetID
			} else if rel.TargetID == root.ID {
				neighbor = rel.SourceID
			} else {
				return false, nil
			}
			node, er := graphGet(ctx, tx, neighbor)
			if er == storage.ErrNotFound {
				return false, nil
			}
			if er != nil {
				return false, er
			}
			if !seen[edge.ID] {
				out.Records = append(out.Records, edge)
				seen[edge.ID] = true
				out.Edges++
			}
			if !seen[node.ID] {
				out.Records = append(out.Records, node)
				seen[node.ID] = true
			}
			return out.Edges >= in.Limit, nil
		}
		finishPage := func() { raw, _ := json.Marshal(cursor); out.NextCursor = base64.RawURLEncoding.EncodeToString(raw) }
		// Curated edges have a small immutable inventory. Persisted edges and
		// classifications use keyset queries; no adjacency list is materialized.
		if cursor.Phase == 0 {
			records := currentCatalog().Records()
			sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
			for _, r := range records {
				if r.Kind != "relationship" || r.ID <= cursor.After {
					continue
				}
				var rel contracts.Relationship
				_ = json.Unmarshal(r.Data, &rel)
				if rel.SourceID != root.ID && rel.TargetID != root.ID {
					continue
				}
				ok, er := available(r.ID, rel.SourceID, rel.TargetID)
				if er != nil {
					return er
				}
				cursor.After = r.ID
				if !ok {
					continue
				}
				full, er := emit(r)
				if er != nil {
					return er
				}
				if full {
					finishPage()
					return nil
				}
			}
			cursor.Phase = 1
			cursor.After = ""
		}
		// Bound even pages where projections disappear or endpoints become hidden.
		scanned := 0
		for cursor.Phase <= 2 {
			kind := "relationship"
			if cursor.Phase == 2 {
				kind = "classification"
			}
			rows, er := tx.List(ctx, storage.Query{Kind: kind, After: cursor.After, Limit: 51, ConnectedTo: []string{root.ID}})
			if er != nil {
				return er
			}
			for _, r := range rows {
				scanned++
				if cursor.Phase == 1 {
					cursor.After = r.ID
					full, er := emit(r)
					if er != nil {
						return er
					}
					if full {
						finishPage()
						return nil
					}
				} else {
					var cl Classification
					if er = json.Unmarshal(r.Data, &cl); er != nil {
						return er
					}
					finding, er := tx.Get(ctx, cl.SourceID)
					if er != nil && er != storage.ErrNotFound {
						return er
					}
					if er == nil && finding.Kind == "finding" {
						ids := classificationTargets(cl)
						sort.Strings(ids)
						for _, id := range ids {
							if cursor.PartialID == r.ID && id <= cursor.TypeAfter {
								continue
							}
							edge := classificationEdge(r, cl, id)
							var rel contracts.Relationship
							_ = json.Unmarshal(edge.Data, &rel)
							if rel.SourceID != root.ID && rel.TargetID != root.ID {
								continue
							}
							ok, er := available(edge.ID, rel.TargetID)
							if er != nil {
								return er
							}
							if !ok {
								continue
							}
							full, er := emit(edge)
							if er != nil {
								return er
							}
							if full {
								cursor.PartialID = r.ID
								cursor.TypeAfter = id
								finishPage()
								return nil
							}
						}
					}
					cursor.After = r.ID
					cursor.PartialID = ""
					cursor.TypeAfter = ""
				}
				if scanned >= 200 {
					finishPage()
					return nil
				}
			}
			if len(rows) < 51 {
				cursor.Phase++
				cursor.After = ""
				cursor.PartialID = ""
				cursor.TypeAfter = ""
			}
		}
		return nil
	})
	return
}
