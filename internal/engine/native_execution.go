package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type NativeContextInput struct {
	Call
	Query    string `json:"query,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	After    string `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}
type NativeSaveInput struct {
	WriteCall
	Payload map[string]any `json:"payload"`
}
type NativePRInput struct {
	WriteCall
	Findings []map[string]any `json:"findings"`
}

func (e *Engine) NativeContext(ctx context.Context, p storage.Principal, in NativeContextInput, search bool) (json.RawMessage, error) {
	if err := authorize(p, in.Intent, "read"); err != nil {
		return nil, err
	}
	if p.NativeRunID == "" {
		return nil, storage.ErrForbidden
	}
	s, ok := e.Store.(storage.NativeReader)
	if !ok {
		return nil, storage.ErrForbidden
	}
	var q *storage.NativeQuery
	if search {
		limit := in.Limit
		if limit == 0 {
			limit = 10
		}
		q = &storage.NativeQuery{Query: in.Query, RecordID: in.RecordID, After: in.After, Limit: limit}
	}
	return s.NativeContext(ctx, p, q)
}
func (e *Engine) SaveNativeFinding(ctx context.Context, p storage.Principal, in NativeSaveInput) (json.RawMessage, error) {
	if p.NativeRunID == "" || len(data(in.Payload)) > 512*1024 || in.Payload == nil {
		return nil, contracts.ErrInvalid
	}
	return e.write(ctx, p, "save_native_finding", "native:submit", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
		n, ok := tx.(storage.NativeWriter)
		if !ok {
			return nil, storage.ErrForbidden
		}
		payload, selection, err := nativeSelection(in.Payload)
		if err != nil {
			return nil, err
		}
		f, err := n.SaveNativeFinding(ctx, data(payload))
		if err != nil {
			return nil, err
		}
		if selection != nil {
			if err = persistNativeSelection(ctx, tx, p, f, *selection); err != nil {
				return nil, err
			}
		}
		return f, nil
	})
}
func (e *Engine) ReplaceNativePRFindings(ctx context.Context, p storage.Principal, in NativePRInput) (json.RawMessage, error) {
	if p.NativeModality != "pr_scan" || len(data(in.Findings)) > 512*1024 || in.Findings == nil {
		return nil, contracts.ErrInvalid
	}
	return e.write(ctx, p, "replace_native_pr_findings", "native:submit", in.WriteCall, in, func(tx storage.Transaction) (any, error) {
		n, ok := tx.(storage.NativeWriter)
		if !ok {
			return nil, storage.ErrForbidden
		}
		payloads := make([]map[string]any, len(in.Findings))
		selections := make([]*ClassificationSelection, len(in.Findings))
		for i, item := range in.Findings {
			var err error
			payloads[i], selections[i], err = nativeSelection(item)
			if err != nil {
				return nil, err
			}
		}
		result, err := n.ReplaceNativePRFindings(ctx, data(payloads))
		if err != nil {
			return nil, err
		}
		var ids []string
		if err = json.Unmarshal(result, &ids); err != nil {
			return nil, err
		}
		if len(ids) != len(selections) {
			return nil, contracts.ErrInvalid
		}
		for i, id := range ids {
			if selections[i] == nil {
				continue
			}
			f, err := tx.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			if err = persistNativeSelection(ctx, tx, p, f, *selections[i]); err != nil {
				return nil, err
			}
		}
		return json.RawMessage(result), nil
	})
}

// Strip presentation metadata before calling canonical App persistence. Selection
// validation and graph writes share its transaction; invalid choices roll back.
func nativeSelection(input map[string]any) (map[string]any, *ClassificationSelection, error) {
	payload := map[string]any{}
	for k, v := range input {
		if k != "classification" {
			payload[k] = v
		}
	}
	value, ok := input["classification"]
	if !ok {
		return nil, nil, contracts.ErrInvalid
	}
	var selection ClassificationSelection
	decoder := json.NewDecoder(bytes.NewReader(data(value)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selection); err != nil {
		return nil, nil, contracts.ErrInvalid
	}
	if err := validateSelection(selection); err != nil {
		return nil, nil, err
	}
	return payload, &selection, nil
}
func persistNativeSelection(ctx context.Context, tx storage.Transaction, p storage.Principal, f storage.Record, selection ClassificationSelection) error {
	expected := int64(0)
	old, err := tx.Get(ctx, classificationID(p.OrganizationID, f.ID))
	if err == nil {
		expected = old.Version
	} else if err != storage.ErrNotFound {
		return err
	}
	_, err = saveAgentClassification(ctx, tx, p, f, expected, selection)
	return err
}
