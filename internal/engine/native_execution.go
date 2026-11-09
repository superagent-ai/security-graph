package engine

import (
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
		return n.SaveNativeFinding(ctx, data(in.Payload))
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
		return n.ReplaceNativePRFindings(ctx, data(in.Findings))
	})
}
