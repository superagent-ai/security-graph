package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

type ListCommentsInput struct {
	Call
	FindingID string `json:"finding_id"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}
type CreateCommentInput struct {
	WriteCall
	FindingID string `json:"finding_id"`
	Body      string `json:"body" jsonschema:"Markdown review context, 1 to 10000 characters. Not proof or a triage instruction."`
}
type DeleteCommentInput struct {
	WriteCall
	FindingID       string `json:"finding_id"`
	CommentID       string `json:"comment_id"`
	ExpectedVersion int64  `json:"expected_version"`
}
type UpdateCommentInput struct {
	DeleteCommentInput
	Body string `json:"body"`
}

func commentResult(r storage.Record, p storage.Principal) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal(r.Data, &result); err != nil {
		return nil, err
	}
	result["id"] = strings.TrimPrefix(r.ID, "comment:")
	result["graph_id"], result["version"] = r.ID, r.Version
	if _, ok := result["created_at"]; !ok {
		result["created_at"] = r.CreatedAt
	}
	if _, ok := result["updated_at"]; !ok {
		result["updated_at"] = r.UpdatedAt
	}
	result["can_manage"] = p.Allows("submit")
	return result, nil
}
func commentBody(body string) (string, error) {
	body = strings.TrimSpace(body)
	if !utf8.ValidString(body) || utf8.RuneCountInString(body) < 1 || utf8.RuneCountInString(body) > 10000 {
		return "", fmt.Errorf("%w: body must contain 1 to 10000 characters", contracts.ErrInvalid)
	}
	return body, nil
}
func (e *Engine) ListFindingComments(ctx context.Context, p storage.Principal, a ListCommentsInput) (any, error) {
	if err := authorize(p, a.Intent, "read"); err != nil {
		return nil, err
	}
	if a.Limit == 0 {
		a.Limit = 25
	}
	if a.Limit < 1 || a.Limit > 100 || a.Offset < 0 || a.Offset > 2147483547 {
		return nil, contracts.ErrInvalid
	}
	var result any
	err := e.Store.View(ctx, p, func(tx storage.Reader) error {
		parent, err := tx.Get(ctx, a.FindingID)
		if err != nil {
			return err
		}
		if parent.Kind != "finding" {
			return storage.ErrNotFound
		}
		reader, ok := tx.(storage.CommentReader)
		if !ok {
			return contracts.ErrInvalid
		}
		rows, total, err := reader.FindingComments(ctx, parent.ID, a.Limit, a.Offset)
		if err != nil {
			return err
		}
		comments := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			c, err := commentResult(row, p)
			if err != nil {
				return err
			}
			comments = append(comments, c)
		}
		result = map[string]any{"data": comments, "pagination": map[string]any{"limit": a.Limit, "offset": a.Offset, "total": total, "has_more": int64(a.Offset+len(rows)) < total}}
		return nil
	})
	return result, err
}
func (e *Engine) CreateFindingComment(ctx context.Context, p storage.Principal, a CreateCommentInput) (json.RawMessage, error) {
	body, err := commentBody(a.Body)
	if err != nil {
		return nil, err
	}
	return e.write(ctx, p, "create_finding_comment", "submit", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		parent, err := tx.Get(ctx, a.FindingID)
		if err != nil {
			return nil, err
		}
		if parent.Kind != "finding" {
			return nil, storage.ErrNotFound
		}
		id := uuid.NewString()
		r, err := tx.Put(ctx, storage.Record{ID: "comment:" + id, Kind: "comment", AssetID: parent.AssetID, ReportID: parent.ReportID, Data: data(map[string]any{
			"id": "comment:" + id, "comment_id": id, "object": "finding_comment", "finding_id": parent.ID, "body": body,
			"title": "Comment by API key", "author": map[string]any{"type": "api_key", "user_id": nil, "name": "API key"},
			"actor_id": p.ActorID, "trust": "attributed_review_context",
		})}, 0)
		if err != nil {
			return nil, err
		}
		return commentResult(r, p)
	})
}
func authorizedComment(ctx context.Context, tx storage.Reader, a DeleteCommentInput) (storage.Record, error) {
	if a.ExpectedVersion < 1 {
		return storage.Record{}, fmt.Errorf("%w: expected_version required", contracts.ErrInvalid)
	}
	r, err := tx.Get(ctx, "comment:"+strings.TrimPrefix(a.CommentID, "comment:"))
	if err != nil {
		return r, err
	}
	var c struct {
		FindingID string `json:"finding_id"`
	}
	if r.Kind != "comment" {
		return r, storage.ErrNotFound
	}
	if err = json.Unmarshal(r.Data, &c); err != nil {
		return r, err
	}
	if c.FindingID != a.FindingID {
		return r, storage.ErrNotFound
	}
	parent, err := tx.Get(ctx, a.FindingID)
	if err != nil {
		return r, err
	}
	if parent.Kind != "finding" {
		return r, storage.ErrNotFound
	}
	if r.Version != a.ExpectedVersion {
		return r, storage.ErrConflict
	}
	return r, nil
}
func (e *Engine) UpdateFindingComment(ctx context.Context, p storage.Principal, a UpdateCommentInput) (json.RawMessage, error) {
	body, err := commentBody(a.Body)
	if err != nil {
		return nil, err
	}
	return e.write(ctx, p, "update_finding_comment", "submit", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		r, err := authorizedComment(ctx, tx, a.DeleteCommentInput)
		if err != nil {
			return nil, err
		}
		var c map[string]any
		if err = json.Unmarshal(r.Data, &c); err != nil {
			return nil, err
		}
		c["body"] = body
		r.Data = data(c)
		r, err = tx.Put(ctx, r, a.ExpectedVersion)
		if err != nil {
			return nil, err
		}
		return commentResult(r, p)
	})
}
func (e *Engine) DeleteFindingComment(ctx context.Context, p storage.Principal, a DeleteCommentInput) (json.RawMessage, error) {
	return e.write(ctx, p, "delete_finding_comment", "submit", a.WriteCall, a, func(tx storage.Transaction) (any, error) {
		r, err := authorizedComment(ctx, tx, a)
		if err != nil {
			return nil, err
		}
		deleter, ok := tx.(storage.CommentDeleter)
		if !ok {
			return nil, contracts.ErrInvalid
		}
		if err = deleter.DeleteComment(ctx, r, a.ExpectedVersion); err != nil {
			return nil, err
		}
		return map[string]any{"deleted": true, "id": strings.TrimPrefix(r.ID, "comment:")}, nil
	})
}
