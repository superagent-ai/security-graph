// Package storage is the backend contract shared by hosted and on-prem engines.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound  = errors.New("not_found")
	ErrConflict  = errors.New("conflict")
	ErrForbidden = errors.New("forbidden")
)

type Principal struct {
	OrganizationID string   `json:"organization_id"`
	ActorID        string   `json:"actor_id"`
	Scopes         []string `json:"scopes"`
	AssetIDs       []string `json:"asset_ids"`
	AllAssets      bool     `json:"all_assets"`
}

func (p Principal) Allows(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
func (p Principal) AllowsAsset(id string) bool {
	if p.AllAssets {
		return true
	}
	for _, s := range p.AssetIDs {
		if s == id {
			return true
		}
	}
	return false
}

type Record struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	AssetID   string          `json:"asset_id"`
	ReportID  string          `json:"report_id,omitempty"`
	Version   int64           `json:"version"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}
type Query struct {
	Kind     string
	ReportID string
	AssetID  string
	Limit    int
	After    string
	Search   string
	// ConnectedTo matches relationship endpoints and classification source_id/target_ids.
	ConnectedTo  []string
	FindingKind  string
	TriageStatus string
	ReportType   string
	Status       string
	Offset       int
}
type Change struct {
	Cursor    int64     `json:"cursor"`
	EntityID  string    `json:"entity_id"`
	Kind      string    `json:"kind"`
	Version   int64     `json:"version"`
	ActorID   string    `json:"actor_id"`
	CreatedAt time.Time `json:"created_at"`
}
type Call struct {
	Intent    string
	Operation string
	Key       string
	Digest    string
}

type Reader interface {
	Get(context.Context, string) (Record, error)
	List(context.Context, Query) ([]Record, error)
	Changes(context.Context, int64, int) ([]Change, error)
}
type Transaction interface {
	Reader
	Put(context.Context, Record, int64) (Record, error)
}

// View provides a consistent authorized snapshot. Update must serialize competing
// organization writes and commit mutations, audit/change events and idempotency
// responses atomically. Retry callbacks only if they have no external effects.
// All reads, including relationship records, must enforce principal asset scope.
type Store interface {
	View(context.Context, Principal, func(Reader) error) error
	Update(context.Context, Principal, Call, func(Transaction) (any, error)) (json.RawMessage, error)
	Ping(context.Context) error
	Close()
}
