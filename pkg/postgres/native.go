package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// Native is a trusted PostgreSQL integration over authoritative app tables.
// It runs in the same transaction as graph history and idempotency records.
type Native interface {
	Get(context.Context, pgx.Tx, storage.Principal, string) (storage.Record, error)
	List(context.Context, pgx.Tx, storage.Principal, storage.Query) ([]storage.Record, error)
	Put(context.Context, pgx.Tx, storage.Principal, storage.Record, int64) (storage.Record, error)
	Authenticate(context.Context, *Store, string) (storage.Principal, error)
}

type NativeExecution interface {
	NativeContext(context.Context, *Store, storage.Principal, *storage.NativeQuery) ([]byte, error)
	SaveNativeFinding(context.Context, pgx.Tx, storage.Principal, []byte) (storage.Record, error)
	ReplaceNativePRFindings(context.Context, pgx.Tx, storage.Principal, []byte) ([]byte, error)
}
