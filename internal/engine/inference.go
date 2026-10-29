package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/superagent-ai/security-graph/pkg/classifier"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

// ErrClassifierCapacity is safe to expose over MCP. There is no inference queue;
// retrying after the cooldown preserves the same idempotency key and payload.
var ErrClassifierCapacity = errors.New("classifier_capacity_exceeded: retryable; retry after 60 seconds")

type inferencePrincipal struct{ organization, actor string }

// Shared by every Engine/MCP session in this process, including custom local
// classifiers. A caller cannot buy another model slot by varying keys or actors.
var localInference = struct {
	slot chan struct{}
	sync.Mutex
	organizations map[string]time.Time
	principals    map[inferencePrincipal]time.Time
}{slot: make(chan struct{}, 1), organizations: make(map[string]time.Time), principals: make(map[inferencePrincipal]time.Time)}

func (e *Engine) classifyLocally(ctx context.Context, p storage.Principal, request classifier.Request) (classifier.Result, error) {
	if err := ctx.Err(); err != nil {
		return classifier.Result{}, err
	}
	select {
	case localInference.slot <- struct{}{}:
		defer func() { <-localInference.slot }()
	default:
		return classifier.Result{}, ErrClassifierCapacity
	}
	localInference.Lock()
	now := time.Now()
	// Keep only active cooldowns. Hard-bound bookkeeping as well as processes;
	// rejected requests never allocate limiter state or enter a waiting queue.
	for id, until := range localInference.organizations {
		if !now.Before(until) {
			delete(localInference.organizations, id)
		}
	}
	for id, until := range localInference.principals {
		if !now.Before(until) {
			delete(localInference.principals, id)
		}
	}
	principal := inferencePrincipal{p.OrganizationID, p.ActorID}
	if now.Before(localInference.organizations[p.OrganizationID]) || now.Before(localInference.principals[principal]) || len(localInference.organizations)+len(localInference.principals)+2 > 4096 {
		localInference.Unlock()
		return classifier.Result{}, ErrClassifierCapacity
	}
	// Failed and cancelled inference also consumes an admission: repeated failures
	// still cost resources. Reads, manual assignments and cached retries do not.
	localInference.organizations[p.OrganizationID] = now.Add(30 * time.Second)
	localInference.principals[principal] = now.Add(time.Minute)
	localInference.Unlock()
	if err := ctx.Err(); err != nil {
		return classifier.Result{}, err
	}
	return e.Classifier.Classify(ctx, request)
}
