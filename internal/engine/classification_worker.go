package engine

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/superagent-ai/security-graph/pkg/classifier"
	"github.com/superagent-ai/security-graph/pkg/contracts"
	"github.com/superagent-ai/security-graph/pkg/storage"
	"time"
)

type ClassificationJob struct {
	ID, OrganizationID, FindingID, AssetID, Lease string
	FindingVersion                                int64
	NextVersion                                   int64
	RetryAfter                                    time.Duration
}
type ClassificationQueue interface {
	Claim(context.Context) (*ClassificationJob, error)
	Finish(context.Context, *ClassificationJob, string, string) error
}

// RunClassificationWorker drains durable intents committed with canonical
// findings. It shares the same bounded classifier and version checks as MCP.
func (e *Engine) RunClassificationWorker(ctx context.Context, q ClassificationQueue) {
	for ctx.Err() == nil {
		// An interactive request can own the shared model. Leave queued work
		// pending rather than repeatedly claiming jobs we cannot execute.
		if len(localInference.slot) == cap(localInference.slot) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(busyClassifierRetry):
				continue
			}
		}
		job, err := q.Claim(ctx)
		if err != nil || job == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		status, code := e.classifyJob(ctx, job)
		_ = q.Finish(ctx, job, status, code)
	}
}
func (e *Engine) classifyJob(ctx context.Context, j *ClassificationJob) (string, string) {
	p := storage.Principal{OrganizationID: j.OrganizationID, ActorID: "system:security-graph-classifier", Scopes: []string{"read", "graph:write"}, AssetIDs: []string{j.AssetID}}
	f, err := e.Get(ctx, p, "Classify a persisted finding using the configured local Julia model.", j.FindingID, "finding")
	if errors.Is(err, storage.ErrNotFound) {
		return "superseded", "source_removed"
	}
	if err != nil {
		return "pending", "source_unavailable"
	}
	if f.Version != j.FindingVersion {
		j.NextVersion = f.Version
		return "superseded", "source_changed"
	}
	var version int64
	old, err := e.GetClassification(ctx, p, "Preserve reviewed classifications and avoid repeating inference.", j.FindingID)
	if err == nil {
		var c Classification
		if json.Unmarshal(old.Data, &c) != nil {
			return "failed", "invalid_classification"
		}
		if c.Method == "agent_asserted" {
			return "manual", "reviewed_assignment"
		}
		if c.FindingVersion == f.Version && c.Method == "model_suggested" && c.SelectionPolicy == PrimaryTypeSelectionPolicy {
			return "completed", ""
		}
		version = old.Version
	} else if !errors.Is(err, storage.ErrNotFound) {
		return "pending", "classification_unavailable"
	}
	_, err = e.ClassifyFinding(ctx, p, ClassifyInput{WriteCall: WriteCall{Intent: "Automatically classify the newly persisted finding; suggestions do not change verification or review.", IdempotencyKey: "auto-classification:" + PrimaryTypeSelectionPolicy + ":" + j.ID}, FindingID: f.ID, ExpectedVersion: f.Version, ExpectedClassificationVersion: version})
	switch {
	case err == nil:
		return "completed", ""
	case errors.Is(err, storage.ErrConflict):
		return "pending", "version_conflict"
	case errors.Is(err, ErrClassifierCapacity):
		j.RetryAfter = busyClassifierRetry
		var capacity capacityDelay
		if errors.As(err, &capacity) {
			j.RetryAfter = capacity.after
		}
		return "pending", "classifier_capacity"
	case errors.Is(err, classifier.ErrTimeout):
		return "pending", "classifier_timeout"
	case errors.Is(err, classifier.ErrUnavailable):
		return "pending", "classifier_unavailable"
	case errors.Is(err, contracts.ErrInvalid):
		return "failed", "invalid_evidence"
	case errors.Is(err, classifier.ErrOutput):
		return "failed", "invalid_classifier_output"
	default:
		return "pending", "classification_unavailable"
	}
}
