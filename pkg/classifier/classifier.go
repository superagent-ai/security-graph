// Package classifier defines a model-independent, local decision contract.
package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"time"

	"github.com/superagent-ai/security-graph/pkg/catalog"
)

type Request struct {
	State      json.RawMessage `json:"state"`
	Candidates []catalog.Type  `json:"candidates"`
}
type Result struct {
	Model    string             `json:"model"`
	Revision string             `json:"revision"`
	Scores   map[string]float64 `json:"scores"`
}

// Classifier must use only the supplied evidence and catalog candidates. Scores
// are model outputs, not calibrated probabilities of vulnerability validity.
type Classifier interface {
	Classify(context.Context, Request) (Result, error)
}

var ErrUnavailable = errors.New("local_classifier_unavailable")
var ErrOutput = errors.New("invalid_classifier_output")
var ErrTimeout = errors.New("local_classifier_timeout")

const DefaultTimeout = 25 * time.Second
const MaxTimeout = 2 * time.Minute

// Command runs an operator-configured executable with a bounded JSON protocol.
// MCP inputs cannot choose its executable, arguments, model or network access.
// Each invocation is isolated; a resident implementation can use the same interface.
type Command struct {
	Path    string
	Args    []string
	Timeout time.Duration
}

func (c Command) Classify(ctx context.Context, in Request) (Result, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	b, err := json.Marshal(in)
	if err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	// A local model receives evidence, not deployment credentials or Python
	// import hooks. Its working directory and writable home are private too.
	work, err := os.MkdirTemp("", "security-graph-classifier-")
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer os.RemoveAll(work)
	cmd.Dir = work
	cmd.Env = []string{"HOME=" + work, "TMPDIR=" + work, "TMP=" + work, "TEMP=" + work, "HF_HOME=" + work, "HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1", "HF_HUB_DISABLE_TELEMETRY=1", "DO_NOT_TRACK=1", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1"}
	for _, key := range []string{"PATH", "SYSTEMROOT", "WINDIR", "JULIA_CPU_THREADS"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	// Do not forward model diagnostics: they can contain finding text or secrets.
	if err = cmd.Start(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, ErrTimeout
		}
		return Result{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(out, 65537))
	if err != nil || len(body) > 65536 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return Result{}, ErrOutput
	}
	if err = cmd.Wait(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, ErrTimeout
		}
		return Result{}, ErrUnavailable
	}
	var result Result
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&result) != nil {
		return Result{}, ErrOutput
	}
	if dec.Decode(new(any)) != io.EOF {
		return Result{}, ErrOutput
	}
	if err = Validate(in, result); err != nil {
		return Result{}, err
	}
	return result, nil
}
func Validate(in Request, out Result) error {
	if out.Model == "" || len(out.Model) > 200 || out.Revision == "" || len(out.Revision) > 200 || len(out.Scores) != len(in.Candidates) {
		return ErrOutput
	}
	allowed := map[string]bool{}
	for _, t := range in.Candidates {
		allowed[t.ID] = true
	}
	for id, s := range out.Scores {
		if !allowed[id] || math.IsNaN(s) || math.IsInf(s, 0) || s < 0 || s > 1 {
			return ErrOutput
		}
	}
	return nil
}
