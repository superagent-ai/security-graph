package demoseed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/superagent-ai/security-graph/pkg/storage"
)

type client struct {
	endpoint, token string
	http            *http.Client
}

func (c client) record(ctx context.Context, name string, args map[string]any) (storage.Record, error) {
	var record storage.Record
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	// Retries preserve exactly the same request bytes and idempotency key. Tool
	// rejections are terminal; only transport and server failures are retried.
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return record, ctx.Err()
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if err != nil {
			return record, fmt.Errorf("construct %s request", name)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		res, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return record, ctx.Err()
			}
			if attempt < 2 {
				continue
			}
			return record, fmt.Errorf("MCP transport failed during %s", name)
		}
		raw, readErr := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		_ = res.Body.Close()
		if readErr != nil || res.StatusCode >= 500 {
			if attempt < 2 {
				continue
			}
			return record, fmt.Errorf("MCP service failed during %s", name)
		}
		if res.StatusCode != http.StatusOK {
			return record, fmt.Errorf("MCP rejected %s (HTTP %d)", name, res.StatusCode)
		}
		var rpc struct {
			Result struct {
				IsError    bool            `json:"isError"`
				Structured json.RawMessage `json:"structuredContent"`
				Content    []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(raw, &rpc) != nil {
			return record, fmt.Errorf("invalid MCP response during %s", name)
		}
		if rpc.Result.IsError || len(rpc.Error) > 0 {
			return record, fmt.Errorf("MCP rejected demo %s; check the current contract and rerun with the same options", name)
		}
		payload := rpc.Result.Structured
		if len(payload) == 0 && len(rpc.Result.Content) == 1 && rpc.Result.Content[0].Type == "text" {
			payload = []byte(rpc.Result.Content[0].Text)
		}
		if json.Unmarshal(payload, &record) != nil || record.ID == "" {
			return record, fmt.Errorf("invalid record returned by %s", name)
		}
		return record, nil
	}
	return record, fmt.Errorf("MCP request exhausted retries during %s", name)
}
