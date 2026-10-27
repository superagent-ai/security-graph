// Export the same input schemas published by the real MCP tool registry.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	ctx := context.Background()
	a, b := mcp.NewInMemoryTransports()
	s, err := server.NewMCP(nil, storage.Principal{}, "schema").Connect(ctx, a, nil)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	c, err := mcp.NewClient(&mcp.Implementation{Name: "schema-export", Version: "1"}, nil).Connect(ctx, b, nil)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	tools, err := c.ListTools(ctx, nil)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(tools.Tools)
}
