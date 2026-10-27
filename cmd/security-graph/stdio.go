package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/superagent-ai/security-graph/pkg/storage"
)

// The local process owns this identity. MCP arguments and client metadata cannot
// select a tenant or grant permissions. Defaults permit assessment, not triage.
func stdioPrincipal(args []string) (storage.Principal, error) {
	fs := flag.NewFlagSet("stdio", flag.ContinueOnError)
	org := fs.String("org", "local", "standalone organization namespace")
	actor := fs.String("actor", "local-agent", "identity recorded for local actions")
	scopes := fs.String("scopes", "read,submit,graph:write", "allowed scopes: read,submit,disposition,graph:write,export")
	assets := fs.String("assets", "", "comma-separated allowed assets; default: all assets in this local organization")
	if err := fs.Parse(args); err != nil {
		return storage.Principal{}, err
	}
	p := storage.Principal{OrganizationID: strings.TrimSpace(*org), ActorID: strings.TrimSpace(*actor), AllAssets: *assets == ""}
	if fs.NArg() != 0 || p.OrganizationID == "" || p.ActorID == "" {
		return p, fmt.Errorf("stdio requires nonempty org/actor and no positional arguments")
	}
	for _, scope := range strings.Split(*scopes, ",") {
		scope = strings.TrimSpace(scope)
		switch scope {
		case "read", "submit", "disposition", "graph:write", "export":
			p.Scopes = append(p.Scopes, scope)
		default:
			return p, fmt.Errorf("invalid stdio scope")
		}
	}
	if !p.AllAssets {
		for _, id := range strings.Split(*assets, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				return p, fmt.Errorf("stdio asset IDs must be nonempty")
			}
			p.AssetIDs = append(p.AssetIDs, id)
		}
	}
	return p, nil
}
