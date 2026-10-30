package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/superagent-ai/security-graph/internal/engine"
	"github.com/superagent-ai/security-graph/internal/server"
	"github.com/superagent-ai/security-graph/pkg/classifier"
	"github.com/superagent-ai/security-graph/pkg/postgres"
	"github.com/superagent-ai/security-graph/pkg/storage"
	"github.com/superagent-ai/security-graph/pkg/superagent"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: security-graph serve|stdio|migrate|issue-key|revoke-key|version")
	}
	if os.Args[1] == "version" {
		fmt.Println(version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var local storage.Principal
	if os.Args[1] == "stdio" {
		// Stdio trusts the operator launching the process, never MCP client input.
		// Native App access must continue through its existing API-key auth.
		if os.Getenv("STORAGE_BACKEND") == "superagent" {
			return fmt.Errorf("stdio supports standalone storage only; use authenticated HTTP for native Superagent access")
		}
		var err error
		local, err = stdioPrincipal(os.Args[2:])
		if err != nil {
			return err
		}
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	store, err := postgres.Open(ctx, url)
	if err != nil {
		return fmt.Errorf("database connection failed")
	}
	defer store.Close()
	backend := os.Getenv("STORAGE_BACKEND")
	if backend != "" && backend != "postgres" && backend != "superagent" {
		return fmt.Errorf("STORAGE_BACKEND must be postgres or superagent")
	}
	if backend == "superagent" && (os.Args[1] == "issue-key" || os.Args[1] == "revoke-key") {
		return fmt.Errorf("manage native API keys through the Superagent app Settings")
	}
	if backend == "superagent" && os.Args[1] == "serve" {
		if err = superagent.Enable(ctx, store); err != nil {
			return err
		}
	}
	eng := &engine.Engine{Store: store}
	if os.Args[1] == "serve" || os.Args[1] == "stdio" {
		if command := os.Getenv("CLASSIFIER_COMMAND"); command != "" {
			var args []string
			if raw := os.Getenv("CLASSIFIER_ARGS"); raw != "" {
				if json.Unmarshal([]byte(raw), &args) != nil {
					return fmt.Errorf("CLASSIFIER_ARGS must be a JSON string array")
				}
			}
			timeout := classifier.DefaultTimeout
			if raw := os.Getenv("CLASSIFIER_TIMEOUT"); raw != "" {
				timeout, err = time.ParseDuration(raw)
				if err != nil || timeout < time.Second || timeout > classifier.MaxTimeout {
					return fmt.Errorf("CLASSIFIER_TIMEOUT must be a duration between 1s and 2m")
				}
			}
			eng.Classifier = classifier.Command{Path: command, Args: args, Timeout: timeout}
		}
		if raw := os.Getenv("CLASSIFICATION_THRESHOLD"); raw != "" {
			value, err := strconv.ParseFloat(raw, 64)
			if err != nil || !(value > 0 && value <= 1) {
				return fmt.Errorf("CLASSIFICATION_THRESHOLD must be in (0,1]")
			}
			eng.ClassificationThreshold = value
		}
	}
	switch os.Args[1] {
	case "stdio":
		err := server.NewMCP(eng, local, version).Run(ctx, &mcp.StdioTransport{MaxLineLength: 1 << 20})
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return nil
		}
		return err
	case "migrate":
		return store.Migrate(ctx)
	case "issue-key":
		fs := flag.NewFlagSet("issue-key", flag.ContinueOnError)
		org := fs.String("org", "", "organization ID")
		actor := fs.String("actor", "", "agent identity")
		scopes := fs.String("scopes", "read", "comma-separated scopes: read,submit,disposition,graph:write,export")
		assets := fs.String("assets", "", "comma-separated allowed asset IDs")
		all := fs.Bool("all-assets", false, "explicitly permit all organization assets")
		ttl := fs.Duration("ttl", 24*time.Hour, "credential lifetime")
		if err = fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *ttl <= 0 || *ttl > 90*24*time.Hour {
			return fmt.Errorf("ttl must be positive and at most 90 days")
		}
		var raw [32]byte
		if _, err = rand.Read(raw[:]); err != nil {
			return err
		}
		token := "sg_" + base64.RawURLEncoding.EncodeToString(raw[:])
		ids := []string{}
		if *assets != "" {
			ids = strings.Split(*assets, ",")
		}
		p := storage.Principal{OrganizationID: *org, ActorID: *actor, Scopes: strings.Split(*scopes, ","), AssetIDs: ids, AllAssets: *all}
		if err = store.IssueKey(ctx, token, p, time.Now().Add(*ttl)); err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case "revoke-key":
		fs := flag.NewFlagSet("revoke-key", flag.ContinueOnError)
		org := fs.String("org", "", "organization ID")
		actor := fs.String("actor", "", "revoke every credential for this agent")
		if err = fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *org == "" || *actor == "" {
			return fmt.Errorf("org and actor required")
		}
		tag, err := store.Pool.Exec(ctx, "UPDATE security_graph.credentials SET revoked_at=now() WHERE organization_id=$1 AND actor_id=$2 AND revoked_at IS NULL", *org, *actor)
		if err == nil {
			fmt.Printf("revoked %d credentials\n", tag.RowsAffected())
		}
		return err
	case "serve":
		addr := os.Getenv("LISTEN_ADDR")
		if addr == "" {
			addr = "127.0.0.1:8080"
		}
		srv := &http.Server{Addr: addr, Handler: server.Handler(eng, store, version), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		go func() {
			<-ctx.Done()
			stop, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			_ = srv.Shutdown(stop)
		}()
		slog.Info("serving security graph", "address", addr, "version", version)
		err = srv.ListenAndServe()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}
