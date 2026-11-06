package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/superagent-ai/security-graph/internal/demoseed"
	"github.com/superagent-ai/security-graph/pkg/postgres"
)

func seedDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("seed-demo", flag.ContinueOnError)
	config := demoseed.Config{}
	fs.StringVar(&config.Organization, "org", "demo-security-graph", "isolated organization; must start with demo-")
	fs.IntVar(&config.Findings, "findings", 2000, "number of synthetic findings")
	fs.IntVar(&config.Assets, "assets", 60, "number of fictional assets")
	fs.IntVar(&config.Reports, "reports", 120, "number of assessment reports")
	fs.IntVar(&config.Workers, "workers", 4, "concurrent report workflows, 1 to 16")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("seed-demo accepts flags only")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if backend := os.Getenv("STORAGE_BACKEND"); backend != "" && backend != "postgres" {
		return errors.New("seed-demo supports standalone PostgreSQL only; never use an app or production database")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required for seed-demo; use a local development database")
	}
	db, err := postgres.Open(ctx, url)
	if err != nil {
		return errors.New("could not connect to the demo database")
	}
	defer db.Close()
	summary, err := demoseed.Run(ctx, db, config, os.Stderr)
	if err != nil {
		return fmt.Errorf("demo seed incomplete; rerun the same options to resume: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(summary)
}
