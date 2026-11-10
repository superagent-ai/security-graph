package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/superagent-ai/security-graph/pkg/catalog"
)

type catalogPayload struct {
	raw  []byte
	etag string
	err  error
}

var catalogPayloads sync.Map

// Only public, immutable publisher definitions are served here. No storage,
// principal, findings or tenant records can enter this response. MCP tools
// continue to require authentication and intent.
func publicCatalog(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("version")
	c, err := catalog.Load()
	if version != "" {
		c, err = catalog.LoadVersion(version)
	}
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		http.Error(w, "catalog version not found", http.StatusNotFound)
		return
	}
	encoded, _ := catalogPayloads.LoadOrStore(c.Version, sync.OnceValue(func() catalogPayload {
		raw, err := json.Marshal(c)
		return catalogPayload{raw: raw, etag: fmt.Sprintf(`"%x"`, sha256.Sum256(raw)), err: err}
	}))
	payload := encoded.(func() catalogPayload)()
	if payload.err != nil {
		http.Error(w, "catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := payload.etag
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", etag)
	if version == "" {
		w.Header().Set("Cache-Control", "public, max-age=30, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(payload.raw)
}
