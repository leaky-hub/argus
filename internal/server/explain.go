package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/model"
	"github.com/leaky-hub/appsec/internal/pipeline"
	"github.com/leaky-hub/appsec/internal/runstore"
	"github.com/leaky-hub/appsec/internal/triage"
)

// On-demand explain endpoint (docs/console-ops.md S5/§12.6). The prompt and
// output boundary live in internal/triage; this file owns the console
// concerns: authz'd routing (operator+, via the authz table), single-flight,
// a bounded cache, config sourcing from the TARGET repo, and the audit line.
// The explanation exists only in this cache and the HTTP response — nothing
// here has a write path to run files.

const explainCacheCap = 200

// ExplainRequest is POST /api/explain. targetId empty = the served repo's
// run history (same resolution rule as GET /api/runs).
type ExplainRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
}

// ExplainResponse is the ephemeral explanation.
type ExplainResponse struct {
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation,omitempty"`
	Model       string `json:"model"`
	Cached      bool   `json:"cached"`
}

// explainEntry is one single-flight cache slot: concurrent requests for the
// same finding block on once while the first computes.
type explainEntry struct {
	once sync.Once
	resp ExplainResponse
	err  error
	code int
}

type explainCache struct {
	mu      sync.Mutex
	entries map[string]*explainEntry
	order   []string // FIFO eviction
}

func (c *explainCache) get(key string) (*explainEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*explainEntry)
	}
	if e, ok := c.entries[key]; ok {
		return e, true
	}
	e := &explainEntry{}
	c.entries[key] = e
	c.order = append(c.order, key)
	if len(c.order) > explainCacheCap {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	return e, false
}

// drop removes a failed computation so a transient provider error does not
// pin the failure until eviction.
func (c *explainCache) drop(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ExplainRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "runId and findingId are required")
		return
	}

	// Resolve the run's home: the served repo, or a registered target by
	// opaque ID (never a path from the request).
	root := s.dir
	if req.TargetID != "" {
		if s.targets == nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		t, err := s.targets.Get(req.TargetID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "target not found")
			return
		}
		root = s.targets.Root(t)
	}

	key := req.TargetID + "|" + req.RunID + "|" + req.FindingID
	entry, cached := s.explains.get(key)
	entry.once.Do(func() {
		entry.resp, entry.code, entry.err = s.computeExplanation(r.Context(), root, req)
		if entry.err != nil {
			s.explains.drop(key)
		}
	})

	s.audit(audit.EventScanExplain, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "finding": req.FindingID,
		"cached": strconv.FormatBool(cached),
	})

	if entry.err != nil {
		writeErr(w, entry.code, entry.err.Error())
		return
	}
	resp := entry.resp
	resp.Cached = cached
	writeJSON(w, http.StatusOK, resp)
}

// computeExplanation loads the finding from the run file and runs the
// explain boundary against the TARGET repo's configured provider.
func (s *Server) computeExplanation(ctx context.Context, root string, req ExplainRequest) (ExplainResponse, int, error) {
	doc, err := runstore.ForRepo(root).Load(req.RunID)
	if err != nil {
		return ExplainResponse{}, http.StatusNotFound, errors.New("run not found")
	}
	var found *model.Finding
	for i := range doc.Findings {
		if doc.Findings[i].ID == req.FindingID {
			found = &doc.Findings[i]
			break
		}
	}
	if found == nil {
		return ExplainResponse{}, http.StatusNotFound, errors.New("finding not found in this run")
	}

	// Provider/model/endpoint come from the target tree's own appsec.yml
	// (defaults when absent) — request input cannot influence them (S3/S5).
	cfg, err := repoConfig(root)
	if err != nil {
		cfg = config.Default()
	}

	factory := s.llmFactory
	if factory == nil {
		factory = pipeline.NewLLMClient
	}
	client := factory(cfg)
	if p, ok := client.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			return ExplainResponse{}, http.StatusServiceUnavailable,
				errors.New("no reachable LLM provider — configure triage in the target's appsec.yml")
		}
	}

	ex, err := triage.Explain(ctx, client, *found, cfg.Triage.AllowSecretCloud,
		time.Duration(cfg.Triage.TimeoutSec)*time.Second)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, triage.ErrSecretCloud) {
			code = http.StatusConflict
		}
		return ExplainResponse{}, code, err
	}
	return ExplainResponse{
		Explanation: ex.Explanation,
		Remediation: ex.Remediation,
		Model:       ex.Model,
	}, 0, nil
}
