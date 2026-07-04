// Package llm defines the provider-agnostic completion interface used by AI
// triage (Phase 2). The scan pipeline never depends on a provider being
// reachable: triage is enrichment, and every provider error degrades
// gracefully upstream.
//
// Security note: callers (internal/triage) treat scanned code as hostile
// input. This package is transport only — prompt assembly and output
// validation live with the caller and must not be duplicated or "helpfully"
// post-processed here.
package llm

import (
	"context"
	"errors"
	"fmt"
)

// Request is a single completion request. Providers must send System and User
// verbatim — no rewriting, trimming, or concatenating with provider-side
// boilerplate — because the caller's prompt structure is a security boundary.
type Request struct {
	System      string  // system prompt (trusted, caller-controlled)
	User        string  // user message (contains delimited untrusted data)
	MaxTokens   int     // hard output cap; providers must set it (never unlimited)
	Temperature float64 // 0 = deterministic-ish; triage wants low variance
	ForceJSON   bool    // ask the provider for JSON-constrained output when supported
}

// Client is a minimal completion client. Implementations must honor ctx
// cancellation/deadline and return the raw model text without interpretation.
type Client interface {
	// Name identifies provider and model for audit trails,
	// e.g. "ollama/qwen3.6:35b-a3b" or "anthropic/claude-haiku-4-5".
	Name() string
	// Local reports whether inference happens on this machine. SECRET-category
	// findings may only be sent to local providers unless the user opts in.
	Local() bool
	Complete(ctx context.Context, req Request) (string, error)
}

// ErrUnavailable marks a provider that cannot serve requests at all (endpoint
// down, missing API key, model not installed). Callers use it to skip triage
// with a single warning instead of failing per finding.
var ErrUnavailable = errors.New("llm provider unavailable")

// Unavailable wraps err so errors.Is(err, ErrUnavailable) holds.
func Unavailable(provider string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, provider, err)
}
