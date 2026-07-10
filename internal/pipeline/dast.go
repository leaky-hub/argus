package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/zer0d4y5/argus/internal/config"
	"github.com/zer0d4y5/argus/internal/dastauth"
	"github.com/zer0d4y5/argus/internal/dastscan"
	"github.com/zer0d4y5/argus/internal/model"
)

// DASTOptions configure one dynamic scan.
type DASTOptions struct {
	URL        string
	Templates  []string
	Tags       []string
	Severities []string
	RateLimit  int
	TimeoutSec int
	Fuzzing    bool     // enable nuclei -dast active fuzzing
	Headers    []string // extra request headers (sent to nuclei, never logged)
	Auth       *DASTAuth
	Config     config.Config
}

// DASTAuth configures pre-scan authentication. When set, RunDAST establishes a
// session before scanning and sends it on every request, so the scan reaches
// pages behind a login. Credential VALUES arrive here already resolved from
// env-var references upstream; they are used in memory and never persisted.
type DASTAuth struct {
	LoginURL    string
	Username    string
	Password    string
	TryDefaults bool // also try the built-in vendor-default list
}

// DASTResult is a completed dynamic scan.
type DASTResult struct {
	Findings    []model.Finding
	ToolVersion string
}

// RunDAST executes a dynamic scan through nuclei and the SAME enrichment half
// as a code or cloud scan (Enrich): unified model -> correlate -> triage seam
// -> risk+band -> compliance. The triage root is "" (a DAST finding has no
// source file; the triager feature-detects that, exactly like cloud).
func RunDAST(ctx context.Context, opts DASTOptions, progress Progress) (DASTResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !dastscan.Available() {
		return DASTResult{}, fmt.Errorf("nuclei not found on PATH: install nuclei to run DAST scans")
	}

	// Authenticate first when configured, and fold the resulting session into
	// the request headers so the scan runs logged in. Auth failure is fatal to
	// the run: silently scanning the login page is worse than a clear error.
	headers := opts.Headers
	if opts.Auth != nil {
		cookie, err := authenticate(ctx, opts, progress)
		if err != nil {
			return DASTResult{}, err
		}
		if cookie != "" {
			headers = append(append([]string{}, headers...), "Cookie: "+cookie)
		}
	}

	scan, err := dastscan.Scan(ctx, dastscan.Options{
		URL:        opts.URL,
		Templates:  opts.Templates,
		Tags:       opts.Tags,
		Severities: opts.Severities,
		RateLimit:  opts.RateLimit,
		TimeoutSec: opts.TimeoutSec,
		Fuzzing:    opts.Fuzzing,
		Headers:    headers,
	}, progress)
	if err != nil {
		return DASTResult{}, err
	}

	findings := Enrich(ctx, opts.Config, "", scan.Raw, progress)
	return DASTResult{Findings: findings, ToolVersion: scan.ToolVersion}, nil
}

// authenticate runs the pre-scan login and returns the session's Cookie header
// value (never logged). An empty return with nil error means the session
// carried no cookies (unusual but not fatal); the scan proceeds unauthenticated.
func authenticate(ctx context.Context, opts DASTOptions, progress Progress) (string, error) {
	a := opts.Auth
	cfg := dastauth.Config{LoginURL: a.LoginURL, TryDefaults: a.TryDefaults}
	if a.Username != "" || a.Password != "" {
		cfg.Credentials = []dastauth.Credential{{Username: a.Username, Password: a.Password}}
	}
	client := &http.Client{Timeout: 20 * time.Second}
	progress(fmt.Sprintf("==> authenticating to %s before scan\n", opts.URL))
	sess, err := dastauth.Authenticate(ctx, client, opts.URL, cfg, progress)
	if err != nil {
		return "", fmt.Errorf("dast auth: %w", err)
	}
	return sess.CookieHeader(), nil
}
