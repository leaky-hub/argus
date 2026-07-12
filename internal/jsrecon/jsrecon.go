// Package jsrecon reverse-engineers a running web target's client-side
// JavaScript to recover the attack surface that link-following never sees:
// endpoints and API routes, sensitive administrative surfaces, and credentials
// hardcoded into bundles served to the browser. It fetches the target's HTML,
// pulls the referenced script bundles (and their sourcemaps when present), and
// extracts that surface, feeding discovered endpoints back to the active engines
// and emitting redacted findings for exposed secrets.
//
// SECURITY:
//   - Every fetch goes through the caller-supplied http.Client, which in the
//     DAST pipeline is the engagement's governed client: recon sends requests
//     too, so it is scope-gated, budgeted, and audited exactly like the crawl.
//     Only same-host, in-scope bundles are fetched; a third-party CDN script is
//     off-scope and the governed transport refuses it.
//   - It reads and parses what the target serves; it never executes JavaScript.
//   - A matched secret's value is never stored: findings carry a redacted
//     preview only (see extract.go), mirroring the SECRET-metadata discipline.
package jsrecon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
)

// Bounds keep recon proportionate: a target cannot make Argus fetch an unbounded
// number of megabyte bundles, and extraction results are capped.
const (
	defaultMaxBundles = 25
	defaultMaxBytes   = int64(3 << 20) // 3 MiB per document
	maxEndpoints      = 400
	maxFindings       = 150
)

// Options tune a recon pass.
type Options struct {
	MaxBundles int      // cap on script bundles fetched (0 = default)
	MaxBytes   int64    // per-document read cap (0 = default)
	Headers    []string // extra request headers (e.g. auth), applied to each fetch
}

// Result is the recovered surface: fuzzable endpoints for the active engines and
// findings for exposed secrets and sensitive surfaces.
type Result struct {
	Endpoints []dastcrawl.Endpoint
	Findings  []model.RawFinding
	Bundles   int // documents (bundles + sourcemaps) analyzed
}

// Analyze fetches baseURL, discovers its script bundles, and extracts the client
// -side attack surface. client carries the engagement's governance and the auth
// session; progress may be nil.
func Analyze(ctx context.Context, client *http.Client, baseURL string, opts Options, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = http.DefaultClient
	}
	if opts.MaxBundles <= 0 {
		opts.MaxBundles = defaultMaxBundles
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return Result{}, fmt.Errorf("jsrecon: invalid base URL: %w", err)
	}

	a := &analyzer{client: client, base: base, opts: opts, progress: progress, seen: map[string]bool{}}

	// Fetch the landing page, analyze its inline scripts, and enumerate its
	// external bundles.
	page, _, ok := a.fetch(ctx, baseURL)
	if !ok {
		progress("==> jsrecon: could not fetch the target page; skipping client-side recon\n")
		return a.result(), nil
	}
	bundles, inlineEps, inlineFindings := a.parseHTML(string(page))
	a.addEndpoints(inlineEps)
	a.addFindings(inlineFindings)

	// Fetch and analyze each external bundle (and its sourcemap) through the
	// governed client, up to the bundle cap.
	for _, b := range bundles {
		if a.bundles >= a.opts.MaxBundles {
			progress(fmt.Sprintf("==> jsrecon: bundle cap (%d) reached; stopping\n", a.opts.MaxBundles))
			break
		}
		a.analyzeBundle(ctx, b)
	}

	progress(fmt.Sprintf("==> jsrecon: %d bundle(s) analyzed, %d endpoint(s) recovered, %d finding(s)\n",
		a.bundles, len(a.endpoints), len(a.findings)))
	return a.result(), nil
}

type analyzer struct {
	client   *http.Client
	base     *url.URL
	opts     Options
	progress func(string)

	seen      map[string]bool // fetched/analyzed URLs, dedup
	endpoints []dastcrawl.Endpoint
	epSeen    map[string]bool
	findings  []model.RawFinding
	bundles   int
}

func (a *analyzer) result() Result {
	return Result{Endpoints: a.endpoints, Findings: a.findings, Bundles: a.bundles}
}

// analyzeBundle fetches one script bundle, extracts its surface, and follows a
// sourcemap when one is present (original sources reveal more than minified code).
func (a *analyzer) analyzeBundle(ctx context.Context, bundleURL string) {
	if a.seen[bundleURL] {
		return
	}
	a.seen[bundleURL] = true
	body, _, ok := a.fetch(ctx, bundleURL)
	if !ok {
		return
	}
	a.bundles++
	src := string(body)

	eps, findings := analyzeSource(src, bundleURL, a.base)
	a.addEndpoints(eps)
	a.addFindings(findings)

	if mapURL := sourceMappingURL(src, bundleURL); mapURL != "" && a.bundles < a.opts.MaxBundles {
		a.analyzeSourceMap(ctx, mapURL)
	}
}

// analyzeSourceMap fetches a sourcemap and analyzes its embedded original
// sources, which typically expose more endpoints than the minified bundle.
func (a *analyzer) analyzeSourceMap(ctx context.Context, mapURL string) {
	if a.seen[mapURL] {
		return
	}
	a.seen[mapURL] = true
	body, _, ok := a.fetch(ctx, mapURL)
	if !ok {
		return
	}
	a.bundles++
	for _, src := range sourcesContent(body) {
		eps, findings := analyzeSource(src, mapURL, a.base)
		a.addEndpoints(eps)
		a.addFindings(findings)
	}
}

// parseHTML enumerates external script src URLs (same-host, resolved) and
// analyzes inline script bodies for endpoints and secrets.
func (a *analyzer) parseHTML(doc string) (bundles []string, eps []dastcrawl.Endpoint, findings []model.RawFinding) {
	node, err := html.Parse(strings.NewReader(doc))
	if err != nil {
		return nil, nil, nil
	}
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			if src := attr(n, "src"); src != "" {
				if u := a.resolveSameHost(src); u != "" && !seen[u] {
					seen[u] = true
					bundles = append(bundles, u)
				}
			} else if n.FirstChild != nil {
				// Inline script body.
				var sb strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						sb.WriteString(c.Data)
					}
				}
				e, f := analyzeSource(sb.String(), a.base.String(), a.base)
				eps = append(eps, e...)
				findings = append(findings, f...)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(node)
	return bundles, eps, findings
}

// resolveSameHost resolves a script src against the base and returns it only if
// it stays on the target host; an off-host CDN bundle is not ours to analyze.
func (a *analyzer) resolveSameHost(ref string) string {
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	abs := a.base.ResolveReference(r)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	if abs.Hostname() != a.base.Hostname() {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

func (a *analyzer) addEndpoints(eps []dastcrawl.Endpoint) {
	if a.epSeen == nil {
		a.epSeen = map[string]bool{}
	}
	for _, e := range eps {
		if len(a.endpoints) >= maxEndpoints {
			return
		}
		key := e.Method + " " + e.URL
		if a.epSeen[key] {
			continue
		}
		a.epSeen[key] = true
		a.endpoints = append(a.endpoints, e)
	}
}

func (a *analyzer) addFindings(fs []model.RawFinding) {
	for _, f := range fs {
		if len(a.findings) >= maxFindings {
			return
		}
		a.findings = append(a.findings, f)
	}
}

// fetch performs a bounded GET through the governed client and returns the body,
// its content type, and ok=false on any error (an off-scope refusal, a network
// error, or a non-2xx). A failed fetch is skipped, never fatal.
func (a *analyzer) fetch(ctx context.Context, rawURL string) ([]byte, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", false
	}
	for _, h := range a.opts.Headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, a.opts.MaxBytes))
	if err != nil {
		return nil, "", false
	}
	return body, resp.Header.Get("Content-Type"), true
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}
