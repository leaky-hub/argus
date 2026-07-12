package jsrecon

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
)

// This file is the hostile-input parser: it reads JavaScript the target served
// and extracts attack surface from it. Go's regexp is RE2 (linear, no
// catastrophic backtracking), so the patterns are safe on adversarial input.
// SECURITY: a matched secret VALUE is never stored in a finding; only a redacted
// preview (first/last few characters) survives, mirroring the SECRET-metadata
// discipline used everywhere else in Argus.

// Endpoint-shaped string references in JS. Each captures a URL or path.
var (
	reFetch = regexp.MustCompile("(?i)\\bfetch\\s*\\(\\s*[\"'`]([^\"'`\\s]+)")
	reHTTP  = regexp.MustCompile("(?i)\\b(?:axios|http|\\$http|request|ajax|superagent|got)\\s*\\.\\s*(?:get|post|put|delete|patch|request|head)\\s*\\(\\s*[\"'`]([^\"'`\\s]+)")
	reURLKV = regexp.MustCompile("(?i)\\b(?:url|endpoint|path|uri|route|baseURL|apiUrl)\\s*[:=]\\s*[\"'`]([^\"'`\\s]+)")
	// Any quoted absolute path. Broad, so it is filtered hard afterwards.
	rePath = regexp.MustCompile("[\"'`](/[A-Za-z0-9_][A-Za-z0-9_\\-./]*(?:\\?[^\"'`\\s]*)?)[\"'`]")
)

// High-confidence provider secret patterns. Deliberately provider-specific to
// keep precision high: a generic "apiKey: '...'" grep would drown the operator
// in false positives (that is gitleaks' job, on the source, not ours here).
type secretPattern struct {
	kind     string
	severity string
	cwe      string
	re       *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"AWS access key id", "high", "CWE-798", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"Google API key", "high", "CWE-798", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Slack token", "high", "CWE-798", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b`)},
	{"Stripe live secret key", "critical", "CWE-798", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}\b`)},
	{"GitHub token", "high", "CWE-798", regexp.MustCompile(`\bgh[posru]_[0-9A-Za-z]{36,}\b`)},
	{"Google OAuth client secret", "high", "CWE-798", regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_\-]{20,}\b`)},
	{"JSON Web Token", "medium", "CWE-200", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)},
}

// reSensitive marks a path that names an administrative, internal, or
// documentation surface worth surfacing on its own (and fuzzing).
var reSensitive = regexp.MustCompile(`(?i)/(admin|internal|debug|actuator|graphql|swagger|api-docs|openapi|\.git|backup|console|management|metrics|healthz?)\b`)

// assetExts are static-asset suffixes not worth treating as fuzzable endpoints.
var assetExts = map[string]bool{
	".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".pdf": true, ".mp4": true, ".webp": true, ".map": true,
	".scss": true, ".less": true, ".wasm": true,
}

// analyzeSource extracts endpoints, secret findings, and sensitive-surface
// findings from one JavaScript source. bundleURL identifies where the source
// came from (a bundle URL, or a sourcemap origin); base anchors relative paths.
func analyzeSource(src, bundleURL string, base *url.URL) ([]dastcrawl.Endpoint, []model.RawFinding) {
	eps := extractEndpoints(src, base)
	var findings []model.RawFinding
	findings = append(findings, extractSecretFindings(src, bundleURL)...)

	surfEps, surfFindings := extractSurfaces(eps, bundleURL)
	findings = append(findings, surfFindings...)
	return surfEps, findings
}

// extractEndpoints collects endpoint-shaped strings and resolves them to
// same-host GET endpoints, dropping assets and off-host references. The result
// is deduplicated by URL.
func extractEndpoints(src string, base *url.URL) []dastcrawl.Endpoint {
	seen := map[string]bool{}
	var out []dastcrawl.Endpoint

	add := func(raw string) {
		u := resolveEndpoint(raw, base)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, dastcrawl.Endpoint{URL: u, Method: "GET"})
	}

	for _, m := range reFetch.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	for _, m := range reHTTP.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	for _, m := range reURLKV.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	for _, m := range rePath.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	return out
}

// resolveEndpoint normalizes one candidate reference to an absolute, same-host
// http(s) URL with a path, or "" if it is not a usable endpoint. It keeps only
// references that resolve to the base host: a third-party URL is out of our
// scope to attack, and a bare relative word is too ambiguous to fuzz.
func resolveEndpoint(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || base == nil {
		return ""
	}
	// Ignore template-literal placeholders and protocol-relative junk we cannot
	// resolve to a concrete request.
	if strings.ContainsAny(raw, "${}<>") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	if abs.Hostname() != base.Hostname() {
		return "" // only the target's own surface
	}
	if abs.Path == "" || abs.Path == "/" {
		return ""
	}
	if isAsset(abs.Path) {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

func isAsset(path string) bool {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return assetExts[strings.ToLower(path[i:])]
	}
	return false
}

// extractSecretFindings runs the provider patterns and emits one redacted
// finding per distinct secret. The raw secret is never stored: only a preview.
func extractSecretFindings(src, bundleURL string) []model.RawFinding {
	var out []model.RawFinding
	seen := map[string]bool{}
	for _, p := range secretPatterns {
		for _, match := range p.re.FindAllString(src, -1) {
			key := p.kind + "\x00" + match
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, model.RawFinding{
				Tool:        "argus-jsrecon",
				Category:    model.CategoryDAST,
				RuleID:      "jsrecon-secret:" + slug(p.kind),
				Title:       "Exposed " + p.kind + " in client-side JavaScript",
				Description: fmt.Sprintf("A %s is hardcoded in JavaScript served to the browser, so any visitor can read it. Rotate the credential and move it server-side.", p.kind),
				RawSeverity: p.severity,
				URL:         bundleURL,
				CWEs:        []string{p.cwe},
				Meta: map[string]string{
					"kind":    p.kind,
					"preview": redact(match),
					"bundle":  bundleURL,
				},
			})
		}
	}
	return out
}

// extractSurfaces splits the discovered endpoints, emitting an informational
// finding for any that names an administrative, internal, or documentation
// surface (which is worth the operator's attention on its own), and returns the
// endpoints unchanged so they are still fuzzed.
func extractSurfaces(eps []dastcrawl.Endpoint, bundleURL string) ([]dastcrawl.Endpoint, []model.RawFinding) {
	var findings []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range eps {
		if !reSensitive.MatchString(ep.URL) || seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		findings = append(findings, model.RawFinding{
			Tool:        "argus-jsrecon",
			Category:    model.CategoryDAST,
			RuleID:      "jsrecon-surface",
			Title:       "Sensitive endpoint referenced in client-side JavaScript",
			Description: fmt.Sprintf("The JavaScript references %s, an administrative, internal, or documentation surface discovered from the client bundle rather than by link-following. Confirm it enforces authorization.", ep.URL),
			RawSeverity: "info",
			URL:         ep.URL,
			CWEs:        []string{"CWE-200"},
			Meta:        map[string]string{"bundle": bundleURL},
		})
	}
	return eps, findings
}

// redact renders a non-reversible preview of a secret: enough to recognize which
// credential it is, never enough to use it.
func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// slug lowercases and hyphenates a kind label for a stable rule id.
func slug(s string) string {
	b := make([]rune, 0, len(s))
	prevDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, r)
			prevDash = false
		} else if !prevDash {
			b = append(b, '-')
			prevDash = true
		}
	}
	return strings.Trim(string(b), "-")
}
