// Package fingerprint identifies a running target's technology stack from what
// the target itself discloses: response headers, session-cookie names, the HTML
// generator tag, and versioned library banners. It turns that into two things:
// version-disclosure findings (leaking an exact server/framework version to
// anonymous clients aids an attacker) and, for CMS families the known-exploited
// catalog tracks, a conservative correlation to CISA KEV.
//
// SECURITY / honesty:
//   - The single fetch goes through the caller's http.Client, which in the DAST
//     pipeline is the engagement's governed client: the request is scope-gated,
//     budgeted, and audited like every other active step.
//   - It only reads what the target serves; it sends no payloads.
//   - KEV correlation is PRODUCT-LEVEL, never a version match: the KEV catalog
//     has no version ranges, so a correlation finding says "this product family
//     is known-exploited, confirm your version is patched", never "you are
//     vulnerable". It carries no CVE field, so it never inflates its own risk
//     score through the exploit-evidence path.
package fingerprint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zer0d4y5/argus/internal/exploit"
	"github.com/zer0d4y5/argus/internal/model"
)

const maxBodyBytes = int64(2 << 20) // 2 MiB of HTML is ample for fingerprinting

// Options tune a fingerprint pass.
type Options struct {
	Headers []string // extra request headers (e.g. auth), applied to the fetch
}

// Result is the identified stack and the findings it produced.
type Result struct {
	Techs    []Tech
	Findings []model.RawFinding
}

// Analyze fetches baseURL once, identifies the stack, and produces
// version-disclosure and KEV-correlation findings. cat may be nil (no KEV
// correlation, disclosure findings still emitted). client carries the
// engagement governance and any auth session; progress may be nil.
func Analyze(ctx context.Context, client *http.Client, baseURL string, cat *exploit.Catalog, opts Options, progress func(string)) (Result, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("fingerprint: %w", err)
	}
	for _, h := range opts.Headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		progress(fmt.Sprintf("==> fingerprint: could not fetch the target: %v\n", err))
		return Result{}, nil // non-fatal: the scan proceeds without a stack profile
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	var techs []Tech
	techs = append(techs, detectHeaders(resp.Header)...)
	techs = append(techs, detectCookies(resp.Header.Values("Set-Cookie"))...)
	techs = append(techs, detectBody(string(body))...)
	techs = dedupeTechs(techs)

	var findings []model.RawFinding
	for _, t := range techs {
		if f, ok := disclosureFinding(t, baseURL); ok {
			findings = append(findings, f)
		}
		if len(t.kevTokens) > 0 {
			if f, ok := correlationFinding(t, baseURL, cat); ok {
				findings = append(findings, f)
			}
		}
	}

	progress(fmt.Sprintf("==> fingerprint: identified %d technolog%s (%s)\n", len(techs), plural(len(techs)), summarize(techs)))
	return Result{Techs: techs, Findings: findings}, nil
}

// disclosureFinding reports an exact version exposed to anonymous clients. Only
// versioned technologies produce one; a bare product name is stack intel, not a
// finding on its own.
func disclosureFinding(t Tech, target string) (model.RawFinding, bool) {
	if t.Version == "" {
		return model.RawFinding{}, false
	}
	return model.RawFinding{
		Tool:        "argus-fingerprint",
		Category:    model.CategoryDAST,
		RuleID:      "fingerprint-version-disclosure:" + slug(t.Name),
		Title:       fmt.Sprintf("Version disclosure: %s %s", t.Name, t.Version),
		Description: fmt.Sprintf("The target discloses %s version %s via its %s. Exposing exact component versions lets an attacker match your stack to known vulnerabilities; suppress the version banner where possible.", t.Name, t.Version, t.Source),
		RawSeverity: "info",
		URL:         target,
		CWEs:        []string{"CWE-200"},
		Meta:        map[string]string{"technology": t.Name, "version": t.Version, "category": t.Category, "source": t.Source},
	}, true
}

// correlationFinding surfaces that a detected product family appears in the KEV
// catalog. It is deliberately hedged (medium, product-level, no CVE field): KEV
// has no version ranges, so it flags a family to verify, never a confirmed
// vulnerability.
func correlationFinding(t Tech, target string, cat *exploit.Catalog) (model.RawFinding, bool) {
	matches := cat.MatchProducts(t.kevTokens...)
	if len(matches) == 0 {
		return model.RawFinding{}, false
	}
	var cves []string
	ransomware := false
	for _, m := range matches {
		cves = append(cves, m.CVE)
		if m.Ransomware {
			ransomware = true
		}
	}
	sample := cves
	if len(sample) > 5 {
		sample = sample[:5]
	}
	verLabel := ""
	if t.Version != "" {
		verLabel = " " + t.Version
	}
	desc := fmt.Sprintf("The target runs %s%s. CISA's Known Exploited Vulnerabilities catalog lists %d known-exploited vulnerabilit%s affecting %s (for example %s). KEV carries no version ranges, so confirm this deployment is patched against them.",
		t.Name, verLabel, len(matches), plural(len(matches)), t.Name, strings.Join(sample, ", "))
	if ransomware {
		desc += " At least one is linked to known ransomware campaigns."
	}
	meta := map[string]string{
		"technology": t.Name,
		"kevCount":   fmt.Sprintf("%d", len(matches)),
		"kevSample":  strings.Join(sample, ", "),
	}
	if t.Version != "" {
		meta["version"] = t.Version
	}
	if ransomware {
		meta["ransomware"] = "true"
	}
	return model.RawFinding{
		Tool:        "argus-fingerprint",
		Category:    model.CategoryDAST,
		RuleID:      "fingerprint-kev-family:" + slug(t.Name),
		Title:       fmt.Sprintf("Known-exploited software family in use: %s", t.Name),
		Description: desc,
		RawSeverity: "medium",
		URL:         target,
		CWEs:        []string{"CWE-1395"}, // dependency on a vulnerable third-party component
		Meta:        meta,
	}, true
}

// summarize renders a short human list of the identified stack for progress.
func summarize(techs []Tech) string {
	if len(techs) == 0 {
		return "none"
	}
	var parts []string
	for _, t := range techs {
		if t.Version != "" {
			parts = append(parts, t.Name+" "+t.Version)
		} else {
			parts = append(parts, t.Name)
		}
	}
	return strings.Join(parts, ", ")
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// slug lowercases and hyphenates a technology name for a stable rule id.
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

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}
