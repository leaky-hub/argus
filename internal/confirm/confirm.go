// Package confirm performs bounded impact confirmation on confirmed dynamic
// findings. A finding is a claim; a confirmation is proof of impact. For the
// classes Argus confirms today (SQL injection and OS command injection) it
// sends the minimum identifying probe against an already-confirmed finding and
// attaches the result as an ImpactProof.
//
// This is active exploitation, so it runs ONLY behind the confirmation
// interlock: the engagement's Confirm flag AND a per-run confirmation, checked
// through the governor, which also scope-gates, budgets, and audits every probe.
// It proves impact and takes nothing more: a DB banner and current user, or a
// single benign `id`. It never dumps data, opens a shell, persists, or changes
// target state (the platform hard limits still refuse regardless).
package confirm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zer0d4y5/argus/internal/cmdiscan"
	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
	"github.com/zer0d4y5/argus/internal/sqlmapscan"
)

// Inputs carry the shared context a confirmation probe needs.
type Inputs struct {
	Client  *http.Client      // governed client for in-process probes (cmdi)
	Cookie  string            // session cookie for subprocess tools (sqlmap)
	Headers []string          // request headers for in-process probes (cmdi)
	Bodies  map[string]string // POST bodies indexed by poc.RequestKey(method, url)
}

// Run confirms impact for the confirmable dynamic findings in raw, attaching an
// ImpactProof to each finding it confirms. It is a no-op unless the confirmation
// interlock is armed. It mutates raw in place and sends the minimum identifying
// probe per finding, each gated and audited through the governor.
func Run(ctx context.Context, gov *engagement.Governor, raw []model.RawFinding, in Inputs, progress func(string)) {
	if progress == nil {
		progress = func(string) {}
	}
	if gov == nil || !gov.ConfirmationArmed() {
		return
	}
	confirmed := 0
	for i := range raw {
		if ctx.Err() != nil {
			break
		}
		r := &raw[i]
		if r.Category != model.CategoryDAST {
			continue
		}
		var imp *model.ImpactProof
		switch poc.ClassForCWEs(r.CWEs) {
		case "sqli":
			imp = confirmSQLi(ctx, gov, r, in, progress)
		case "cmdi":
			imp = confirmCmdi(ctx, gov, r, in, progress)
		}
		if imp != nil {
			attachImpact(r, imp)
			confirmed++
		}
	}
	if confirmed > 0 {
		progress(fmt.Sprintf("confirm: bounded impact confirmed for %d finding(s)\n", confirmed))
	}
}

func confirmSQLi(ctx context.Context, gov *engagement.Governor, r *model.RawFinding, in Inputs, progress func(string)) *model.ImpactProof {
	const action = "sql-identity"
	if err := gov.RequireConfirmation(action); err != nil {
		progress(fmt.Sprintf("  ! confirmation refused: %v\n", err))
		return nil
	}
	// sqlmap is a subprocess: scope- and budget-gate it at dispatch.
	if urls := gov.FilterEndpoints("sqlmap-confirm", []string{r.URL}); len(urls) == 0 {
		return nil
	}
	ep := endpointFor(r, in.Bodies)
	id, err := sqlmapscan.ConfirmIdentity(ctx, ep, sqlmapscan.Options{Cookie: in.Cookie})
	if err != nil {
		progress(fmt.Sprintf("  ! sqlmap confirm %s: %v\n", r.URL, err))
		return nil
	}
	if id == nil {
		return nil
	}
	return &model.ImpactProof{
		Kind:    "sql-identity",
		Summary: formatIdentity(*id),
		Detail:  identityDetail(*id),
	}
}

func confirmCmdi(ctx context.Context, gov *engagement.Governor, r *model.RawFinding, in Inputs, progress func(string)) *model.ImpactProof {
	const action = "cmd-id"
	if err := gov.RequireConfirmation(action); err != nil {
		progress(fmt.Sprintf("  ! confirmation refused: %v\n", err))
		return nil
	}
	param := strings.TrimSpace(r.Meta["param"])
	if param == "" {
		return nil
	}
	ep := endpointFor(r, in.Bodies)
	// cmdi runs through the governed client, so each probe is scope-checked,
	// budgeted, and audited per request.
	line, ok, err := cmdiscan.ConfirmID(ctx, in.Client, ep, param, in.Headers)
	if err != nil {
		progress(fmt.Sprintf("  ! cmdi confirm %s: %v\n", r.URL, err))
		return nil
	}
	if !ok {
		return nil
	}
	return &model.ImpactProof{
		Kind:    "cmd-id",
		Command: "id",
		Summary: line,
	}
}

// endpointFor reconstructs the request context for a finding from its URL, its
// method (Meta method or sqlmap's place), and the discovered POST body.
func endpointFor(r *model.RawFinding, bodies map[string]string) dastcrawl.Endpoint {
	method := firstNonEmpty(r.Meta["method"], r.Meta["place"], "GET")
	method = strings.ToUpper(method)
	body := r.Meta["body"]
	if body == "" && bodies != nil {
		body = bodies[poc.RequestKey(method, r.URL)]
	}
	return dastcrawl.Endpoint{URL: r.URL, Method: method, Body: body}
}

// formatIdentity renders the one-line impact summary from a SQLi identity.
func formatIdentity(id sqlmapscan.Identity) string {
	parts := make([]string, 0, 3)
	if id.Banner != "" {
		parts = append(parts, id.Banner)
	}
	if id.CurrentUser != "" {
		parts = append(parts, "current user "+id.CurrentUser)
	}
	if id.CurrentDB != "" {
		parts = append(parts, "current database "+id.CurrentDB)
	}
	if len(parts) == 0 {
		return "injection reaches the database (identity retrieved)"
	}
	return strings.Join(parts, ", ")
}

func identityDetail(id sqlmapscan.Identity) string {
	var b strings.Builder
	if id.Banner != "" {
		fmt.Fprintf(&b, "banner: %s\n", id.Banner)
	}
	if id.CurrentUser != "" {
		fmt.Fprintf(&b, "current user: %s\n", id.CurrentUser)
	}
	if id.CurrentDB != "" {
		fmt.Fprintf(&b, "current database: %s\n", id.CurrentDB)
	}
	return strings.TrimRight(b.String(), "\n")
}

// attachImpact records the confirmation on the finding's proof, creating the
// proof if the reproduction builder did not (a confirmed finding normally
// already carries one).
func attachImpact(r *model.RawFinding, imp *model.ImpactProof) {
	if r.Proof == nil {
		r.Proof = &model.Proof{}
	}
	r.Proof.Impact = imp
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
