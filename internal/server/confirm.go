package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/zer0d4y5/argus/internal/audit"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/pipeline"
	"github.com/zer0d4y5/argus/internal/poc"
	"github.com/zer0d4y5/argus/internal/runstore"
	"github.com/zer0d4y5/argus/internal/targets"
)

// Bounded impact confirmation from the console (Workstream B). This is active
// exploitation of an already-confirmed finding, so it is admin-only, needs an
// explicit confirm in the request body (the confirmation interlock's second
// latch) on top of the engagement's Confirm flag (the first latch), and re-runs
// the minimum identifying probe live. The result is returned in the response
// and audited; it is NOT written back into the historical run file, matching the
// console's other post-scan seams (explain/validate).

// ConfirmImpactRequest is POST /api/confirm-impact. Confirm must be true: it is
// the operator's explicit affirmation that they are exercising the finding.
type ConfirmImpactRequest struct {
	TargetID  string `json:"targetId"`
	RunID     string `json:"runId"`
	FindingID string `json:"findingId"`
	Confirm   bool   `json:"confirm"`
}

// ConfirmImpactResponse carries the bounded confirmation result.
type ConfirmImpactResponse struct {
	Confirmed bool               `json:"confirmed"`
	Impact    *model.ImpactProof `json:"impact,omitempty"`
	Message   string             `json:"message,omitempty"`
}

func (s *Server) handleConfirmImpact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ConfirmImpactRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetID == "" || req.RunID == "" || req.FindingID == "" {
		writeErr(w, http.StatusBadRequest, "targetId, runId, and findingId are required")
		return
	}
	// The second latch: the operator must explicitly affirm active exploitation.
	if !req.Confirm {
		writeErr(w, http.StatusBadRequest, "bounded confirmation actively exploits the finding; resend with confirm:true to affirm")
		return
	}

	if s.targets == nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	t, err := s.targets.Get(req.TargetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	if t.Kind() != targets.TypeDAST {
		writeErr(w, http.StatusBadRequest, "impact confirmation applies to DAST targets only")
		return
	}
	dir, ok := s.targets.NonFSRunStore(t)
	if !ok {
		writeErr(w, http.StatusBadRequest, "target has no dynamic run history")
		return
	}
	store := runstore.Store{Dir: dir}
	doc, err := store.Load(req.RunID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "run not found")
		return
	}
	var found *model.Finding
	for i := range doc.Findings {
		if doc.Findings[i].ID == req.FindingID {
			found = &doc.Findings[i]
			break
		}
	}
	if found == nil {
		writeErr(w, http.StatusNotFound, "finding not found in this run")
		return
	}
	class := poc.ClassForCWEs(found.CWEs)
	if class != "sqli" && class != "cmdi" {
		writeErr(w, http.StatusUnprocessableEntity, "no bounded confirmation exists for this finding class")
		return
	}
	if found.Location.URL == "" {
		writeErr(w, http.StatusUnprocessableEntity, "finding has no URL to probe")
		return
	}

	// Arm the confirmation interlock's second latch (this admin action is the
	// affirmation); the engagement's Confirm flag is still required.
	gov, err := consoleGovernor(s.targets, true, func(string) {})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if !gov.Engagement().Confirm {
		writeErr(w, http.StatusConflict, "the active engagement does not permit confirmation; recreate it with --allow-confirmation")
		return
	}

	// Resolve the target's DAST auth config so the probe can re-establish a
	// session (creds from named env vars, in memory only).
	var opts pipeline.DASTOptions
	applyDastConfig(&opts, t, func(string) {})

	imp, cerr := pipeline.ConfirmImpact(r.Context(), pipeline.ConfirmOptions{
		Governor: gov,
		Auth:     opts.Auth,
		LoginURL: t.URL,
		Target: pipeline.ConfirmTarget{
			URL:    found.Location.URL,
			Method: metaGet(found.Meta, "method", "place"),
			Body:   metaGet(found.Meta, "body"),
			Param:  metaGet(found.Meta, "param"),
			Class:  class,
		},
	}, func(string) {})

	s.audit(audit.EventConfirmImpact, actorFrom(r), map[string]string{
		"target": req.TargetID, "run": req.RunID, "finding": req.FindingID,
		"class": class, "confirmed": strconv.FormatBool(imp != nil && cerr == nil),
	})

	if cerr != nil {
		code := http.StatusConflict
		if strings.Contains(cerr.Error(), "dast auth") {
			code = http.StatusBadGateway
		}
		writeErr(w, code, cerr.Error())
		return
	}
	if imp == nil {
		writeJSON(w, http.StatusOK, ConfirmImpactResponse{Confirmed: false, Message: "the probe did not confirm impact this run"})
		return
	}
	writeJSON(w, http.StatusOK, ConfirmImpactResponse{Confirmed: true, Impact: imp})
}

// metaGet returns the first present, non-empty value among keys from a possibly
// nil map.
func metaGet(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
