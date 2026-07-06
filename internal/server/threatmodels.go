package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/leaky-hub/appsec/internal/audit"
	"github.com/leaky-hub/appsec/internal/threatlib"
	"github.com/leaky-hub/appsec/internal/threatmodel"
)

// Threat-modeling endpoints. A model is scoped to a target; its components drive
// deterministic STRIDE enumeration from the curated library (internal/threatlib),
// and its threats link to real findings, controls, and mitigations. Operators
// create and edit, admins delete, every mutation is audited. The LLM never sets
// a threat's status (no assisted pass in v1); content is curated or hand-authored.

// handleThreatLibrary: GET the curated component types, for the "add component"
// tech picker.
func (s *Server) handleThreatLibrary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": threatlib.Components()})
}

// ThreatModelDetail is the full model payload.
type ThreatModelDetail struct {
	threatmodel.Model
	Components []threatmodel.Component       `json:"components"`
	Threats    []threatmodel.Threat          `json:"threats"`
	Links      map[string][]threatmodel.Link `json:"links"`
}

func (s *Server) handleThreatModels(w http.ResponseWriter, r *http.Request) {
	if s.threats == nil {
		writeErr(w, http.StatusNotFound, "threat modeling is not enabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		models, err := s.threats.ListModels(r.URL.Query().Get("target"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list models")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": models})
	case http.MethodPost:
		var req struct{ TargetID, Name, Description string }
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		m, err := s.threats.CreateModel(req.TargetID, req.Name, req.Description, actorFrom(r), time.Now())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(audit.EventThreatModel, actorFrom(r), map[string]string{"model": m.ID, "target": req.TargetID, "action": "create"})
		writeJSON(w, http.StatusCreated, m)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleThreatModelByID(w http.ResponseWriter, r *http.Request) {
	if s.threats == nil {
		writeErr(w, http.StatusNotFound, "threat modeling is not enabled")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/threat-models/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid model id")
		return
	}
	actor := actorFrom(r)
	now := time.Now()

	switch {
	case sub == "" && r.Method == http.MethodGet:
		m, err := s.threats.GetModel(id)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		comps, _ := s.threats.Components(id)
		threats, _ := s.threats.Threats(id)
		links, _ := s.threats.LinksForModel(id)
		if links == nil {
			links = map[string][]threatmodel.Link{}
		}
		writeJSON(w, http.StatusOK, ThreatModelDetail{Model: m, Components: comps, Threats: threats, Links: links})

	case sub == "" && r.Method == http.MethodDelete:
		if err := s.threats.DeleteModel(id); err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatModel, actor, map[string]string{"model": id, "action": "delete"})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case sub == "components" && r.Method == http.MethodPost:
		var req struct{ Kind, Name, Tech, Notes string }
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		c, err := s.threats.AddComponent(id, req.Kind, req.Name, req.Tech, req.Notes, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "add-component"})
		writeJSON(w, http.StatusCreated, c)

	case sub == "enumerate" && r.Method == http.MethodPost:
		var req struct{ ComponentID string }
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		n, err := s.threats.EnumerateComponent(req.ComponentID, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "enumerate", "added": itoa(n)})
		writeJSON(w, http.StatusOK, map[string]int{"added": n})

	case sub == "threats" && r.Method == http.MethodPost:
		var req struct{ ComponentID, Category, Title, Description, Mitigation string }
		if err := decodeBody(w, r, &req, 1<<20); err != nil {
			return
		}
		t, err := s.threats.AddThreat(id, req.ComponentID, req.Category, req.Title, req.Description, "curated", req.Mitigation, actor, now)
		if err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "add-threat"})
		writeJSON(w, http.StatusCreated, t)

	case sub == "threat-status" && r.Method == http.MethodPost:
		var req struct{ ThreatID, Status string }
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		if err := s.threats.SetThreatStatus(req.ThreatID, req.Status, now); err != nil {
			s.writeThreatErr(w, err)
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "status", "status": req.Status})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case sub == "links" && r.Method == http.MethodPost:
		var req struct {
			ThreatID, Kind, Ref, TargetID string
			Remove                        bool
		}
		if err := decodeBody(w, r, &req, 8192); err != nil {
			return
		}
		var err error
		if req.Remove {
			err = s.threats.UnlinkThreat(req.ThreatID, req.Kind, req.Ref, req.TargetID)
		} else {
			err = s.threats.LinkThreat(req.ThreatID, req.Kind, req.Ref, req.TargetID)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(audit.EventThreatUpdate, actor, map[string]string{"model": id, "action": "link", "kind": req.Kind})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	default:
		writeErr(w, http.StatusNotFound, "unknown threat-model action")
	}
}

func (s *Server) writeThreatErr(w http.ResponseWriter, err error) {
	if errors.Is(err, threatmodel.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "threat model not found")
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}

// decodeBody is the shared JSON body reader with a byte cap.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return err
	}
	return nil
}
