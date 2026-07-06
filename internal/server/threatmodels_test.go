package server

import (
	"encoding/json"
	"testing"
)

// TestThreatModelLifecycle drives the threat-model endpoints: create a model,
// add a component, enumerate STRIDE from the curated library, set a threat's
// status, link it to a finding, then admin delete.
func TestThreatModelLifecycle(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	viewer := f.mustLogin("vera")

	// The library lists component types for the picker.
	rec := f.do("GET", "/api/threat-library", "", viewer)
	if rec.Code != 200 || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("threat-library: %d", rec.Code)
	}

	// Operator creates a model.
	rec = f.do("POST", "/api/threat-models", `{"name":"Checkout","targetId":""}`, oper)
	if rec.Code != 201 {
		t.Fatalf("create model: %d %s", rec.Code, rec.Body.String())
	}
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	// Add a web-app component.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/components", `{"name":"Web frontend","tech":"web-app","kind":"component"}`, oper)
	if rec.Code != 201 {
		t.Fatalf("add component: %d %s", rec.Code, rec.Body.String())
	}
	var c struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &c)

	// Enumerate STRIDE for it.
	rec = f.do("POST", "/api/threat-models/"+m.ID+"/enumerate", `{"componentId":"`+c.ID+`"}`, oper)
	if rec.Code != 200 {
		t.Fatalf("enumerate: %d %s", rec.Code, rec.Body.String())
	}
	var en struct{ Added int }
	json.Unmarshal(rec.Body.Bytes(), &en)
	if en.Added == 0 {
		t.Error("enumerate added no threats")
	}

	// Detail carries the enumerated threats.
	rec = f.do("GET", "/api/threat-models/"+m.ID, "", viewer)
	var detail struct {
		Threats []struct {
			ID       string
			Category string
			Status   string
			Source   string
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &detail)
	if len(detail.Threats) != en.Added {
		t.Fatalf("detail threats = %d, want %d", len(detail.Threats), en.Added)
	}
	th := detail.Threats[0]
	if th.Source != "curated" || th.Status != "open" {
		t.Errorf("bad enumerated threat: %+v", th)
	}

	// Set a status and link a finding.
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/threat-status", `{"threatId":"`+th.ID+`","status":"mitigated"}`, oper); rec.Code != 200 {
		t.Errorf("status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/links", `{"threatId":"`+th.ID+`","kind":"finding","ref":"fp-abc","targetId":""}`, oper); rec.Code != 200 {
		t.Errorf("link: %d %s", rec.Code, rec.Body.String())
	}

	// Viewer cannot mutate; only admin deletes.
	if rec := f.do("POST", "/api/threat-models", `{"name":"x"}`, viewer); rec.Code != 403 {
		t.Errorf("viewer create = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/threat-models/"+m.ID, "", oper); rec.Code != 403 {
		t.Errorf("operator delete = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/threat-models/"+m.ID, "", admin); rec.Code != 200 {
		t.Errorf("admin delete = %d %s", rec.Code, rec.Body.String())
	}
}
