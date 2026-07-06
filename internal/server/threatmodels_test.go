package server

import (
	"encoding/json"
	"testing"

	"github.com/leaky-hub/appsec/internal/config"
	"github.com/leaky-hub/appsec/internal/llm"
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

// TestThreatModelFromTargetIaC: scanning a target dir with IaC builds a baseline
// model with the detected components and enumerated STRIDE, deterministically.
func TestThreatModelFromTargetIaC(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	// The fixture's registered target points at f.scanDir; drop some IaC there.
	writeFile(t, f.scanDir, "main.tf", `
resource "aws_db_instance" "primary" {}
resource "aws_s3_bucket" "assets" {}
`)
	rec := f.do("POST", "/api/threat-models/from-target", `{"targetId":"`+f.targetID+`","name":"Prod baseline"}`, oper)
	if rec.Code != 201 {
		t.Fatalf("from-target: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ModelID    string
		Components int
		Threats    int
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Components != 2 || out.Threats == 0 {
		t.Errorf("baseline: components=%d threats=%d, want 2 components and some threats", out.Components, out.Threats)
	}
}

// TestThreatSuggest: the assisted pass returns validated candidates (STRIDE only,
// injection text inert) without persisting them; a confirm adds one as assisted.
func TestThreatSuggest(t *testing.T) {
	f := newConsole(t, nil)
	f.srv.llmFactory = func(config.Config) llm.Client {
		return &llm.Fake{IsLocal: true, Respond: func(llm.Request) (string, error) {
			return `{"threats":[
				{"category":"tampering","title":"CI pipeline poisoning","description":"An attacker with commit access alters the build."},
				{"category":"not-stride","title":"dropped","description":"x"}
			]}`, nil
		}}
	}
	oper := f.mustLogin("oscar")
	rec := f.do("POST", "/api/threat-models", `{"name":"Svc"}`, oper)
	var m struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &m)

	rec = f.do("POST", "/api/threat-models/"+m.ID+"/suggest", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("suggest: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Suggestions []struct{ Category, Title string }
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Suggestions) != 1 || out.Suggestions[0].Category != "tampering" {
		t.Fatalf("suggestions filtered wrong: %+v", out.Suggestions)
	}

	// Suggestions are NOT persisted until confirmed.
	det := f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d struct{ Threats []any }
	json.Unmarshal(det.Body.Bytes(), &d)
	if len(d.Threats) != 0 {
		t.Errorf("suggestions were persisted without confirmation: %d", len(d.Threats))
	}

	// Confirming adds it as source=assisted.
	body := `{"category":"tampering","title":"CI pipeline poisoning","description":"x","source":"assisted"}`
	if rec := f.do("POST", "/api/threat-models/"+m.ID+"/threats", body, oper); rec.Code != 201 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	det = f.do("GET", "/api/threat-models/"+m.ID, "", oper)
	var d2 struct {
		Threats []struct{ Source string }
	}
	json.Unmarshal(det.Body.Bytes(), &d2)
	if len(d2.Threats) != 1 || d2.Threats[0].Source != "assisted" {
		t.Errorf("confirmed threat not assisted: %+v", d2.Threats)
	}
}
