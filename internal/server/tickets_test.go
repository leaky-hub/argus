package server

import (
	"encoding/json"
	"testing"

	"github.com/leaky-hub/appsec/internal/disposition"
)

// TestTicketLifecycle drives the ticket endpoints end to end: create from a
// finding selection, list with a computed severity rollup, comment, update,
// and the close-fixed bridge that writes a "fixed" disposition. Then admin-only
// delete.
func TestTicketLifecycle(t *testing.T) {
	f := newConsole(t, nil)
	_, sastID, _ := seedRun(t, f.dir) // a HIGH SQLi finding in the served store
	admin := f.mustLogin("alice")
	oper := f.mustLogin("oscar")
	viewer := f.mustLogin("vera")

	// Operator creates a ticket linking the seeded finding (served store => target "").
	body := `{"title":"Fix the SQLi","priority":"high","targetId":"","findingIds":["` + sastID + `"]}`
	rec := f.do("POST", "/api/tickets", body, oper)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("no ticket id returned")
	}

	// Viewer can read; the list rollup resolves the linked finding's severity.
	rec = f.do("GET", "/api/tickets", "", viewer)
	if rec.Code != 200 {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Tickets []struct {
			ID        string
			LinkCount int
			Rollup    struct {
				Total, Resolved int
				Max             string
			}
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Tickets) != 1 {
		t.Fatalf("list len = %d, want 1", len(list.Tickets))
	}
	tk := list.Tickets[0]
	if tk.LinkCount != 1 || tk.Rollup.Resolved != 1 || tk.Rollup.Max != "high" {
		t.Errorf("rollup wrong: %+v", tk.Rollup)
	}

	// Operator comments and updates.
	if rec := f.do("POST", "/api/tickets/"+created.ID+"/comments", `{"body":"on it"}`, oper); rec.Code != 201 {
		t.Errorf("comment: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("PATCH", "/api/tickets/"+created.ID, `{"status":"in-progress"}`, oper); rec.Code != 200 {
		t.Errorf("update: %d %s", rec.Code, rec.Body.String())
	}

	// Viewer cannot mutate.
	if rec := f.do("PATCH", "/api/tickets/"+created.ID, `{"status":"done"}`, viewer); rec.Code != 403 {
		t.Errorf("viewer update = %d, want 403", rec.Code)
	}

	// close-fixed marks the linked finding fixed via the disposition store.
	rec = f.do("POST", "/api/tickets/"+created.ID+"/close-fixed", "{}", oper)
	if rec.Code != 200 {
		t.Fatalf("close-fixed: %d %s", rec.Code, rec.Body.String())
	}
	var cf struct{ MarkedFixed int }
	json.Unmarshal(rec.Body.Bytes(), &cf)
	if cf.MarkedFixed != 1 {
		t.Errorf("markedFixed = %d, want 1", cf.MarkedFixed)
	}
	// The disposition store (served repo) now records the finding as fixed.
	disp, _ := dispositionStore(f.srv.store).All()
	if rec, ok := disp[sastID]; !ok || rec.Status != disposition.StatusFixed {
		t.Errorf("finding not marked fixed via ticket: %+v ok=%v", rec, ok)
	}

	// Operator cannot delete; admin can.
	if rec := f.do("DELETE", "/api/tickets/"+created.ID, "", oper); rec.Code != 403 {
		t.Errorf("operator delete = %d, want 403", rec.Code)
	}
	if rec := f.do("DELETE", "/api/tickets/"+created.ID, "", admin); rec.Code != 200 {
		t.Errorf("admin delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do("GET", "/api/tickets/"+created.ID, "", viewer); rec.Code != 404 {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

// TestTicketValidation: bad input is rejected with 400.
func TestTicketValidation(t *testing.T) {
	f := newConsole(t, nil)
	oper := f.mustLogin("oscar")
	if rec := f.do("POST", "/api/tickets", `{"title":"  "}`, oper); rec.Code != 400 {
		t.Errorf("empty title = %d, want 400", rec.Code)
	}
	if rec := f.do("POST", "/api/tickets", `{"title":"x","priority":"bogus"}`, oper); rec.Code != 400 {
		t.Errorf("bad priority = %d, want 400", rec.Code)
	}
	rec := f.do("POST", "/api/tickets", `{"title":"x"}`, oper)
	var tk struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &tk)
	if rec := f.do("PATCH", "/api/tickets/"+tk.ID, `{"status":"nope"}`, oper); rec.Code != 400 {
		t.Errorf("bad status = %d, want 400", rec.Code)
	}
}
