package threatmodel

import (
	"sync"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

var t0 = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func TestModelComponentEnumerate(t *testing.T) {
	s := newStore(t)
	m, err := s.CreateModel("t-1", "Checkout service", "", "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.AddComponent(m.ID, "component", "Web frontend", "web-app", "", t0)
	if err != nil {
		t.Fatal(err)
	}

	// Enumerate pulls the curated STRIDE threats for web-app.
	n, err := s.EnumerateComponent(c.ID, t0)
	if err != nil || n == 0 {
		t.Fatalf("enumerate = %d, %v", n, err)
	}
	threats, _ := s.Threats(m.ID)
	if len(threats) != n {
		t.Errorf("threats = %d, want %d", len(threats), n)
	}
	// Every enumerated threat is curated and open, and one is a spoofing threat
	// wired to the auth-session mitigation.
	foundSpoof := false
	for _, th := range threats {
		if th.Source != "curated" || th.Status != "open" {
			t.Errorf("bad enumerated threat: %+v", th)
		}
		if th.Category == "spoofing" && th.Mitigation == "auth-session" {
			foundSpoof = true
		}
	}
	if !foundSpoof {
		t.Error("expected a spoofing threat wired to auth-session")
	}

	// Enumerate is idempotent: a second pass adds nothing.
	if n2, _ := s.EnumerateComponent(c.ID, t0); n2 != 0 {
		t.Errorf("re-enumerate added %d, want 0", n2)
	}
}

func TestThreatStatusAndLinks(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	th, err := s.AddThreat(m.ID, "", "tampering", "SQLi at the query layer", "", "manual", "sqli", "a", t0)
	if err != nil {
		t.Fatal(err)
	}
	// Status transitions are validated.
	if err := s.SetThreatStatus(m.ID, th.ID, "mitigated", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetThreatStatus(m.ID, th.ID, "bogus", t0); err == nil {
		t.Error("invalid status must be rejected")
	}
	// Link to a finding, a control, and a mitigation.
	if err := s.LinkThreat(m.ID, th.ID, "finding", "fp-123", "t-1"); err != nil {
		t.Fatal(err)
	}
	s.LinkThreat(m.ID, th.ID, "control", "ASVS:V5.3.4", "")
	s.LinkThreat(m.ID, th.ID, "mitigation", "sqli", "")
	if err := s.LinkThreat(m.ID, th.ID, "bogus", "x", ""); err == nil {
		t.Error("invalid link kind must be rejected")
	}
	links, _ := s.LinksForModel(m.ID)
	if len(links[th.ID]) != 3 {
		t.Errorf("links = %d, want 3", len(links[th.ID]))
	}
}

// TestCrossModelScoping: a threat can only be moved, linked, or attached to a
// component through its OWN model — addressing it via another model's id is
// refused, so the audit trail can't record the wrong model.
func TestCrossModelScoping(t *testing.T) {
	s := newStore(t)
	mA, _ := s.CreateModel("", "A", "", "a", t0)
	mB, _ := s.CreateModel("", "B", "", "a", t0)
	compB, _ := s.AddComponent(mB.ID, "component", "DB", "database", "", t0)
	th, err := s.AddThreat(mA.ID, "", "tampering", "T", "", "manual", "", "a", t0)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetThreatStatus(mB.ID, th.ID, "mitigated", t0); err != ErrNotFound {
		t.Errorf("cross-model status = %v, want ErrNotFound", err)
	}
	if got, _ := s.Threats(mA.ID); got[0].Status != "open" {
		t.Errorf("cross-model status write landed: %q", got[0].Status)
	}
	if err := s.LinkThreat(mB.ID, th.ID, "control", "ASVS:V1.1.1", ""); err != ErrNotFound {
		t.Errorf("cross-model link = %v, want ErrNotFound", err)
	}
	if err := s.UnlinkThreat(mB.ID, th.ID, "control", "ASVS:V1.1.1", ""); err != ErrNotFound {
		t.Errorf("cross-model unlink = %v, want ErrNotFound", err)
	}
	// A threat may not point at a component from another model.
	if _, err := s.AddThreat(mA.ID, compB.ID, "tampering", "X", "", "manual", "", "a", t0); err == nil {
		t.Error("threat attached to another model's component")
	}
}

// TestThreatSourceProvenance: "curated" means the threatlib library wrote it.
// A hand-authored threat is "manual" even if the caller claims otherwise; only
// "assisted" (human-confirmed LLM suggestion) passes through.
func TestThreatSourceProvenance(t *testing.T) {
	s := newStore(t)
	m, _ := s.CreateModel("", "M", "", "a", t0)
	for _, tc := range []struct{ give, want string }{
		{"curated", "manual"}, {"", "manual"}, {"llm", "manual"},
		{"manual", "manual"}, {"assisted", "assisted"},
	} {
		th, err := s.AddThreat(m.ID, "", "spoofing", "src "+tc.give, "", tc.give, "", "a", t0)
		if err != nil {
			t.Fatal(err)
		}
		if th.Source != tc.want {
			t.Errorf("AddThreat source %q stored %q, want %q", tc.give, th.Source, tc.want)
		}
	}
}

func TestModelCascadeAndValidation(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateModel("", "  ", "", "a", t0); err == nil {
		t.Error("empty model name must be rejected")
	}
	m, _ := s.CreateModel("", "M", "", "a", t0)
	c, _ := s.AddComponent(m.ID, "component", "DB", "database", "", t0)
	s.EnumerateComponent(c.ID, t0)
	// Deleting the model cascades components and threats.
	if err := s.DeleteModel(m.ID); err != nil {
		t.Fatal(err)
	}
	if comps, _ := s.Components(m.ID); len(comps) != 0 {
		t.Error("components not cascaded")
	}
	if threats, _ := s.Threats(m.ID); len(threats) != 0 {
		t.Error("threats not cascaded")
	}
	if _, err := s.GetModel(m.ID); err != ErrNotFound {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
}

// TestConcurrentEnumerateNoDuplicates: EnumerateComponent reads the existing
// threats and inserts what's missing; two racing enumerations of the same
// component must not double-insert the curated set. The transaction makes the
// read-then-insert atomic.
func TestConcurrentEnumerateNoDuplicates(t *testing.T) {
	s := newStore(t)
	m, err := s.CreateModel("t-1", "Race", "", "a", t0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.AddComponent(m.ID, "component", "API", "api-service", "", t0)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.EnumerateComponent(c.ID, t0)
		}()
	}
	close(start)
	wg.Wait()

	threats, err := s.Threats(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, th := range threats {
		key := th.Category + "\x00" + th.Title
		if seen[key] {
			t.Fatalf("duplicate threat from racing enumerations: %s / %s", th.Category, th.Title)
		}
		seen[key] = true
	}
}
