package server

import (
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/runstore"
)

// TestBaselineDocSelection pins how a run-detail view chooses the run its
// new/resolved delta is measured against: the previous run by default, a
// specific run when one is requested, never the run itself, and nothing when
// there is no earlier run.
func TestBaselineDocSelection(t *testing.T) {
	store := runstore.Store{Dir: t.TempDir()}
	fs := func(ids ...string) []model.Finding {
		out := make([]model.Finding, 0, len(ids))
		for _, id := range ids {
			f := model.Finding{Tool: "semgrep", Category: "SAST", RuleID: id, Location: model.Location{File: id + ".go", StartLine: 1}}
			f.ID = model.Fingerprint(f)
			out = append(out, f)
		}
		return out
	}
	r1, err := store.Save(fs("a"), time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := store.Save(fs("a", "b"), time.Unix(2000, 0))
	r3, _ := store.Save(fs("a", "b", "c"), time.Unix(3000, 0))

	s := &Server{}
	cases := []struct {
		name           string
		runID, request string
		wantBaseID     string
		wantDoc        bool
	}{
		{"default = previous run", r3.ID, "", r2.ID, true},
		{"explicit older baseline", r3.ID, r1.ID, r1.ID, true},
		{"baseline == self falls back to previous", r3.ID, r3.ID, r2.ID, true},
		{"first run has no baseline", r1.ID, "", "", false},
		{"missing requested baseline yields none", r3.ID, "does-not-exist", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, baseID := s.baselineDoc(store, tc.runID, tc.request)
			if baseID != tc.wantBaseID {
				t.Errorf("baseID = %q, want %q", baseID, tc.wantBaseID)
			}
			if (doc != nil) != tc.wantDoc {
				t.Errorf("doc present = %v, want %v", doc != nil, tc.wantDoc)
			}
		})
	}
}

// TestBuildRunDetailBaselineChangesNewIDs proves the end-to-end effect: the same
// run reports a different "new" set depending on the baseline it is compared to.
func TestBuildRunDetailBaselineChangesNewIDs(t *testing.T) {
	store := runstore.Store{Dir: t.TempDir()}
	fs := func(ids ...string) []model.Finding {
		out := make([]model.Finding, 0, len(ids))
		for _, id := range ids {
			f := model.Finding{Tool: "semgrep", Category: "SAST", RuleID: id, Location: model.Location{File: id + ".go", StartLine: 1}}
			f.ID = model.Fingerprint(f)
			out = append(out, f)
		}
		return out
	}
	r1, _ := store.Save(fs("a"), time.Unix(1000, 0))
	_, _ = store.Save(fs("a", "b"), time.Unix(2000, 0)) // r2 (previous of r3)
	r3, _ := store.Save(fs("a", "b", "c"), time.Unix(3000, 0))

	s := &Server{}
	// vs previous run (r2): only c is new.
	vsPrev, err := s.buildRunDetail(store, r3.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vsPrev.NewIDs) != 1 {
		t.Errorf("vs previous: want 1 new (c), got %d", len(vsPrev.NewIDs))
	}
	// vs the first run (r1): both b and c are new.
	vsR1, err := s.buildRunDetail(store, r3.ID, r1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vsR1.NewIDs) != 2 {
		t.Errorf("vs r1: want 2 new (b, c), got %d", len(vsR1.NewIDs))
	}
	if vsR1.BaselineID != r1.ID {
		t.Errorf("BaselineID = %q, want %q", vsR1.BaselineID, r1.ID)
	}
}
