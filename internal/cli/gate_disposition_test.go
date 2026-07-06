package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/leaky-hub/appsec/internal/disposition"
	"github.com/leaky-hub/appsec/internal/model"
)

// TestExcludeDispositioned locks in the default-on gate behavior: accepted-risk
// and false-positive dispositions in the scanned tree's .appsec store drop out
// of the gate; in-progress/fixed/open still gate. A missing store suppresses
// nothing.
func TestExcludeDispositioned(t *testing.T) {
	root := t.TempDir()
	findings := []model.Finding{
		{ID: "a", Severity: model.SeverityHigh},
		{ID: "b", Severity: model.SeverityHigh},
		{ID: "c", Severity: model.SeverityHigh},
		{ID: "d", Severity: model.SeverityHigh},
	}

	// No store yet → nothing suppressed.
	if got, n := excludeDispositioned(root, findings); n != 0 || len(got) != 4 {
		t.Fatalf("empty store: got %d kept, %d suppressed; want 4,0", len(got), n)
	}

	store := disposition.At(filepath.Join(root, ".appsec"))
	now := time.Unix(1700000000, 0)
	store.Set("a", disposition.StatusAcceptedRisk, "accepted", "u", now)
	store.Set("b", disposition.StatusFalsePositive, "not real", "u", now)
	store.Set("c", disposition.StatusInProgress, "wip", "u", now)
	// d stays open.

	got, n := excludeDispositioned(root, findings)
	if n != 2 {
		t.Errorf("suppressed = %d, want 2 (accepted-risk + false-positive)", n)
	}
	kept := map[string]bool{}
	for _, f := range got {
		kept[f.ID] = true
	}
	if kept["a"] || kept["b"] {
		t.Error("accepted-risk/false-positive must not gate")
	}
	if !kept["c"] || !kept["d"] {
		t.Error("in-progress and open must still gate")
	}
}
