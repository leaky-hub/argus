package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

func mkFinding(tool, rule, file string, line int) model.Finding {
	f := model.Finding{
		Tool:     tool,
		Category: "SAST",
		RuleID:   rule,
		Location: model.Location{File: file, StartLine: line},
	}
	f.ID = model.Fingerprint(f)
	return f
}

func TestFromFindingsDedupSortsAndSkipsEmpty(t *testing.T) {
	a := mkFinding("semgrep", "rule-a", "a.go", 10)
	b := mkFinding("semgrep", "rule-b", "b.go", 20)
	empty := model.Finding{RuleID: "no-id"} // ID left blank on purpose

	bf := FromFindings([]model.Finding{b, a, a, empty}, "target", time.Unix(0, 0))
	if bf.Count != 2 {
		t.Fatalf("want 2 entries (dedup a, skip empty), got %d: %+v", bf.Count, bf.Entries)
	}
	if bf.Entries[0].ID > bf.Entries[1].ID {
		t.Errorf("entries not sorted by id: %v", bf.Entries)
	}
	for _, e := range bf.Entries {
		if e.ID == "" {
			t.Error("empty-id finding leaked into baseline")
		}
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "baseline.json")
	a := mkFinding("semgrep", "rule-a", "a.go", 10)
	b := mkFinding("gitleaks", "aws-key", "b.env", 3)

	if err := Write(path, FromFindings([]model.Finding{a, b}, "t", time.Now())); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("want 2 ids, got %d", len(set))
	}
	if _, ok := set[a.ID]; !ok {
		t.Error("finding a missing from loaded set")
	}
	// The file is valid JSON with a trailing newline.
	data, _ := os.ReadFile(path)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("baseline file should end in a newline")
	}
}

func TestPartitionNewVsKnown(t *testing.T) {
	a := mkFinding("semgrep", "rule-a", "a.go", 10) // baselined -> known
	b := mkFinding("semgrep", "rule-b", "b.go", 20) // not baselined -> new
	noID := model.Finding{RuleID: "x"}              // empty id -> always new

	base := Set{a.ID: struct{}{}}
	newF, known := Partition([]model.Finding{a, b, noID}, base)

	if len(known) != 1 || known[0].ID != a.ID {
		t.Fatalf("want a known, got %+v", known)
	}
	if len(newF) != 2 {
		t.Fatalf("want b and the empty-id finding new, got %d: %+v", len(newF), newF)
	}
}

func TestLoadMissingIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("loading a missing baseline should error")
	}
}

func TestLoadEmptyEntriesYieldsEmptySet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := Write(path, FromFindings(nil, "t", time.Now())); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if set == nil {
		t.Fatal("empty baseline should load a non-nil (empty) set")
	}
	if len(set) != 0 {
		t.Fatalf("want 0 ids, got %d", len(set))
	}
}
