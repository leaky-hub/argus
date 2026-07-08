// Package baseline implements "only new findings" gating: a baseline records
// the stable fingerprints of the findings that existed at a point in time, and
// a later scan can gate on just the findings whose fingerprint is NOT in the
// baseline. This is what makes a scanner adoptable in CI: a repository with a
// backlog of known issues can still fail the build on anything NEW without
// drowning in pre-existing noise.
//
// The baseline is a set of finding IDs (model.Fingerprint). It is deliberately
// the SAME identity the run store and disposition store key on, so "known"
// means exactly "the same issue, same tool, same place" across runs. Human
// hints (rule id, file:line) are stored alongside each id for auditability but
// are never used for matching.
//
// SECURITY NOTE: a baseline suppresses findings from the gate, so it is
// gate-affecting input, on par with the disposition store. It is the user's
// own file (written by --write-baseline over their own scan); Argus never
// fetches it. A baseline that happens to cover every current finding gates on
// nothing new; that is the user's explicit choice, the same as running with a
// permissive --fail-severity. Matching is exact on the 32-char fingerprint, so
// a truncated or malformed entry simply fails to match (fails safe: the
// finding counts as new and can still fail the gate).
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/zer0d4y5/argus/internal/model"
)

// SchemaVersion is the on-disk baseline schema. Bump only on a breaking change
// to the file shape; the fingerprint algorithm has its own version inside the
// id (see model.Fingerprint).
const SchemaVersion = 1

// Entry is one baselined finding: its stable id plus human-readable hints that
// make the file reviewable in a diff. Only ID participates in matching.
type Entry struct {
	ID    string `json:"id"`
	Rule  string `json:"rule,omitempty"`
	Where string `json:"where,omitempty"` // "file:line" or resource, for humans
}

// File is the serialized baseline document.
type File struct {
	Schema  int     `json:"schema"`
	Created string  `json:"created,omitempty"`
	Target  string  `json:"target,omitempty"`
	Count   int     `json:"count"`
	Entries []Entry `json:"entries"`
}

// Set is the in-memory lookup: fingerprint -> present.
type Set map[string]struct{}

// FromFindings builds a baseline document from a run's findings, sorted by id
// for a stable, diff-friendly file. Findings with an empty id are skipped
// (Normalize always sets one, but defense in depth): an empty id would match
// every un-fingerprinted finding, which must never suppress anything.
func FromFindings(findings []model.Finding, target string, now time.Time) File {
	entries := make([]Entry, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if f.ID == "" {
			continue
		}
		if _, dup := seen[f.ID]; dup {
			continue
		}
		seen[f.ID] = struct{}{}
		entries = append(entries, Entry{ID: f.ID, Rule: f.RuleID, Where: where(f)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return File{
		Schema:  SchemaVersion,
		Created: now.UTC().Format(time.RFC3339),
		Target:  target,
		Count:   len(entries),
		Entries: entries,
	}
}

// where renders a compact human hint for the location, never used for matching.
func where(f model.Finding) string {
	if f.Location.File != "" {
		if f.Location.StartLine > 0 {
			return fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine)
		}
		return f.Location.File
	}
	return f.Location.Resource
}

// Write serializes a baseline document to path (pretty-printed, trailing
// newline), creating parent directories as needed. The write is atomic via a
// temp file + rename so a crash mid-write never leaves a truncated baseline
// that would silently under-suppress on the next run.
func Write(path string, bf File) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("baseline: create dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: encode: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("baseline: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("baseline: rename: %w", err)
	}
	return nil
}

// Load reads a baseline file into a lookup set. A missing file is a hard error
// (the caller asked to compare against a baseline that is not there); the
// caller decides whether that is fatal. An empty entries list yields an empty
// set (everything is new), never a nil map.
func Load(path string) (Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: read %s: %w", path, err)
	}
	var bf File
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	set := make(Set, len(bf.Entries))
	for _, e := range bf.Entries {
		if e.ID != "" {
			set[e.ID] = struct{}{}
		}
	}
	return set, nil
}

// Partition splits findings into those NEW relative to the baseline set and
// those already KNOWN. Order within each slice is preserved. A finding with an
// empty id is always treated as new (it cannot be reliably matched, so it must
// not be silently suppressed).
func Partition(findings []model.Finding, base Set) (newF, known []model.Finding) {
	for _, f := range findings {
		if f.ID != "" {
			if _, ok := base[f.ID]; ok {
				known = append(known, f)
				continue
			}
		}
		newF = append(newF, f)
	}
	return newF, known
}
