package compliance

import (
	"sort"
	"strings"
	"testing"
)

// TestRelevanceTableMatchesEmbeddedData pins the S6 correspondence: every
// embedded framework has exactly one relevance row, and every scanner named
// in the table is one the framework's scope can actually use. Adding a
// framework data file without a curated row fails here, loudly.
func TestRelevanceTableMatchesEmbeddedData(t *testing.T) {
	fws, err := Frameworks()
	if err != nil {
		t.Fatal(err)
	}
	var dataIDs []string
	for _, fw := range fws {
		dataIDs = append(dataIDs, fw.ID)
	}
	sort.Strings(dataIDs)
	tableIDs := RelevanceTableIDs()
	if strings.Join(dataIDs, ",") != strings.Join(tableIDs, ",") {
		t.Fatalf("relevance table (%v) does not match embedded frameworks (%v) — curate a row per framework", tableIDs, dataIDs)
	}
	// IAC-only frameworks must not name code/secret/dependency scanners.
	scannerCategory := map[string]string{
		"semgrep": "SAST", "gitleaks": "SECRET", "trivy": "SCA",
		"checkov": "IAC", "trivy-config": "IAC",
	}
	for _, fw := range fws {
		inScope := map[string]bool{}
		for _, c := range fw.Scope {
			inScope[c] = true
		}
		for _, s := range scannerRelevance[fw.ID] {
			cat, known := scannerCategory[s]
			if !known {
				t.Errorf("%s: unknown scanner %q in relevance row", fw.ID, s)
				continue
			}
			if !inScope[cat] {
				t.Errorf("%s: scanner %q (%s) is outside the framework's scope %v", fw.ID, s, cat, fw.Scope)
			}
		}
	}
}

func TestValidateFrameworkIDs(t *testing.T) {
	if err := ValidateFrameworkIDs([]string{"ASVS", "PCI-DSS"}); err != nil {
		t.Errorf("known ids rejected: %v", err)
	}
	if err := ValidateFrameworkIDs([]string{"SOC2"}); err == nil {
		t.Error("unknown framework accepted")
	}
	if err := ValidateFrameworkIDs(nil); err != nil {
		t.Errorf("empty list rejected: %v", err)
	}
}

func TestNarrowScanners(t *testing.T) {
	got, err := NarrowScanners([]string{"semgrep", "gitleaks", "checkov"}, []string{"ASVS"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "semgrep,gitleaks" {
		t.Errorf("ASVS narrowing = %v", got)
	}

	// Union across frameworks.
	got, err = NarrowScanners([]string{"semgrep", "checkov"}, []string{"ASVS", "CIS-AWS"})
	if err != nil || strings.Join(got, ",") != "semgrep,checkov" {
		t.Errorf("union narrowing = %v, err=%v", got, err)
	}

	// Empty intersection is an error, never a silent no-op (S6).
	if _, err := NarrowScanners([]string{"checkov"}, []string{"ASVS"}); err == nil {
		t.Error("empty intersection accepted")
	}
	if _, err := NarrowScanners([]string{"semgrep"}, []string{"NOPE"}); err == nil {
		t.Error("unknown framework accepted")
	}

	// No frameworks = passthrough.
	got, err = NarrowScanners([]string{"semgrep"}, nil)
	if err != nil || len(got) != 1 {
		t.Errorf("passthrough = %v, err=%v", got, err)
	}
}
