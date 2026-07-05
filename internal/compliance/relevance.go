package compliance

import (
	"fmt"
	"sort"
	"strings"
)

// Framework→scanner relevance (docs/console-ops.md S6/§12.5): when a scan is
// focused on frameworks, scanner selection narrows to the tools that can
// produce evidence those frameworks map. HAND-CURATED against each
// framework's declared scope — this table never changes mapping logic, only
// which scanners are worth running. A loader test pins that every embedded
// framework has exactly one row here.
var scannerRelevance = map[string][]string{
	// ASVS 4.0.3 scope is SAST/SECRET/SCA: application code (semgrep),
	// leaked credentials (gitleaks), vulnerable dependencies (trivy).
	"ASVS": {"semgrep", "gitleaks", "trivy"},
	// PCI-DSS 4.0 scope spans all four categories; every scanner can
	// contribute evidence.
	"PCI-DSS": {"semgrep", "gitleaks", "trivy", "checkov", "trivy-config"},
	// The CIS benchmarks are IAC-only: misconfiguration engines only.
	"CIS-AWS":    {"checkov", "trivy-config"},
	"CIS-DOCKER": {"checkov", "trivy-config"},
	"CIS-K8S":    {"checkov", "trivy-config"},
}

// ValidateFrameworkIDs checks ids against the embedded framework enum.
func ValidateFrameworkIDs(ids []string) error {
	fws, err := Frameworks()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(fws))
	var names []string
	for _, fw := range fws {
		known[fw.ID] = true
		names = append(names, fw.ID)
	}
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("unknown framework %q (known: %s)", id, strings.Join(names, ", "))
		}
	}
	return nil
}

// RelevanceTableIDs returns the framework IDs the relevance table covers
// (for the test pinning table↔data correspondence).
func RelevanceTableIDs() []string {
	ids := make([]string, 0, len(scannerRelevance))
	for id := range scannerRelevance {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// NarrowScanners intersects the chosen scanner set with the union of the
// requested frameworks' relevant scanners. chosen must already be the
// EFFECTIVE set (never empty-meaning-all — callers expand that first). An
// empty intersection is an error, not a silent no-op scan: the caller turns
// it into a 400 (console) or a CLI error.
func NarrowScanners(chosen, frameworkIDs []string) ([]string, error) {
	if len(frameworkIDs) == 0 {
		return chosen, nil
	}
	if err := ValidateFrameworkIDs(frameworkIDs); err != nil {
		return nil, err
	}
	relevant := map[string]bool{}
	for _, id := range frameworkIDs {
		for _, s := range scannerRelevance[id] {
			relevant[s] = true
		}
	}
	var out []string
	for _, s := range chosen {
		if relevant[strings.ToLower(s)] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("none of the selected scanners (%s) are relevant to %s — widen the scanner set or drop the framework focus",
			strings.Join(chosen, ", "), strings.Join(frameworkIDs, ", "))
	}
	return out, nil
}
