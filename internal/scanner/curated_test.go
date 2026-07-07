package scanner

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCuratedRulesetValidates: the embedded ruleset must pass semgrep's own
// validator — a malformed rule would otherwise silently drop out of every
// scan. Needs semgrep; no network (the config is local).
func TestCuratedRulesetValidates(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the semgrep binary")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	path, cleanup, err := materializeCuratedRules()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	out, err := exec.Command("semgrep", "--validate", "--metrics=off", "--config", path).CombinedOutput()
	if err != nil {
		t.Fatalf("curated ruleset failed semgrep --validate: %v\n%s", err, truncate(out, 800))
	}
}

// TestCuratedRuleIDsCarryTheMarker: every rule id in the embedded ruleset must
// start with the marker, or stableCuratedID cannot restore it after semgrep
// prefixes the temp path.
func TestCuratedRuleIDsCarryTheMarker(t *testing.T) {
	count := 0
	for _, line := range strings.Split(string(curatedRulesYAML), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- id:") {
			continue
		}
		count++
		id := strings.TrimSpace(strings.TrimPrefix(trimmed, "- id:"))
		if !strings.HasPrefix(id, curatedIDMarker) {
			t.Errorf("curated rule id %q does not start with %q", id, curatedIDMarker)
		}
	}
	if count < 10 {
		t.Fatalf("only %d rule ids found in the embedded ruleset — parsing drifted or rules were dropped", count)
	}
}

// TestStableCuratedID: temp-path-prefixed check_ids map back to the stable id;
// registry ids pass through untouched.
func TestStableCuratedID(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		rewrote bool
	}{
		{"var.folders.ab.T.argus-rules-123.argus-curated-kt-sqli-concat", "argus-curated-kt-sqli-concat", true},
		{"argus-curated-swift-weak-hash-md5", "argus-curated-swift-weak-hash-md5", true},
		{"javascript.express.security.audit.express-open-redirect", "javascript.express.security.audit.express-open-redirect", false},
	}
	for _, tc := range cases {
		got, ok := stableCuratedID(tc.in)
		if got != tc.want || ok != tc.rewrote {
			t.Errorf("stableCuratedID(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.rewrote)
		}
	}
}

// TestCuratedRulesetInStandardProfile: the sentinel is part of the standard
// (and therefore max) pack list, and the materialized file round-trips the
// embedded bytes.
func TestCuratedRulesetInStandardProfile(t *testing.T) {
	for _, prof := range []string{ProfileStandard, ProfileMax} {
		found := false
		for _, p := range ResolveSemgrepRulesets(prof, nil) {
			if p == CuratedRuleset {
				found = true
			}
		}
		if !found {
			t.Errorf("profile %s does not include %s", prof, CuratedRuleset)
		}
	}
	path, cleanup, err := materializeCuratedRules()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(curatedRulesYAML) {
		t.Error("materialized ruleset does not match the embedded bytes")
	}
}
