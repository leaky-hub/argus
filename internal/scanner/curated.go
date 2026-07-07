package scanner

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
)

// Curated local semgrep rules: the platform's own vetted detections for
// weaknesses the registry packs provably miss. A rule lands here under the
// same bar as a registry pack (profiles.go): it must catch a labeled plant in
// testdata/polyglot that every registry pack in the profile misses, proven by
// TestProfileRecall. The ruleset is version-pinned embedded data, reviewed
// like the pack lists, shipped in the binary, never fetched.

//go:embed rules/curated.yaml
var curatedRulesYAML []byte

// CuratedRuleset is the sentinel pack name that resolves to the embedded
// curated ruleset. It deliberately looks like neither a registry pack (p/...)
// nor a filesystem path; the semgrep adapter materializes it to a temp file
// at scan time. A repo overriding `semgrep_rulesets:` can include it by name
// to keep the curated rules alongside its own list.
const CuratedRuleset = "argus/curated"

// curatedIDMarker prefixes every rule id inside rules/curated.yaml. Semgrep
// prefixes a local rule file's ids with the config file's dotted directory
// path, which for a temp file would leak an unstable path into rule ids and
// therefore into finding fingerprints. The adapter strips the prefix back to
// the stable id using this marker.
const curatedIDMarker = "argus-curated-"

// materializeCuratedRules writes the embedded ruleset to a temp file for one
// scan and returns its path and a cleanup func.
func materializeCuratedRules() (string, func(), error) {
	f, err := os.CreateTemp("", "argus-rules-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("curated rules: %w", err)
	}
	if _, err := f.Write(curatedRulesYAML); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("curated rules: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("curated rules: %w", err)
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// stableCuratedID maps a semgrep check_id for a curated rule back to its
// stable path-independent id: ".../T.argus-curated-elixir-sqli" becomes
// "argus-curated-elixir-sqli". Non-curated ids pass through unchanged.
func stableCuratedID(checkID string) (string, bool) {
	i := strings.LastIndex(checkID, curatedIDMarker)
	if i < 0 {
		return checkID, false
	}
	return checkID[i:], true
}
