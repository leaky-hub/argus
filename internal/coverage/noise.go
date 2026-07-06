package coverage

import (
	"fmt"
	"strings"
)

// NoiseStats quantifies duplicate volume on the polyglot fixture tree for one
// profile: how many findings the scan produced before and after correlation.
// The collapse never suppresses — TestProfileRecall proves catch sets are
// identical pre/post — so Before-After is pure duplicate noise removed.
type NoiseStats struct {
	Profile string
	Before  int // findings after Normalize, before Correlate
	After   int // findings after Correlate
	Plants  int // labeled plants in the tree, for the findings-per-plant ratio
}

// GenerateNoiseSection renders the noise metric for docs/coverage.md from a
// live scan. Like the matrix, it is derived from real findings — the
// before/after counts are measured, never asserted.
func GenerateNoiseSection(stats []NoiseStats) string {
	var b strings.Builder
	b.WriteString("## Noise metric (correlation collapse, measured)\n\n")
	b.WriteString("Wide profiles flag one weakness through several overlapping rules; the\n")
	b.WriteString("same-tool collapse in `internal/correlate` merges those into one finding\n")
	b.WriteString("(same tool + same file + overlapping range + shared CWE + different rule\n")
	b.WriteString("IDs), unioning the evidence and recording absorbed rule IDs in\n")
	b.WriteString("`meta.alsoRuleIds`. Collapse is NOT suppression: `TestProfileRecall`\n")
	b.WriteString("asserts the plant catch set is identical before and after correlation at\n")
	b.WriteString("every profile. Counts below are from the live scan that generated this file.\n\n")
	b.WriteString("| Profile | Findings pre-correlate | Post-correlate | Duplicates collapsed | Findings per plant (post) |\n")
	b.WriteString("|---|---:|---:|---:|---:|\n")
	for _, s := range stats {
		perPlant := "n/a"
		if s.Plants > 0 {
			perPlant = fmt.Sprintf("%.1f", float64(s.After)/float64(s.Plants))
		}
		b.WriteString(fmt.Sprintf("| `%s` | %d | %d | %d | %s |\n",
			s.Profile, s.Before, s.After, s.Before-s.After, perPlant))
	}
	b.WriteString("\n")
	return b.String()
}
