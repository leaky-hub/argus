package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the DETECTION POLICY of the platform: the curated semgrep
// rulesets behind each scan profile. It is deliberately hand-maintained and
// reviewed — the breadth of what we detect is the product. Ruleset lists are
// data, so a repo can override them via `semgrep_rulesets:` in appsec.yml, but
// the defaults below are the vetted baseline every scan uses out of the box.
//
// Every pack listed here is validated against the semgrep registry
// (`semgrep --config <pack> --validate`) before being added; a typo'd pack
// silently narrows coverage, which is the one failure this file exists to
// prevent. See docs/coverage.md for the profile × language × cost matrix.

// Profile names. String-typed because they appear verbatim in the CLI flag and
// in appsec.yml.
const (
	ProfileFast     = "fast"
	ProfileStandard = "standard"
	ProfileMax      = "max"
)

// DefaultProfile is what a scan uses when neither --profile nor config sets one.
// standard is the breadth/false-positive tradeoff we want the demo to show:
// wide multi-language coverage, with AI triage (Phase 2) as the FP answer.
const DefaultProfile = ProfileStandard

// semgrepProfiles maps each profile to its curated registry pack list.
//
//   - fast     — semgrep's own curated low-noise CI pack. Fastest; what Phase 1
//     shipped. Good for tight PR gates.
//   - standard — security-audit + OWASP Top Ten + a per-language security pack
//     for every language we claim to cover. The default. Broadest useful signal
//     without the long-tail noise of p/default.
//   - max      — standard plus the long-tail: the full default ruleset, a
//     dedicated secrets pass, gosec, and framework/category packs. Highest
//     recall, highest FP volume (that is the point — triage handles it).
//
// Order within a list is preserved and de-duplicated at resolution time, so
// packs shared across profiles are expressed once via composition.
var semgrepProfiles = map[string][]string{
	ProfileFast: {
		"p/ci",
	},
	ProfileStandard: standardPacks,
	ProfileMax:      append(append([]string{}, standardPacks...), maxOnlyPacks...),
}

// standardPacks: cross-cutting security audit + OWASP, then one vetted security
// pack per language we cover. Adding a language means adding its pack here AND
// a labeled fixture under testdata/polyglot/ — and the pack must EARN its slot
// by catching a plant the existing packs miss (TestProfileRecall), or it is
// not added (same bar as maxOnlyPacks).
var standardPacks = []string{
	"p/security-audit",
	"p/owasp-top-ten",
	"p/python",
	"p/javascript",
	"p/typescript",
	"p/golang",
	"p/java",
	"p/csharp",
	"p/ruby",
	"p/php",
	"p/kotlin",
	// Cloud-posture session languages. Only packs that caught a plant the
	// existing standard packs miss are here:
	"p/rust",  // rust: untrusted-input (CWE-807), unsafe-usage (CWE-242)
	"p/scala", // scala: tainted-sql-string (CWE-89); p/security-audit catches none
	// C landed too but via p/security-audit's own C rules (insecure-use-gets-fn,
	// CWE-676) — p/c added nothing over it on the plants, so it is NOT listed
	// (see docs/coverage.md). Elixir did NOT land: p/elixir caught nothing
	// plantable, and the OSS engine cannot parse Elixir at all (Pro-only), so
	// curated local rules cannot cover it either (documented, not added).
	// Swift landed via argus/curated below (p/swift itself caught nothing).

	// The platform's own curated rules (internal/scanner/rules/curated.yaml,
	// embedded): detections for weaknesses every registry pack above provably
	// misses. Same earn-your-slot bar, held per rule by TestProfileRecall.
	CuratedRuleset,
}

// maxOnlyPacks: long-tail recall added on top of standard. Every pack here
// was registry-validated (TestSemgrepPacksResolve) AND earned its slot by
// catching a labeled plant in testdata/polyglot that max-without-it misses
// (TestProfileRecall) — a pack that detects nothing new does not land.
// Evaluated and rejected on that bar: p/flask, p/django, p/brakeman (added
// no detections over the packs below on their languages' plants).
var maxOnlyPacks = []string{
	"p/default",
	"p/secrets",
	"p/gosec",
	"p/nodejsscan",
	"p/react",
	"p/command-injection",
	"p/sql-injection",
	"p/xss",
	"p/jwt",
	"p/insecure-transport",
	// Per-language completeness (deep-scan session): one deep pack per
	// claimed language that had none beyond standard's p/<lang>.
	"p/bandit",               // python: predictable-PRNG-for-token & co (plant py-weak-random)
	"p/findsecbugs",          // java: weak random, Runtime.exec cmdi (plants java-weak-random, java-cmdi)
	"p/security-code-scan",   // C#: weak random, ProcessStartInfo cmdi (plants cs-weak-random, cs-cmdi)
	"p/mobsfscan",            // kotlin: ECB-mode cipher (plant kt-ecb-cipher)
	"p/phpcs-security-audit", // php: dynamic include (plant php-dynamic-include)
}

// KnownProfiles returns the valid profile names, sorted, for validation and
// help text.
func KnownProfiles() []string {
	names := make([]string, 0, len(semgrepProfiles))
	for name := range semgrepProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidProfile reports whether name is a known profile.
func ValidProfile(name string) bool {
	_, ok := semgrepProfiles[name]
	return ok
}

// AdditiveMarker is the leading token that flips an override list from REPLACE
// to ADD: `semgrep_rulesets: ["+", ./rules/x.yml]` runs the profile packs AND
// x.yml, where `["+"]` alone is just the profile. A bare override list with no
// marker replaces the profile packs entirely (the original contract). The
// console defaults to additive so a custom rule never silently drops the
// curated breadth; the CLI keeps replace as its default for back-compat.
const AdditiveMarker = "+"

// ResolveSemgrepRulesets returns the semgrep pack list a scan should use.
//
// Precedence: an explicit override (from `semgrep_rulesets:` in config) is
// used instead of the profile packs, either REPLACING them or ADDING to them.
// A leading "+" marker (AdditiveMarker) selects additive: the profile's packs
// come first, then the override entries. Without the marker the override
// replaces the profile packs entirely. An empty override (or a bare "+" with
// no entries) yields the profile's packs. An empty/unknown profile falls back
// to DefaultProfile rather than erroring, so a scan never runs with zero rules.
//
// The returned slice is de-duplicated (first occurrence wins) so profile
// composition and additive merges can freely repeat packs. It always contains
// at least one pack. Entries may be registry packs, the argus/curated
// sentinel, or local rule file/dir paths; this function does not validate
// them (see customrules.go); it only decides which list to run.
func ResolveSemgrepRulesets(profile string, override []string) []string {
	additive, entries := splitAdditive(override)
	if len(entries) > 0 {
		if additive {
			return dedupePacks(append(append([]string{}, profilePacks(profile)...), entries...))
		}
		return dedupePacks(entries)
	}
	return dedupePacks(profilePacks(profile))
}

// splitAdditive reports whether an override list is additive (its first
// non-empty token is the marker) and returns the entries with that marker
// removed.
func splitAdditive(override []string) (additive bool, entries []string) {
	for i, e := range override {
		if strings.TrimSpace(e) == "" {
			continue
		}
		if strings.TrimSpace(e) == AdditiveMarker {
			return true, override[i+1:]
		}
		return false, override
	}
	return false, nil
}

// profilePacks returns the curated pack list for a profile, falling back to the
// default profile for an empty or unknown name.
func profilePacks(profile string) []string {
	packs, ok := semgrepProfiles[profile]
	if !ok {
		packs = semgrepProfiles[DefaultProfile]
	}
	return packs
}

// dedupePacks trims, drops empties, and removes duplicates while preserving
// first-seen order.
func dedupePacks(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// ValidateProfile returns a descriptive error if profile is non-empty and
// unknown. Empty is valid (means "use the default").
func ValidateProfile(profile string) error {
	if profile == "" || ValidProfile(profile) {
		return nil
	}
	return fmt.Errorf("unknown profile %q; must be one of %s", profile, strings.Join(KnownProfiles(), ", "))
}
