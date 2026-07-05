package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		tool, raw string
		want      Severity
	}{
		{"semgrep", "ERROR", SeverityHigh},
		{"semgrep", "WARNING", SeverityMedium},
		{"semgrep", "INFO", SeverityInfo},
		{"semgrep", "bogus", SeverityMedium}, // unknown fails toward medium
		{"gitleaks", "HIGH", SeverityHigh},
		{"gitleaks", "", SeverityHigh}, // secrets are always high
		{"trivy", "CRITICAL", SeverityCritical},
		{"trivy", "HIGH", SeverityHigh},
		{"trivy", "MEDIUM", SeverityMedium},
		{"trivy", "LOW", SeverityLow},
		{"trivy", "UNKNOWN", SeverityMedium}, // un-scored is not harmless
		{"trivy", "", SeverityMedium},
		{"trivy-config", "CRITICAL", SeverityCritical},
		{"trivy-config", "HIGH", SeverityHigh},
		{"trivy-config", "LOW", SeverityLow},
		{"trivy-config", "UNKNOWN", SeverityMedium},
		{"trivy-config", "bogus", SeverityMedium},
		{"checkov", "", SeverityMedium}, // OSS checkov emits no severity
		{"checkov", "CRITICAL", SeverityCritical},
		{"checkov", "HIGH", SeverityHigh},
		{"checkov", "MEDIUM", SeverityMedium},
		{"checkov", "LOW", SeverityLow},
		{"checkov", "INFO", SeverityInfo},
		{"checkov", "bogus", SeverityMedium},         // unknown fails toward medium
		{"futuretool", "critical", SeverityCritical}, // direct parse for new tools
		{"futuretool", "???", SeverityMedium},
	}
	for _, tt := range tests {
		if got := NormalizeSeverity(tt.tool, tt.raw); got != tt.want {
			t.Errorf("NormalizeSeverity(%q, %q) = %v, want %v", tt.tool, tt.raw, got, tt.want)
		}
	}
}

// TestSeverityForScore pins every band boundary of the canonical table in
// docs/risk-scoring.md. Scores are one-decimal, so these are ALL the edges.
func TestSeverityForScore(t *testing.T) {
	tests := []struct {
		score float64
		want  Severity
	}{
		{0.0, SeverityInfo}, // reachable: stage-1 floor is 0.0
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
		// Defensive: out-of-range inputs clamp into the scale.
		{-1.0, SeverityInfo},
		{11.0, SeverityCritical},
	}
	for _, tt := range tests {
		if got := SeverityForScore(tt.score); got != tt.want {
			t.Errorf("SeverityForScore(%.1f) = %v, want %v", tt.score, got, tt.want)
		}
	}
	// Float-representation hostility: values arithmetically equal to a
	// boundary must band identically however they were computed.
	if got := SeverityForScore(6.9999999999); got != SeverityHigh {
		t.Errorf("SeverityForScore(≈7.0) = %v, want high (decisecond rounding)", got)
	}
	if got := SeverityForScore(8.9000000000000004); got != SeverityHigh {
		t.Errorf("SeverityForScore(8.9 as float64) = %v, want high", got)
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(SeverityCritical > SeverityHigh && SeverityHigh > SeverityMedium &&
		SeverityMedium > SeverityLow && SeverityLow > SeverityInfo) {
		t.Fatal("severity ordering broken — the gate depends on it")
	}
}

func TestGate(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityLow},
		{Severity: SeverityHigh},
	}
	high := SeverityHigh
	critical := SeverityCritical
	if !GateExceeded(findings, &high) {
		t.Error("high finding must trip a high gate")
	}
	if GateExceeded(findings, &critical) {
		t.Error("high finding must not trip a critical gate")
	}
	if GateExceeded(findings, nil) {
		t.Error("nil gate (none) must never fail")
	}
	if GateExceeded(nil, &high) {
		t.Error("no findings must never fail")
	}
}

func TestParseGate(t *testing.T) {
	if g, err := ParseGate("none"); err != nil || g != nil {
		t.Errorf("ParseGate(none) = %v, %v; want nil, nil", g, err)
	}
	if g, err := ParseGate("HIGH"); err != nil || g == nil || *g != SeverityHigh {
		t.Errorf("ParseGate(HIGH) = %v, %v; want high", g, err)
	}
	if _, err := ParseGate("severe"); err == nil {
		t.Error("ParseGate must reject unknown values, not guess")
	}
}

func TestFingerprintStability(t *testing.T) {
	f := Finding{
		Tool: "semgrep", Category: CategorySAST, RuleID: "rule.sqli",
		Location: Location{File: "app.py", StartLine: 10},
	}
	id1 := Fingerprint(f)
	// 2.0.0 relies on this: titles became human-derived and severity became
	// risk-banded, and BOTH may change without breaking run deltas. Prove the
	// fingerprint never sees them.
	f.Title = "SQL injection from tainted string"
	f.Description = "reworded by a new tool version"
	f.Severity = SeverityCritical
	low := SeverityLow
	f.ToolSeverity = &low
	f.RawSeverity = "ERROR"
	if Fingerprint(f) != id1 {
		t.Error("fingerprint must ignore title/description/severity/toolSeverity")
	}
	f.Location.StartLine = 11
	if Fingerprint(f) == id1 {
		t.Error("fingerprint must change when the location changes")
	}
	// Field-separator soundness: shifting a boundary must change the hash.
	a := Fingerprint(Finding{Tool: "ab", Category: "c"})
	b := Fingerprint(Finding{Tool: "a", Category: "bc"})
	if a == b {
		t.Error("fingerprint fields must be unambiguously separated")
	}
}

func TestNormalize(t *testing.T) {
	raws := []RawFinding{{
		Tool: "semgrep", Category: CategorySAST, RuleID: "r1",
		RawSeverity: "ERROR", File: "a\\b.py", StartLine: 5, EndLine: 3,
		CWEs: []string{"cwe-89", "CWE-89: SQL Injection", "89", ""},
	}}
	out := Normalize(raws)
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.RawSeverity != "ERROR" {
		t.Error("raw severity must be preserved verbatim")
	}
	if f.ToolSeverity == nil || *f.ToolSeverity != SeverityHigh {
		t.Errorf("toolSeverity = %v, want high (always set by Normalize)", f.ToolSeverity)
	}
	if f.Location.File != "a/b.py" {
		t.Errorf("file = %q, want forward slashes", f.Location.File)
	}
	if f.Location.EndLine != 5 {
		t.Errorf("endLine = %d, want clamped to startLine", f.Location.EndLine)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != "CWE-89" {
		t.Errorf("CWEs = %v, want [CWE-89]", f.CWEs)
	}
	if f.ID == "" || f.Title != "r1" {
		t.Errorf("ID/title not populated: %q / %q", f.ID, f.Title)
	}
}

func TestFilterIgnored(t *testing.T) {
	findings := []Finding{
		{RuleID: "keep", Location: Location{File: "src/app.py"}},
		{RuleID: "keep", Location: Location{File: "testdata/fixture/app.py"}},
		{RuleID: "suppressed-rule", Location: Location{File: "src/other.py"}},
		{RuleID: "keep", Location: Location{File: "vendor/lib/x.go"}},
		{RuleID: "keep", Location: Location{File: ""}}, // SCA: no path, never path-ignored
	}
	kept, suppressed := FilterIgnored(findings,
		[]string{"testdata/**", "vendor"}, []string{"suppressed-rule"})
	if suppressed != 3 {
		t.Errorf("suppressed = %d, want 3", suppressed)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
	for _, f := range kept {
		if f.RuleID != "keep" {
			t.Errorf("wrong finding kept: %+v", f)
		}
	}
	// Ignoring nothing keeps everything.
	kept, suppressed = FilterIgnored(findings, nil, nil)
	if len(kept) != 5 || suppressed != 0 {
		t.Error("empty ignore lists must keep all findings")
	}
}

// TestToolSeverityRoundTrip pins the ≤1.4.0 compatibility contract: an old
// document without toolSeverity must round-trip as ABSENT (nil pointer, key
// omitted) — never as a fabricated "info" — while new findings emit it even
// when it is genuinely info.
func TestToolSeverityRoundTrip(t *testing.T) {
	old := []byte(`{"id":"x","tool":"semgrep","category":"SAST","ruleId":"r","title":"t","severity":"high","location":{}}`)
	var f Finding
	if err := json.Unmarshal(old, &f); err != nil {
		t.Fatal(err)
	}
	if f.ToolSeverity != nil {
		t.Fatalf("old document must yield nil toolSeverity, got %v", *f.ToolSeverity)
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "toolSeverity") {
		t.Error("re-marshaled old finding must not fabricate a toolSeverity")
	}

	info := SeverityInfo
	f.ToolSeverity = &info
	out, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"toolSeverity":"info"`) {
		t.Errorf("a genuine info toolSeverity must be emitted, got %s", out)
	}
}
