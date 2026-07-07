package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyRuleset(t *testing.T) {
	cases := []struct {
		in      string
		want    RulesetKind
		wantErr bool
	}{
		{"p/python", KindRegistryPack, false},
		{"p/owasp-top-ten", KindRegistryPack, false},
		{"r/java.lang.security.audit.foo", KindRegistryPack, false},
		{CuratedRuleset, KindRegistryPack, false},
		{"./rules/custom.yml", KindLocalPath, false},
		{"rules", KindLocalPath, false},
		{"/abs/path/rules.yaml", KindLocalPath, false},
		{"", 0, true},
		{"   ", 0, true},
		{AdditiveMarker, 0, true},
		{"https://evil.example/rules.yml", 0, true},
		{"http://x/y", 0, true},
		{"file:///etc/passwd", 0, true},
	}
	for _, tc := range cases {
		got, err := ClassifyRuleset(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ClassifyRuleset(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ClassifyRuleset(%q) = (%v, %v), want (%v, nil)", tc.in, got, err, tc.want)
		}
	}
}

func TestResolveLocalRuleset(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ok.yml")
	if err := os.WriteFile(good, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	txt := filepath.Join(dir, "notes.txt")
	os.WriteFile(txt, []byte("x"), 0o644)

	// Absolute file with a rule extension resolves.
	if p, err := resolveLocalRuleset(good, ""); err != nil || p != good {
		t.Errorf("good file: (%q, %v)", p, err)
	}
	// Directory resolves.
	if _, err := resolveLocalRuleset(dir, ""); err != nil {
		t.Errorf("dir: %v", err)
	}
	// Relative path resolves against baseDir.
	if p, err := resolveLocalRuleset("ok.yml", dir); err != nil || p != good {
		t.Errorf("relative: (%q, %v)", p, err)
	}
	// Missing path is a clear error.
	if _, err := resolveLocalRuleset(filepath.Join(dir, "nope.yml"), ""); err == nil {
		t.Error("missing path accepted")
	}
	// Wrong extension refused.
	if _, err := resolveLocalRuleset(txt, ""); err == nil {
		t.Error("non-rule extension accepted")
	}
}

func TestValidateRulesetsClassificationOnly(t *testing.T) {
	// Packs and the sentinel are OK without semgrep; a URL and a missing file
	// are flagged. (Does not require the semgrep binary: local paths fail at
	// resolve/classify before validation runs.)
	statuses := ValidateRulesets(context.Background(),
		[]string{AdditiveMarker, "p/python", CuratedRuleset, "https://x/y", "./does-not-exist.yml"}, "")
	byEntry := map[string]RulesetStatus{}
	for _, s := range statuses {
		byEntry[s.Entry] = s
	}
	if len(statuses) != 4 { // the leading additive marker is stripped
		t.Fatalf("got %d statuses, want 4: %+v", len(statuses), statuses)
	}
	if !byEntry["p/python"].OK || !byEntry[CuratedRuleset].OK {
		t.Error("registry packs should validate OK")
	}
	if byEntry["https://x/y"].OK {
		t.Error("remote URL should be rejected")
	}
	if byEntry["./does-not-exist.yml"].OK {
		t.Error("missing local file should be rejected")
	}
	if inv := FirstInvalid(statuses); inv == nil {
		t.Error("FirstInvalid should surface the URL/missing entries")
	}
}

// TestValidateRulesetsSemgrep exercises the real semgrep validator against a
// good and a malformed rule file.
func TestValidateRulesetsSemgrep(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the semgrep binary")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yml")
	os.WriteFile(good, []byte(`rules:
  - id: byo-eval
    languages: [python]
    severity: WARNING
    message: eval on user input
    pattern: eval(...)
`), 0o644)
	bad := filepath.Join(dir, "bad.yml")
	os.WriteFile(bad, []byte(`rules:
  - id: byo-broken
    languages: [python]
    message: missing severity and pattern
`), 0o644)

	statuses := ValidateRulesets(context.Background(), []string{good, bad}, "")
	if len(statuses) != 2 {
		t.Fatalf("got %d statuses", len(statuses))
	}
	if !statuses[0].OK {
		t.Errorf("good rule flagged invalid: %s", statuses[0].Message)
	}
	if statuses[1].OK {
		t.Error("malformed rule passed validation")
	}
	if statuses[1].Message == "" || !strings.Contains(statuses[1].Message, "bad.yml") {
		t.Errorf("invalid-rule message should name the file: %q", statuses[1].Message)
	}
}
