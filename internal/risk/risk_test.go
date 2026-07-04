package risk

import (
	"testing"

	"github.com/leaky-hub/appsec/internal/model"
)

func fp(v float64) *float64 { return &v }

// TestWorkedExamples pins the exact worked examples from docs/risk-scoring.md.
// If this test needs changing, the doc changes with it.
func TestWorkedExamples(t *testing.T) {
	cases := []struct {
		name string
		f    model.Finding
		want float64
	}{
		{
			name: "semgrep SQLi TP",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySAST,
				CWEs:   []string{"CWE-89"},
				Triage: &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 0.9},
			},
			want: 8.4,
		},
		{
			name: "gitleaks AWS key untriaged",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySecret,
				CWEs: []string{"CWE-798"},
			},
			want: 8.5,
		},
		{
			name: "trivy critical CVE with fix",
			f: model.Finding{
				Severity: model.SeverityCritical, Category: model.CategorySCA,
				Remediation: "upgrade to 2.1.4",
			},
			want: 9.3,
		},
		{
			name: "shell=True constant marked FP",
			f: model.Finding{
				Severity: model.SeverityMedium, Category: model.CategorySAST,
				Triage: &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1.0},
			},
			want: 1.0,
		},
		{
			name: "example secret marked FP",
			f: model.Finding{
				Severity: model.SeverityHigh, Category: model.CategorySecret,
				CWEs:   []string{"CWE-798"},
				Triage: &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 0.8},
			},
			want: 5.3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := []model.Finding{tc.f}
			Apply(fs)
			if fs[0].RiskScore == nil {
				t.Fatal("RiskScore not set")
			}
			if got := *fs[0].RiskScore; got != tc.want {
				t.Errorf("score = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEveryFindingScored(t *testing.T) {
	fs := []model.Finding{
		{Severity: model.SeverityInfo},
		{Severity: model.SeverityCritical, Category: model.CategorySecret, CWEs: []string{"CWE-798"}, Confidence: "HIGH", Remediation: "rotate"},
		{}, // zero value
	}
	Apply(fs)
	for i, f := range fs {
		if f.RiskScore == nil {
			t.Fatalf("finding %d has no risk score", i)
		}
		if *f.RiskScore < 0 || *f.RiskScore > 10 {
			t.Fatalf("finding %d score %v out of [0,10]", i, *f.RiskScore)
		}
	}
}

// TestBounds: a hostile/hallucinating model can move a score at most
// -4.0/+1.0 from baseline, and an FP verdict can never zero a finding out.
func TestBounds(t *testing.T) {
	base := model.Finding{Severity: model.SeverityLow, Category: model.CategorySAST}

	tp := base
	tp.Triage = &model.Triage{Verdict: model.VerdictTruePositive, Confidence: 99} // out-of-range confidence
	fs := []model.Finding{tp}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 4.0 { // 3.0 + capped 1.0*1
		t.Errorf("TP with wild confidence = %v, want 4.0", got)
	}

	fpF := base
	fpF.Triage = &model.Triage{Verdict: model.VerdictFalsePositive, Confidence: 1}
	fpF.Severity = model.SeverityInfo // baseline 1.0, adjustment -4 → floored
	fs = []model.Finding{fpF}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 0.5 {
		t.Errorf("FP floor = %v, want 0.5", got)
	}

	unk := base
	unk.Triage = &model.Triage{Verdict: "delete-everything", Confidence: 1} // unknown verdict: no adjustment
	fs = []model.Finding{unk}
	Apply(fs)
	if got := *fs[0].RiskScore; got != 3.0 {
		t.Errorf("unknown verdict adjusted the score: %v, want 3.0", got)
	}
}

func TestConfidenceModifiers(t *testing.T) {
	for _, tc := range []struct {
		conf string
		want float64
	}{
		{"high", 5.5}, {"HIGH", 5.5}, {"low", 4.0}, {"medium", 5.0}, {"", 5.0}, {"weird", 5.0},
	} {
		f := model.Finding{Severity: model.SeverityMedium, Confidence: tc.conf}
		if got := Baseline(f); got != tc.want {
			t.Errorf("confidence %q: baseline = %v, want %v", tc.conf, got, tc.want)
		}
	}
}
