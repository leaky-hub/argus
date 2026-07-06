package cvss

import (
	"math"
	"testing"
)

// TestScoreKnownVectors checks the arithmetic against published CVSS 3.1
// examples so a refactor can't drift the formula.
func TestScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		sev    string
	}{
		// Classic reflected XSS (scope changed).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"},
		// Unauth RCE — the canonical 9.8.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"},
		// SQLi reading data, no integrity/availability impact.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"},
		// Local, low impact.
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "Low"},
		// All-none → 0.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"},
	}
	for _, c := range cases {
		b, err := Parse(c.vector)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.vector, err)
		}
		got := b.Score()
		if math.Abs(got-c.want) > 0.001 {
			t.Errorf("Score(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
		if s := Severity(got); s != c.sev {
			t.Errorf("Severity(%.1f) = %s, want %s", got, s, c.sev)
		}
		// Round-trips through the canonical vector.
		if b.Vector() != c.vector {
			t.Errorf("Vector() = %q, want %q", b.Vector(), c.vector)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "CVSS:3.1/AV:N", // missing metrics
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV
		"garbage",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should have failed", bad)
		}
	}
}
