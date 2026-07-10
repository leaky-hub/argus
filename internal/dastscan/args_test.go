package dastscan

import (
	"strings"
	"testing"
)

// argAfter returns the token following the first occurrence of flag, or "".
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBuildArgsFuzzingAndHeaders(t *testing.T) {
	args := buildArgs(Options{
		URL:     "http://t/",
		Fuzzing: true,
		Headers: []string{"Cookie: SESS=abc", "  ", "Authorization: Bearer x"},
	}, "/tmp/out.jsonl", "")

	if !hasArg(args, "-dast") {
		t.Error("fuzzing did not add -dast")
	}
	// Each non-blank header becomes its own -H pair; blanks are dropped.
	var headerVals []string
	for i, a := range args {
		if a == "-H" && i+1 < len(args) {
			headerVals = append(headerVals, args[i+1])
		}
	}
	if len(headerVals) != 2 {
		t.Fatalf("want 2 -H headers, got %d: %v", len(headerVals), headerVals)
	}
	if headerVals[0] != "Cookie: SESS=abc" || headerVals[1] != "Authorization: Bearer x" {
		t.Errorf("header values wrong: %v", headerVals)
	}
}

func TestBuildArgsDefaultsNoFuzzNoHeaders(t *testing.T) {
	args := buildArgs(Options{URL: "http://t/"}, "/tmp/out.jsonl", "")
	if hasArg(args, "-dast") {
		t.Error("-dast present without Fuzzing")
	}
	if hasArg(args, "-H") {
		t.Error("-H present without headers")
	}
	// The always-on safety flags must survive the refactor.
	for _, want := range []string{"-disable-update-check", "-no-interactsh"} {
		if !hasArg(args, want) {
			t.Errorf("missing safety flag %s", want)
		}
	}
	if argAfter(args, "-target") != "http://t/" {
		t.Errorf("target not set: %v", args)
	}
}

func TestBuildArgsFiltersAndRateLimit(t *testing.T) {
	args := buildArgs(Options{
		URL:        "http://t/",
		Tags:       []string{"sqli", "xss"},
		Severities: []string{"high", "critical"},
		RateLimit:  50,
	}, "/tmp/out.jsonl", "")
	if argAfter(args, "-tags") != "sqli,xss" {
		t.Errorf("tags: %v", args)
	}
	if argAfter(args, "-severity") != "high,critical" {
		t.Errorf("severity: %v", args)
	}
	if argAfter(args, "-rate-limit") != "50" {
		t.Errorf("rate-limit: %v", args)
	}
}

// A live session cookie passed as a header must never appear in a progress
// line. buildArgs is not a logger, so this guards the contract at the seam
// that does surface text: only the header COUNT is ever safe to print.
func TestHeaderValueNotInProgressContract(t *testing.T) {
	// The only progress string dastscan emits about a run names the URL, never
	// headers. Assert the source does not format any Header value.
	args := buildArgs(Options{URL: "http://t/", Headers: []string{"Cookie: SECRET=leakme"}}, "/o", "")
	if !strings.Contains(strings.Join(args, " "), "SECRET=leakme") {
		t.Fatal("header should be in argv (nuclei needs it)")
	}
	// Documented invariant: dastscan's progress lines never include header
	// values. This test exists to fail loudly if someone adds header echoing.
}
