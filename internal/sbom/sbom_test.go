package sbom

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"":          CycloneDX, // default
		"cyclonedx": CycloneDX,
		"CycloneDX": CycloneDX, // case-insensitive
		"  spdx  ":  SPDXTag,   // trimmed
		"spdx-json": SPDXJSON,
	} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseFormat("sarif"); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestFormatsSorted(t *testing.T) {
	got := Formats()
	want := []string{"cyclonedx", "spdx", "spdx-json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Formats() = %v, want %v", got, want)
	}
}

func TestBuildArgs(t *testing.T) {
	args, err := buildArgs(Options{Target: "./svc", Format: CycloneDX})
	if err != nil {
		t.Fatalf("buildArgs: %v", err)
	}
	want := []string{"fs", "--quiet", "--format", "cyclonedx", "--", "./svc"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("buildArgs = %v, want %v", args, want)
	}
	// The target always sits after "--" so a "-"-leading target can never be
	// read as a flag.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 || args[len(args)-1] != "./svc" || sep != len(args)-2 {
		t.Errorf("target not isolated after --: %v", args)
	}

	if _, err := buildArgs(Options{Target: "x", Format: Format("bogus")}); err == nil {
		t.Error("unknown format accepted by buildArgs")
	}
	if _, err := buildArgs(Options{Target: "  ", Format: CycloneDX}); err == nil {
		t.Error("empty target accepted by buildArgs")
	}
}

func TestBuildArgsFormatMapping(t *testing.T) {
	for f, wantFlag := range map[Format]string{
		CycloneDX: "cyclonedx",
		SPDXJSON:  "spdx-json",
		SPDXTag:   "spdx",
	} {
		args, err := buildArgs(Options{Target: ".", Format: f})
		if err != nil {
			t.Fatalf("buildArgs(%q): %v", f, err)
		}
		var flag string
		for i, a := range args {
			if a == "--format" && i+1 < len(args) {
				flag = args[i+1]
			}
		}
		if flag != wantFlag {
			t.Errorf("format %q -> trivy flag %q, want %q", f, flag, wantFlag)
		}
	}
}

// TestSmokeGenerate runs the real trivy binary against the repo fixture and
// asserts a spec-valid CycloneDX document. Skipped with -short or when trivy
// is not installed, matching the scanner smoke-test pattern.
func TestSmokeGenerate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping trivy SBOM smoke test in -short mode")
	}
	if !Available() {
		t.Skip("trivy not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	doc, err := Generate(ctx, Options{Target: "../../testdata/fixture", Format: CycloneDX})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cdx struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []any  `json:"components"`
	}
	if err := json.Unmarshal(doc, &cdx); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if cdx.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", cdx.BOMFormat)
	}
	if !strings.HasPrefix(cdx.SpecVersion, "1.") {
		t.Errorf("specVersion = %q, want 1.x", cdx.SpecVersion)
	}
	if len(cdx.Components) == 0 {
		t.Error("SBOM has no components")
	}
}
