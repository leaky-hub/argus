// Package sbom generates a Software Bill of Materials (SBOM) for a target
// directory or image, in a standard interchange format (CycloneDX or SPDX),
// using trivy: the same engine and the same component inventory as the SCA
// findings pass, so the SBOM and the vulnerability report describe one set of
// components.
//
// An SBOM is an artifact, not a set of findings: it lists what is present,
// not what is wrong. So this package sits beside the findings pipeline rather
// than inside it: no normalization, no risk scoring, no gate. trivy's output
// is a spec-valid CycloneDX or SPDX document, and it is passed through
// FAITHFULLY (never re-serialized), so the document argus emits is
// byte-for-byte a document a compliance consumer can validate against the
// upstream schema.
package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Format is an SBOM interchange format argus can emit.
type Format string

const (
	// CycloneDX is the OWASP CycloneDX JSON format (the procurement default).
	CycloneDX Format = "cyclonedx"
	// SPDXJSON is the Linux Foundation SPDX format, JSON encoding.
	SPDXJSON Format = "spdx-json"
	// SPDXTag is SPDX in the tag-value (text) encoding.
	SPDXTag Format = "spdx"
)

// trivyFormat maps an argus format name to trivy's -f value. They currently
// coincide, but the indirection keeps argus's public format names decoupled
// from the tool's flag vocabulary.
var trivyFormat = map[Format]string{
	CycloneDX: "cyclonedx",
	SPDXJSON:  "spdx-json",
	SPDXTag:   "spdx",
}

// Formats lists the supported format names, sorted, for help text and errors.
func Formats() []string {
	out := make([]string, 0, len(trivyFormat))
	for f := range trivyFormat {
		out = append(out, string(f))
	}
	sort.Strings(out)
	return out
}

// ParseFormat validates a format name (case-insensitive), defaulting an empty
// value to CycloneDX. An unknown name is an error naming the valid set.
func ParseFormat(name string) (Format, error) {
	if name == "" {
		return CycloneDX, nil
	}
	f := Format(strings.ToLower(strings.TrimSpace(name)))
	if _, ok := trivyFormat[f]; !ok {
		return "", fmt.Errorf("unknown SBOM format %q; must be one of %s", name, strings.Join(Formats(), ", "))
	}
	return f, nil
}

// Options configure one SBOM generation.
type Options struct {
	Target string // directory or file to inventory
	Format Format
}

// Available reports whether trivy is on PATH.
func Available() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

// buildArgs constructs the trivy command line. Split out from Generate so the
// argv (and its format validation) is unit-testable without invoking trivy.
// The SBOM pass never scans for vulnerabilities: --scanners is empty, so the
// output is a pure component inventory, deterministic and network-light.
func buildArgs(opts Options) ([]string, error) {
	tf, ok := trivyFormat[opts.Format]
	if !ok {
		return nil, fmt.Errorf("unknown SBOM format %q; must be one of %s", opts.Format, strings.Join(Formats(), ", "))
	}
	if strings.TrimSpace(opts.Target) == "" {
		return nil, fmt.Errorf("sbom: empty target")
	}
	// "--" terminates flags so a target that begins with "-" can never be read
	// as an option. SBOM formats already list every package, so no
	// vulnerability scanner and no --list-all-pkgs are needed.
	return []string{"fs", "--quiet", "--format", tf, "--", opts.Target}, nil
}

// Generate runs trivy and returns the SBOM document bytes verbatim. trivy's
// output is already a spec-valid document; it is returned unmodified so the
// bytes a consumer validates are exactly what the SBOM engine produced.
func Generate(ctx context.Context, opts Options) ([]byte, error) {
	if !Available() {
		return nil, fmt.Errorf("trivy not found on PATH: install trivy to generate an SBOM")
	}
	args, err := buildArgs(opts)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("sbom: trivy timed out")
		}
		// Surface trivy's first stderr line for a diagnosable error, never the
		// whole (potentially large) buffer.
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("sbom: trivy failed: %s", msg)
	}
	out := stdout.Bytes()
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("sbom: trivy produced no output")
	}
	return out, nil
}
