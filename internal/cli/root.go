// Package cli implements the appsec command-line interface.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build metadata, injected at release time via -ldflags -X (see
// .goreleaser.yaml). The defaults are what a plain `go build` or `go install`
// produces: an honest "dev" build with no release provenance.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus — AppSec + cloud posture, one wall",
	Long: `Argus runs open-source security scanners against your code and cloud
accounts, merges their output into one risk-scored, compliance-mapped findings
model, gates CI on severity, and serves a web console for triage and reporting.
It covers code (SAST), secrets, dependencies (SCA), infrastructure-as-code, and
cloud posture (prowler).`,
	Version: version,
	// Errors and usage are handled in Execute: a severity-gate failure is a
	// scan outcome, not a CLI mistake, and must never print usage text.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command. Exit codes: 0 success, 1 severity gate
// exceeded, 2 any other error.
func Execute() int {
	// A release build stamps version/commit/date; a dev build reports "dev".
	// The commit and date make a binary traceable to the exact source and the
	// provenance attestation that covers it.
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("argus version %s (commit %s, built %s)\n", version, commit, date))
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errGateFailed) {
			fmt.Fprintln(os.Stderr, "FAIL: severity gate exceeded")
			return 1
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 2
	}
	return 0
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
