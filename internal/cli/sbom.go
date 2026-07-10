package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/sbom"
)

func init() {
	sbomCmd.Flags().StringP("format", "f", "cyclonedx", "SBOM format: cyclonedx, spdx-json, or spdx")
	sbomCmd.Flags().StringP("output", "o", "", "Output file path (default is stdout)")
	sbomCmd.Flags().Int("timeout", 300, "Generation timeout in seconds")
	rootCmd.AddCommand(sbomCmd)
}

var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Generate a Software Bill of Materials (CycloneDX or SPDX) for a target",
	Long: `Generates a Software Bill of Materials: the inventory of components and
dependencies in a target directory, in a standard interchange format
(CycloneDX or SPDX). Increasingly required by procurement and executive
orders, and cheap on top of the dependency inventory Argus already builds for
the SCA pass: the SBOM and the vulnerability report describe the same
components.

An SBOM lists what is present, not what is wrong, so this command produces a
document, never findings, and never gates. The output is a spec-valid
document passed through faithfully from the SBOM engine (trivy).

  argus sbom .                                  # CycloneDX to stdout
  argus sbom . --format spdx-json -o sbom.json  # SPDX (JSON) to a file
  argus sbom ./service --format cyclonedx -o service.cdx.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSBOM,
}

func runSBOM(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	formatName, _ := cmd.Flags().GetString("format")
	format, err := sbom.ParseFormat(formatName)
	if err != nil {
		return err
	}

	timeoutSec, _ := cmd.Flags().GetInt("timeout")
	ctx := cmd.Context()
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	doc, err := sbom.Generate(ctx, sbom.Options{Target: target, Format: format})
	if err != nil {
		return err
	}

	outputPath, _ := cmd.Flags().GetString("output")
	if outputPath == "" {
		_, err := os.Stdout.Write(doc)
		return err
	}
	if err := os.WriteFile(outputPath, doc, 0o644); err != nil {
		return fmt.Errorf("sbom: write %s: %w", outputPath, err)
	}
	fmt.Fprintf(os.Stderr, "==> wrote %s SBOM to %s\n", format, outputPath)
	return nil
}
