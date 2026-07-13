package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/report"
)

func init() {
	engagementReportCmd.Flags().String("run", "", "A specific saved DAST run file to report on (default: the latest run under .appsec/dast/*/runs for each target)")
	engagementReportCmd.Flags().String("out", "", "Output HTML file (default: engagement-<id>-report.html); a Markdown copy is written alongside")
	engagementCmd.AddCommand(engagementReportCmd)
}

var engagementReportCmd = &cobra.Command{
	Use:   "report [id]",
	Short: "Generate a pentest-grade report for an engagement (HTML + Markdown)",
	Long: `Assembles a pentest-grade deliverable for an engagement: the scope and
authorization statement, the confirmed findings with their proof-of-concept and
evidence, and the tamper-evident audit trail as an appendix. Reads the latest
saved DAST run(s) for the engagement's targets, or a specific run with --run.
The report is self-contained HTML (prints to a clean PDF) plus a Markdown copy.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEngagementReport,
}

func runEngagementReport(cmd *cobra.Command, args []string) error {
	store, err := engagementStore()
	if err != nil {
		return err
	}
	e, err := resolveEngagementArg(store, args)
	if err != nil {
		return err
	}

	runFile, _ := cmd.Flags().GetString("run")
	findings, sources, err := loadReportFindings(runFile)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return fmt.Errorf("no dynamic findings to report: run `argus dast <url> --engagement %s --save` first, or pass --run <file>", e.ID)
	}
	model.Sort(findings)

	auditPath := store.AuditPath(e.ID)
	vr, _ := engagement.Verify(auditPath)
	entries, _ := engagement.Entries(auditPath)

	engRep := &report.EngagementReport{
		Name:             e.Name,
		AuthorizationRef: e.AuthorizationRef,
		Contact:          e.Contact,
		Window:           reportWindowLabel(e.Window),
		InScope:          e.Scope.InScope,
		OutOfScope:       e.Scope.OutOfScope,
		AuditVerified:    vr.OK,
		AuditEntries:     vr.Entries,
		AuditEvents:      auditRows(entries),
	}
	if !vr.OK {
		engRep.AuditError = vr.Reason
	}

	meta := report.HTMLMeta{
		Target:      strings.Join(e.Scope.InScope, ", "),
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Engagement:  engRep,
	}

	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		out = "engagement-" + e.ID + "-report.html"
	}
	hf, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	if err := report.WriteHTML(hf, findings, meta); err != nil {
		hf.Close()
		return fmt.Errorf("write html: %w", err)
	}
	hf.Close()

	mdPath := strings.TrimSuffix(out, ".html") + ".md"
	if mf, err := os.Create(mdPath); err == nil {
		_ = report.WriteMarkdown(mf, findings)
		mf.Close()
	}

	fmt.Fprintf(os.Stdout, "Wrote pentest report for %q (%s): %s (+ %s)\n", e.Name, e.ID, out, mdPath)
	fmt.Fprintf(os.Stdout, "  %d finding(s) from %s\n", len(findings), strings.Join(sources, ", "))
	if vr.OK {
		fmt.Fprintf(os.Stdout, "  audit trail intact: %d entr%s\n", vr.Entries, plural(vr.Entries))
	} else {
		fmt.Fprintf(os.Stdout, "  WARNING: audit trail failed verification at seq %d: %s\n", vr.BadSeq, vr.Reason)
	}
	return nil
}

// loadReportFindings reads either a specific run file or the newest run in each
// DAST target's store under .appsec/dast/*/runs.
func loadReportFindings(runFile string) ([]model.Finding, []string, error) {
	if runFile != "" {
		fs, err := decodeRun(runFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read run %s: %w", runFile, err)
		}
		return fs, []string{filepath.Base(runFile)}, nil
	}
	dirs, _ := filepath.Glob(filepath.Join(".appsec", "dast", "*", "runs"))
	var all []model.Finding
	var sources []string
	for _, d := range dirs {
		runs, _ := filepath.Glob(filepath.Join(d, "*.json"))
		if len(runs) == 0 {
			continue
		}
		sort.Strings(runs) // timestamped filenames sort chronologically
		newest := runs[len(runs)-1]
		fs, err := decodeRun(newest)
		if err != nil {
			continue
		}
		all = append(all, fs...)
		sources = append(sources, filepath.Base(filepath.Dir(d))+"/"+filepath.Base(newest))
	}
	return all, sources, nil
}

func decodeRun(path string) ([]model.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Findings []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Findings, nil
}

// reportWindowLabel renders the testing window for the report, or "" when the
// window is unbounded (so the row is omitted).
func reportWindowLabel(w engagement.Window) string {
	if w.Start.IsZero() && w.End.IsZero() {
		return ""
	}
	return windowLabel(w)
}

// auditRows renders the audit entries for the report appendix, most-recent last,
// bounded so a long engagement does not produce an unwieldy table.
func auditRows(entries []engagement.Entry) []report.AuditEventRow {
	const maxRows = 300
	start := 0
	if len(entries) > maxRows {
		start = len(entries) - maxRows
	}
	rows := make([]report.AuditEventRow, 0, len(entries)-start)
	for _, e := range entries[start:] {
		rows = append(rows, report.AuditEventRow{
			Seq:    int(e.Seq),
			Time:   e.Time.UTC().Format("15:04:05"),
			Event:  e.Event,
			Detail: detailLabel(e.Details),
		})
	}
	return rows
}

func detailLabel(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	s := strings.Join(parts, " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
