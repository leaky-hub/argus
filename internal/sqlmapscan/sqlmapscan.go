// Package sqlmapscan drives sqlmap over discovered endpoints (GET and POST) and
// maps its confirmed SQL-injection points into the unified model (category
// DAST). It complements nuclei: sqlmap confirms boolean/time-based BLIND
// injection that error-signature fuzzing cannot see, and tests POST bodies.
//
// SECURITY: sqlmap is run in --batch (non-interactive) mode and is NEVER given
// data-exfiltration flags (no --dump, --os-shell, --sql-query, ...): the
// adapter only asks "is this parameter injectable?" and records the answer. The
// parser reads sqlmap's injection-point summary (parameter, place, technique),
// never dumped data. The auth cookie is passed to sqlmap but never logged.
package sqlmapscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
)

// Available reports whether sqlmap is on PATH.
func Available() bool {
	_, err := exec.LookPath("sqlmap")
	return err == nil
}

// Options configure a sqlmap run.
type Options struct {
	Cookie     string
	Endpoints  []dastcrawl.Endpoint
	PerReqSecs int // per-endpoint wall-clock budget (0 = default)
	Level      int // sqlmap --level (0 = default 1)
	Risk       int // sqlmap --risk (0 = default 1)
}

// Scan runs sqlmap against each endpoint and returns unified raw findings, one
// per confirmed injectable parameter.
func Scan(ctx context.Context, opts Options, progress func(string)) ([]model.RawFinding, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if !Available() {
		return nil, fmt.Errorf("sqlmap not found on PATH")
	}

	var out []model.RawFinding
	seen := map[string]bool{}
	for _, ep := range opts.Endpoints {
		stdout, err := runOne(ctx, ep, opts, progress)
		if err != nil {
			progress(fmt.Sprintf("  ! sqlmap %s: %v\n", ep.URL, err))
			continue
		}
		for _, f := range parseSqlmap(stdout, ep) {
			key := f.RuleID + "\x00" + f.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	progress(fmt.Sprintf("sqlmap: %d SQL-injection finding(s)\n", len(out)))
	return out, nil
}

func runOne(ctx context.Context, ep dastcrawl.Endpoint, opts Options, progress func(string)) ([]byte, error) {
	level, risk := opts.Level, opts.Risk
	if level <= 0 {
		level = 1
	}
	if risk <= 0 {
		risk = 1
	}
	budget := opts.PerReqSecs
	if budget <= 0 {
		budget = 120
	}
	args := []string{
		"-u", ep.URL,
		"--batch",          // never prompt
		"--flush-session",  // do not reuse a prior session's verdict
		"--disable-coloring",
		"--level", itoa(level),
		"--risk", itoa(risk),
		"--timeout", "10",
		"--retries", "1",
		// A hard cap so one endpoint cannot stall the whole scan.
		"--time-limit", itoa(budget),
	}
	if ep.Method == "POST" && ep.Body != "" {
		args = append(args, "--data", ep.Body)
	}
	if opts.Cookie != "" {
		args = append(args, "--cookie", opts.Cookie)
	}

	cmd := exec.CommandContext(ctx, "sqlmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // sqlmap's exit code is not a reliable found/not-found signal
	return stdout.Bytes(), nil
}

// parseSqlmap extracts confirmed injection points from sqlmap's summary block:
//
//	sqlmap identified the following injection point(s) ...:
//	Parameter: id (GET)
//	    Type: boolean-based blind
//	    Title: ...
//	    Type: time-based blind
//	    ...
//
// One RawFinding per parameter, with the techniques folded into the title.
func parseSqlmap(stdout []byte, ep dastcrawl.Endpoint) []model.RawFinding {
	text := string(stdout)
	marker := strings.Index(text, "sqlmap identified the following injection point")
	if marker < 0 {
		return nil
	}
	dbms := parseDBMS(text)

	var out []model.RawFinding
	var curParam, curPlace string
	var techniques []string

	flush := func() {
		if curParam == "" {
			return
		}
		title := "SQL Injection"
		if len(techniques) > 0 {
			title = "SQL Injection (" + strings.Join(techniques, ", ") + ")"
		}
		desc := fmt.Sprintf("sqlmap confirmed parameter %q (%s) is SQL-injectable.", curParam, curPlace)
		if dbms != "" {
			desc += " Back-end DBMS: " + dbms + "."
		}
		meta := map[string]string{"param": curParam, "place": curPlace, "dbms": dbms}
		if ep.Method == "POST" && ep.Body != "" {
			meta["body"] = ep.Body
		}
		out = append(out, model.RawFinding{
			Tool:        "sqlmap",
			Category:    model.CategoryDAST,
			RuleID:      "sqlmap-sqli:" + strings.ToLower(curPlace) + ":" + curParam,
			Title:       title,
			Description: desc,
			RawSeverity: "critical", // a confirmed injection point is critical
			URL:         ep.URL,
			CWEs:        []string{"CWE-89"},
			Meta:        meta,
		})
		curParam, curPlace, techniques = "", "", nil
	}

	sc := bufio.NewScanner(strings.NewReader(text[marker:]))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if p, place, ok := parseParameterLine(line); ok {
			flush() // previous parameter block ends here
			curParam, curPlace = p, place
			continue
		}
		if curParam != "" && strings.HasPrefix(line, "Type:") {
			t := strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			if t != "" {
				techniques = append(techniques, t)
			}
		}
	}
	flush()
	return out
}

// parseParameterLine matches `Parameter: <name> (<place>)`.
func parseParameterLine(line string) (name, place string, ok bool) {
	if !strings.HasPrefix(line, "Parameter:") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Parameter:"))
	open := strings.LastIndex(rest, "(")
	close := strings.LastIndex(rest, ")")
	if open < 0 || close < open {
		return strings.TrimSpace(rest), "GET", true
	}
	return strings.TrimSpace(rest[:open]), strings.TrimSpace(rest[open+1 : close]), true
}

// parseDBMS pulls the reported back-end DBMS, for context in the finding.
func parseDBMS(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "back-end DBMS:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Identity is the minimum identifying evidence a bounded SQLi confirmation
// retrieves: the database banner and the current user/database. It is enough to
// demonstrate the injection reaches the real database, and nothing more. It
// never carries table data.
type Identity struct {
	Banner      string
	CurrentUser string
	CurrentDB   string
}

// Empty reports whether nothing identifying was retrieved.
func (id Identity) Empty() bool {
	return id.Banner == "" && id.CurrentUser == "" && id.CurrentDB == ""
}

// ConfirmIdentity re-runs sqlmap against a known-injectable endpoint asking ONLY
// for identity: the banner and the current user and database. It is the bounded
// impact confirmation for SQLi: it proves the injection reaches the live
// database without extracting any table data. It never passes --dump,
// --sql-query, or --os-shell. It returns the identity (which may be partial), or
// nil if sqlmap did not confirm the injection this run.
func ConfirmIdentity(ctx context.Context, ep dastcrawl.Endpoint, opts Options) (*Identity, error) {
	if !Available() {
		return nil, fmt.Errorf("sqlmap not found on PATH")
	}
	level, risk := opts.Level, opts.Risk
	if level <= 0 {
		level = 1
	}
	if risk <= 0 {
		risk = 1
	}
	budget := opts.PerReqSecs
	if budget <= 0 {
		budget = 120
	}
	args := []string{
		"-u", ep.URL,
		"--batch",
		"--disable-coloring",
		"--level", itoa(level),
		"--risk", itoa(risk),
		"--timeout", "10",
		"--retries", "1",
		"--time-limit", itoa(budget),
		// Identity retrieval only. NEVER --dump/--sql-query/--os-shell.
		"--banner", "--current-user", "--current-db",
	}
	if ep.Method == "POST" && ep.Body != "" {
		args = append(args, "--data", ep.Body)
	}
	if opts.Cookie != "" {
		args = append(args, "--cookie", opts.Cookie)
	}
	cmd := exec.CommandContext(ctx, "sqlmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // sqlmap's exit code is not a reliable signal
	id := parseIdentity(stdout.String())
	if id.Empty() {
		return nil, nil
	}
	return &id, nil
}

// parseIdentity reads the banner and current user/database from sqlmap's output.
// It reads only those labelled identity lines, never any fetched row data.
func parseIdentity(text string) Identity {
	var id Identity
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := cutIdentity(line, "banner:"); ok {
			id.Banner = v
		} else if v, ok := cutIdentity(line, "current user:"); ok {
			id.CurrentUser = v
		} else if v, ok := cutIdentity(line, "current database:"); ok {
			id.CurrentDB = v
		}
	}
	if id.Banner == "" {
		id.Banner = parseDBMS(text)
	}
	return id
}

// cutIdentity matches a "<label> '<value>'" line and returns the unquoted,
// length-bounded value.
func cutIdentity(line, label string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.ToLower(line), label)
	if !ok {
		return "", false
	}
	// Recover the original-case value using the matched length.
	v := strings.TrimSpace(line[len(label):])
	_ = rest
	v = strings.Trim(v, "'\"")
	if len(v) > 200 {
		v = v[:200]
	}
	return strings.TrimSpace(v), v != ""
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
