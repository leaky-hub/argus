package cloudremediate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Execution of a built plan. The command NEVER comes from the client: the
// server builds a Plan from the catalog and a finding, and the runner executes
// exactly that plan's dry-run or apply commands. The write credential follows
// the same shape cloud scans use per provider: AWS runs with a validated
// profile NAME resolved by the AWS SDK inside the child process; Azure and GCP
// run with the operator's own az/gcloud login, scoped by the subscription or
// project already baked (grammar-validated) into the argv. No key material
// enters Argus for any provider.
//
// Defense in depth over the already-vetted, argv-only, grammar-validated
// catalog: the binary must be the plan provider's CLI, and no argument may
// carry a shell metacharacter or that CLI's destructive verbs. A command that
// fails these never runs.

// Executor runs one argv and returns combined output. profile is the AWS write
// profile name, or "" for providers that use ambient CLI auth. Injected so
// tests exercise the runner without a live account.
type Executor interface {
	Run(ctx context.Context, argv []string, profile string) (output string, err error)
}

// providerBinary maps a plan provider to the ONLY CLI its commands may invoke.
var providerBinary = map[string]string{
	"aws":   "aws",
	"azure": "az",
	"gcp":   "gcloud",
}

// shellMeta rejects shell metacharacters in any argument (there is no shell,
// but assert it anyway).
var shellMeta = regexp.MustCompile(`[;&|$` + "`" + `><\n\r]`)

// forbiddenVerbs is each CLI's destructive-verb grammar: no argument of a
// catalog command may contain one, whatever the surrounding subcommand. The
// word boundary also catches hyphenated subcommands (remove-iam-policy-binding).
var forbiddenVerbs = map[string]*regexp.Regexp{
	"aws":    regexp.MustCompile(`(?i)\b(delete|terminate|remove|destroy|rm|drop|revoke|mkfs)\b`),
	"az":     regexp.MustCompile(`(?i)\b(delete|purge|remove|destroy|terminate|rm|drop|revoke|mkfs|logout)\b`),
	"gcloud": regexp.MustCompile(`(?i)\b(delete|remove|abandon|destroy|terminate|rm|drop|revoke|mkfs)\b`),
}

// CommandResult is the outcome of running one command in a plan.
type CommandResult struct {
	Command Command `json:"command"`
	Output  string  `json:"output"`
	Err     string  `json:"error,omitempty"`
}

// Runner executes plan commands through an Executor with profile validation.
type Runner struct {
	Exec Executor
	// ValidProfile reports whether a write-profile name is in the local config's
	// closed list. Injected (cloudscan.ListAWSProfiles in production) so this
	// package doesn't depend on cloudscan.
	ValidProfile func(name string) bool
}

// Mode selects which commands of a plan to run.
type Mode int

const (
	DryRun Mode = iota // preview: read current state, never mutate
	Apply              // make the change
)

// Run validates the credential reference and each command, then executes the
// plan's dry-run or apply commands in order, stopping at the first failure. It
// returns the per-command results. A safety-check failure is an error BEFORE
// anything runs.
//
// Credential semantics per provider: an AWS plan requires a validated write
// profile; an Azure or GCP plan runs with the operator's own az/gcloud login
// and REFUSES a profile (nothing may look like it selected a credential when
// it didn't).
func (r *Runner) Run(ctx context.Context, plan Plan, mode Mode, profile string) ([]CommandResult, error) {
	profile = strings.TrimSpace(profile)
	switch plan.Provider {
	case "aws":
		if profile == "" {
			return nil, fmt.Errorf("an AWS write profile is required")
		}
		if r.ValidProfile != nil && !r.ValidProfile(profile) {
			return nil, fmt.Errorf("unknown AWS profile %q: not present in the local AWS config", profile)
		}
	case "azure", "gcp":
		if profile != "" {
			return nil, fmt.Errorf("%s remediation runs with your local %s login; a write profile does not apply", plan.Provider, providerBinary[plan.Provider])
		}
	default:
		return nil, fmt.Errorf("plan %s has unknown provider %q", plan.ID, plan.Provider)
	}
	cmds := plan.DryRun
	if mode == Apply {
		cmds = plan.Apply
	}
	if len(cmds) == 0 {
		return nil, fmt.Errorf("plan %s has no %s commands", plan.ID, modeName(mode))
	}
	// Safety-check EVERY command up front so a partial run can't leave a bad one
	// unchecked mid-sequence.
	for _, c := range cmds {
		if err := checkCommand(plan.Provider, c); err != nil {
			return nil, err
		}
	}
	if r.Exec == nil {
		return nil, fmt.Errorf("no executor configured")
	}

	results := make([]CommandResult, 0, len(cmds))
	for _, c := range cmds {
		out, err := r.Exec.Run(ctx, []string(c), profile)
		res := CommandResult{Command: c, Output: out}
		if err != nil {
			res.Err = err.Error()
			results = append(results, res)
			return results, fmt.Errorf("%s command failed: %s", modeName(mode), lastLine(out, err))
		}
		results = append(results, res)
	}
	return results, nil
}

// checkCommand is the pre-execution guard: the binary must be the plan
// provider's own CLI (an azure plan can never run aws), and no argument may
// carry a shell metacharacter or that CLI's destructive verbs.
// Belt-and-suspenders over the catalog's own guarantees.
func checkCommand(provider string, c Command) error {
	if len(c) == 0 {
		return fmt.Errorf("empty command")
	}
	bin := providerBinary[provider]
	if bin == "" || c[0] != bin {
		return fmt.Errorf("command binary %q is not allowed for provider %q", c[0], provider)
	}
	verbs := forbiddenVerbs[bin]
	for _, arg := range c {
		if shellMeta.MatchString(arg) || verbs.MatchString(arg) {
			return fmt.Errorf("command argument %q failed the safety check", arg)
		}
	}
	return nil
}

func modeName(m Mode) string {
	if m == Apply {
		return "apply"
	}
	return "dry-run"
}

func lastLine(out string, err error) string {
	s := strings.TrimSpace(out)
	if s == "" {
		return err.Error()
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// execProcess is the production Executor: it runs the argv in a child, with an
// AWS write profile referenced via AWS_PROFILE when one applies, the SAME
// credential-reference shape cloudscan uses. Azure/GCP commands get NO injected
// credential env: auth is the operator's own az/gcloud login, and the account
// scope rides in the already-validated argv, exactly like their cloud scans.
// Output is captured (never streamed; it can echo account identifiers). The
// profile value never appears in Argus's own state.
type execProcess struct {
	timeout time.Duration
}

// NewExecutor returns the production process executor with a per-command
// timeout.
func NewExecutor(timeout time.Duration) Executor {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &execProcess{timeout: timeout}
}

func (e *execProcess) Run(ctx context.Context, argv []string, profile string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	cmd.Env = append([]string{}, os.Environ()...)
	if profile != "" {
		// The credential REFERENCE: a validated profile NAME, resolved by the
		// AWS SDK inside the child. The value dies with the process. Azure/GCP
		// plans arrive with profile == "" (the runner enforces it) and add
		// nothing to the environment.
		cmd.Env = append(cmd.Env, "AWS_PROFILE="+profile)
	}
	out, err := cmd.CombinedOutput()
	if cctx.Err() != nil {
		return string(out), fmt.Errorf("command timed out")
	}
	return string(out), err
}
