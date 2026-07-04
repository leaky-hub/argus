# appsec

One CLI that runs the best open-source security scanners against your repo,
merges their results into a single deduplicated report, scores and AI-triages
every finding, and gates your CI on severity — SAST, secrets, and dependency
(SCA) scanning with LLM-backed false-positive triage and 0–10 risk scoring
today; IaC, DAST, and compliance mapping on the [roadmap](docs/roadmap.md).

> **Naming:** `appsec` is the working name. Proposed project name: **Bulwark** —
> a defensive wall built from many stones: independent scanners mortared into
> one structure. Rename is a single `go.mod`/import sweep; the CLI keeps a
> short binary name either way.

```
appsec scan ./repo
  → runs in parallel:  semgrep (SAST) · gitleaks (secrets) · trivy fs (SCA)
  → normalizes everything into one findings model
  → dedups/correlates overlapping findings
  → AI triage (opt-in): LLM verdicts true/false-positive per finding
  → risk-scores every finding 0–10 (heuristic baseline ± bounded LLM adjustment)
  → writes SARIF 2.1.0 / Markdown / JSON
  → exits non-zero when findings hit your severity gate
```

## Quickstart

```bash
# Prereqs: Go 1.22+, plus whichever scanners you want on PATH:
#   pipx install semgrep     (or: pip install semgrep)
#   brew install gitleaks trivy
go build -o appsec ./cmd/appsec

# Scan a repository (markdown report to stdout):
./appsec scan path/to/repo

# SARIF for GitHub code scanning:
./appsec scan . --format sarif -o results.sarif

# Fail CI on high or critical findings:
./appsec scan . --fail-severity high

# AI triage against a local Ollama model (default provider — nothing leaves
# your machine), plus opt-in exclusion of LLM-marked false positives:
./appsec scan . --triage
./appsec scan . --triage --exclude-fp
```

Missing scanners are skipped with a note — the CLI degrades gracefully and
runs whatever the environment provides. The same applies to triage: no LLM
reachable means the scan simply runs without verdicts.

## AI triage & risk scoring

Every finding always gets a deterministic **risk score** (0–10; formula in
[docs/risk-scoring.md](docs/risk-scoring.md)). With `--triage` (or
`triage.enabled: true`), an LLM additionally reviews each finding with a
bounded source snippet and records a verdict — `true-positive`,
`false-positive`, or `uncertain` — plus a rationale, which reporters surface
alongside the score. Verdicts are additive metadata: severity and the CI gate
never move on LLM output, and `--exclude-fp` is the only (explicit, counted)
way a verdict removes a finding from the report and gate.

Providers: **Ollama** (default, local) and **Anthropic** (set
`ANTHROPIC_API_KEY`; keys are env-only, never config). Scanned code is treated
as hostile input: snippets enter prompts only inside per-request random
boundary markers, model output is schema-validated, and SECRET findings never
leave the machine unless `allow_secret_cloud: true` is set.

## Configuration — `appsec.yml`

Looked up in the working directory (override with `--config`); flags beat file
values.

```yaml
scanners: []            # subset to run, e.g. [semgrep, gitleaks]; empty = all
fail_severity: high     # critical | high | medium | low | info | none
format: markdown        # sarif | markdown | json
ignore_paths:           # glob patterns; `dir/**` ignores a subtree
  - testdata/**
  - vendor
ignore_rules:           # exact rule IDs to suppress
  - generic-api-key
timeout: 600            # per-scanner timeout, seconds
triage:                 # AI triage (Phase 2) — off unless enabled here or via --triage
  enabled: false
  provider: ollama      # ollama | anthropic (API key via ANTHROPIC_API_KEY env)
  model: qwen3.6:35b-a3b
  endpoint: http://localhost:11434
  timeout: 90           # per-LLM-request seconds
  concurrency: 4
  max_findings: 200     # triage the N most severe findings; 0 = all
  exclude_fp: false     # opt-in: drop LLM-marked false positives from report + gate
  allow_secret_cloud: false  # opt-in: allow SECRET findings to non-local providers
```

Suppressed findings are counted on stderr — suppression is never silent.

## GitHub Action

`.github/workflows/appsec.yml` runs on every PR: it scans, uploads SARIF to
GitHub code scanning, and fails the build on high+ findings. Copy it into any
repo and adjust the gate.

## Output formats

- **SARIF 2.1.0** — validates against the official schema; ingested by GitHub
  code scanning (severity mapped to `security-severity` so alerts bucket
  correctly; stable fingerprints so alerts track across commits).
- **Markdown** — human-readable summary + findings grouped by severity.
- **JSON** — the full unified findings model (`docs/findings-model.md`),
  including per-tool raw payload passthrough.

## Docs

- [Architecture](docs/architecture.md) — orchestrator design, package layout, design rules
- [Findings model](docs/findings-model.md) — the unified schema (versioned)
- [Risk scoring](docs/risk-scoring.md) — the 0–10 formula and the bounded LLM adjustment
- [Roadmap](docs/roadmap.md) — Phases 3–8: IaC, compliance, DAST, threat modeling, IAST, platform

## Development

```bash
go build ./... && go test ./...
./appsec scan testdata/fixture   # deliberately vulnerable sample; expect findings
```

Licensed under Apache-2.0.
