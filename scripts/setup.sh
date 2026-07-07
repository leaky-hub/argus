#!/usr/bin/env bash
# Argus setup: build the binary, check which scanners are installed, and say
# exactly what works with what you have. Idempotent, no sudo, no downloads —
# it never installs anything for you, it tells you what to install and how.
set -euo pipefail

bold=$(tput bold 2>/dev/null || true)
dim=$(tput dim 2>/dev/null || true)
red=$(tput setaf 1 2>/dev/null || true)
green=$(tput setaf 2 2>/dev/null || true)
yellow=$(tput setaf 3 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)

ok()   { printf "  %s✓%s %s\n" "$green" "$reset" "$1"; }
miss() { printf "  %s✗%s %-10s %s%s%s\n" "$red" "$reset" "$1" "$dim" "$2" "$reset"; }
note() { printf "  %s•%s %s\n" "$yellow" "$reset" "$1"; }

cd "$(dirname "$0")/.."
printf "%sArgus setup%s\n\n" "$bold" "$reset"

# --- Go toolchain + build ---------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  printf "%sGo is required to build Argus.%s\n" "$red" "$reset"
  echo "  install: https://go.dev/dl/ (or: brew install go)"
  exit 1
fi
gover=$(go env GOVERSION)
printf "%sBuild%s (Go %s)\n" "$bold" "$reset" "${gover#go}"
go build -o argus ./cmd/argus
ok "built ./argus"

# --- Scanners ----------------------------------------------------------------
printf "\n%sScanners%s (each is optional; Argus runs whatever is installed)\n" "$bold" "$reset"
found=0
check_tool() { # name, what it adds, install hint
  if command -v "$1" >/dev/null 2>&1; then
    ok "$(printf '%-10s %s' "$1" "$2")"
    found=$((found + 1))
  else
    miss "$1" "$2 — install: $3"
  fi
}
check_tool semgrep "SAST (code vulnerabilities)"        "brew install semgrep  |  pipx install semgrep"
check_tool gitleaks "secrets (worktree + git history)"  "brew install gitleaks"
check_tool trivy   "SCA + IaC misconfigurations"        "brew install trivy"
check_tool checkov "IaC misconfigurations"              "brew install checkov  |  pipx install checkov"
check_tool prowler "cloud posture (AWS)"                "brew install prowler  |  pipx install prowler"

if [ "$found" -eq 0 ]; then
  printf "\n%sNo scanners found — a scan will produce nothing. Install at least one.%s\n" "$red" "$reset"
fi

# --- Local LLM (optional) ----------------------------------------------------
printf "\n%sAssistive AI%s (optional; every deterministic feature works without it)\n" "$bold" "$reset"
if curl -sf --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
  ok "Ollama reachable at localhost:11434 (triage, explain, threat suggestions)"
else
  note "Ollama not running — AI triage/explain/suggest are disabled until it is (https://ollama.com)"
fi

# --- Next steps ----------------------------------------------------------------
printf "\n%sNext steps%s\n" "$bold" "$reset"
cat <<'EOF'
  ./argus scan <path> --save          # scan a repo and record the run
  ./argus user add you --role admin   # create the first console user
  ./argus serve -d <path>             # open the console at http://127.0.0.1:8080
  ./argus comply <path>               # compliance gap report
  ./argus cloud-scan --profile <p>    # AWS posture via prowler (read-only creds)
EOF
printf "%sDocs: docs/architecture.md · docs/console-ops.md%s\n" "$dim" "$reset"
