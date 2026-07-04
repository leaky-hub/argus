# Risk Scoring

Every finding in every run gets a risk score in **[0, 10]** (`riskScore` in the
model, one decimal place). The score is computed in `internal/risk` in two
stages:

1. a **deterministic heuristic baseline** — always computed, no LLM required;
2. a **bounded LLM adjustment** — applied only when AI triage produced a
   verdict for the finding. The LLM never invents the number; it can only move
   the baseline within the documented bounds below via its verdict and
   confidence.

The score is a *prioritization* signal. It never changes `severity`, never
feeds the severity gate, and never suppresses a finding.

## Stage 1 — heuristic baseline

```
baseline = clamp( base(severity)
                + confidence_mod(tool_confidence)
                + category_mod(category)
                + cwe_mod(cwes)
                + fix_mod(remediation) , 0, 10 )
```

| Component | Value | Rationale |
|---|---|---|
| `base(critical)` | 9.0 | anchors to the normalized severity scale |
| `base(high)` | 7.0 | |
| `base(medium)` | 5.0 | |
| `base(low)` | 3.0 | |
| `base(info)` | 1.0 | |
| `confidence_mod(high)` | +0.5 | tool is sure → fewer FP discounts |
| `confidence_mod(medium or empty)` | 0.0 | absence of confidence is not evidence |
| `confidence_mod(low)` | −1.0 | tool itself flags likely-FP |
| `category_mod(SECRET)` | +1.0 | a leaked credential is directly exploitable, no chain needed |
| `category_mod(other)` | 0.0 | |
| `cwe_mod` | +0.5 | if any CWE is in the high-impact class (below), else 0 |
| `fix_mod` | +0.25 | if remediation/fixed-version is known: a public fix means a public advisory, and cheap mitigation raises the cost of *not* acting |

**High-impact CWE class** (direct code-execution / auth-bypass / data-exfil
primitives): CWE-22, 77, 78, 89, 94, 95, 287, 306, 434, 502, 611, 798, 918,
1336. The set is a package-level constant in `internal/risk`; extending it is
a normal reviewed change, not a schema event.

Tool confidence strings are matched case-insensitively (`HIGH`/`high`;
semgrep's `extra.metadata.confidence` style). Unrecognized values count as
medium.

## Stage 2 — bounded LLM adjustment

AI triage yields `verdict ∈ {true-positive, false-positive, uncertain}` and
`confidence ∈ [0, 1]` (validated and clamped at parse time — see
`internal/triage`). The adjustment is a pure function of those two values:

| Verdict | Adjustment | Bound |
|---|---|---|
| `true-positive` | `+1.0 × confidence` | capped at 10.0 |
| `false-positive` | `−4.0 × confidence` | floored at **0.5** |
| `uncertain` | 0 | — |

Design constraints, in order of importance:

- **A false-positive verdict can deprioritize but never erase.** The 0.5 floor
  keeps the finding visible and above "no risk"; an LLM verdict is advice, not
  proof. Removing FP-marked findings from output is a separate, explicit,
  opt-in step (`--exclude-fp`) — never the score's job.
- **The adjustment is bounded and monotone in confidence**, so a prompt-injected
  or hallucinating model can move a score by at most −4.0/+1.0 — it cannot set
  an arbitrary value, and it cannot touch any *other* finding (triage is
  strictly per-finding).
- The downward bound is larger than the upward one on purpose: the main value
  of triage is FP suppression; severity already carries the upside.

`final = round1( clamp( baseline + adjustment, floor, 10 ) )` where
`floor = 0.5` for false-positive verdicts and `0` otherwise.

## Worked examples

| Finding | Baseline | Triage | Final |
|---|---|---|---|
| semgrep SQLi (high, CWE-89, no conf, no fix) | 7.0 + 0.5 = 7.5 | TP @ 0.9 | 8.4 |
| gitleaks AWS key (high, SECRET, CWE-798) | 7.0 + 1.0 + 0.5 = 8.5 | none | 8.5 |
| trivy CVE (critical, fix available) | 9.0 + 0.25 = 9.25 | none | 9.3 |
| semgrep `shell=True` on a constant (medium) | 5.0 | FP @ 1.0 | 1.0 |
| gitleaks canonical example key (high, SECRET, CWE-798) | 8.5 | FP @ 0.8 | 5.3 |

## Where the score surfaces

- **JSON**: `riskScore` on each finding (schema slot since 1.0.0).
- **Markdown**: `Risk` column in the findings tables.
- **SARIF**: `properties.riskScore` on each result. It deliberately does NOT
  replace `properties.security-severity`, which stays severity-derived —
  GitHub's bucketing must not move on LLM output.

## Triage response schema (contract with `internal/triage`)

The LLM must answer with exactly one JSON object:

```json
{"verdict": "true-positive" | "false-positive" | "uncertain",
 "confidence": 0.0-1.0,
 "rationale": "one or two sentences"}
```

Validation (in `internal/triage`, security-critical, never delegated):
verdict must match the enum exactly; confidence is clamped to [0,1]
(missing → 0.5); rationale is free text but truncated to 500 runes with
control characters stripped — it is the ONLY place model free-text reaches a
report. Anything else — malformed JSON, unknown verdict, refusals, prose —
degrades that one finding to `uncertain` with zero score adjustment.
