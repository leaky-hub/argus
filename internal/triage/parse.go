package triage

// LLM output parsing is a security boundary and is never delegated or
// auto-generated. Model output is only trusted after validation: the verdict
// must match the enum exactly, confidence is clamped into [0,1], and free
// text reaches reports only through the sanitized, length-bounded rationale.
// Anything else fails parsing and the finding degrades to "uncertain".

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/leaky-hub/appsec/internal/model"
)

type rawVerdict struct {
	Verdict    string   `json:"verdict"`
	Confidence *float64 `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// parseVerdict validates raw model output into a bounded Triage value
// (Model field left empty; the caller stamps it). It never returns a partially
// trusted result: on error the caller must discard everything.
func parseVerdict(raw string) (model.Triage, error) {
	v, err := decodeFirstObject(raw)
	if err != nil {
		return model.Triage{}, err
	}

	verdict := strings.ToLower(strings.TrimSpace(v.Verdict))
	switch verdict {
	case model.VerdictTruePositive, model.VerdictFalsePositive, model.VerdictUncertain:
	default:
		return model.Triage{}, fmt.Errorf("unknown verdict %.40q", v.Verdict)
	}

	// Missing confidence is "no opinion", not certainty: 0.5 keeps the risk
	// adjustment moderate. NaN/Inf and out-of-range values are clamped.
	conf := 0.5
	if v.Confidence != nil && !math.IsNaN(*v.Confidence) && !math.IsInf(*v.Confidence, 0) {
		conf = math.Min(1, math.Max(0, *v.Confidence))
	}

	return model.Triage{
		Verdict:    verdict,
		Confidence: conf,
		Rationale:  sanitizeRationale(v.Rationale),
	}, nil
}

// decodeFirstObject finds and decodes the first JSON object in s, tolerating
// prose or code fences around it (models add those), but nothing looser.
func decodeFirstObject(s string) (rawVerdict, error) {
	for idx := 0; idx < len(s); idx++ {
		if s[idx] != '{' {
			continue
		}
		var v rawVerdict
		dec := json.NewDecoder(strings.NewReader(s[idx:]))
		if err := dec.Decode(&v); err == nil {
			return v, nil
		}
	}
	return rawVerdict{}, errors.New("no JSON object in model output")
}

// sanitizeRationale is the ONLY path by which model free-text reaches a
// report: control characters collapse to spaces and length is bounded.
func sanitizeRationale(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
		if n >= maxRationaleRunes {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
