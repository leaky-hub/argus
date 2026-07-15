package xxescan

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
	"github.com/zer0d4y5/argus/internal/ssrfscan"
)

// oobFinding is a blind XXE confirmed by an out-of-band callback: the XML parser
// resolved the external entity and connected back to the local listener.
func (s *scanner) oobFinding(pr xxeProbe, cb ssrfscan.Callback) model.RawFinding {
	f := model.RawFinding{
		Tool:        "argus-xxe",
		Category:    model.CategoryDAST,
		RuleID:      "xxe-oob:post", // sendXML always POSTs, regardless of how the endpoint was discovered
		Title:       "XML External Entity (XXE) processing",
		Description: "The endpoint parses XML with external-entity resolution enabled: an injected external entity was fetched, proven by a connection back to the tester's listener. This can be used to read local files or reach internal services.",
		RawSeverity: "high",
		URL:         pr.ep.URL,
		CWEs:        []string{"CWE-611"},
		Meta:        map[string]string{"method": "POST"},
	}
	observed := fmt.Sprintf("The XML parser connected back to the operator's local listener (source %s) after resolving the injected external entity. Only a parser that fetches external entities produces that callback.", cb.RemoteAddr)
	f.Proof = poc.Build("xxe", poc.Request{Method: http.MethodPost, URL: stripQuery(pr.ep.URL), Body: pr.body, CookiePresent: s.cookiePresent()}, "the XML body", observed)
	return f
}

// reflectedFinding is an in-band XXE: the parser resolved the entity and echoed
// the listener's marker into the response.
func (s *scanner) reflectedFinding(ep dastcrawl.Endpoint, xml, respBody string) model.RawFinding {
	f := model.RawFinding{
		Tool:        "argus-xxe",
		Category:    model.CategoryDAST,
		RuleID:      "xxe-reflected:post", // sendXML always POSTs, regardless of how the endpoint was discovered
		Title:       "XML External Entity (XXE) processing (reflected)",
		Description: "The endpoint parses XML with external-entity resolution and reflects the fetched entity content: the listener's marker appeared in the response.",
		RawSeverity: "high",
		URL:         ep.URL,
		CWEs:        []string{"CWE-611"},
		Meta:        map[string]string{"method": "POST"},
	}
	f.Proof = poc.Build("xxe", poc.Request{Method: http.MethodPost, URL: stripQuery(ep.URL), Body: xml, CookiePresent: s.cookiePresent()}, "the XML body",
		"The response contained the marker served by the tester's listener, so the parser fetched the injected external entity and returned its content.")
	if f.Proof != nil {
		f.Proof.Response = poc.RedactResponse(respBody)
	}
	return f
}

// deserFindings flags parameter values that look like a serialized object. This
// is a passive surface finding (CWE-502): it sends no payload and does not
// confirm exploitability, only that a serialized object is being accepted, which
// is worth manual review.
func (s *scanner) deserFindings(ep dastcrawl.Endpoint, seen map[string]bool) []model.RawFinding {
	var out []model.RawFinding
	params := paramValues(ep)
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic subset when an endpoint has >maxParamsPerEP params
	for i, name := range names {
		if i >= maxParamsPerEP {
			break
		}
		value := params[name]
		if kind := serializedKind(value); kind != "" {
			f := model.RawFinding{
				Tool:        "argus-deser",
				Category:    model.CategoryDAST,
				RuleID:      "deserialization-surface:" + name,
				Title:       "Serialized Object in a Parameter",
				Description: fmt.Sprintf("Parameter %q (%s) carries what looks like a %s serialized object. If the server deserializes untrusted input, this is an insecure-deserialization attack surface; confirm how the value is processed. (Detected passively; not exploited.)", name, ep.Method, kind),
				RawSeverity: "low",
				URL:         ep.URL,
				CWEs:        []string{"CWE-502"},
				Meta:        map[string]string{"param": name, "method": methodOf(ep), "format": kind},
			}
			if fd, ok := dedup(seen, f); ok {
				out = append(out, fd)
			}
		}
	}
	return out
}

func methodOf(ep dastcrawl.Endpoint) string {
	if ep.Method == "" {
		return http.MethodGet
	}
	return ep.Method
}

// serializedKind returns the serialized-object format a value looks like, or "".
// The signatures are specific enough that ordinary values do not match.
func serializedKind(v string) string {
	t := strings.TrimSpace(v)
	if len(t) < 8 {
		return ""
	}
	switch {
	case strings.HasPrefix(t, "rO0AB"): // base64 of Java stream header 0xACED0005
		return "Java (base64)"
	case strings.HasPrefix(t, "\xac\xed\x00"): // raw Java serialization header
		return "Java"
	case phpSerialized(t):
		return "PHP"
	case strings.HasPrefix(t, "AAEAAAD/////"): // .NET BinaryFormatter (base64)
		return ".NET (base64)"
	}
	return ""
}

// phpSerialized reports whether a value has the shape of a PHP serialized
// object or array: O:<n>:"Name":<n>:{ or a:<n>:{.
func phpSerialized(t string) bool {
	if !strings.HasPrefix(t, "O:") && !strings.HasPrefix(t, "a:") {
		return false
	}
	rest := t[2:]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits >= len(rest) {
		return false
	}
	next := rest[digits]
	// O:<n>:"...  or  a:<n>:{
	return next == ':' && (t[0] == 'O' && strings.Contains(rest[digits:], `:"`) || t[0] == 'a' && strings.Contains(rest[digits:], ":{"))
}
