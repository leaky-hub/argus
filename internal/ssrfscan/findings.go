package ssrfscan

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
)

// oobFinding is a blind SSRF confirmed by an out-of-band callback to the local
// listener. The callback source is the proof; there is no in-band response.
func oobFinding(pr probe, cb Callback, cookiePresent bool) model.RawFinding {
	method, u, body := requestTarget(pr.ep, pr.base, pr.param, pr.payload)
	f := model.RawFinding{
		Tool:        "argus-ssrf",
		Category:    model.CategoryDAST,
		RuleID:      "ssrf-oob:" + strings.ToLower(method) + ":" + pr.param,
		Title:       "Server-Side Request Forgery (blind, out-of-band)",
		Description: fmt.Sprintf("Parameter %q (%s) drives a server-side request: the target connected back to the local listener when given a URL of the tester's choosing.", pr.param, method),
		RawSeverity: "high",
		URL:         pr.ep.URL,
		CWEs:        []string{"CWE-918"},
		Meta:        map[string]string{"param": pr.param, "method": method},
	}
	if body != "" {
		f.Meta["body"] = body
	}
	observed := fmt.Sprintf("The target's server connected back to the operator's local listener (source %s) after fetching the injected URL. Only a server-side request to the tester-controlled address produces that callback.", cb.RemoteAddr)
	f.Proof = poc.Build("ssrf", poc.Request{Method: method, URL: u, Body: body, CookiePresent: cookiePresent}, pr.param, observed)
	return f
}

// reflectedFinding is an in-band SSRF: the target fetched the listener URL and
// reflected the served marker into its own response.
func reflectedFinding(ep dastcrawl.Endpoint, base url.Values, param, payload, respBody string, cookiePresent bool) model.RawFinding {
	method, u, body := requestTarget(ep, base, param, payload)
	f := model.RawFinding{
		Tool:        "argus-ssrf",
		Category:    model.CategoryDAST,
		RuleID:      "ssrf-reflected:" + strings.ToLower(method) + ":" + param,
		Title:       "Server-Side Request Forgery (reflected)",
		Description: fmt.Sprintf("Parameter %q (%s) drives a server-side request and reflects the fetched content: the listener's marker appeared in the response.", param, method),
		RawSeverity: "high",
		URL:         ep.URL,
		CWEs:        []string{"CWE-918"},
		Meta:        map[string]string{"param": param, "method": method},
	}
	if body != "" {
		f.Meta["body"] = body
	}
	f.Proof = poc.Build("ssrf", poc.Request{Method: method, URL: u, Body: body, CookiePresent: cookiePresent}, param,
		"The response contained the marker served by the tester's listener, so the server fetched the injected URL and returned its content.")
	if f.Proof != nil {
		f.Proof.Response = poc.RedactResponse(respBody)
	}
	return f
}

// metadataFinding is SSRF reaching the cloud metadata service, the canonical
// escalation. Reachability is proven by the metadata index signature; no
// credential path is requested.
func metadataFinding(ep dastcrawl.Endpoint, base url.Values, param, payload, respBody string, cookiePresent bool) model.RawFinding {
	method, u, body := requestTarget(ep, base, param, payload)
	f := model.RawFinding{
		Tool:        "argus-ssrf",
		Category:    model.CategoryDAST,
		RuleID:      "ssrf-cloud-metadata:" + strings.ToLower(method) + ":" + param,
		Title:       "SSRF to Cloud Metadata Service",
		Description: fmt.Sprintf("Parameter %q (%s) can reach the cloud instance metadata service (169.254.169.254). An attacker can pivot from here to instance role credentials.", param, method),
		RawSeverity: "critical",
		URL:         ep.URL,
		CWEs:        []string{"CWE-918"},
		Meta:        map[string]string{"param": param, "method": method, "cloud": "aws"},
	}
	if body != "" {
		f.Meta["body"] = body
	}
	f.Proof = poc.Build("ssrf", poc.Request{Method: method, URL: u, Body: body, CookiePresent: cookiePresent}, param,
		"The response carried the metadata index (instance-id, ami-id, and similar), so the server fetched 169.254.169.254 on the tester's behalf. Credential paths were not requested.")
	if f.Proof != nil {
		f.Proof.Response = poc.RedactResponse(respBody)
	}
	return f
}

// requestTarget builds the (method, url, body) for a request that sets param to
// value, matching how send issues it. It sends nothing.
func requestTarget(ep dastcrawl.Endpoint, base url.Values, param, value string) (method, u, body string) {
	vals := cloneValues(base)
	vals.Set(param, value)
	if ep.Method == http.MethodPost {
		return http.MethodPost, stripQuery(ep.URL), vals.Encode()
	}
	return http.MethodGet, stripQuery(ep.URL) + "?" + vals.Encode(), ""
}

// paramsOf returns an endpoint's parameter names and base values (query for GET,
// body for POST).
func paramsOf(ep dastcrawl.Endpoint) ([]string, url.Values, error) {
	var vals url.Values
	if ep.Method == http.MethodPost {
		v, err := url.ParseQuery(ep.Body)
		if err != nil {
			return nil, nil, err
		}
		vals = v
	} else {
		u, err := url.Parse(ep.URL)
		if err != nil {
			return nil, nil, err
		}
		vals = u.Query()
	}
	names := make([]string, 0, len(vals))
	for name := range vals {
		names = append(names, name)
	}
	return names, vals, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func stripQuery(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i]
	}
	return raw
}

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}
