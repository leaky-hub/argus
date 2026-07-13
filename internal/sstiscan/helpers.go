package sstiscan

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

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

func hasCookie(headers []string) bool {
	for _, h := range headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}
