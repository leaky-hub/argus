// Package xxescan detects XML external entity (XXE) processing and flags the
// deserialization attack surface. XXE is confirmed the same way SSRF is: by
// injecting an XML document whose external entity points at a listener Argus
// runs itself on 127.0.0.1, then observing whether the parser connects back.
// The entity NEVER points at a real file (no file:///etc/passwd) or a
// third-party service, so it proves the parser resolves external entities
// without exfiltrating any secret.
//
// The deserialization pass is passive: it flags parameter values that look like
// a serialized object (Java, PHP, .NET, Python), surfacing the attack surface
// for manual review. It never sends a gadget payload, since safe confirmation of
// insecure deserialization requires weaponized gadget chains, which this tool
// does not use.
package xxescan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/ssrfscan"
)

const (
	maxBodyBytes     = 512 << 10
	maxEndpoints     = 40  // active XXE injection budget
	maxScanEndpoints = 200 // total endpoints inspected (incl. the passive deser pass)
	maxParamsPerEP   = 12
	defaultCallback  = 3 * time.Second
)

// Options configure an XXE scan.
type Options struct {
	Endpoints    []dastcrawl.Endpoint
	Headers      []string
	CallbackWait time.Duration // wait for async callbacks (0 = default)
}

// Listener is the local out-of-band listener XXE reuses from the SSRF engine.
type Listener = ssrfscan.Listener

type xxeProbe struct {
	token string
	ep    dastcrawl.Endpoint
	body  string
}

// Scan tests each endpoint for XXE by posting an XML document whose external
// entity points at the local listener, and flags any parameter that looks like
// a serialized object. It sends through the governed client.
func Scan(ctx context.Context, client *http.Client, listener *Listener, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil || listener == nil {
		return nil
	}
	s := &scanner{client: client, headers: opts.Headers}

	var out []model.RawFinding
	seen := map[string]bool{}      // deser findings, keyed by rule+url
	xxeSeen := map[string]bool{}   // one XXE finding per URL (reflected wins over blind)
	var probes []xxeProbe

	tested := 0
	for i, ep := range opts.Endpoints {
		if ctx.Err() != nil || i >= maxScanEndpoints {
			break
		}
		// Passive deserialization surface: any endpoint's parameter value that
		// looks like a serialized object.
		out = append(out, s.deserFindings(ep, seen)...)

		// Active XXE: inject XML into the endpoints that can take a body. A blind
		// url-encoded form endpoint will not parse XML, but the out-of-band
		// confirmation means a non-parsing target simply produces nothing.
		if tested >= maxEndpoints {
			continue
		}
		tested++
		for _, payload := range xxePayloads(listener) {
			token := payload.token
			body, err := s.sendXML(ctx, ep, payload.body)
			// In-band confirmation wins over the blind callback (it carries the
			// response), so record it under the per-URL key.
			if err == nil && strings.Contains(body, ssrfscan.Marker(token)) && !xxeSeen[ep.URL] {
				xxeSeen[ep.URL] = true
				out = append(out, s.reflectedFinding(ep, payload.body, body))
			}
			probes = append(probes, xxeProbe{token: token, ep: ep, body: payload.body})
		}
	}

	// Wait once for asynchronous callbacks, then collect blind out-of-band hits
	// for URLs not already confirmed in-band.
	wait := opts.CallbackWait
	if wait <= 0 {
		wait = defaultCallback
	}
	if len(probes) > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	for _, pr := range probes {
		cb, ok := listener.Hit(pr.token)
		if !ok || xxeSeen[pr.ep.URL] {
			continue
		}
		xxeSeen[pr.ep.URL] = true
		out = append(out, s.oobFinding(pr, cb))
	}

	progress(fmt.Sprintf("xxe: %d XML/deserialization finding(s)\n", len(out)))
	return out
}

type scanner struct {
	client  *http.Client
	headers []string
}

type payload struct {
	token string
	body  string
}

// xxePayloads builds the benign XXE probes: a general external entity and a
// parameter entity, both pointing at the local listener. Each gets a fresh
// token so a callback is attributable.
func xxePayloads(l *Listener) []payload {
	t1 := l.NewToken()
	t2 := l.NewToken()
	return []payload{
		{token: t1, body: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "%s">]><data>&xxe;</data>`, l.URLFor(t1))},
		{token: t2, body: fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY %% xxe SYSTEM "%s"> %%xxe;]><data>probe</data>`, l.URLFor(t2))},
	}
}

// sendXML posts an XML body to the endpoint's URL and returns the response body.
func (s *scanner) sendXML(ctx context.Context, ep dastcrawl.Endpoint, xml string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stripQuery(ep.URL), strings.NewReader(xml))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/xml")
	for _, h := range s.headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), nil
}

func (s *scanner) cookiePresent() bool {
	for _, h := range s.headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}

func dedup(seen map[string]bool, f model.RawFinding) (model.RawFinding, bool) {
	key := f.RuleID + "\x00" + f.URL
	if seen[key] {
		return model.RawFinding{}, false
	}
	seen[key] = true
	return f, true
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

func paramValues(ep dastcrawl.Endpoint) map[string]string {
	out := map[string]string{}
	if strings.EqualFold(ep.Method, http.MethodPost) {
		if v, err := url.ParseQuery(ep.Body); err == nil {
			for k := range v {
				out[k] = v.Get(k)
			}
		}
		return out
	}
	if u, err := url.Parse(ep.URL); err == nil {
		for k, vs := range u.Query() {
			if len(vs) > 0 {
				out[k] = vs[0]
			}
		}
	}
	return out
}
