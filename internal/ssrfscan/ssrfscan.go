package ssrfscan

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
)

const (
	maxBodyBytes   = 512 << 10
	maxParamsPerEP = 12
	// callbackWait is how long to wait, after sending all probes, for the target
	// to make an out-of-band callback (some SSRF fetches happen asynchronously).
	callbackWait = 3 * time.Second
	// cloudMetadataURL is the AWS instance metadata service, the canonical SSRF
	// escalation target. Reachability is confirmed by a signature in the
	// response; credentials are never requested.
	cloudMetadataURL = "http://169.254.169.254/latest/meta-data/"
)

// Options configure an SSRF scan.
type Options struct {
	Endpoints     []dastcrawl.Endpoint
	Headers       []string      // e.g. "Cookie: ..." for auth
	CloudMetadata bool          // also probe cloud-metadata reachability (in-band)
	CallbackWait  time.Duration // how long to wait for async callbacks (0 = default)
}

// probe records one injected callback so its token can be checked for a blind
// out-of-band hit after all probes are sent.
type probe struct {
	token   string
	ep      dastcrawl.Endpoint
	base    url.Values
	param   string
	payload string
}

// Scan injects the listener's callback URLs into each endpoint's parameters and
// reports the parameters that drive a server-side request: a blind out-of-band
// hit on the listener, an in-band reflection of the listener's marker, or (opt
// in) a reachable cloud-metadata service. It sends through the governed client,
// so every request is scope-gated, budgeted, and audited.
func Scan(ctx context.Context, client *http.Client, listener *Listener, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil || listener == nil {
		return nil
	}
	s := &scanner{client: client, headers: opts.Headers}

	var out []model.RawFinding
	var probes []probe
	seen := map[string]bool{}

	for _, ep := range opts.Endpoints {
		if ctx.Err() != nil {
			break
		}
		names, base, err := paramsOf(ep)
		if err != nil {
			continue
		}
		tested := 0
		for _, p := range names {
			if tested >= maxParamsPerEP {
				break
			}
			tested++

			// Out-of-band callback probe (blind + in-band via the served marker).
			token := listener.NewToken()
			payload := listener.URLFor(token)
			body, err := s.send(ctx, ep, base, p, payload)
			if err == nil && strings.Contains(body, Marker(token)) {
				if f, ok := dedup(seen, reflectedFinding(ep, base, p, payload, body, s.cookiePresent())); ok {
					out = append(out, f)
				}
			}
			probes = append(probes, probe{token: token, ep: ep, base: base, param: p, payload: payload})

			// Cloud-metadata reachability (in-band only): inject the metadata URL
			// and look for a metadata signature in the response.
			if opts.CloudMetadata {
				body, err := s.send(ctx, ep, base, p, cloudMetadataURL)
				if err == nil && looksLikeCloudMetadata(body) {
					if f, ok := dedup(seen, metadataFinding(ep, base, p, cloudMetadataURL, body, s.cookiePresent())); ok {
						out = append(out, f)
					}
				}
			}
		}
	}

	// Wait once for asynchronous callbacks, then collect blind out-of-band hits.
	wait := opts.CallbackWait
	if wait <= 0 {
		wait = callbackWait
	}
	if len(probes) > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	for _, pr := range probes {
		cb, ok := listener.Hit(pr.token)
		if !ok {
			continue
		}
		if f, ok := dedup(seen, oobFinding(pr, cb, s.cookiePresent())); ok {
			out = append(out, f)
		}
	}

	progress(fmt.Sprintf("ssrf: %d server-side-request-forgery finding(s)\n", len(out)))
	return out
}

type scanner struct {
	client  *http.Client
	headers []string
}

func (s *scanner) cookiePresent() bool {
	for _, h := range s.headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}

// send issues the request with param set to value, returning the response body.
func (s *scanner) send(ctx context.Context, ep dastcrawl.Endpoint, base url.Values, param, value string) (string, error) {
	method, u, reqBody := requestTarget(ep, base, param, value)
	var req *http.Request
	var err error
	if method == http.MethodPost {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	}
	if err != nil {
		return "", err
	}
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

// looksLikeCloudMetadata reports whether a response looks like the AWS metadata
// service's index, using a conservative multi-signal signature so ordinary
// content cannot masquerade as it. It never inspects credential paths.
func looksLikeCloudMetadata(body string) bool {
	hits := 0
	for _, sig := range []string{"ami-id", "instance-id", "instance-type", "hostname", "iam/", "local-ipv4"} {
		if strings.Contains(body, sig) {
			hits++
		}
	}
	return hits >= 2
}

func dedup(seen map[string]bool, f model.RawFinding) (model.RawFinding, bool) {
	key := f.RuleID + "\x00" + f.URL
	if seen[key] {
		return model.RawFinding{}, false
	}
	seen[key] = true
	return f, true
}
