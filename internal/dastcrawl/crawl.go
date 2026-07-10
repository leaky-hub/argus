// Package dastcrawl walks a running web target to discover the endpoints an
// active DAST scan should fuzz: URLs that carry query parameters, and GET-form
// submissions synthesized into parameterized URLs. It is a bounded, same-host
// crawler (breadth-first, capped depth and page count) that runs authenticated
// via caller-supplied headers, so it reaches the app behind a login.
//
// It deliberately never crawls logout/login/setup pages, so following a link
// cannot destroy the session the scan depends on. It reads HTML only and
// never submits a form or mutates state: it synthesizes candidate URLs for the
// fuzzer, which is the component that actually sends injection payloads (behind
// the scan's own authorization).
package dastcrawl

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

const (
	defaultMaxDepth = 3
	defaultMaxPages = 150
	maxResults      = 600
	maxBodyBytes    = 4 << 20
	seedValue       = "1" // benign placeholder; the fuzzer mutates it
)

// Options tune the crawl.
type Options struct {
	MaxDepth int      // link-follow depth from the base (default 3)
	MaxPages int      // hard cap on pages fetched (default 150)
	Headers  []string // request headers, e.g. "Cookie: SESS=..." for auth
}

// Crawl discovers fuzzable endpoints under baseURL. The returned list is the
// deduplicated, sorted set of URLs that carry query parameters (existing links
// plus synthesized GET-form submissions): exactly the surface nuclei -dast can
// fuzz. progress may be nil.
func Crawl(ctx context.Context, client *http.Client, baseURL string, opts Options, progress func(string)) ([]string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = defaultMaxPages
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}

	c := &crawler{
		client:  client,
		host:    base.Hostname(),
		opts:    opts,
		visited: map[string]bool{},
		results: map[string]bool{},
	}
	c.enqueue(base.String(), 0)

	for len(c.queue) > 0 && c.pages < opts.MaxPages {
		if ctx.Err() != nil {
			break
		}
		item := c.queue[0]
		c.queue = c.queue[1:]
		c.visit(ctx, item)
	}
	progress(fmtProgress(c.pages, len(c.results)))
	return c.sortedResults(), nil
}

type queued struct {
	url   string
	depth int
}

type crawler struct {
	client  *http.Client
	host    string
	opts    Options
	visited map[string]bool
	results map[string]bool
	queue   []queued
	pages   int
}

func (c *crawler) enqueue(raw string, depth int) {
	if depth > c.opts.MaxDepth || c.visited[raw] {
		return
	}
	c.visited[raw] = true
	c.queue = append(c.queue, queued{raw, depth})
}

func (c *crawler) addResult(raw string) {
	if len(c.results) < maxResults {
		c.results[raw] = true
	}
}

func (c *crawler) visit(ctx context.Context, item queued) {
	body, finalURL := c.fetch(ctx, item.url)
	if body == nil {
		return
	}
	c.pages++

	// The fetched URL itself is fuzzable if it carries parameters.
	if u, err := url.Parse(finalURL); err == nil && u.RawQuery != "" {
		c.addResult(finalURL)
	}
	base, err := url.Parse(finalURL)
	if err != nil {
		return
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}
	c.walk(doc, base, item.depth)
}

// walk extracts links (to follow) and forms (to synthesize fuzzable URLs).
func (c *crawler) walk(n *html.Node, base *url.URL, depth int) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "a":
			if href := attr(n, "href"); href != "" {
				c.consumeLink(base, href, depth)
			}
		case "form":
			c.consumeForm(base, n)
		}
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		c.walk(ch, base, depth)
	}
}

// consumeLink resolves a link, records it as a result if it has parameters, and
// enqueues in-scope HTML pages for further crawling.
func (c *crawler) consumeLink(base *url.URL, href string, depth int) {
	ref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return
	}
	abs := base.ResolveReference(ref)
	abs.Fragment = ""
	if abs.Hostname() != c.host || (abs.Scheme != "http" && abs.Scheme != "https") {
		return
	}
	if isAsset(abs.Path) || isAuthPath(abs.Path) {
		return
	}
	if abs.RawQuery != "" {
		c.addResult(abs.String())
	}
	c.enqueue(abs.String(), depth+1)
}

// consumeForm synthesizes a fuzzable URL from a GET form: the action plus every
// field seeded with a placeholder the fuzzer will mutate. POST forms are noted
// by their action page (already enqueued) but not synthesized here: URL-param
// fuzzing does not cover POST bodies (a later phase).
func (c *crawler) consumeForm(base *url.URL, form *html.Node) {
	method := strings.ToUpper(strings.TrimSpace(attr(form, "method")))
	if method != "" && method != "GET" {
		return
	}
	action := strings.TrimSpace(attr(form, "action"))
	actionURL := base
	if action != "" {
		if ref, err := url.Parse(action); err == nil {
			actionURL = base.ResolveReference(ref)
		}
	}
	if actionURL.Hostname() != c.host || isAuthPath(actionURL.Path) {
		return
	}

	values := url.Values{}
	collectFields(form, values)
	if len(values) == 0 {
		return
	}
	// Never synthesize a credential-changing form: fuzzing it would change the
	// scan's own password and lock the session out.
	if changesCredentials(values) {
		return
	}
	u := *actionURL
	u.RawQuery = values.Encode()
	c.addResult(u.String())
}

// collectFields fills values from a form's inputs: hidden fields keep their
// value (so tokens and submit buttons round-trip), everything else gets the
// seed placeholder.
func collectFields(form *html.Node, values url.Values) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
			name := strings.TrimSpace(attr(n, "name"))
			if name != "" {
				typ := strings.ToLower(attr(n, "type"))
				switch typ {
				case "submit", "hidden", "button", "image":
					values.Set(name, attr(n, "value"))
				default:
					values.Set(name, seedValue)
				}
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(form)
}

func (c *crawler) fetch(ctx context.Context, raw string) ([]byte, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, ""
	}
	for _, h := range c.opts.Headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "html") {
		return nil, "" // only HTML carries links and forms
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, ""
	}
	final := raw
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return body, final
}

func (c *crawler) sortedResults() []string {
	out := make([]string, 0, len(c.results))
	for r := range c.results {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
