package jsrecon

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// reSourceMap matches the sourceMappingURL annotation a bundler appends, in
// either the // or /* */ comment form.
var reSourceMap = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s*]+)`)

// sourceMappingURL returns the absolute URL of a bundle's sourcemap, or "" when
// there is none or it is an inline data: URI (already inline, nothing to fetch).
func sourceMappingURL(src, bundleURL string) string {
	m := reSourceMap.FindStringSubmatch(src)
	if m == nil {
		return ""
	}
	ref := strings.TrimSpace(m[1])
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	base, err := url.Parse(bundleURL)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(r)
	// Keep sourcemaps on the same host as their bundle; the governed transport
	// refuses anything off-scope anyway, this just avoids a wasted request.
	if abs.Hostname() != base.Hostname() {
		return ""
	}
	return abs.String()
}

// sourceMap is the subset of the Source Map v3 format we read: the original
// source contents, which carry the pre-minification endpoints and strings.
type sourceMap struct {
	SourcesContent []string `json:"sourcesContent"`
}

// sourcesContent parses a sourcemap document and returns its embedded original
// sources. A malformed map yields nothing, never an error: recon degrades to the
// minified bundle it already analyzed.
func sourcesContent(data []byte) []string {
	var sm sourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil
	}
	out := make([]string, 0, len(sm.SourcesContent))
	for _, s := range sm.SourcesContent {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
