package fingerprint

import (
	"net/http"
	"regexp"
	"strings"
)

// Technology categories.
const (
	catServer    = "server"
	catLanguage  = "language"
	catFramework = "framework"
	catCMS       = "cms"
	catLibrary   = "library"
)

// Tech is one identified technology in the target's stack.
type Tech struct {
	Name     string // "nginx", "PHP", "WordPress", "jQuery"
	Version  string // "" when only the product, not its version, is exposed
	Category string
	Source   string // where it was observed: a header name, "cookie", "generator", "body"
	// kevTokens, when set, are the curated product identifiers used to correlate
	// this technology against the known-exploited catalog. Empty means do not
	// correlate (the product is not one KEV tracks by a clear name).
	kevTokens []string
}

// cmsKEVTokens is the curated, deliberately narrow map of fingerprintable
// products to the tokens that match their entries in the KEV catalog. Kept to
// CMS families with unambiguous KEV names, where a product-level match is
// meaningful and low-noise; generic web servers and languages are not
// correlated (their KEV overlap is thin and the match would over-fire).
var cmsKEVTokens = map[string][]string{
	"WordPress": {"wordpress"},
	"Drupal":    {"drupal"},
	"Joomla":    {"joomla"},
}

// detectHeaders identifies technologies from response headers that disclose them.
func detectHeaders(h http.Header) []Tech {
	var out []Tech

	if s := strings.TrimSpace(h.Get("Server")); s != "" {
		if name, ver := splitProductVersion(s); name != "" {
			out = append(out, Tech{Name: normalizeServer(name), Version: ver, Category: catServer, Source: "Server header"})
		}
	}
	if s := strings.TrimSpace(h.Get("X-Powered-By")); s != "" {
		name, ver := splitProductVersion(s)
		out = append(out, Tech{Name: normalizePowered(name), Version: ver, Category: poweredCategory(name), Source: "X-Powered-By header"})
	}
	if v := strings.TrimSpace(h.Get("X-AspNet-Version")); v != "" {
		out = append(out, Tech{Name: "ASP.NET", Version: v, Category: catFramework, Source: "X-AspNet-Version header"})
	}
	if v := strings.TrimSpace(h.Get("X-Generator")); v != "" {
		if name, ver := splitProductVersion(v); name != "" {
			out = append(out, withCMSTokens(Tech{Name: name, Version: ver, Category: catCMS, Source: "X-Generator header"}))
		}
	}
	if h.Get("X-Drupal-Cache") != "" || h.Get("X-Drupal-Dynamic-Cache") != "" {
		out = append(out, withCMSTokens(Tech{Name: "Drupal", Category: catCMS, Source: "X-Drupal-Cache header"}))
	}
	return out
}

// detectCookies identifies technologies from Set-Cookie names.
func detectCookies(setCookie []string) []Tech {
	var out []Tech
	seen := map[string]bool{}
	add := func(name, cat string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, withCMSTokens(Tech{Name: name, Category: cat, Source: "cookie"}))
	}
	for _, c := range setCookie {
		name := cookieName(c)
		switch {
		case strings.EqualFold(name, "PHPSESSID"):
			add("PHP", catLanguage)
		case strings.EqualFold(name, "JSESSIONID"):
			add("Java", catLanguage)
		case strings.EqualFold(name, "ASP.NET_SessionId"), strings.HasPrefix(strings.ToUpper(name), "ASPSESSION"):
			add("ASP.NET", catFramework)
		case strings.EqualFold(name, "laravel_session"):
			add("Laravel", catFramework)
		case strings.EqualFold(name, "ci_session"):
			add("CodeIgniter", catFramework)
		case strings.EqualFold(name, "connect.sid"):
			add("Express", catFramework)
		case strings.EqualFold(name, "csrftoken"):
			add("Django", catFramework)
		case strings.HasPrefix(strings.ToLower(name), "wordpress_"), strings.HasPrefix(strings.ToLower(name), "wp-settings"):
			add("WordPress", catCMS)
		}
	}
	return out
}

var (
	reGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reJQuery    = regexp.MustCompile(`(?i)jQuery(?:\s+JavaScript\s+Library)?\s+v?(\d+\.\d+(?:\.\d+)?)`)
	reBootstrap = regexp.MustCompile(`(?i)Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)`)
)

// detectBody identifies technologies from the HTML body: the generator meta tag,
// framework markers, and versioned JS-library banners.
func detectBody(body string) []Tech {
	var out []Tech
	if m := reGenerator.FindStringSubmatch(body); m != nil {
		if name, ver := splitProductVersion(strings.TrimSpace(m[1])); name != "" {
			out = append(out, withCMSTokens(Tech{Name: name, Version: ver, Category: catCMS, Source: "generator meta"}))
		}
	}
	if m := reJQuery.FindStringSubmatch(body); m != nil {
		out = append(out, Tech{Name: "jQuery", Version: m[1], Category: catLibrary, Source: "body"})
	}
	if m := reBootstrap.FindStringSubmatch(body); m != nil {
		out = append(out, Tech{Name: "Bootstrap", Version: m[1], Category: catLibrary, Source: "body"})
	}
	// Marker-only CMS hints (no version), useful when the generator tag is absent.
	if strings.Contains(body, "/wp-content/") || strings.Contains(body, "/wp-includes/") {
		out = append(out, withCMSTokens(Tech{Name: "WordPress", Category: catCMS, Source: "body"}))
	}
	if strings.Contains(body, "Drupal.settings") || strings.Contains(body, "/sites/default/files") {
		out = append(out, withCMSTokens(Tech{Name: "Drupal", Category: catCMS, Source: "body"}))
	}
	return out
}

// dedupeTechs collapses duplicate technologies (same name), preferring the
// observation that carries a version and merging the KEV tokens.
func dedupeTechs(techs []Tech) []Tech {
	byName := map[string]*Tech{}
	var order []string
	for _, t := range techs {
		if t.Name == "" {
			continue
		}
		if existing, ok := byName[t.Name]; ok {
			if existing.Version == "" && t.Version != "" {
				existing.Version = t.Version
				existing.Source = t.Source
			}
			if len(existing.kevTokens) == 0 {
				existing.kevTokens = t.kevTokens
			}
			continue
		}
		cp := t
		byName[t.Name] = &cp
		order = append(order, t.Name)
	}
	out := make([]Tech, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// withCMSTokens attaches KEV-correlation tokens to a tech when it is a CMS the
// curated map covers.
func withCMSTokens(t Tech) Tech {
	if toks, ok := cmsKEVTokens[t.Name]; ok {
		t.kevTokens = toks
	}
	return t
}

// splitProductVersion parses "nginx/1.18.0", "PHP/7.4.3", "WordPress 6.4.2", or
// "Drupal 10 (https://...)" into a product name and a version ("" when absent).
func splitProductVersion(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	// "name/version" form (headers like nginx/1.18.0): the product has no space
	// and the version starts with a digit. This guards against a "/" that is part
	// of a URL in the value (e.g. a generator tag's trailing homepage link).
	if i := strings.Index(s, "/"); i > 0 {
		lhs := strings.TrimSpace(s[:i])
		rhs := strings.TrimSpace(s[i+1:])
		if !strings.ContainsAny(lhs, " \t") && len(rhs) > 0 && rhs[0] >= '0' && rhs[0] <= '9' {
			if j := strings.IndexAny(rhs, " (\t"); j >= 0 {
				rhs = rhs[:j]
			}
			return lhs, cleanVersion(rhs)
		}
	}
	// "name version ..." form (generator meta).
	fields := strings.Fields(s)
	if len(fields) == 1 {
		return fields[0], ""
	}
	// Take a leading product phrase, then the first version-looking token.
	var nameParts []string
	for _, f := range fields {
		if isVersionToken(f) {
			return strings.Join(nameParts, " "), cleanVersion(f)
		}
		nameParts = append(nameParts, f)
	}
	return strings.Join(nameParts, " "), ""
}

var reVersionToken = regexp.MustCompile(`^v?\d+(\.\d+)*$`)

func isVersionToken(s string) bool { return reVersionToken.MatchString(s) }

func cleanVersion(s string) string {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if !reVersionToken.MatchString("v" + s) {
		return ""
	}
	return s
}

// normalizeServer canonicalizes common Server-header product names.
func normalizeServer(name string) string {
	switch strings.ToLower(name) {
	case "microsoft-iis":
		return "Microsoft IIS"
	case "apache":
		return "Apache"
	default:
		return name
	}
}

// normalizePowered canonicalizes X-Powered-By product names.
func normalizePowered(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "asp.net":
		return "ASP.NET"
	case "express":
		return "Express"
	case "php":
		return "PHP"
	default:
		return strings.TrimSpace(name)
	}
}

// poweredCategory classifies an X-Powered-By product.
func poweredCategory(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "php":
		return catLanguage
	default:
		return catFramework
	}
}

// cookieName returns the cookie name from a Set-Cookie value ("NAME=value; ...").
func cookieName(setCookie string) string {
	s := strings.TrimSpace(setCookie)
	if i := strings.Index(s, "="); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return ""
}
