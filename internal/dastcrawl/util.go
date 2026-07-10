package dastcrawl

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// assetExts are static-asset suffixes not worth crawling or fuzzing.
var assetExts = []string{
	".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
	".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".mp4", ".webp", ".map",
}

// authPathHints mark logout/login/setup pages: crawling them can destroy the
// authenticated session the scan depends on, so they are never followed.
var authPathHints = []string{"logout", "signout", "sign-out", "login", "signin", "sign-in", "setup"}

// credFieldHints mark form fields that change the current account's
// credentials. A form carrying one is skipped for synthesis: fuzzing a
// password-change form would lock the scan out of its own session (this
// really happened against DVWA's CSRF page). This is a self-preservation
// guard, not a completeness claim about destructive forms.
var credFieldHints = []string{"password_new", "password_conf", "new_password", "confirm_password", "newpass", "passwd_new"}

// changesCredentials reports whether any form field name looks like it changes
// the logged-in user's password.
func changesCredentials(values map[string][]string) bool {
	for name := range values {
		lower := strings.ToLower(name)
		for _, hint := range credFieldHints {
			if strings.Contains(lower, hint) {
				return true
			}
		}
	}
	return false
}

func isAsset(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range assetExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func isAuthPath(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range authPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// splitHeader parses a "Name: value" header line.
func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func fmtProgress(pages, found int) string {
	return fmt.Sprintf("==> crawl: %d page(s) walked, %d fuzzable endpoint(s) discovered\n", pages, found)
}
