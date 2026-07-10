package dastauth

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// userNameHints identify the username field by name/id substring when the form
// has more than one text input. A CSRF/anti-forgery token needs no special
// handling: every named input (hidden token included) is re-read per attempt
// and echoed back on submit, so it round-trips with its current value.
var userNameHints = []string{"user", "email", "login", "name", "account", "identifier"}

// parseLoginForm finds the form containing a password input and extracts where
// to submit it, the username/password field names, and every named input's
// value (hidden fields and submit buttons included, so they round-trip). pageURL
// is the (post-redirect) URL of the page, used to resolve a relative action.
func parseLoginForm(pageURL string, body []byte) (*loginForm, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("bad page URL: %w", err)
	}

	var found *loginForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if found != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			if f := extractForm(base, n); f != nil {
				found = f
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	if found == nil {
		return nil, fmt.Errorf("no login form (no password field) found")
	}
	return found, nil
}

// extractForm builds a loginForm from a <form> node, or nil if it has no
// password field (so it is not a login form).
func extractForm(base *url.URL, form *html.Node) *loginForm {
	f := &loginForm{
		method: strings.ToUpper(attr(form, "method")),
		fields: map[string]string{},
	}
	if f.method == "" {
		f.method = "GET" // the HTML default; real login forms declare POST
	}
	action := strings.TrimSpace(attr(form, "action"))
	if action == "" {
		f.action = base.String()
	} else if u, err := url.Parse(action); err == nil {
		f.action = base.ResolveReference(u).String()
	} else {
		f.action = base.String()
	}

	var textFields []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name := strings.TrimSpace(attr(n, "name"))
			typ := strings.ToLower(strings.TrimSpace(attr(n, "type")))
			val := attr(n, "value")
			if name != "" {
				// Record every named input so hidden values and submit buttons
				// (e.g. DVWA's Login=Login) are echoed back on submit.
				f.fields[name] = val
			}
			switch typ {
			case "password":
				if f.passField == "" {
					f.passField = name
				}
			case "text", "email", "tel", "":
				if name != "" {
					textFields = append(textFields, name)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)

	if f.passField == "" {
		return nil // not a login form
	}
	f.userField = pickUserField(textFields)
	return f
}

// pickUserField chooses the username field from the form's text-like inputs:
// the first whose name hints at a username, else the first text field.
func pickUserField(textFields []string) string {
	for _, name := range textFields {
		lower := strings.ToLower(name)
		for _, hint := range userNameHints {
			if strings.Contains(lower, hint) {
				return name
			}
		}
	}
	if len(textFields) > 0 {
		return textFields[0]
	}
	return ""
}

// attr returns the value of a node's attribute, or "".
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// hasPasswordInput reports whether the HTML contains any password input, used
// to decide (heuristically) whether a page is still showing a login form.
func hasPasswordInput(body []byte) bool {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		// If it will not parse, fall back to a substring check.
		return strings.Contains(strings.ToLower(string(body)), `type="password"`) ||
			strings.Contains(strings.ToLower(string(body)), `type='password'`)
	}
	found := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if found {
			return
		}
		if n.Type == html.ElementNode && n.Data == "input" &&
			strings.EqualFold(attr(n, "type"), "password") {
			found = true
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return found
}
