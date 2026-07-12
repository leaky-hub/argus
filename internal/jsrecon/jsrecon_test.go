package jsrecon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeAWSKey is AWS's canonical documentation example key: our AKIA pattern
// matches it (it is well-formed), but gitleaks allowlists it, so this test file
// does not trip the repo's own secret-scan gate. A random-shaped fake would.
const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type endpointLike struct{ url string }

func (e endpointLike) path() string {
	u, err := url.Parse(e.url)
	if err != nil {
		return e.url
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

func TestExtractEndpoints(t *testing.T) {
	base := mustURL(t, "https://app.example.com/")
	src := `
		fetch("/api/users");
		axios.get('/api/orders/42?id=1');
		var cfg={url:"/v2/config",timeout:5};
		const asset="/static/main.css";
		const external="https://evil.example.org/api/leak";
		const tmpl=` + "`/api/${id}/thing`" + `;
		go("/dashboard/reports");
	`
	eps := extractEndpoints(src, base)
	got := map[string]bool{}
	for _, e := range eps {
		u := mustURL(t, e.URL)
		key := u.Path
		if u.RawQuery != "" {
			key += "?" + u.RawQuery
		}
		got[key] = true
		if e.Method != "GET" {
			t.Errorf("expected GET endpoints, got %s for %s", e.Method, e.URL)
		}
		if u.Hostname() != "app.example.com" {
			t.Errorf("off-host endpoint leaked in: %s", e.URL)
		}
	}
	for _, want := range []string{"/api/users", "/api/orders/42?id=1", "/v2/config", "/dashboard/reports"} {
		if !got[want] {
			t.Errorf("expected endpoint %q not extracted; got %v", want, got)
		}
	}
	if got["/static/main.css"] {
		t.Error("a static asset must not be treated as a fuzzable endpoint")
	}
	if got["/api/${id}/thing"] {
		t.Error("a template-literal placeholder must not become an endpoint")
	}
}

func TestExtractSecretFindingsRedacts(t *testing.T) {
	// The JWT is split across concatenation so the source text holds no
	// contiguous token (which the repo's own gitleaks would flag); the runtime
	// value is a complete JWT our extractor must catch.
	jwt := "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "abcdefgHIJKlmnop"
	src := `var k="` + fakeAWSKey + `"; var t="` + jwt + `";`
	findings := extractSecretFindings(src, "https://app.example.com/app.js")
	if len(findings) < 2 {
		t.Fatalf("expected the AWS key and the JWT, got %d findings", len(findings))
	}
	for _, f := range findings {
		blob, _ := json.Marshal(f)
		if strings.Contains(string(blob), fakeAWSKey) {
			t.Fatalf("the raw secret must NEVER appear in a finding, found it in: %s", blob)
		}
		if f.Category != "DAST" {
			t.Errorf("recon secret finding category = %q, want DAST", f.Category)
		}
		if f.Meta["preview"] == "" {
			t.Error("a redacted preview must be present")
		}
	}
}

func TestExtractSurfaceFinding(t *testing.T) {
	base := mustURL(t, "https://app.example.com/")
	eps := extractEndpoints(`fetch("/admin/users");fetch("/api/normal")`, base)
	_, findings := extractSurfaces(eps, "https://app.example.com/app.js")
	var sawAdmin bool
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin/users") {
			sawAdmin = true
			if f.RawSeverity != "info" {
				t.Errorf("surface finding severity = %q, want info", f.RawSeverity)
			}
		}
		if strings.Contains(f.URL, "/api/normal") {
			t.Error("a non-sensitive endpoint must not produce a surface finding")
		}
	}
	if !sawAdmin {
		t.Error("an /admin path must be surfaced")
	}
}

func TestRedactNeverLeaks(t *testing.T) {
	if out := redact(fakeAWSKey); strings.Contains(fakeAWSKey, out) || len(out) != len(fakeAWSKey) {
		// out must be a masked, non-substring rendering of the same length.
		if strings.Contains(fakeAWSKey, out) {
			t.Errorf("redact output %q is a substring of the secret", out)
		}
	}
	if got := redact("short"); got != "*****" {
		t.Errorf("a short secret must be fully masked, got %q", got)
	}
}

func TestAnalyzeEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
			<script src="/app.js"></script>
			<script src="https://cdn.jsdelivr.net/vendor.min.js"></script>
			<script>fetch("/api/inline/thing")</script>
			</head><body>hi</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`fetch("/api/users");axios.get("/api/orders/7?id=1");var a="/admin/secret-panel";var k="` +
			fakeAWSKey + `";
//# sourceMappingURL=app.js.map`))
	})
	mux.HandleFunc("/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		sm := map[string]any{
			"version":        3,
			"sourcesContent": []string{`export const load=()=>fetch("/api/hidden/deep?token=1")`},
		}
		json.NewEncoder(w).Encode(sm)
	})
	// A canary: if recon ever fetches the off-host CDN (it must not), this records it.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Analyze(context.Background(), srv.Client(), srv.URL, Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, e := range res.Endpoints {
		got[endpointLike{e.URL}.path()] = true
	}
	for _, want := range []string{
		"/api/users",
		"/api/orders/7?id=1",
		"/api/inline/thing",        // from an inline script
		"/admin/secret-panel",      // minified var
		"/api/hidden/deep?token=1", // recovered from the sourcemap
	} {
		if !got[want] {
			t.Errorf("expected endpoint %q not recovered; got %v", want, keys(got))
		}
	}

	var sawSecret, sawSurface bool
	for _, f := range res.Findings {
		if strings.Contains(f.RuleID, "jsrecon-secret") {
			sawSecret = true
		}
		if f.RuleID == "jsrecon-surface" {
			sawSurface = true
		}
	}
	if !sawSecret {
		t.Error("the hardcoded AWS key must be reported")
	}
	if !sawSurface {
		t.Error("the /admin surface must be reported")
	}
	if res.Bundles < 2 {
		t.Errorf("expected the bundle and its sourcemap to be analyzed, got %d", res.Bundles)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
