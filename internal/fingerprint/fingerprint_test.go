package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/exploit"
)

func techByName(techs []Tech, name string) (Tech, bool) {
	for _, t := range techs {
		if t.Name == name {
			return t, true
		}
	}
	return Tech{}, false
}

func TestDetectHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	h.Add("X-Powered-By", "PHP/7.4.3")
	h.Set("X-AspNet-Version", "4.0.30319")
	h.Set("X-Generator", "Drupal 10 (https://www.drupal.org)")

	techs := dedupeTechs(detectHeaders(h))
	cases := map[string]struct{ ver, cat string }{
		"nginx":   {"1.18.0", catServer},
		"PHP":     {"7.4.3", catLanguage},
		"ASP.NET": {"4.0.30319", catFramework},
		"Drupal":  {"10", catCMS},
	}
	for name, want := range cases {
		got, ok := techByName(techs, name)
		if !ok {
			t.Errorf("expected to detect %s; got %v", name, techs)
			continue
		}
		if got.Version != want.ver || got.Category != want.cat {
			t.Errorf("%s: got version=%q cat=%q, want version=%q cat=%q", name, got.Version, got.Category, want.ver, want.cat)
		}
	}
	// Drupal must carry KEV tokens for correlation.
	if d, _ := techByName(techs, "Drupal"); len(d.kevTokens) == 0 {
		t.Error("Drupal must carry KEV correlation tokens")
	}
}

func TestDetectCookies(t *testing.T) {
	techs := detectCookies([]string{
		"PHPSESSID=abc; path=/; HttpOnly",
		"laravel_session=xyz; path=/",
		"wordpress_logged_in_9=foo; path=/",
	})
	for _, want := range []string{"PHP", "Laravel", "WordPress"} {
		if _, ok := techByName(techs, want); !ok {
			t.Errorf("expected %s from cookies; got %v", want, techs)
		}
	}
}

func TestDetectBody(t *testing.T) {
	body := `<html><head>
		<meta name="generator" content="WordPress 6.4.2">
		<script>/*! jQuery v3.5.1 */</script>
		</head><body><img src="/wp-content/uploads/x.png"></body></html>`
	techs := dedupeTechs(detectBody(body))
	if wp, ok := techByName(techs, "WordPress"); !ok || wp.Version != "6.4.2" {
		t.Errorf("expected WordPress 6.4.2; got %+v", techs)
	}
	if jq, ok := techByName(techs, "jQuery"); !ok || jq.Version != "3.5.1" {
		t.Errorf("expected jQuery 3.5.1; got %+v", techs)
	}
}

func TestSplitProductVersion(t *testing.T) {
	cases := []struct{ in, name, ver string }{
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"Apache/2.4.41 (Ubuntu)", "Apache", "2.4.41"},
		{"PHP/7.4.3", "PHP", "7.4.3"},
		{"WordPress 6.4.2", "WordPress", "6.4.2"},
		{"Drupal 10 (https://www.drupal.org)", "Drupal", "10"},
		{"Joomla! - Open Source Content Management", "Joomla! - Open Source Content Management", ""},
		{"Express", "Express", ""},
	}
	for _, c := range cases {
		name, ver := splitProductVersion(c.in)
		if name != c.name || ver != c.ver {
			t.Errorf("splitProductVersion(%q) = (%q,%q), want (%q,%q)", c.in, name, ver, c.name, c.ver)
		}
	}
}

func TestAnalyzeEndToEndWithKEV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>hi</body></html>`))
	}))
	defer srv.Close()

	cat, err := exploit.Load("") // real embedded KEV, now product-enriched
	if err != nil {
		t.Fatal(err)
	}

	res, err := Analyze(context.Background(), srv.Client(), srv.URL, cat, Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Version disclosure for the versioned technologies.
	var sawNginxDisclosure, sawWPCorrelation bool
	for _, f := range res.Findings {
		if f.RuleID == "fingerprint-version-disclosure:nginx" {
			sawNginxDisclosure = true
			if f.RawSeverity != "info" {
				t.Errorf("version disclosure severity = %q, want info", f.RawSeverity)
			}
		}
		if f.RuleID == "fingerprint-kev-family:wordpress" {
			sawWPCorrelation = true
			if f.RawSeverity != "medium" {
				t.Errorf("KEV correlation severity = %q, want medium", f.RawSeverity)
			}
			// A product-level correlation must NOT carry a CVE (which would
			// inflate its own risk through the exploit-evidence path).
			blob, _ := json.Marshal(f)
			if strings.Contains(string(blob), `"CVE"`) && f.CVE != "" {
				t.Error("correlation finding must not set a CVE field")
			}
			if !strings.Contains(f.Description, "confirm") {
				t.Error("correlation must be hedged (verify your version)")
			}
		}
	}
	if !sawNginxDisclosure {
		t.Error("expected an nginx version-disclosure finding")
	}
	if !sawWPCorrelation {
		t.Error("expected a WordPress KEV-correlation finding (WordPress is in the pinned KEV)")
	}
}

func TestNoDisclosureWithoutVersion(t *testing.T) {
	// A cookie-only detection has no version, so it must not emit a disclosure.
	if f, ok := disclosureFinding(Tech{Name: "PHP", Category: catLanguage}, "http://x/"); ok {
		t.Errorf("a version-less tech must not produce a disclosure finding, got %+v", f)
	}
}
