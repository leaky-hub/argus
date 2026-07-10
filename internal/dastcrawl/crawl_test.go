package dastcrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A small app: an index linking to a GET-form page (like DVWA's sqli), a
// parameterized link (like fi/?page=), a logout link (must NOT be crawled),
// and an off-site link (must be ignored).
func fakeApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/sqli/">SQLi</a>
			<a href="/fi/?page=include.php">File include</a>
			<a href="/logout.php">Logout</a>
			<a href="https://evil.example/">offsite</a>
		</body></html>`)
	})
	mux.HandleFunc("/sqli/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/sqli/" method="GET">
			<input type="text" name="id">
			<input type="submit" name="Submit" value="Submit">
		</form></body></html>`)
	})
	mux.HandleFunc("/fi/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>included</body></html>`)
	})
	mux.HandleFunc("/logout.php", func(w http.ResponseWriter, _ *http.Request) {
		// If the crawler ever hits this, the test asserts it did not.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>logged out</body></html>`)
	})
	return mux
}

func TestCrawlDiscoversParamsAndForms(t *testing.T) {
	srv := httptest.NewServer(fakeApp())
	defer srv.Close()

	urls, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(urls, "\n")

	// The GET form is synthesized into a fuzzable URL with its fields.
	if !strings.Contains(joined, "/sqli/?") || !strings.Contains(joined, "id=1") || !strings.Contains(joined, "Submit=Submit") {
		t.Errorf("sqli form not synthesized into a fuzzable URL:\n%s", joined)
	}
	// The parameterized link is captured.
	if !strings.Contains(joined, "/fi/?page=include.php") {
		t.Errorf("parameterized link not discovered:\n%s", joined)
	}
}

func TestCrawlNeverFollowsLogoutOrOffsite(t *testing.T) {
	var logoutHit bool
	mux := http.NewServeMux()
	base := fakeApp()
	mux.HandleFunc("/logout.php", func(w http.ResponseWriter, _ *http.Request) { logoutHit = true })
	mux.Handle("/", base)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	urls, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if logoutHit {
		t.Error("crawler fetched the logout page (would destroy the session)")
	}
	for _, u := range urls {
		if strings.Contains(u, "evil.example") {
			t.Errorf("off-site URL leaked into results: %s", u)
		}
		if strings.Contains(u, "logout") {
			t.Errorf("logout URL in results: %s", u)
		}
	}
}

func TestCrawlBoundsPages(t *testing.T) {
	// A page that links to a fresh page forever; the page cap must stop it.
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="%s/p%d">next</a>`, "", count)
	}))
	defer srv.Close()

	if _, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{MaxPages: 5}, nil); err != nil {
		t.Fatal(err)
	}
	if count > 6 { // 5 pages plus a little slack for in-flight
		t.Errorf("page cap not honored: fetched %d pages", count)
	}
}

// A password-change form must not be synthesized into a fuzzable URL: fuzzing
// it would change the session's own credentials and lock the scan out.
func TestCrawlSkipsCredentialChangeForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/csrf/">csrf</a></body></html>`)
	})
	mux.HandleFunc("/csrf/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/csrf/" method="GET">
			<input name="password_new"><input name="password_conf">
			<input type="submit" name="Change" value="Change"></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	urls, err := Crawl(context.Background(), srv.Client(), srv.URL+"/", Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range urls {
		if strings.Contains(u, "password_new") {
			t.Errorf("credential-change form was synthesized (self-lockout risk): %s", u)
		}
	}
}

func TestIsAssetAndAuthPath(t *testing.T) {
	for _, p := range []string{"/x.css", "/a/b.js", "/img.PNG"} {
		if !isAsset(p) {
			t.Errorf("%s should be an asset", p)
		}
	}
	for _, p := range []string{"/logout.php", "/user/login", "/setup.php"} {
		if !isAuthPath(p) {
			t.Errorf("%s should be an auth path", p)
		}
	}
	if isAuthPath("/vulnerabilities/sqli/") {
		t.Error("a normal page misclassified as an auth path")
	}
}
