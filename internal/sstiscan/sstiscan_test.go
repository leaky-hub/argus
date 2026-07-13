package sstiscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// jinjaApp simulates a Jinja2-style template sink: it evaluates a {{A*B}}
// expression in the "name" parameter and renders the product.
func jinjaApp() http.HandlerFunc {
	re := regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		v := r.Form.Get("name")
		rendered := re.ReplaceAllStringFunc(v, func(m string) string {
			g := re.FindStringSubmatch(m)
			a, _ := strconv.Atoi(g[1])
			b, _ := strconv.Atoi(g[2])
			return fmt.Sprintf("%d", a*b)
		})
		io.WriteString(w, "<h1>Hello "+rendered+"</h1>")
	}
}

func TestScanDetectsSSTI(t *testing.T) {
	srv := httptest.NewServer(jinjaApp())
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?name=x", Method: "GET"}},
	}, nil)

	if len(fs) != 1 {
		t.Fatalf("want 1 SSTI finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.CWEs[0] != "CWE-1336" || f.Meta["param"] != "name" {
		t.Errorf("wrong finding: %v / %v", f.CWEs, f.Meta)
	}
	if f.Proof == nil || f.Proof.Response == "" || !strings.Contains(f.Proof.Observed, "template") {
		t.Errorf("proof should carry the response and describe template evaluation: %+v", f.Proof)
	}
}

// A reflecting app that echoes the payload verbatim (never evaluates it) must
// not be flagged: the product only appears when the template is rendered.
func TestScanNoFalsePositiveOnReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		io.WriteString(w, "you said: "+r.Form.Get("name")) // echoes {{A*B}} literally
	}))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		Endpoints: []dastcrawl.Endpoint{{URL: srv.URL + "/?name=x", Method: "GET"}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("a reflecting-but-not-evaluating app must not be flagged: %+v", fs)
	}
}
