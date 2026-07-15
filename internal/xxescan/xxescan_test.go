package xxescan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/ssrfscan"
)

// xmlApp simulates an XXE-vulnerable endpoint: it parses the posted XML with
// external-entity resolution, fetching whatever the entity's SYSTEM URL names.
// When reflect is true it echoes the fetched content into its response.
func xmlApp(reflect bool) http.HandlerFunc {
	sysRe := regexp.MustCompile(`SYSTEM "([^"]+)"`)
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		m := sysRe.FindStringSubmatch(string(body))
		if m == nil {
			io.WriteString(w, "ok")
			return
		}
		resp, err := http.Get(m[1]) // the vulnerable external-entity fetch
		if err != nil {
			io.WriteString(w, "parse error")
			return
		}
		defer resp.Body.Close()
		fetched, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if reflect {
			w.Write(fetched)
			return
		}
		io.WriteString(w, "processed")
	}
}

func TestScanDetectsBlindXXE(t *testing.T) {
	l, err := ssrfscan.NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srv := httptest.NewServer(xmlApp(false)) // resolves the entity, does not reflect
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:    []dastcrawl.Endpoint{{URL: srv.URL + "/api", Method: "POST", Body: "x=1"}},
		CallbackWait: 200e6,
	}, nil)

	var oob bool
	for _, f := range fs {
		if strings.Contains(f.RuleID, "xxe-oob") {
			oob = true
			if f.CWEs[0] != "CWE-611" {
				t.Errorf("wrong CWE: %v", f.CWEs)
			}
			if f.Proof == nil || !strings.Contains(f.Proof.Observed, "connected back") {
				t.Errorf("proof should describe the callback: %+v", f.Proof)
			}
		}
	}
	if !oob {
		t.Fatalf("expected a blind XXE finding, got %+v", fs)
	}
}

func TestScanDetectsReflectedXXE(t *testing.T) {
	l, err := ssrfscan.NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	srv := httptest.NewServer(xmlApp(true)) // reflects the fetched entity content
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:    []dastcrawl.Endpoint{{URL: srv.URL + "/api", Method: "POST", Body: "x=1"}},
		CallbackWait: 200e6,
	}, nil)
	var reflected bool
	for _, f := range fs {
		if strings.Contains(f.RuleID, "xxe-reflected") {
			reflected = true
			if f.Proof == nil || f.Proof.Response == "" {
				t.Error("reflected XXE proof should carry the response")
			}
		}
	}
	if !reflected {
		t.Fatalf("expected a reflected XXE finding, got %+v", fs)
	}
}

func TestScanReflectedXXENotDuplicated(t *testing.T) {
	l, err := ssrfscan.NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// A reflecting target both echoes the marker in-band AND records an
	// out-of-band callback. It must collapse to a single XXE finding, not one
	// reflected plus one blind for the same URL.
	srv := httptest.NewServer(xmlApp(true))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:    []dastcrawl.Endpoint{{URL: srv.URL + "/api", Method: "POST", Body: "x=1"}},
		CallbackWait: 200e6,
	}, nil)

	xxe := 0
	for _, f := range fs {
		if strings.Contains(f.RuleID, "xxe") {
			xxe++
		}
	}
	if xxe != 1 {
		t.Fatalf("expected exactly one XXE finding for the reflecting URL, got %d: %+v", xxe, fs)
	}
}

func TestScanNoXXEWhenNoEntityResolution(t *testing.T) {
	l, err := ssrfscan.NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// A safe endpoint that echoes the body but never parses XML entities.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		io.WriteString(w, "you sent: "+string(body)) // reflects the payload, resolves nothing
	}))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:    []dastcrawl.Endpoint{{URL: srv.URL + "/api", Method: "POST", Body: "x=1"}},
		CallbackWait: 200e6,
	}, nil)
	for _, f := range fs {
		if strings.Contains(f.RuleID, "xxe") {
			t.Errorf("a non-resolving endpoint must not be flagged for XXE: %+v", f)
		}
	}
}

func TestSerializedKind(t *testing.T) {
	cases := map[string]string{
		"rO0ABXNyABFqYXZhLnV0aWwu":            "Java (base64)",
		`O:8:"stdClass":1:{s:1:"a";i:1;}`:      "PHP",
		"a:2:{i:0;s:1:\"x\";i:1;s:1:\"y\";}":   "PHP",
		"AAEAAAD/////AQAAAAAAAAAM":             ".NET (base64)",
		"just a normal value":                  "",
		"12345":                                "",
		"laptop":                               "",
	}
	for v, want := range cases {
		if got := serializedKind(v); got != want {
			t.Errorf("serializedKind(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestDeserSurfaceFinding(t *testing.T) {
	l, err := ssrfscan.NewListener()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), l, Options{
		Endpoints:    []dastcrawl.Endpoint{{URL: srv.URL + "/app?state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", Method: "GET"}},
		CallbackWait: 200e6,
	}, nil)
	var found bool
	for _, f := range fs {
		if f.RuleID == "deserialization-surface:state" && f.CWEs[0] == "CWE-502" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a deserialization-surface finding for the Java-serialized param, got %+v", fs)
	}
}
