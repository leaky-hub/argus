package uploadscan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// uploadApp stores whatever is uploaded and serves it back under /files/, with
// no type restriction (the vulnerability). It reports the stored path in the
// upload response when reportPath is true.
type uploadApp struct {
	mu         sync.Mutex
	files      map[string]string
	reportPath bool
}

func newUploadApp(reportPath bool) *uploadApp {
	return &uploadApp{files: map[string]string{}, reportPath: reportPath}
}

func (a *uploadApp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			io.WriteString(w, "upload form")
			return
		}
		f, hdr, err := r.FormFile("uploaded")
		if err != nil {
			io.WriteString(w, "no file")
			return
		}
		defer f.Close()
		body, _ := io.ReadAll(f)
		a.mu.Lock()
		a.files[hdr.Filename] = string(body)
		a.mu.Unlock()
		if a.reportPath {
			io.WriteString(w, "stored at ../files/"+hdr.Filename)
		} else {
			io.WriteString(w, "upload complete")
		}
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/files/")
		a.mu.Lock()
		content, ok := a.files[name]
		a.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, content) // served as-is, no restriction
	})
	return mux
}

func TestScanDetectsUnrestrictedUpload_PathInResponse(t *testing.T) {
	app := newUploadApp(true)
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		BaseURL: srv.URL + "/",
		Forms:   []dastcrawl.UploadForm{{Action: srv.URL + "/upload", FileField: "uploaded", Fields: map[string]string{"Upload": "Upload"}}},
	}, nil)

	if len(fs) != 1 {
		t.Fatalf("want 1 upload finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].CWEs[0] != "CWE-434" || fs[0].Meta["param"] != "uploaded" {
		t.Errorf("wrong finding: %v / %v", fs[0].CWEs, fs[0].Meta)
	}
	if fs[0].Proof == nil || fs[0].Proof.Response == "" {
		t.Errorf("proof should carry the fetched-back file: %+v", fs[0].Proof)
	}
}

func TestScanDetectsUnrestrictedUpload_CommonDirFallback(t *testing.T) {
	app := newUploadApp(false) // does not reveal the path; must be found by fallback
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		BaseURL: srv.URL + "/",
		Forms:   []dastcrawl.UploadForm{{Action: srv.URL + "/upload", FileField: "uploaded"}},
	}, nil)
	if len(fs) != 1 {
		t.Fatalf("common-dir fallback should still confirm: got %d: %+v", len(fs), fs)
	}
}

func TestScanNoFalsePositiveWhenNotServed(t *testing.T) {
	// Accepts the upload but never serves it back (restriction enforced).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.WriteString(w, "rejected: type not allowed")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fs := Scan(context.Background(), srv.Client(), Options{
		BaseURL: srv.URL + "/",
		Forms:   []dastcrawl.UploadForm{{Action: srv.URL + "/upload", FileField: "uploaded"}},
	}, nil)
	if len(fs) != 0 {
		t.Errorf("an upload that is not served back must not be flagged: %+v", fs)
	}
}
