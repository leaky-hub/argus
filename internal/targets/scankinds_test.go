package targets

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAddDASTRegistersAndRejectsDuplicates(t *testing.T) {
	r := ForRepo(t.TempDir())
	tg, err := r.AddDAST("staging", "https://staging.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Kind() != TypeDAST || tg.URL != "https://staging.example.com" || tg.Path != "" {
		t.Fatalf("dast target shape wrong: %+v", tg)
	}
	// Same URL: rejected. Different URL: accepted.
	if _, err := r.AddDAST("staging2", "https://staging.example.com"); err == nil {
		t.Error("duplicate url accepted")
	}
	if _, err := r.AddDAST("prod", "https://prod.example.com"); err != nil {
		t.Errorf("distinct url rejected: %v", err)
	}
	// Bad URLs are refused at registration (dastscan.ValidateURL owns this).
	for _, bad := range []string{"", "ftp://x", "file:///etc/passwd", "https://user:pw@h", "notaurl"} {
		if _, err := r.AddDAST("x", bad); err == nil {
			t.Errorf("bad dast url %q accepted", bad)
		}
	}
	// Its run history resolves to the per-target dast store.
	dir, ok := r.NonFSRunStore(tg)
	if !ok || !strings.Contains(dir, filepath.Join("dast", tg.ID, "runs")) {
		t.Errorf("dast run store = %q, ok=%v", dir, ok)
	}
}

func TestAddImageRegistersAndRejectsDuplicates(t *testing.T) {
	r := ForRepo(t.TempDir())
	tg, err := r.AddImage("web", "nginx:1.27-alpine")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Kind() != TypeImage || tg.Ref != "nginx:1.27-alpine" || tg.Path != "" || tg.URL != "" {
		t.Fatalf("image target shape wrong: %+v", tg)
	}
	if _, err := r.AddImage("web2", "nginx:1.27-alpine"); err == nil {
		t.Error("duplicate image ref accepted")
	}
	if _, err := r.AddImage("db", "postgres:16"); err != nil {
		t.Errorf("distinct image ref rejected: %v", err)
	}
	for _, bad := range []string{"", "-oEvil", "nginx alpine", "img;rm -rf"} {
		if _, err := r.AddImage("x", bad); err == nil {
			t.Errorf("bad image ref %q accepted", bad)
		}
	}
	dir, ok := r.NonFSRunStore(tg)
	if !ok || !strings.Contains(dir, filepath.Join("image", tg.ID, "runs")) {
		t.Errorf("image run store = %q, ok=%v", dir, ok)
	}
}

func TestNonFSRunStoreFilesystemKinds(t *testing.T) {
	r := ForRepo(t.TempDir())
	dir, _ := r.Add("code", t.TempDir(), nil, "")
	if _, ok := r.NonFSRunStore(dir); ok {
		t.Error("a dir target must not resolve to a non-filesystem run store")
	}
}
