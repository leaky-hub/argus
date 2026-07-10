package dastauth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegrationDVWA authenticates against a real DVWA instance via the
// default-credential path (admin/password is in the built-in list) and asserts
// a usable session comes back. Skipped in -short, or when no DVWA is reachable.
// Point it at your instance with DVWA_URL (default http://127.0.0.1/).
func TestIntegrationDVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DVWA integration test in -short mode")
	}
	base := os.Getenv("DVWA_URL")
	if base == "" {
		base = "http://127.0.0.1/"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	// Reachability probe: a DVWA landing page carries a login form.
	body, _, err := get(context.Background(), withJar(client, mustJar(t)), base)
	if err != nil || !hasPasswordInput(body) {
		t.Skipf("no DVWA login form reachable at %s (err=%v)", base, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := Authenticate(ctx, client, base, Config{TryDefaults: true}, nil)
	if err != nil {
		t.Fatalf("Authenticate against DVWA: %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("expected to authenticate as admin, got %q", sess.User)
	}
	cookie := sess.CookieHeader()
	if !strings.Contains(cookie, "PHPSESSID=") {
		t.Errorf("session cookie header missing PHPSESSID: %q", cookie)
	}
}

func mustJar(t *testing.T) http.CookieJar {
	t.Helper()
	j, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
