package cmdiscan

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
)

// TestIntegrationCmdiDVWA confirms the detector finds DVWA's command injection
// (the exec/ POST form). Skipped in -short or when no authenticated DVWA is
// reachable. Set DVWA_COOKIE to a session cookie (security=low).
func TestIntegrationCmdiDVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cmdi integration test in -short mode")
	}
	cookie := os.Getenv("DVWA_COOKIE")
	base := os.Getenv("DVWA_URL")
	if base == "" {
		base = "http://localhost/"
	}
	execURL := strings.TrimRight(base, "/") + "/vulnerabilities/exec/"
	if cookie == "" || !reachable(execURL, cookie) {
		t.Skip("no authenticated DVWA reachable (set DVWA_COOKIE)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fs, err := Scan(ctx, &http.Client{Timeout: 30 * time.Second}, Options{
		Endpoints: []dastcrawl.Endpoint{{URL: execURL, Method: "POST", Body: "ip=127.0.0.1&Submit=Submit"}},
		Headers:   []string{"Cookie: " + cookie},
	}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("no command injection found on DVWA exec (expected one)")
	}
	if fs[0].CWEs[0] != "CWE-78" || fs[0].Meta["param"] != "ip" {
		t.Errorf("unexpected finding: %v / %v", fs[0].CWEs, fs[0].Meta)
	}
}

func reachable(u, cookie string) bool {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Cookie", cookie)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
