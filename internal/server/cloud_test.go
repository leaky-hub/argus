package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAWSConfig points cloudscan's profile discovery at a temp config with a
// known closed list, so the cloud-target tests need no real ~/.aws.
func writeAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(cfg, []byte("[default]\nregion=us-east-1\n\n[profile security-audit]\nregion=us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A credentials file with real-looking key material: discovery must read
	// ONLY the section header, never the values.
	if err := os.WriteFile(creds, []byte("[legacy]\naws_access_key_id=AKIAEXAMPLEEXAMPLE12\naws_secret_access_key=verysecretvalue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
}

func TestCloudProfilesDiscovery(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	view := f.mustLogin("vera")

	// Viewer is denied (admin-only, config-disclosing).
	if rec := f.do(http.MethodGet, "/api/cloud/profiles", "", view); rec.Code != http.StatusForbidden {
		t.Errorf("viewer got %d, want 403", rec.Code)
	}

	rec := f.do(http.MethodGet, "/api/cloud/profiles", "", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin got %d: %s", rec.Code, rec.Body.String())
	}
	var resp CloudProfilesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Providers) != 1 || resp.Providers[0].Provider != "aws" {
		t.Fatalf("providers = %+v, want one aws entry", resp.Providers)
	}
	got := strings.Join(resp.Providers[0].Profiles, ",")
	if got != "default,legacy,security-audit" {
		t.Errorf("profiles = %q, want the three section names", got)
	}
	// The credential value must never appear in the response.
	if strings.Contains(rec.Body.String(), "verysecretvalue") || strings.Contains(rec.Body.String(), "AKIA") {
		t.Error("cloud profile discovery leaked credential material into the API response")
	}
}

func TestCloudTargetRegistration(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	// A profile NOT in the discovered closed list is rejected (C1/C2).
	bad := `{"name":"bad cloud","provider":"aws","profileName":"nonexistent"}`
	if rec := f.do(http.MethodPost, "/api/targets", bad, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown profile got %d, want 400", rec.Code)
	}

	// An injection-shaped name is rejected the same way — never reaches an env.
	inj := `{"name":"inj","provider":"aws","profileName":"default; rm -rf /"}`
	if rec := f.do(http.MethodPost, "/api/targets", inj, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("injection profile got %d, want 400", rec.Code)
	}

	// A valid registration binds the NAME, stores no key material.
	ok := `{"name":"prod aws","provider":"aws","profileName":"security-audit","regions":["us-east-1"]}`
	rec := f.do(http.MethodPost, "/api/targets", ok, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid cloud target got %d: %s", rec.Code, rec.Body.String())
	}
	var tgt map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tgt); err != nil {
		t.Fatal(err)
	}
	if tgt["type"] != "cloud" || tgt["provider"] != "aws" || tgt["profileName"] != "security-audit" {
		t.Errorf("registered target = %+v", tgt)
	}

	// The stored targets.json must contain the NAME and never a key.
	raw, err := os.ReadFile(filepath.Join(f.dir, ".appsec", "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "security-audit") {
		t.Error("profile name not persisted")
	}
	if strings.Contains(string(raw), "AKIA") || strings.Contains(string(raw), "verysecretvalue") {
		t.Error("credential material reached targets.json")
	}
}

func TestCloudTargetScanLaunchRejectsFilesystemOptions(t *testing.T) {
	writeAWSConfig(t)
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")

	create := `{"name":"cloud1","provider":"aws","profileName":"security-audit"}`
	rec := f.do(http.MethodPost, "/api/targets", create, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cloud target: %d %s", rec.Code, rec.Body.String())
	}
	var tgt struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tgt)

	// Scope/scanners/profile/frameworks must be rejected for a cloud target.
	for _, opts := range []string{
		`{"scope":"src"}`,
		`{"scanners":["semgrep"]}`,
		`{"profile":"max"}`,
		`{"frameworks":["CIS-AWS"]}`,
	} {
		body := `{"targetId":"` + tgt.ID + `","options":` + opts + `}`
		if r := f.do(http.MethodPost, "/api/scans", body, admin); r.Code != http.StatusBadRequest {
			t.Errorf("options %s got %d, want 400", opts, r.Code)
		}
	}

	// A bare launch (triage toggle only) is accepted into the queue.
	body := `{"targetId":"` + tgt.ID + `","options":{"triage":false}}`
	if r := f.do(http.MethodPost, "/api/scans", body, admin); r.Code != http.StatusAccepted {
		t.Errorf("bare cloud launch got %d, want 202: %s", r.Code, r.Body.String())
	}
}
