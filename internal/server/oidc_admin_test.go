package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdminOIDCGetDefault: with nothing configured, GET reports disabled and
// no secret, and never invents a source.
func TestAdminOIDCGetDefault(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	rec := f.do("GET", "/api/admin/oidc", "", admin)
	if rec.Code != 200 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	var v struct {
		Enabled       bool
		Source        string
		SecretEnvName string
		SecretPresent bool
	}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Enabled || v.Source != "none" || v.SecretEnvName != "ARGUS_OIDC_SECRET" || v.SecretPresent {
		t.Errorf("default view wrong: %+v", v)
	}
}

// TestAdminOIDCPutRoundTrip: an admin saves a valid config; it persists to the
// store, becomes the effective config, flips ssoEnabled, and never echoes a
// secret. The write is audited.
func TestAdminOIDCPutRoundTrip(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	body := `{
		"issuer":"https://accounts.google.com",
		"clientId":"cid-123",
		"redirectUrl":"http://127.0.0.1:8080/api/auth/oidc/callback",
		"allowedDomains":["example.com"," ","corp.io"],
		"defaultRole":"viewer",
		"clientSecretEnv":"MY_OIDC_SECRET"
	}`
	rec := f.do("PUT", "/api/admin/oidc", body, admin)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	var v struct {
		Enabled        bool
		Source         string
		SecretEnvName  string
		AllowedDomains []string
	}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.Enabled || v.Source != "store" || v.SecretEnvName != "MY_OIDC_SECRET" {
		t.Errorf("view after put wrong: %+v", v)
	}
	if len(v.AllowedDomains) != 2 { // the blank entry is dropped
		t.Errorf("allowed domains not cleaned: %+v", v.AllowedDomains)
	}
	// The store file exists and holds NO secret value.
	raw, err := os.ReadFile(filepath.Join(f.dir, ".appsec", "oidc.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "secret\":\"http") || strings.Contains(string(raw), "clientSecret\":\"s") {
		t.Error("store may contain a secret value")
	}
	// ssoEnabled now reports true via me (unauthenticated view).
	me := f.do("GET", "/api/auth/me", "", session{})
	if !strings.Contains(me.Body.String(), `"ssoEnabled":true`) {
		t.Errorf("ssoEnabled not flipped after config: %s", me.Body.String())
	}
	// Audited.
	auditRaw, _ := os.ReadFile(filepath.Join(f.dir, ".appsec", "audit.jsonl"))
	if !strings.Contains(string(auditRaw), "config.change") {
		t.Error("config change not audited")
	}
}

// TestAdminOIDCPutValidation: malformed configs are refused with a message and
// never persisted.
func TestAdminOIDCPutValidation(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	bad := []string{
		`{"issuer":"","clientId":"c","redirectUrl":"http://x/api/auth/oidc/callback"}`,
		`{"issuer":"ftp://x","clientId":"c","redirectUrl":"http://x/api/auth/oidc/callback"}`,
		`{"issuer":"https://x","clientId":"c","redirectUrl":"http://x/wrong-path"}`,
		`{"issuer":"https://x","clientId":"c","redirectUrl":"http://x/api/auth/oidc/callback","defaultRole":"superuser"}`,
		`{"issuer":"https://x","clientId":"c","redirectUrl":"http://x/api/auth/oidc/callback","roleMap":{"g":"wizard"}}`,
	}
	for _, b := range bad {
		if rec := f.do("PUT", "/api/admin/oidc", b, admin); rec.Code != 400 {
			t.Errorf("invalid config accepted (%d): %s", rec.Code, b)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "oidc.json")); !os.IsNotExist(err) {
		t.Error("an invalid config left a store file behind")
	}
}

// TestAdminOIDCDisableClearsStore: disable removes the store and reverts to
// off (or appsec.yml).
func TestAdminOIDCDisableClearsStore(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	f.do("PUT", "/api/admin/oidc", `{"issuer":"https://x","clientId":"c","redirectUrl":"http://x/api/auth/oidc/callback"}`, admin)
	rec := f.do("PUT", "/api/admin/oidc", `{"disable":true}`, admin)
	if rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	var v struct {
		Enabled bool
		Source  string
	}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Enabled || v.Source != "none" {
		t.Errorf("disable did not clear: %+v", v)
	}
	if _, err := os.Stat(filepath.Join(f.dir, ".appsec", "oidc.json")); !os.IsNotExist(err) {
		t.Error("store file survived disable")
	}
}

// TestAdminOIDCStoreOverridesConfig: the console store wins over appsec.yml.
func TestAdminOIDCStoreOverridesConfig(t *testing.T) {
	f := newConsole(t, nil)
	admin := f.mustLogin("alice")
	writeFile(t, f.dir, "appsec.yml", "auth:\n  oidc:\n    issuer: https://file-issuer\n    client_id: file-cid\n    redirect_url: http://127.0.0.1:8080/api/auth/oidc/callback\n")
	// Store a different issuer via the admin API.
	f.do("PUT", "/api/admin/oidc", `{"issuer":"https://store-issuer","clientId":"store-cid","redirectUrl":"http://127.0.0.1:8080/api/auth/oidc/callback"}`, admin)
	rec := f.do("GET", "/api/admin/oidc", "", admin)
	var v struct {
		Issuer string
		Source string
	}
	json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Issuer != "https://store-issuer" || v.Source != "store" {
		t.Errorf("store did not override config: %+v", v)
	}
}
