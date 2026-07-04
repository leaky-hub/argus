package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTriageDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Triage.Enabled {
		t.Error("triage enabled should be false by default")
	}
	if cfg.Triage.Provider != "ollama" {
		t.Errorf("triage provider = %q, want ollama", cfg.Triage.Provider)
	}
	if cfg.Triage.Model != "qwen3.6:35b-a3b" {
		t.Errorf("triage model = %q, want qwen3.6:35b-a3b", cfg.Triage.Model)
	}
	if cfg.Triage.Endpoint != "http://localhost:11434" {
		t.Errorf("triage endpoint = %q, want http://localhost:11434", cfg.Triage.Endpoint)
	}
	if cfg.Triage.TimeoutSec != 90 {
		t.Errorf("triage timeout = %d, want 90", cfg.Triage.TimeoutSec)
	}
	if cfg.Triage.Concurrency != 4 {
		t.Errorf("triage concurrency = %d, want 4", cfg.Triage.Concurrency)
	}
	if cfg.Triage.MaxFindings != 200 {
		t.Errorf("triage max_findings = %d, want 200", cfg.Triage.MaxFindings)
	}
	if cfg.Triage.ExcludeFP {
		t.Error("triage exclude_fp should be false by default")
	}
	if cfg.Triage.AllowSecretCloud {
		t.Error("triage allow_secret_cloud should be false by default")
	}
}

func TestTriageYAMLOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appsec.yml")
	content := `
triage:
  enabled: true
  provider: anthropic
  model: claude-3-opus-20240229
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Triage.Enabled {
		t.Error("triage enabled should be true after override")
	}
	if cfg.Triage.Provider != "anthropic" {
		t.Errorf("triage provider = %q, want anthropic", cfg.Triage.Provider)
	}
	if cfg.Triage.Model != "claude-3-opus-20240229" {
		t.Errorf("triage model = %q, want claude-3-opus-20240229", cfg.Triage.Model)
	}

	// Unrelated defaults should remain
	if cfg.FailSeverity != "high" {
		t.Errorf("fail_severity = %q, want high", cfg.FailSeverity)
	}
	if cfg.Format != "markdown" {
		t.Errorf("format = %q, want markdown", cfg.Format)
	}
}

func TestTriageEnabledInvalidProviderFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appsec.yml")
	content := `
triage:
  enabled: true
  provider: invalid_provider
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	err = cfg.Validate()
	if err == nil {
		t.Error("Validate should fail with invalid provider when triage is enabled")
	} else if !strings.Contains(err.Error(), "invalid triage provider") {
		t.Errorf("Validate error should mention 'invalid triage provider', got: %v", err)
	}
}

func TestTriageDisabledInvalidProviderPasses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appsec.yml")
	content := `
triage:
  enabled: false
  provider: invalid_provider
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	err = cfg.Validate()
	if err != nil {
		t.Errorf("Validate should pass when triage is disabled, got error: %v", err)
	}
}
