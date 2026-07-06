package iacdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func techs(comps []Component) map[string]bool {
	m := map[string]bool{}
	for _, c := range comps {
		m[c.Tech] = true
	}
	return m
}

func TestScanTerraform(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "aws_db_instance" "primary" { engine = "postgres" }
resource "aws_s3_bucket" "assets" { bucket = "my-assets" }
resource "aws_lb" "public" {}
resource "aws_cognito_user_pool" "users" {}
resource "aws_iam_role" "noise" {}   # not an architecture component
`)
	comps, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := techs(comps)
	for _, want := range []string{"database", "object-store", "api-service", "auth-service"} {
		if !got[want] {
			t.Errorf("missing tech %q in %+v", want, comps)
		}
	}
	// The iam_role is not a mapped component.
	for _, c := range comps {
		if c.Name == "noise" {
			t.Error("unmapped resource surfaced as a component")
		}
	}
}

func TestScanCompose(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "docker-compose.yml", `
services:
  web:
    image: nginx:1.25
  db:
    image: postgres:16
  cache:
    image: redis:7
`)
	got := techs(mustScan(t, dir))
	if !got["web-app"] || !got["database"] {
		t.Errorf("compose detect wrong: %v", got)
	}
}

func TestScanKubernetes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "k8s/deploy.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: mycorp/api-service:latest
`)
	// A generic image → the workload kind makes it an api-service.
	if !techs(mustScan(t, dir))["api-service"] {
		t.Error("k8s Deployment not detected as api-service")
	}
}

func TestScanSkipsVendorAndGit(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".git/config.tf", `resource "aws_s3_bucket" "leak" {}`)
	write(t, dir, "node_modules/x/main.tf", `resource "aws_db_instance" "leak" {}`)
	write(t, dir, "app.tf", `resource "aws_s3_bucket" "real" {}`)
	comps := mustScan(t, dir)
	if len(comps) != 1 || comps[0].Name != "real" {
		t.Errorf("walked skip dirs: %+v", comps)
	}
}

func mustScan(t *testing.T, dir string) []Component {
	t.Helper()
	c, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
