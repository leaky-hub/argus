package iacdetect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestScanCloudFormationYAML: CFN and SAM templates are usually YAML, which
// used to fall through to the Kubernetes branch (requires "kind:") and get
// missed entirely. Both spellings must detect.
func TestScanCloudFormationYAML(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "template.yaml", `
AWSTemplateFormatVersion: "2010-09-09"
Transform: AWS::Serverless-2016-10-31
Resources:
  Api:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
  Db:
    Type: "AWS::RDS::DBInstance"
  Assets:
    Type: AWS::S3::Bucket
`)
	got := techs(mustScan(t, dir))
	for _, want := range []string{"api-service", "database", "object-store"} {
		if !got[want] {
			t.Errorf("CFN YAML missing tech %q: %v", want, got)
		}
	}
}

func TestScanCloudFormationJSON(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "stack.json", `{"Resources":{"Q":{"Type":"AWS::DynamoDB::Table"}}}`)
	if !techs(mustScan(t, dir))["database"] {
		t.Error("CFN JSON not detected")
	}
}

// TestScanHostileFiles: enormous and malformed inputs must neither hang nor
// error the scan — the bounded read holds and unparseable content yields
// nothing.
func TestScanHostileFiles(t *testing.T) {
	dir := t.TempDir()
	// A 3 MB single line (no newline at all): the line cap makes the read fail
	// closed to an empty body.
	write(t, dir, "oneline.tf", strings.Repeat("x", 3<<20))
	// A multi-line file with a real resource before the byte cap and one after.
	var big strings.Builder
	big.WriteString("resource \"aws_s3_bucket\" \"early\" {}\n")
	for big.Len() < maxFileBytes+4096 {
		big.WriteString("# padding line to push past the read cap ----------------------------\n")
	}
	big.WriteString("resource \"aws_db_instance\" \"late\" {}\n")
	write(t, dir, "big.tf", big.String())
	// Resource names with quotes/newlines never match the strict name pattern.
	write(t, dir, "weird.tf", "resource \"aws_s3_bucket\" \"bad\nname\" {}\nresource \"aws_s3_bucket\" \"with\\\"quote\" {}\n")

	comps := mustScan(t, dir)
	names := map[string]bool{}
	for _, c := range comps {
		names[c.Name] = true
		for _, r := range c.Name {
			if r < 0x20 {
				t.Errorf("component name contains control character: %q", c.Name)
			}
		}
	}
	if !names["early"] {
		t.Error("resource before the read cap missed")
	}
	if names["late"] {
		t.Error("read cap did not hold: resource past the cap detected")
	}
}

// TestScanSymlinkLoopTerminates: WalkDir does not follow directory symlinks,
// so a self-referencing tree must terminate and still find the real file.
func TestScanSymlinkLoopTerminates(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/main.tf", `resource "aws_s3_bucket" "real" {}`)
	if err := os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "a", "loop")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	comps := mustScan(t, dir)
	if len(comps) != 1 || comps[0].Name != "real" {
		t.Errorf("symlink loop scan wrong: %+v", comps)
	}
}

// TestScanCandidateFileCap: a tree with more matching files than the cap
// finishes quickly and returns at most the capped candidates' components.
func TestScanCandidateFileCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxCandidateFiles+50; i++ {
		write(t, dir, fmt.Sprintf("f%05d.tf", i), fmt.Sprintf(`resource "aws_s3_bucket" "b%05d" {}`, i))
	}
	comps := mustScan(t, dir)
	if len(comps) == 0 || len(comps) > maxCandidateFiles {
		t.Errorf("candidate cap wrong: %d components", len(comps))
	}
}

// TestBroadenedMappings spot-checks the GCP/Azure/modern-AWS additions a
// security engineer would expect a baseline to catch.
func TestBroadenedMappings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "gcp.tf", `
resource "google_bigquery_dataset" "dw" {}
resource "google_container_cluster" "gke" {}
resource "google_cloudfunctions2_function" "fn" {}
`)
	write(t, dir, "azure.tf", `
resource "azurerm_mssql_server" "sql" {}
resource "azurerm_cosmosdb_account" "cosmos" {}
resource "azurerm_kubernetes_cluster" "aks" {}
resource "azurerm_linux_web_app" "site" {}
`)
	write(t, dir, "aws.tf", `
resource "aws_eks_cluster" "eks" {}
resource "aws_redshift_cluster" "dw" {}
`)
	write(t, dir, "docker-compose.yml", "services:\n  es:\n    image: opensearchproject/opensearch:2\n  proxy:\n    image: traefik:v3\n  sso:\n    image: hashicorp/vault:1.16\n")
	comps := mustScan(t, dir)
	byName := map[string]string{}
	for _, c := range comps {
		byName[c.Name] = c.Tech
	}
	expect := map[string]string{
		"dw": "database", "gke": "api-service", "fn": "api-service",
		"sql": "database", "cosmos": "database", "aks": "api-service", "site": "web-app",
		"eks": "api-service",
		"opensearch": "database", "traefik": "web-app", "vault": "auth-service",
	}
	for name, tech := range expect {
		if byName[name] != tech {
			t.Errorf("%s: got tech %q, want %q (all: %v)", name, byName[name], tech, byName)
		}
	}
}
