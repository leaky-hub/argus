package cloudremediate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec records what it was asked to run and returns canned output.
type fakeExec struct {
	calls    [][]string
	profiles []string
	out      string
	err      error
}

func (f *fakeExec) Run(_ context.Context, argv []string, profile string) (string, error) {
	f.calls = append(f.calls, argv)
	f.profiles = append(f.profiles, profile)
	return f.out, f.err
}

func s3Plan(t *testing.T) Plan {
	t.Helper()
	r, _ := ByID("aws-s3-block-public-access")
	p, err := Build(r, cloudFinding("s3_bucket_public_access", map[string]string{"service": "s3", "resourceName": "prod-assets"}))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func azurePlan(t *testing.T) Plan {
	t.Helper()
	r, _ := ByID("azure-storage-disallow-blob-public-access")
	p, err := Build(r, providerFinding("azure", "storage_blob_public_access_level_is_disabled", testARMID,
		map[string]string{"service": "storage", "resourceName": "prodassets"}))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func gcpPlan(t *testing.T) Plan {
	t.Helper()
	r, _ := ByID("gcp-storage-public-access-prevention")
	p, err := Build(r, providerFinding("gcp", "cloudstorage_bucket_public_access", "",
		map[string]string{"service": "cloudstorage", "resourceName": "my-bucket"}))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDryRunAndApply(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}
	plan := s3Plan(t)

	if _, err := r.Run(context.Background(), plan, DryRun, "sec-write"); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if len(fx.calls) != 1 || fx.calls[0][1] != "s3api" || fx.calls[0][2] != "get-public-access-block" {
		t.Errorf("dry-run ran the wrong command: %v", fx.calls)
	}
	if fx.profiles[0] != "sec-write" {
		t.Errorf("profile not passed to executor: %v", fx.profiles)
	}

	fx.calls = nil
	if _, err := r.Run(context.Background(), plan, Apply, "sec-write"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if fx.calls[0][2] != "put-public-access-block" {
		t.Errorf("apply ran the wrong command: %v", fx.calls)
	}
}

func TestRunProfileValidation(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(name string) bool { return name == "known" }}
	plan := s3Plan(t)
	if _, err := r.Run(context.Background(), plan, Apply, "unknown"); err == nil {
		t.Error("unknown profile must be refused")
	}
	if _, err := r.Run(context.Background(), plan, Apply, ""); err == nil {
		t.Error("empty profile must be refused")
	}
	if len(fx.calls) != 0 {
		t.Error("executor ran despite an invalid profile")
	}
}

// TestRunSafetyGuard: a plan carrying a command that violates the argv guard is
// refused before ANY command runs — defense in depth over the catalog.
func TestRunSafetyGuard(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}

	bad := []struct {
		name    string
		plan    Plan
		profile string
	}{
		{"non-allowlisted binary", Plan{ID: "x", Provider: "aws", Apply: []Command{{"curl", "http://evil"}}}, "p"},
		{"destructive verb", Plan{ID: "x", Provider: "aws", Apply: []Command{{"aws", "s3api", "delete-bucket", "--bucket", "b"}}}, "p"},
		{"shell metachar", Plan{ID: "x", Provider: "aws", Apply: []Command{{"aws", "s3api", "get", "b; rm -rf /"}}}, "p"},
		{"pipe", Plan{ID: "x", Provider: "aws", Apply: []Command{{"aws", "x", "| sh"}}}, "p"},
		{"unknown provider", Plan{ID: "x", Provider: "oci", Apply: []Command{{"oci", "os", "bucket"}}}, ""},
		{"azure plan may not run aws", Plan{ID: "x", Provider: "azure", Apply: []Command{{"aws", "s3api", "get-bucket-acl"}}}, ""},
		{"aws plan may not run az", Plan{ID: "x", Provider: "aws", Apply: []Command{{"az", "storage", "account", "show"}}}, "p"},
		{"az purge", Plan{ID: "x", Provider: "azure", Apply: []Command{{"az", "keyvault", "purge", "--name", "v"}}}, ""},
		{"az destructive verb", Plan{ID: "x", Provider: "azure", Apply: []Command{{"az", "storage", "account", "delete", "--ids", "i"}}}, ""},
		{"gcloud destructive verb", Plan{ID: "x", Provider: "gcp", Apply: []Command{{"gcloud", "storage", "buckets", "delete", "gs://b"}}}, ""},
		{"gcloud remove subcommand", Plan{ID: "x", Provider: "gcp", Apply: []Command{{"gcloud", "projects", "remove-iam-policy-binding", "p"}}}, ""},
	}
	for _, tc := range bad {
		if _, err := r.Run(context.Background(), tc.plan, Apply, tc.profile); err == nil {
			t.Errorf("%s: guard did not refuse", tc.name)
		}
	}
	if len(fx.calls) != 0 {
		t.Errorf("a guarded command reached the executor: %v", fx.calls)
	}
}

// TestRunCredentialSemantics: an AWS plan needs a validated profile; Azure and
// GCP plans run with the operator's ambient az/gcloud login and REFUSE a
// profile, and never consult the AWS profile list.
func TestRunCredentialSemantics(t *testing.T) {
	fx := &fakeExec{out: "ok"}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return false }} // no AWS profile is ever valid

	for _, tc := range []struct {
		name string
		plan Plan
	}{
		{"azure", azurePlan(t)},
		{"gcp", gcpPlan(t)},
	} {
		if _, err := r.Run(context.Background(), tc.plan, DryRun, "sec-write"); err == nil {
			t.Errorf("%s: a profile must be refused", tc.name)
		}
		res, err := r.Run(context.Background(), tc.plan, DryRun, "")
		if err != nil {
			t.Errorf("%s: ambient-auth dry-run failed: %v", tc.name, err)
		}
		if len(res) == 0 {
			t.Errorf("%s: no command ran", tc.name)
		}
	}
	// Every executed command carried an empty credential reference.
	for _, p := range fx.profiles {
		if p != "" {
			t.Errorf("non-AWS command got a profile: %q", p)
		}
	}
	// The binaries were the providers' own CLIs.
	if fx.calls[0][0] != "az" || fx.calls[1][0] != "gcloud" {
		t.Errorf("wrong binaries ran: %v", fx.calls)
	}
	// And an AWS plan still requires a profile the validator accepts.
	if _, err := r.Run(context.Background(), s3Plan(t), DryRun, "sec-write"); err == nil {
		t.Error("aws: an unknown profile must be refused")
	}
}

// TestRunStopsAtFirstFailure: a failing command halts the sequence and the
// error carries the tail of its output.
func TestRunStopsAtFirstFailure(t *testing.T) {
	fx := &fakeExec{out: "AccessDenied: not authorized", err: errors.New("exit 254")}
	r := &Runner{Exec: fx, ValidProfile: func(string) bool { return true }}
	res, err := r.Run(context.Background(), s3Plan(t), Apply, "p")
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("failure not surfaced: %v", err)
	}
	if len(res) != 1 || res[0].Err == "" {
		t.Errorf("result did not record the failure: %+v", res)
	}
}
