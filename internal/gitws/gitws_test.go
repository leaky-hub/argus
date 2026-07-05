package gitws

// Workspace sync tests run against local bare-repo fixtures (`git init
// --bare` in a tempdir) cloned over file:// — permitted ONLY through the
// explicit NewInsecureFileForTest constructor. No network is touched.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureRepo builds a bare repo with one commit and returns its file:// URL
// plus a helper that commits a new file version and returns the new HEAD.
func fixtureRepo(t *testing.T) (url string, commit func(name, content string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	base := t.TempDir()
	bare := filepath.Join(base, "origin.git")
	work := filepath.Join(base, "work")

	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	git(base, "init", "--bare", "--initial-branch=main", bare)
	git(base, "clone", bare, work)
	commit = func(name, content string) string {
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		git(work, "add", ".")
		git(work, "commit", "-m", "update "+name)
		git(work, "push", "origin", "HEAD:main")
		return git(work, "rev-parse", "HEAD")
	}
	first := commit("app.py", "print('v1')\n")
	_ = first
	return "file://" + bare, commit
}

func TestSyncCloneRefreshAndProvenance(t *testing.T) {
	url, commit := fixtureRepo(t)
	ws := filepath.Join(t.TempDir(), "workspace", "t-abc")
	s := NewInsecureFileForTest()

	var lines []string
	sha1, err := s.Sync(context.Background(), url, "main", ws, func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if len(sha1) < 40 {
		t.Fatalf("commit sha = %q", sha1)
	}
	if data, err := os.ReadFile(filepath.Join(ws, "app.py")); err != nil || string(data) != "print('v1')\n" {
		t.Fatalf("clone content: %q %v", data, err)
	}
	joined := strings.Join(lines, "")
	if !strings.Contains(joined, "cloning") || !strings.Contains(joined, "at commit "+sha1) {
		t.Errorf("progress lines missing clone/commit: %q", joined)
	}

	// The workspace's own run history must survive a refresh (reset --hard,
	// never clean -fdx).
	runsDir := filepath.Join(ws, ".appsec", "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runFile := filepath.Join(runsDir, "2026-01-01T00-00-00Z.json")
	if err := os.WriteFile(runFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	want2 := commit("app.py", "print('v2')\n")
	sha2, err := s.Sync(context.Background(), url, "main", ws, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if sha2 != want2 || sha2 == sha1 {
		t.Fatalf("refresh sha = %s, want %s (old %s)", sha2, want2, sha1)
	}
	if data, _ := os.ReadFile(filepath.Join(ws, "app.py")); string(data) != "print('v2')\n" {
		t.Fatalf("refresh did not update the tree: %q", data)
	}
	if _, err := os.Stat(runFile); err != nil {
		t.Errorf("refresh destroyed the workspace run history: %v", err)
	}
}

// TestProductionSyncerRefusesFileProtocol pins the transport lockdown: the
// PRODUCTION construction cannot clone file:// even when handed such a URL
// (defense in depth behind ValidateGitURL).
func TestProductionSyncerRefusesFileProtocol(t *testing.T) {
	url, _ := fixtureRepo(t)
	ws := filepath.Join(t.TempDir(), "ws")
	if _, err := New().Sync(context.Background(), url, "main", ws, nil); err == nil {
		t.Fatal("production syncer cloned a file:// URL — transport lockdown broken")
	}
}

func TestSyncSizeBudget(t *testing.T) {
	url, commit := fixtureRepo(t)
	commit("big.bin", strings.Repeat("A", 4096))
	ws := filepath.Join(t.TempDir(), "ws")
	s := NewInsecureFileForTest()
	s.maxBytes = 1024 // tiny budget for the test
	if _, err := s.Sync(context.Background(), url, "main", ws, nil); err == nil || !strings.Contains(err.Error(), "size budget") {
		t.Fatalf("oversized workspace accepted: err=%v", err)
	}
}

func TestBranchPinning(t *testing.T) {
	url, commit := fixtureRepo(t)
	mainSha := commit("main.txt", "on main\n")
	ws := filepath.Join(t.TempDir(), "ws")
	s := NewInsecureFileForTest()
	sha, err := s.Sync(context.Background(), url, "main", ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sha != mainSha {
		t.Fatalf("pinned branch sha = %s, want %s", sha, mainSha)
	}
	// An unknown branch fails loudly, with bounded stderr in the message.
	if _, err := s.Sync(context.Background(), url, "no-such-branch", filepath.Join(t.TempDir(), "ws2"), nil); err == nil {
		t.Fatal("unknown branch accepted")
	}
}
