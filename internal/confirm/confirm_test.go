package confirm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zer0d4y5/argus/internal/engagement"
	"github.com/zer0d4y5/argus/internal/model"
)

// vulnHandler simulates a command-injection sink: an injected `id` after a shell
// separator "executes" and the process identity appears in the response.
func vulnHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.Contains(r.Form.Get("cmd"), "id") {
			io.WriteString(w, "result: uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
			return
		}
		io.WriteString(w, "ok\n")
	}
}

func cmdiFinding(url string) model.RawFinding {
	return model.RawFinding{
		Tool: "argus-cmdi", Category: model.CategoryDAST, RuleID: "cmdi:get:cmd",
		URL: url, CWEs: []string{"CWE-78"},
		Meta: map[string]string{"param": "cmd", "method": "GET"},
	}
}

func armedGovernor(t *testing.T, host string, confirm, perRun bool) *engagement.Governor {
	t.Helper()
	eng := &engagement.Engagement{
		Name:  "t",
		Scope: engagement.Scope{InScope: []string{host}},
	}
	eng.Confirm = confirm
	return engagement.NewGovernor(eng, nil, false, perRun)
}

func TestConfirmCmdiAttachesImpactWhenArmed(t *testing.T) {
	srv := httptest.NewServer(vulnHandler())
	defer srv.Close()

	gov := armedGovernor(t, "127.0.0.1", true, true)
	raw := []model.RawFinding{cmdiFinding(srv.URL + "/?cmd=1")}
	Run(context.Background(), gov, raw, Inputs{Client: gov.Client(srv.Client())}, nil)

	p := raw[0].Proof
	if p == nil || p.Impact == nil {
		t.Fatal("armed confirmation should attach an ImpactProof")
	}
	if p.Impact.Kind != "cmd-id" || p.Impact.Command != "id" {
		t.Errorf("wrong impact: %+v", p.Impact)
	}
	if !strings.Contains(p.Impact.Summary, "uid=33(www-data)") {
		t.Errorf("impact summary should carry the id output: %q", p.Impact.Summary)
	}
}

func TestConfirmNoOpWhenNotArmed(t *testing.T) {
	srv := httptest.NewServer(vulnHandler())
	defer srv.Close()

	// Engagement flag on, but no per-run confirmation: the interlock is not armed.
	gov := armedGovernor(t, "127.0.0.1", true, false)
	raw := []model.RawFinding{cmdiFinding(srv.URL + "/?cmd=1")}
	Run(context.Background(), gov, raw, Inputs{Client: gov.Client(srv.Client())}, nil)

	if raw[0].Proof != nil && raw[0].Proof.Impact != nil {
		t.Error("confirmation must not run when the interlock is not armed")
	}
}

func TestConfirmSkipsNonDAST(t *testing.T) {
	gov := armedGovernor(t, "127.0.0.1", true, true)
	raw := []model.RawFinding{{
		Category: model.CategorySAST, CWEs: []string{"CWE-78"},
		URL: "http://127.0.0.1/", Meta: map[string]string{"param": "cmd"},
	}}
	Run(context.Background(), gov, raw, Inputs{}, nil)
	if raw[0].Proof != nil {
		t.Error("a non-DAST finding must never be confirmed")
	}
}
