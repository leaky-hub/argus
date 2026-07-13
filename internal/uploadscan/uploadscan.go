// Package uploadscan tests discovered upload forms for unrestricted file
// upload. It uploads a benign marker file whose type should be rejected (a
// .php name with an image content-type), then tries to fetch it back. A file
// that is both accepted and retrievable proves the type restriction can be
// bypassed. The marker file contains no executable code: this confirms the
// weakness without planting a web shell.
package uploadscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/zer0d4y5/argus/internal/dastcrawl"
	"github.com/zer0d4y5/argus/internal/model"
	"github.com/zer0d4y5/argus/internal/poc"
)

const (
	maxBodyBytes = 512 << 10
	maxForms     = 20
)

// commonUploadDirs are where apps stash uploads, tried as a fallback when the
// upload response does not reveal the stored path.
var commonUploadDirs = []string{
	"uploads/", "upload/", "files/", "file/", "media/", "images/", "img/",
	"hackable/uploads/", "assets/uploads/", "static/uploads/",
}

// Options configure an upload scan.
type Options struct {
	BaseURL string
	Forms   []dastcrawl.UploadForm
	Headers []string
}

// Scan tests each upload form and returns a finding per form that stores and
// serves a benign file of a disallowed type.
func Scan(ctx context.Context, client *http.Client, opts Options, progress func(string)) []model.RawFinding {
	if progress == nil {
		progress = func(string) {}
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var out []model.RawFinding
	for i, form := range opts.Forms {
		if i >= maxForms || ctx.Err() != nil {
			break
		}
		if f, ok := testForm(ctx, client, opts, form); ok {
			out = append(out, f)
		}
	}
	progress(fmt.Sprintf("upload: %d unrestricted-file-upload finding(s)\n", len(out)))
	return out
}

func testForm(ctx context.Context, client *http.Client, opts Options, form dastcrawl.UploadForm) (model.RawFinding, bool) {
	token := newToken()
	filename := "argus-" + token + ".php"
	marker := "ARGUS-UPLOAD-" + token
	content := marker + " :: benign upload-restriction test, contains no executable code"

	// Refresh any per-request CSRF token on the form so the upload is accepted
	// (the token captured at crawl time may have rotated).
	fields := refreshFields(ctx, client, opts.Headers, form)

	reqDump, respBody, err := doUpload(ctx, client, opts.Headers, dastcrawl.UploadForm{
		Action: form.Action, FileField: form.FileField, Fields: fields,
	}, filename, content)
	if err != nil {
		return model.RawFinding{}, false
	}

	storedURL, fetched, ok := confirmStored(ctx, client, opts.Headers, opts.BaseURL, form.Action, filename, marker, respBody)
	if !ok {
		return model.RawFinding{}, false
	}

	f := model.RawFinding{
		Tool:        "argus-upload",
		Category:    model.CategoryDAST,
		RuleID:      "unrestricted-upload:" + form.FileField,
		Title:       "Unrestricted File Upload",
		Description: fmt.Sprintf("The upload form field %q accepted a file with a disallowed type (a .php name), and the stored file was retrievable at %s. The type restriction can be bypassed, which is the first step toward storing a web shell.", form.FileField, storedURL),
		RawSeverity: "high",
		URL:         form.Action,
		CWEs:        []string{"CWE-434"},
		Meta:        map[string]string{"param": form.FileField, "method": "POST", "storedAt": storedURL},
	}
	f.Proof = poc.Build("upload", poc.Request{Method: "POST", URL: form.Action, CookiePresent: hasCookie(opts.Headers)}, form.FileField,
		fmt.Sprintf("A benign file named %s was uploaded and then retrieved at %s with its marker intact, so the disallowed type was stored and served.", filename, storedURL))
	if f.Proof != nil {
		// The reproduction request is the multipart upload; the response is the
		// fetched-back file proving it was stored.
		f.Proof.Request = reqDump
		f.Proof.Response = poc.RedactResponse(fetched)
	}
	return f, true
}

// doUpload sends the multipart upload and returns a human-readable request
// summary and the response body.
func doUpload(ctx context.Context, client *http.Client, headers []string, form dastcrawl.UploadForm, filename, content string) (reqDump, respBody string, err error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// The form's other fields (hidden tokens, size limits, submit button).
	for k, v := range form.Fields {
		_ = mw.WriteField(k, v)
	}
	// The file part: an image content-type over a .php name, the classic
	// content-type bypass.
	part, err := createImagePart(mw, form.FileField, filename)
	if err != nil {
		return "", "", err
	}
	_, _ = io.WriteString(part, content)
	if err := mw.Close(); err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action, &buf)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for _, h := range headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	dump := fmt.Sprintf("POST %s\nContent-Type: multipart/form-data\n\n[multipart] %s=@%s (image/png), plus %d form field(s)",
		form.Action, form.FileField, filename, len(form.Fields))
	return dump, string(body), nil
}

// refreshFields re-fetches the form's page and updates any token-like field
// (a name containing token/csrf/nonce) with the value currently rendered, so a
// per-request anti-CSRF token is valid at upload time. It returns a copy; on any
// error it falls back to the crawl-time fields.
func refreshFields(ctx context.Context, client *http.Client, headers []string, form dastcrawl.UploadForm) map[string]string {
	out := map[string]string{}
	for k, v := range form.Fields {
		out[k] = v
	}
	body, ok := fetch(ctx, client, headers, form.Action)
	if !ok {
		return out
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return out
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, value := "", ""
			for _, a := range n.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "value":
					value = a.Val
				}
			}
			if name != "" && isTokenField(name) {
				out[name] = value
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return out
}

func isTokenField(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "token") || strings.Contains(l, "csrf") || strings.Contains(l, "nonce")
}

func createImagePart(mw *multipart.Writer, field, filename string) (io.Writer, error) {
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename)}
	h["Content-Type"] = []string{"image/png"}
	return mw.CreatePart(h)
}

// confirmStored tries to retrieve the uploaded file and confirm the marker is
// served. It first mines the upload response for the stored path, then falls
// back to common upload directories.
func confirmStored(ctx context.Context, client *http.Client, headers []string, baseURL, action, filename, marker, respBody string) (storedURL, fetched string, ok bool) {
	base := action
	if baseURL != "" {
		base = baseURL
	}
	for _, cand := range candidatePaths(respBody, base, action, filename) {
		body, ok := fetch(ctx, client, headers, cand)
		if ok && strings.Contains(body, marker) {
			return cand, body, true
		}
	}
	return "", "", false
}

// candidatePaths returns URLs that might serve the uploaded file: paths that
// reference the filename in the response, then common upload directories.
func candidatePaths(respBody, baseURL, action, filename string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}

	actionURL, _ := url.Parse(action)
	// 1. Paths in the response that end in the uploaded filename.
	re := regexp.MustCompile(`[\w./~-]*` + regexp.QuoteMeta(filename))
	for _, m := range re.FindAllString(respBody, 20) {
		m = strings.TrimLeft(m, ".") // "../../x" -> resolve cleanly below
		if ref, err := url.Parse(strings.TrimSpace(m)); err == nil && actionURL != nil {
			add(actionURL.ResolveReference(ref).String())
		}
	}
	// 2. Common upload directories relative to the target root.
	if root, err := url.Parse(baseURL); err == nil {
		for _, dir := range commonUploadDirs {
			if ref, err := url.Parse(dir + filename); err == nil {
				add(root.ResolveReference(ref).String())
			}
		}
	}
	return out
}

func fetch(ctx context.Context, client *http.Client, headers []string, u string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	for _, h := range headers {
		if k, v, ok := splitHeader(h); ok {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return string(body), true
}

func newToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func splitHeader(h string) (key, val string, ok bool) {
	i := strings.Index(h, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}

func hasCookie(headers []string) bool {
	for _, h := range headers {
		if k, _, ok := splitHeader(h); ok && strings.EqualFold(strings.TrimSpace(k), "Cookie") {
			return true
		}
	}
	return false
}
