package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Ollama implements Client for local Ollama instances.
type Ollama struct {
	endpoint string
	model    string
	httpc    *http.Client
}

// NewOllama creates an Ollama client. Trims trailing "/" from endpoint.
func NewOllama(endpoint, model string, timeout time.Duration) *Ollama {
	return &Ollama{
		endpoint: strings.TrimRight(endpoint, "/"),
		model:    model,
		httpc: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier.
func (o *Ollama) Name() string {
	return "ollama/" + o.model
}

// Local reports whether inference happens on this machine.
func (o *Ollama) Local() bool {
	u, err := url.Parse(o.endpoint)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// Ping checks if the endpoint is reachable and the model is installed.
func (o *Ollama) Ping(ctx context.Context) error {
	// Derive a 5-second timeout from ctx, but don't override ctx's own deadline/timeout
	// if it's already shorter than 5s. We create a new context with a fixed 5s timeout
	// for the ping check itself to ensure we don't hang indefinitely on network issues.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(pingCtx, http.MethodGet, o.endpoint+"/api/tags", nil)
	if err != nil {
		return Unavailable("ollama", err)
	}

	resp, err := o.httpc.Do(req)
	if err != nil {
		return Unavailable("ollama", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Unavailable("ollama", fmt.Errorf("unexpected status: %d", resp.StatusCode))
	}

	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Unavailable("ollama", err)
	}

	for _, m := range body.Models {
		if m.Name == o.model {
			return nil
		}
	}

	return Unavailable("ollama", fmt.Errorf("model %q not installed", o.model))
}

// Complete sends a completion request to the Ollama API.
func (o *Ollama) Complete(ctx context.Context, req Request) (string, error) {
	msgs := []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{
		{Role: "system", Content: req.System},
		{Role: "user", Content: req.User},
	}

	// num_predict only when a cap is set: 0 would mean "generate nothing".
	opts := map[string]interface{}{"temperature": req.Temperature}
	if req.MaxTokens > 0 {
		opts["num_predict"] = req.MaxTokens
	}

	bodyMap := map[string]interface{}{
		"model":      o.model,
		"stream":     false,
		"think":      false,
		"messages":   msgs,
		"options":    opts,
		"keep_alive": "10m",
	}

	if req.ForceJSON {
		bodyMap["format"] = "json"
	}

	jsonBody, err := json.Marshal(bodyMap)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	reqObj, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint+"/api/chat", bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	reqObj.Header.Set("Content-Type", "application/json")

	resp, err := o.httpc.Do(reqObj)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 300)
		bodyBytes, _ := io.ReadAll(limitReader)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	limitReader := io.LimitReader(resp.Body, 1<<20)
	respBody, err := io.ReadAll(limitReader)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return result.Message.Content, nil
}
