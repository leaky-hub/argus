package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const anthropicURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

// Anthropic implements Client for the Anthropic API.
type Anthropic struct {
	apiKey string
	model  string
	httpc  *http.Client
}

// NewAnthropic creates an Anthropic client.
func NewAnthropic(apiKey, model string, timeout time.Duration) *Anthropic {
	return &Anthropic{
		apiKey: apiKey,
		model:  model,
		httpc: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the provider identifier.
func (a *Anthropic) Name() string {
	return "anthropic/" + a.model
}

// Local reports whether inference happens on this machine.
func (a *Anthropic) Local() bool {
	return false
}

// Ping checks if the API key is set. No network call.
func (a *Anthropic) Ping(ctx context.Context) error {
	if a.apiKey == "" {
		return Unavailable("anthropic", errors.New("API key not set (ANTHROPIC_API_KEY)"))
	}
	return nil
}

// Complete sends a completion request to the Anthropic API.
func (a *Anthropic) Complete(ctx context.Context, req Request) (string, error) {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 1024
	}

	bodyMap := map[string]interface{}{
		"model":       a.model,
		"max_tokens":  maxTokens,
		"temperature": req.Temperature,
		"system":      req.System,
		"messages": []map[string]string{
			{"role": "user", "content": req.User},
		},
	}

	jsonBody, err := json.Marshal(bodyMap)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	reqObj, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	reqObj.Header.Set("x-api-key", a.apiKey)
	reqObj.Header.Set("anthropic-version", anthropicVersion)
	reqObj.Header.Set("content-type", "application/json")

	resp, err := a.httpc.Do(reqObj)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", Unavailable("anthropic", fmt.Errorf("status %d", resp.StatusCode))
	}

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
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	var sb []byte
	for _, block := range result.Content {
		if block.Type == "text" {
			sb = append(sb, []byte(block.Text)...)
		}
	}

	return string(sb), nil
}
