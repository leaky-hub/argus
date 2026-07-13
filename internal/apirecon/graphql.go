package apirecon

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// introspectionQuery is a minimal introspection request: enough to tell whether
// the server answers introspection at all, without pulling the full schema.
const introspectionQuery = `{"query":"query{__schema{queryType{name}}}"}`

// introspectionEnabled reports whether a GraphQL endpoint answers an
// introspection query with schema data (rather than an error or a refusal). It
// sends one POST through the governed client and reads a bounded response.
func introspectionEnabled(ctx context.Context, client *http.Client, u string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(introspectionQuery))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	s := string(body)
	// A schema-bearing response carries the data envelope and the queryType the
	// introspection asked for. Requiring "data" avoids treating an error
	// response that merely echoes the query text as introspection being enabled.
	return strings.Contains(s, "\"data\"") &&
		strings.Contains(s, "__schema") &&
		strings.Contains(s, "queryType")
}
