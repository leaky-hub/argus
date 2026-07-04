package llm

import (
	"context"
	"sync"
)

// Fake is a deterministic in-memory Client for tests. Respond receives each
// request and returns the canned model output; calls are recorded for prompt
// assertions. Safe for concurrent use.
type Fake struct {
	NameStr  string
	IsLocal  bool
	Respond  func(Request) (string, error)
	mu       sync.Mutex
	requests []Request
}

func (f *Fake) Name() string {
	if f.NameStr == "" {
		return "fake/test"
	}
	return f.NameStr
}

func (f *Fake) Local() bool { return f.IsLocal }

func (f *Fake) Complete(ctx context.Context, req Request) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	return f.Respond(req)
}

// Requests returns a snapshot of every request seen so far.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Request, len(f.requests))
	copy(out, f.requests)
	return out
}
