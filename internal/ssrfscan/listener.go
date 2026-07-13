// Package ssrfscan detects server-side request forgery by injecting URLs that
// point at a listener Argus runs itself, then observing whether the target's
// server connects back. It never uses a third-party out-of-band service, so the
// network-free discipline holds: the only callback endpoint is local.
package ssrfscan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Listener is a local out-of-band HTTP listener bound to 127.0.0.1. A probe URL
// points at it with a unique token; the target fetching that URL is proof of
// SSRF. It records which tokens were received, and serves a per-token marker so
// an in-band reflection can be detected too.
type Listener struct {
	srv  *http.Server
	ln   net.Listener
	base string

	mu   sync.Mutex
	hits map[string]Callback
}

// Callback is what the listener observed when a probe URL was fetched: the
// source address and when, never a secret.
type Callback struct {
	RemoteAddr string
	At         time.Time
}

// markerPrefix is embedded in each token's served body so an in-band reflection
// (the target echoing the fetched content) is detectable in the scan response.
const markerPrefix = "ARGUS-OOB-"

// NewListener binds a local out-of-band listener on 127.0.0.1 (an ephemeral
// port) and starts serving. Close it when the scan is done.
func NewListener() (*Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ssrf: bind oob listener: %w", err)
	}
	l := &Listener{
		ln:   ln,
		base: "http://" + ln.Addr().String(),
		hits: map[string]Callback{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oob/", l.handle)
	l.srv = &http.Server{Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	go l.srv.Serve(ln)
	return l, nil
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/oob/")
	token = strings.SplitN(token, "/", 2)[0]
	if token != "" {
		l.mu.Lock()
		if _, seen := l.hits[token]; !seen {
			l.hits[token] = Callback{RemoteAddr: r.RemoteAddr, At: time.Now().UTC()}
		}
		l.mu.Unlock()
	}
	io.WriteString(w, markerPrefix+token)
}

// NewToken returns a fresh CSPRNG token for one probe.
func (l *Listener) NewToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// URLFor is the probe URL for a token: the callback the target would fetch.
func (l *Listener) URLFor(token string) string {
	return l.base + "/oob/" + token
}

// Marker is the body the listener serves for a token, for in-band detection.
func Marker(token string) string { return markerPrefix + token }

// Hit reports whether a token's probe URL was fetched, and the callback details.
func (l *Listener) Hit(token string) (Callback, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.hits[token]
	return c, ok
}

// Close stops the listener.
func (l *Listener) Close() {
	if l.srv != nil {
		_ = l.srv.Close()
	}
}
