// Package threatlib is Argus's curated STRIDE threat library: for each common
// component type (web app, API service, database, object store, auth service,
// …) it holds hand-authored, contributable per-category threats, each pre-wired
// to a suggested mitigation (a weakness id in internal/mitigation) and the
// compliance controls it touches.
//
// It is the deterministic anchor of threat modeling, the same pattern as the
// mitigation library: enumerating STRIDE for a component looks its tech up here
// and emits reviewable, versioned threats — no model. An optional LLM pass may
// only SUGGEST additional threats (source="assisted", human-confirmed); it is
// never the source of truth for risk. Adding a component type is a data-only
// change: drop in JSON, no code.
package threatlib

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed data/*.json
var dataFS embed.FS

// STRIDE categories, the closed set a threat's category must belong to.
var strideCategories = map[string]bool{
	"spoofing": true, "tampering": true, "repudiation": true,
	"info-disclosure": true, "denial-of-service": true, "elevation": true,
}

// ValidCategory reports whether c is a STRIDE category.
func ValidCategory(c string) bool { return strideCategories[c] }

// Threat is one curated STRIDE threat for a component type.
type Threat struct {
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Mitigation  string   `json:"mitigation,omitempty"` // weakness id in internal/mitigation
	Controls    []string `json:"controls,omitempty"`   // e.g. "ASVS:V5.3.4"
}

// Component is the library entry for one component type (tech).
type Component struct {
	Tech    string   `json:"tech"`
	Title   string   `json:"title"`
	Threats []Threat `json:"threats"`
}

var (
	loadOnce sync.Once
	loadErr  error
	byTech   map[string]Component
	order    []string
)

func load() {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		loadErr = fmt.Errorf("threatlib: read data dir: %w", err)
		return
	}
	byTech = map[string]Component{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := dataFS.ReadFile("data/" + e.Name())
		if err != nil {
			loadErr = fmt.Errorf("threatlib: read %s: %w", e.Name(), err)
			return
		}
		var c Component
		if err := json.Unmarshal(raw, &c); err != nil {
			loadErr = fmt.Errorf("threatlib: parse %s: %w", e.Name(), err)
			return
		}
		if c.Tech == "" {
			loadErr = fmt.Errorf("threatlib: %s has no tech id", e.Name())
			return
		}
		if _, dup := byTech[c.Tech]; dup {
			loadErr = fmt.Errorf("threatlib: duplicate tech id %q", c.Tech)
			return
		}
		for _, th := range c.Threats {
			if !strideCategories[th.Category] {
				loadErr = fmt.Errorf("threatlib: %s threat %q has invalid category %q", c.Tech, th.Title, th.Category)
				return
			}
		}
		byTech[c.Tech] = c
		order = append(order, c.Tech)
	}
	sort.Strings(order)
}

func ensureLoaded() error {
	loadOnce.Do(load)
	return loadErr
}

// Enumerate returns the curated STRIDE threats for a component tech. ok is false
// when the library has no entry for that tech (the caller can still add threats
// by hand).
func Enumerate(tech string) ([]Threat, bool) {
	if ensureLoaded() != nil {
		return nil, false
	}
	c, ok := byTech[strings.ToLower(strings.TrimSpace(tech))]
	if !ok {
		return nil, false
	}
	return c.Threats, true
}

// Components returns every library entry, sorted by tech, for the component-type
// picker.
func Components() []Component {
	if ensureLoaded() != nil {
		return nil
	}
	out := make([]Component, 0, len(order))
	for _, t := range order {
		out = append(out, byTech[t])
	}
	return out
}
