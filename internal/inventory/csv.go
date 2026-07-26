// Package inventory loads a portfolio of domains from a file. Onboarding an
// agency means getting a hundred domains in without typing them, so the reader
// accepts both a proper CSV and the plain list people actually paste first.
package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

// knownColumns maps accepted header names onto fields.
var knownColumns = map[string]string{
	"client":      "client",
	"client_name": "client",
	"customer":    "client",
	"account":     "client",
	"domain":      "domain",
	"name":        "domain",
	"zone":        "domain",
	"hosts":       "hosts",
	"hostnames":   "hosts",
	"notes":       "notes",
	"note":        "notes",
}

// LoadFile reads a portfolio from path.
func LoadFile(path string) ([]watch.Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Load reads a portfolio from r.
//
// A header row is required for CSV mode and may name the columns in any order
// and any case. If the first non-empty line has no comma, the whole file is
// read as one domain per line under the client "unassigned".
func Load(r io.Reader) ([]watch.Target, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}
	if !strings.Contains(firstMeaningfulLine(text), ",") {
		return loadPlain(text), nil
	}

	cr := csv.NewReader(strings.NewReader(text))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}

	index := map[string]int{}
	for i, h := range records[0] {
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		if field, ok := knownColumns[key]; ok {
			index[field] = i
		}
	}
	if _, ok := index["domain"]; !ok {
		return nil, fmt.Errorf("csv header has no domain column (accepted: domain, name, zone)")
	}

	var out []watch.Target
	seen := map[string]bool{}
	for lineNo, rec := range records[1:] {
		domain := normaliseDomain(field(rec, index, "domain"))
		if domain == "" {
			continue
		}
		if seen[domain] {
			return nil, fmt.Errorf("line %d: domain %q appears twice; every domain belongs to exactly one client",
				lineNo+2, domain)
		}
		seen[domain] = true

		client := strings.TrimSpace(field(rec, index, "client"))
		if client == "" {
			client = "unassigned"
		}
		out = append(out, watch.Target{
			Client: client,
			Domain: domain,
			Hosts:  splitHosts(field(rec, index, "hosts")),
			Notes:  strings.TrimSpace(field(rec, index, "notes")),
		})
	}
	return out, nil
}

func loadPlain(text string) []watch.Target {
	var out []watch.Target
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := normaliseDomain(line)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, watch.Target{Client: "unassigned", Domain: d})
	}
	return out
}

func firstMeaningfulLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			return s
		}
	}
	return ""
}

func field(rec []string, index map[string]int, name string) string {
	i, ok := index[name]
	if !ok || i >= len(rec) {
		return ""
	}
	return rec[i]
}

// normaliseDomain strips the things people paste by accident: a scheme, a path,
// a trailing dot, a leading www on the apex, stray case.
func normaliseDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "www.")
	if !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func splitHosts(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ';' || r == '|' || r == '\t'
	})
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
