// Package report renders check results as the artefact an agency actually
// pays for: a per-client sheet its account manager can forward to the client
// without editing. Markdown first, because it pastes into email and Notion;
// the PDF renderer in a later phase consumes the same structure.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

// Options control the report header.
type Options struct {
	// Agency is the name printed in the title, e.g. the agency being pitched.
	Agency string
	// GeneratedAt is the timestamp in the header; pass a fixed value in tests.
	GeneratedAt time.Time
}

// Markdown renders a full audit for a set of results, grouped by client and
// ordered worst-first so the reader's eye lands on the thing that will break.
func Markdown(results []watch.Result, opts Options) string {
	var b strings.Builder

	title := "Domain & certificate audit"
	if opts.Agency != "" {
		title += " — " + opts.Agency
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Generated %s UTC by cert-domain-watch.\n\n",
		opts.GeneratedAt.UTC().Format("2006-01-02 15:04"))

	if len(results) == 0 {
		b.WriteString("No domains were checked.\n")
		return b.String()
	}

	writeSummary(&b, results)
	writeClients(&b, results)
	writeCoverageNotes(&b, results)
	return b.String()
}

func writeSummary(b *strings.Builder, results []watch.Result) {
	counts := map[finding.Severity]int{}
	clients := map[string]bool{}
	for _, r := range results {
		clients[clientOf(r)] = true
		for _, f := range r.Findings {
			counts[f.Severity]++
		}
	}

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(b, "- Clients: **%d**\n", len(clients))
	fmt.Fprintf(b, "- Domains checked: **%d**\n", len(results))
	fmt.Fprintf(b, "- Critical findings: **%d**\n", counts[finding.Critical])
	fmt.Fprintf(b, "- Warnings: **%d**\n", counts[finding.Warning])
	fmt.Fprintf(b, "- Informational: **%d**\n\n", counts[finding.Info])
}

func writeClients(b *strings.Builder, results []watch.Result) {
	byClient := map[string][]watch.Result{}
	for _, r := range results {
		c := clientOf(r)
		byClient[c] = append(byClient[c], r)
	}

	names := make([]string, 0, len(byClient))
	for c := range byClient {
		names = append(names, c)
	}
	// Clients with the most critical findings first; ties broken by name so the
	// output is stable across runs.
	sort.SliceStable(names, func(i, j int) bool {
		ci, cj := criticals(byClient[names[i]]), criticals(byClient[names[j]])
		if ci != cj {
			return ci > cj
		}
		return names[i] < names[j]
	})

	for _, name := range names {
		rows := byClient[name]
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Severity != rows[j].Severity {
				return rows[i].Severity > rows[j].Severity
			}
			return rows[i].Domain < rows[j].Domain
		})

		fmt.Fprintf(b, "## %s\n\n", name)
		b.WriteString("| Domain | Registrar | Registration expiry | Transfer lock | Certificate | Status |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for _, r := range rows {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
				r.Domain, registrarCell(r), expiryCell(r), lockCell(r), certCell(r), statusCell(r))
		}
		b.WriteString("\n")

		for _, r := range rows {
			if len(r.Findings) == 0 {
				continue
			}
			fmt.Fprintf(b, "### %s\n\n", r.Domain)
			for _, f := range r.Findings {
				scope := ""
				if f.Scope != "" && f.Scope != r.Domain {
					scope = fmt.Sprintf(" (`%s`)", f.Scope)
				}
				fmt.Fprintf(b, "- **%s** `%s`%s — %s\n",
					strings.ToUpper(f.Severity.String()), f.Code, scope, f.Message)
			}
			b.WriteString("\n")
		}
	}
}

// writeCoverageNotes exists because "we could not determine the expiry" must be
// visible in the deliverable. An agency that reads a clean report and later
// loses a .de domain would be right to blame the report.
func writeCoverageNotes(b *strings.Builder, results []watch.Result) {
	notes := map[string]string{}
	for _, r := range results {
		if r.Registration != nil && r.Registration.ExpiryState == rdap.ExpiryKnown {
			continue
		}
		tld := r.Coverage.TLD
		if tld == "" {
			tld = tldOf(r.Domain)
		}
		note := r.Coverage.Note
		if note == "" {
			note = "registry does not publish a registration expiry over RDAP"
		}
		if r.Coverage.Registry != "" {
			note = r.Coverage.Registry + ": " + note
		}
		notes["."+tld] = note
	}
	if len(notes) == 0 {
		return
	}

	keys := make([]string, 0, len(notes))
	for k := range notes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b.WriteString("## Coverage notes\n\n")
	b.WriteString("Renewal dates below could not be confirmed automatically and must be checked " +
		"in the registrar account.\n\n")
	for _, k := range keys {
		fmt.Fprintf(b, "- `%s` — %s\n", k, notes[k])
	}
	b.WriteString("\n")
}

func clientOf(r watch.Result) string {
	if r.Client == "" {
		return "unassigned"
	}
	return r.Client
}

func criticals(rows []watch.Result) int {
	n := 0
	for _, r := range rows {
		for _, f := range r.Findings {
			if f.Severity == finding.Critical {
				n++
			}
		}
	}
	return n
}

func registrarCell(r watch.Result) string {
	if r.Registration == nil || r.Registration.Registrar == "" {
		return "unknown"
	}
	return r.Registration.Registrar
}

func expiryCell(r watch.Result) string {
	if r.Registration == nil {
		return "unknown"
	}
	if r.Registration.ExpiryState != rdap.ExpiryKnown || r.Registration.Expiry == nil {
		return "not published"
	}
	s := r.Registration.Expiry.UTC().Format(time.DateOnly)
	if r.Registration.DaysToExpiry != nil {
		s += fmt.Sprintf(" (%d d)", *r.Registration.DaysToExpiry)
	}
	return s
}

func lockCell(r watch.Result) string {
	if r.Registration == nil {
		return "unknown"
	}
	switch r.Registration.TransferLock {
	case rdap.Yes:
		return "locked"
	case rdap.No:
		return "**off**"
	default:
		return "unknown"
	}
}

func certCell(r watch.Result) string {
	best := ""
	for _, t := range r.TLS {
		if t.DaysToExpiry == nil || t.Leaf == nil {
			continue
		}
		cell := fmt.Sprintf("%s (%d d)", t.Leaf.NotAfter.UTC().Format(time.DateOnly), *t.DaysToExpiry)
		if best == "" {
			best = cell
		}
	}
	if best == "" {
		return "not checked"
	}
	return best
}

func statusCell(r watch.Result) string {
	if len(r.Findings) == 0 {
		return "OK"
	}
	c := finding.Count(r.Findings)
	var parts []string
	if c[finding.Critical] > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", c[finding.Critical]))
	}
	if c[finding.Warning] > 0 {
		parts = append(parts, fmt.Sprintf("%d warning", c[finding.Warning]))
	}
	if c[finding.Info] > 0 {
		parts = append(parts, fmt.Sprintf("%d info", c[finding.Info]))
	}
	return strings.Join(parts, ", ")
}

func tldOf(domain string) string {
	if i := strings.Index(domain, "."); i >= 0 && i+1 < len(domain) {
		return domain[i+1:]
	}
	return domain
}
