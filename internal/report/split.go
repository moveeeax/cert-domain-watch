package report

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

// ClientResults is one client's share of a portfolio run.
type ClientResults struct {
	// Client is the client name as it appears in the portfolio.
	Client string
	// Slug is the file-name-safe form of Client, e.g. "acme-ltd".
	Slug string
	// Results are the client's domains, in input order.
	Results []watch.Result
}

// SplitByClient groups results into one set per client, ordered by client name,
// so each set can be written to its own file and forwarded on its own.
//
// Two client names that reduce to the same slug ("Acme Ltd" and "acme-ltd")
// are an error rather than a silent merge: merging would put one client's
// domains in another client's report.
func SplitByClient(results []watch.Result) ([]ClientResults, error) {
	byClient := map[string][]watch.Result{}
	for _, r := range results {
		c := clientOf(r)
		byClient[c] = append(byClient[c], r)
	}

	names := make([]string, 0, len(byClient))
	for c := range byClient {
		names = append(names, c)
	}
	sort.Strings(names)

	out := make([]ClientResults, 0, len(names))
	owner := map[string]string{}
	for _, name := range names {
		slug := Slug(name)
		if prev, ok := owner[slug]; ok {
			return nil, fmt.Errorf("clients %q and %q both map to the file name %q; rename one in the portfolio",
				prev, name, slug)
		}
		owner[slug] = name
		out = append(out, ClientResults{Client: name, Slug: slug, Results: byClient[name]})
	}
	return out, nil
}

// Slug turns a client name into a file name: lower case, letters and digits
// kept (any script), every other run of characters collapsed to one hyphen.
func Slug(name string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			hyphen = false
			continue
		}
		if b.Len() > 0 && !hyphen {
			b.WriteByte('-')
			hyphen = true
		}
	}
	s := strings.TrimSuffix(b.String(), "-")
	if s == "" {
		return "client"
	}
	return s
}
