package report

import (
	"strings"
	"testing"

	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

func TestSlug(t *testing.T) {
	tests := map[string]string{
		"Acme Ltd":             "acme-ltd",
		"  Beta GmbH  ":        "beta-gmbh",
		"O'Neill & Sons, Inc.": "o-neill-sons-inc",
		"Müller Bäckerei":      "müller-bäckerei",
		"../../etc/passwd":     "etc-passwd",
		"unassigned":           "unassigned",
		"***":                  "client",
		"":                     "client",
	}
	for in, want := range tests {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitByClient(t *testing.T) {
	groups, err := SplitByClient(sample())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	if groups[0].Client != "Acme Ltd" || groups[0].Slug != "acme-ltd" || len(groups[0].Results) != 1 {
		t.Errorf("first group = %s/%s with %d result(s)", groups[0].Client, groups[0].Slug, len(groups[0].Results))
	}
	beta := groups[1]
	if beta.Client != "Beta GmbH" || beta.Slug != "beta-gmbh" || len(beta.Results) != 2 {
		t.Fatalf("second group = %s/%s with %d result(s)", beta.Client, beta.Slug, len(beta.Results))
	}
	// Input order is kept inside a group.
	if beta.Results[0].Domain != "beispiel.de" || beta.Results[1].Domain != "beispiel.com" {
		t.Errorf("Beta GmbH results out of input order: %s, %s", beta.Results[0].Domain, beta.Results[1].Domain)
	}
}

func TestSplitByClientRejectsSlugCollision(t *testing.T) {
	_, err := SplitByClient([]watch.Result{
		{Client: "Acme Ltd", Domain: "a.example"},
		{Client: "acme-ltd", Domain: "b.example"},
	})
	if err == nil || !strings.Contains(err.Error(), "acme-ltd") {
		t.Fatalf("err = %v, want a slug collision error", err)
	}
}

func TestSplitByClientUnassigned(t *testing.T) {
	groups, err := SplitByClient([]watch.Result{{Domain: "a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Client != "unassigned" || groups[0].Slug != "unassigned" {
		t.Errorf("unexpected groups: %+v", groups)
	}
}
