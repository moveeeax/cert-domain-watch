package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
	"github.com/moveeeax/cert-domain-watch/internal/tlscheck"
	"github.com/moveeeax/cert-domain-watch/internal/watch"
)

var update = flag.Bool("update", false, "rewrite the golden report files")

var refTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// sample is the fixture portfolio: one client in trouble, one client with a
// registry that publishes nothing, one clean domain.
func sample() []watch.Result {
	comCoverage, _ := rdap.Lookup("example.com")
	deCoverage, _ := rdap.Lookup("beispiel.de")

	expiry := time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)
	renewed := time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC)

	return []watch.Result{
		{
			Client:    "Acme Ltd",
			Domain:    "example.com",
			CheckedAt: refTime,
			Coverage:  comCoverage,
			Registration: &rdap.Domain{
				Name:         "example.com",
				Registrar:    "Example Registrar, Inc.",
				Expiry:       &expiry,
				ExpiryState:  rdap.ExpiryKnown,
				DaysToExpiry: ptr(10),
				TransferLock: rdap.No,
				Nameservers:  []string{"ns1.example-dns.net", "ns2.example-dns.net"},
			},
			TLS: []tlscheck.Result{{
				Host:         "www.example.com",
				Checked:      true,
				DaysToExpiry: ptr(-4),
				Leaf: &tlscheck.Certificate{
					NotAfter: time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC),
				},
			}},
			Findings: []finding.Finding{
				{
					Code:     finding.CertExpired,
					Severity: finding.Critical,
					Scope:    "www.example.com",
					Message:  "certificate expired 4 day(s) ago, on 2026-02-25",
				},
				{
					Code:     finding.DomainExpiring,
					Severity: finding.Critical,
					Scope:    "example.com",
					Message:  "domain registration expires in 10 day(s), on 2026-03-12",
				},
				{
					Code:     finding.TransferLockOff,
					Severity: finding.Warning,
					Scope:    "example.com",
					Message:  "transfer lock is off; the domain can be moved to another registrar without a lock release",
				},
			},
			Severity: finding.Critical,
		},
		{
			Client:    "Beta GmbH",
			Domain:    "beispiel.de",
			CheckedAt: refTime,
			Coverage:  deCoverage,
			Registration: &rdap.Domain{
				Name:         "beispiel.de",
				ExpiryState:  rdap.ExpiryNotPublished,
				TransferLock: rdap.Unknown,
			},
			Findings: []finding.Finding{
				{
					Code:     finding.DomainExpiryUnknown,
					Severity: finding.Warning,
					Scope:    "beispiel.de",
					Message: "registry publishes no expiration date over RDAP — renewal must be confirmed " +
						"in the registrar account",
				},
			},
			Severity: finding.Warning,
		},
		{
			Client:    "Beta GmbH",
			Domain:    "beispiel.com",
			CheckedAt: refTime,
			Coverage:  comCoverage,
			Registration: &rdap.Domain{
				Name:         "beispiel.com",
				Registrar:    "Placeholder Registrar Ltd",
				Expiry:       &renewed,
				ExpiryState:  rdap.ExpiryKnown,
				DaysToExpiry: ptr(309),
				TransferLock: rdap.Yes,
			},
			Severity: finding.Info,
		},
	}
}

func TestMarkdownGolden(t *testing.T) {
	got := Markdown(sample(), Options{Agency: "Northbound Digital", GeneratedAt: refTime})

	golden := filepath.Join("testdata", "audit.golden.md")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run: go test ./internal/report -update): %v", err)
	}
	if got != string(want) {
		t.Errorf("report does not match golden file.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The client with critical findings must come first: the report is read top
// down by an account manager who has five minutes.
func TestMarkdownOrdersWorstClientFirst(t *testing.T) {
	out := Markdown(sample(), Options{GeneratedAt: refTime})
	acme := strings.Index(out, "## Acme Ltd")
	beta := strings.Index(out, "## Beta GmbH")
	if acme < 0 || beta < 0 {
		t.Fatalf("both clients should appear:\n%s", out)
	}
	if acme > beta {
		t.Error("the client with critical findings must be listed first")
	}
}

// A registry that publishes no expiry must be called out in the deliverable.
// A clean-looking report that hides a blind spot is the worst possible outcome.
func TestMarkdownAlwaysExplainsCoverageGaps(t *testing.T) {
	out := Markdown(sample(), Options{GeneratedAt: refTime})
	if !strings.Contains(out, "## Coverage notes") {
		t.Fatal("expected a coverage notes section")
	}
	if !strings.Contains(out, "`.de`") {
		t.Errorf("coverage notes should name .de:\n%s", out)
	}
	if strings.Contains(out, "`.com`") {
		t.Error(".com resolved fine and must not appear as a coverage gap")
	}
}

func TestMarkdownEmptyPortfolio(t *testing.T) {
	out := Markdown(nil, Options{GeneratedAt: refTime})
	if !strings.Contains(out, "No domains were checked.") {
		t.Errorf("unexpected output for an empty portfolio:\n%s", out)
	}
}
