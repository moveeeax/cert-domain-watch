package watch

import (
	"context"
	"testing"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
	"github.com/moveeeax/cert-domain-watch/internal/tlscheck"
)

var refTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// fakeRDAP returns a canned answer or error, so watch is tested without a
// network and without depending on any registry being up.
type fakeRDAP struct {
	domain *rdap.Domain
	err    error
}

func (f fakeRDAP) Lookup(context.Context, string, time.Time) (*rdap.Domain, error) {
	return f.domain, f.err
}

type fakeTLS struct {
	byHost map[string]tlscheck.Result
}

func (f fakeTLS) Check(_ context.Context, host string, _ time.Time) tlscheck.Result {
	if r, ok := f.byHost[host]; ok {
		return r
	}
	return tlscheck.Result{Host: host, Checked: true}
}

func ptr[T any](v T) *T { return &v }

func registration(days int, lock rdap.Tristate, ns ...string) *rdap.Domain {
	exp := refTime.AddDate(0, 0, days)
	return &rdap.Domain{
		Name:         "example.com",
		Registrar:    "Example Registrar, Inc.",
		Expiry:       &exp,
		ExpiryState:  rdap.ExpiryKnown,
		DaysToExpiry: ptr(days),
		TransferLock: lock,
		Nameservers:  ns,
	}
}

func codes(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f.Code))
	}
	return out
}

func has(fs []finding.Finding, want finding.Code) bool {
	for _, f := range fs {
		if f.Code == want {
			return true
		}
	}
	return false
}

func TestCheckHealthyDomain(t *testing.T) {
	c := &Checker{
		RDAP: fakeRDAP{domain: registration(200, rdap.Yes, "ns1.example-dns.net")},
		TLS:  fakeTLS{},
	}
	res := c.Check(context.Background(), Target{Client: "Acme", Domain: "example.com"}, refTime)

	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %v", codes(res.Findings))
	}
	if res.Severity != finding.Info {
		t.Errorf("severity = %s, want info", res.Severity)
	}
	if len(res.TLS) != 2 {
		t.Errorf("expected apex and www to be checked, got %d hosts", len(res.TLS))
	}
	if res.Coverage.TLD != "com" {
		t.Errorf("coverage tld = %q, want com", res.Coverage.TLD)
	}
}

func TestCheckDomainExpiryLadder(t *testing.T) {
	tests := []struct {
		days     int
		wantCode finding.Code
		wantSev  finding.Severity
		wantNone bool
	}{
		{days: 200, wantNone: true},
		{days: 61, wantNone: true},
		{days: 60, wantCode: finding.DomainExpiring, wantSev: finding.Warning},
		{days: 15, wantCode: finding.DomainExpiring, wantSev: finding.Warning},
		{days: 14, wantCode: finding.DomainExpiring, wantSev: finding.Critical},
		{days: -2, wantCode: finding.DomainExpired, wantSev: finding.Critical},
	}
	for _, tc := range tests {
		c := &Checker{RDAP: fakeRDAP{domain: registration(tc.days, rdap.Yes)}, SkipTLS: true}
		res := c.Check(context.Background(), Target{Domain: "example.com"}, refTime)

		if tc.wantNone {
			if len(res.Findings) != 0 {
				t.Errorf("days=%d: expected no findings, got %v", tc.days, codes(res.Findings))
			}
			continue
		}
		if !has(res.Findings, tc.wantCode) {
			t.Errorf("days=%d: expected %s, got %v", tc.days, tc.wantCode, codes(res.Findings))
			continue
		}
		if res.Severity != tc.wantSev {
			t.Errorf("days=%d: severity = %s, want %s", tc.days, res.Severity, tc.wantSev)
		}
	}
}

func TestCheckUnknownExpiryIsReportedNotAssumed(t *testing.T) {
	c := &Checker{
		RDAP: fakeRDAP{domain: &rdap.Domain{
			Name:         "example.de",
			ExpiryState:  rdap.ExpiryNotPublished,
			TransferLock: rdap.Unknown,
		}},
		SkipTLS: true,
	}
	res := c.Check(context.Background(), Target{Domain: "example.de"}, refTime)

	if !has(res.Findings, finding.DomainExpiryUnknown) {
		t.Fatalf("expected an explicit unknown-expiry finding, got %v", codes(res.Findings))
	}
	if !has(res.Findings, finding.TransferLockUnknown) {
		t.Errorf("expected an explicit unknown-lock finding, got %v", codes(res.Findings))
	}
	// An unknown expiry must never be silently treated as fine.
	if res.Severity != finding.Warning {
		t.Errorf("severity = %s, want warning", res.Severity)
	}
}

func TestCheckTransferLockOff(t *testing.T) {
	c := &Checker{RDAP: fakeRDAP{domain: registration(300, rdap.No)}, SkipTLS: true}
	res := c.Check(context.Background(), Target{Domain: "example.com"}, refTime)

	if !has(res.Findings, finding.TransferLockOff) {
		t.Fatalf("expected transfer-lock-off finding, got %v", codes(res.Findings))
	}
}

func TestCheckRDAPNotFoundIsCritical(t *testing.T) {
	c := &Checker{RDAP: fakeRDAP{err: rdap.ErrNotFound}, SkipTLS: true}
	res := c.Check(context.Background(), Target{Domain: "dropped.example.com"}, refTime)

	if res.Severity != finding.Critical {
		t.Fatalf("a domain the registry no longer knows must be critical, got %s", res.Severity)
	}
}

func TestCheckRDAPUnsupportedTLDIsInfo(t *testing.T) {
	c := &Checker{RDAP: fakeRDAP{err: rdap.ErrNoService}, SkipTLS: true}
	res := c.Check(context.Background(), Target{Domain: "example.zzz"}, refTime)

	if !has(res.Findings, finding.RDAPUnavailable) {
		t.Fatalf("expected rdap_unavailable, got %v", codes(res.Findings))
	}
	if res.Severity != finding.Info {
		t.Errorf("severity = %s, want info: a TLD without RDAP is a gap, not an incident", res.Severity)
	}
}

func TestCheckAttachesHostScopeToTLSFindings(t *testing.T) {
	c := &Checker{
		RDAP: fakeRDAP{domain: registration(300, rdap.Yes)},
		TLS: fakeTLS{byHost: map[string]tlscheck.Result{
			"shop.example.com": {
				Host:         "shop.example.com",
				Checked:      true,
				DaysToExpiry: ptr(3),
				Findings: []finding.Finding{{
					Code:     finding.CertExpiring,
					Severity: finding.Critical,
					Message:  "certificate expires in 3 day(s)",
				}},
			},
		}},
	}
	res := c.Check(context.Background(), Target{
		Domain: "example.com",
		Hosts:  []string{"shop.example.com"},
	}, refTime)

	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %v", codes(res.Findings))
	}
	if res.Findings[0].Scope != "shop.example.com" {
		t.Errorf("scope = %q, want shop.example.com", res.Findings[0].Scope)
	}
}

func TestCheckSortsWorstFirst(t *testing.T) {
	c := &Checker{
		RDAP: fakeRDAP{domain: registration(20, rdap.No)}, // warning + warning
		TLS: fakeTLS{byHost: map[string]tlscheck.Result{
			"example.com": {
				Host:    "example.com",
				Checked: true,
				Findings: []finding.Finding{{
					Code:     finding.CertExpired,
					Severity: finding.Critical,
					Message:  "expired",
				}},
			},
		}},
	}
	res := c.Check(context.Background(), Target{Domain: "example.com"}, refTime)

	if len(res.Findings) < 2 {
		t.Fatalf("expected several findings, got %v", codes(res.Findings))
	}
	if res.Findings[0].Severity != finding.Critical {
		t.Errorf("first finding = %s, want the critical one first", res.Findings[0].Severity)
	}
}

func TestEffectiveHosts(t *testing.T) {
	if got := (Target{Domain: "example.com"}).EffectiveHosts(); len(got) != 2 ||
		got[0] != "example.com" || got[1] != "www.example.com" {
		t.Errorf("default hosts = %v", got)
	}
	explicit := Target{Domain: "example.com", Hosts: []string{"api.example.com"}}
	if got := explicit.EffectiveHosts(); len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("explicit hosts = %v", got)
	}
}
