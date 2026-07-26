// Package watch orchestrates one full check of a domain — registration data
// from RDAP plus the TLS chain of every hostname under it — and folds both into
// a single result carrying every finding.
package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
	"github.com/moveeeax/cert-domain-watch/internal/tlscheck"
)

// Target is one domain in a client's portfolio.
type Target struct {
	// Client is the agency's client this domain belongs to. Every domain
	// belongs to exactly one client.
	Client string `json:"client"`
	// Domain is the registered domain queried over RDAP, e.g. example.com.
	Domain string `json:"domain"`
	// Hosts are the hostnames whose TLS chains are inspected. Empty means
	// the apex plus www.
	Hosts []string `json:"hosts,omitempty"`
	Notes string   `json:"notes,omitempty"`
}

// EffectiveHosts returns the hostnames to inspect, defaulting to apex and www.
func (t Target) EffectiveHosts() []string {
	if len(t.Hosts) > 0 {
		return t.Hosts
	}
	return []string{t.Domain, "www." + t.Domain}
}

// Result is the structured outcome for one domain: the JSON row that later
// becomes a database record, an alert and a line in the monthly client report.
type Result struct {
	Client       string            `json:"client"`
	Domain       string            `json:"domain"`
	CheckedAt    time.Time         `json:"checked_at"`
	Registration *rdap.Domain      `json:"registration,omitempty"`
	Coverage     rdap.TLDCoverage  `json:"tld_coverage"`
	TLS          []tlscheck.Result `json:"tls"`
	Findings     []finding.Finding `json:"findings"`
	Severity     finding.Severity  `json:"severity"`
}

// RDAPLookup is the RDAP surface watch depends on, so tests can inject a
// fixture-backed lookup instead of reaching the network.
type RDAPLookup interface {
	Lookup(ctx context.Context, domain string, now time.Time) (*rdap.Domain, error)
}

// TLSCheck is the certificate surface watch depends on.
type TLSCheck interface {
	Check(ctx context.Context, host string, now time.Time) tlscheck.Result
}

// Checker runs checks for targets.
type Checker struct {
	RDAP RDAPLookup
	TLS  TLSCheck
	// SkipTLS turns off certificate inspection, for RDAP-only runs.
	SkipTLS bool
	// SkipRDAP turns off registration lookups, for TLS-only runs.
	SkipRDAP bool
}

// Check runs every enabled check for one target and merges the findings.
func (c *Checker) Check(ctx context.Context, t Target, now time.Time) Result {
	res := Result{
		Client:    t.Client,
		Domain:    strings.ToLower(strings.TrimSpace(t.Domain)),
		CheckedAt: now.UTC(),
	}
	res.Coverage, _ = rdap.Lookup(res.Domain)

	if !c.SkipRDAP && c.RDAP != nil {
		reg, err := c.RDAP.Lookup(ctx, res.Domain, now)
		if err != nil {
			res.Findings = append(res.Findings, rdapErrorFinding(res.Domain, err))
		} else {
			res.Registration = reg
			res.Findings = append(res.Findings, registrationFindings(res.Domain, reg)...)
		}
	}

	if !c.SkipTLS && c.TLS != nil {
		for _, host := range t.EffectiveHosts() {
			tr := c.TLS.Check(ctx, host, now)
			for i := range tr.Findings {
				tr.Findings[i].Scope = host
			}
			res.Findings = append(res.Findings, tr.Findings...)
			res.TLS = append(res.TLS, tr)
		}
	}

	finding.SortBySeverity(res.Findings)
	res.Severity = finding.Worst(res.Findings)
	return res
}

func rdapErrorFinding(domain string, err error) finding.Finding {
	switch {
	case errors.Is(err, rdap.ErrNotFound):
		return finding.Finding{
			Code:     finding.DomainExpiryUnknown,
			Severity: finding.Critical,
			Scope:    domain,
			Message:  "registry reports no such domain — it may have been dropped or never registered",
		}
	case errors.Is(err, rdap.ErrNoService):
		return finding.Finding{
			Code:     finding.RDAPUnavailable,
			Severity: finding.Info,
			Scope:    domain,
			Message:  "no RDAP service for this TLD; registration expiry cannot be checked automatically",
		}
	default:
		return finding.Finding{
			Code:     finding.RDAPUnavailable,
			Severity: finding.Warning,
			Scope:    domain,
			Message:  "RDAP lookup failed: " + err.Error(),
		}
	}
}

func registrationFindings(domain string, d *rdap.Domain) []finding.Finding {
	var out []finding.Finding

	switch d.ExpiryState {
	case rdap.ExpiryKnown:
		days := 0
		if d.DaysToExpiry != nil {
			days = *d.DaysToExpiry
		}
		date := d.Expiry.UTC().Format(time.DateOnly)
		switch {
		case days < 0:
			out = append(out, finding.Finding{
				Code:     finding.DomainExpired,
				Severity: finding.Critical,
				Scope:    domain,
				Message:  fmt.Sprintf("domain registration expired on %s, %d day(s) ago", date, -days),
			})
		case days <= DomainCriticalDays:
			out = append(out, finding.Finding{
				Code:     finding.DomainExpiring,
				Severity: finding.Critical,
				Scope:    domain,
				Message:  fmt.Sprintf("domain registration expires in %d day(s), on %s", days, date),
			})
		case days <= DomainWarningDays:
			out = append(out, finding.Finding{
				Code:     finding.DomainExpiring,
				Severity: finding.Warning,
				Scope:    domain,
				Message:  fmt.Sprintf("domain registration expires in %d day(s), on %s", days, date),
			})
		}
	default:
		out = append(out, finding.Finding{
			Code:     finding.DomainExpiryUnknown,
			Severity: finding.Warning,
			Scope:    domain,
			Message: "registry publishes no expiration date over RDAP — renewal must be confirmed " +
				"in the registrar account",
		})
	}

	switch d.TransferLock {
	case rdap.No:
		out = append(out, finding.Finding{
			Code:     finding.TransferLockOff,
			Severity: finding.Warning,
			Scope:    domain,
			Message:  "transfer lock is off; the domain can be moved to another registrar without a lock release",
		})
	case rdap.Unknown:
		out = append(out, finding.Finding{
			Code:     finding.TransferLockUnknown,
			Severity: finding.Info,
			Scope:    domain,
			Message:  "registry publishes no status codes; transfer lock state is unknown",
		})
	}
	return out
}
