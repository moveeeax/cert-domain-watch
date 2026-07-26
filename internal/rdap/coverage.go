// Package rdap queries and parses RDAP (RFC 9083) responses for a domain's
// registration data: expiry, registrar, transfer lock and nameservers.
//
// RDAP coverage is uneven. Some registries publish an expiration event, some
// deliberately do not, some have no RDAP service at all. This package never
// guesses: an absent field becomes an explicit unknown state that propagates
// into the report, because a wrong renewal date is worse than a missing one.
package rdap

import "strings"

// Coverage describes what a registry is expected to publish for a TLD.
type Coverage int

const (
	// CoverageUnknown means nobody has probed this TLD yet. This is the default
	// for every TLD not listed in the matrix, and it is a feature: unlisted
	// TLDs must be probed, not assumed.
	CoverageUnknown Coverage = iota
	// CoverageExpiry means the registry is expected to publish an expiration event.
	CoverageExpiry
	// CoverageNoExpiry means RDAP works but the registry withholds expiry.
	CoverageNoExpiry
	// CoverageNoRDAP means the registry publishes no RDAP service at all.
	CoverageNoRDAP
)

// String renders the coverage as the token used in JSON and the CLI matrix.
func (c Coverage) String() string {
	switch c {
	case CoverageExpiry:
		return "expiry"
	case CoverageNoExpiry:
		return "no-expiry"
	case CoverageNoRDAP:
		return "no-rdap"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the coverage as its string form.
func (c Coverage) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.String() + `"`), nil
}

// TLDCoverage is one row of the coverage matrix.
type TLDCoverage struct {
	TLD      string   `json:"tld"`
	Registry string   `json:"registry"`
	Expected Coverage `json:"expected"`
	// Verified is true only once a live probe has confirmed the expectation.
	// An unverified row is a guess and is labelled as one.
	Verified bool `json:"verified"`
	// VerifiedOn is the date of that probe, so a stale matrix is visible rather
	// than merely old. Registries change what they publish.
	VerifiedOn string `json:"verified_on,omitempty"`
	Note       string `json:"note,omitempty"`
}

// probeDate is when the verified rows below were last confirmed against live
// registries. See docs/rdap-coverage.md for the method and the raw results.
const probeDate = "2026-07-26"

// matrix holds the TLDs an agency portfolio actually contains. It is a lookup
// aid for onboarding and reporting, never a substitute for an actual lookup:
// the checker always uses what the registry said today.
var matrix = []TLDCoverage{
	{TLD: "com", Registry: "Verisign", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.verisign.com"},
	{TLD: "net", Registry: "Verisign", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.verisign.com"},
	{TLD: "org", Registry: "PIR", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.publicinterestregistry.org"},
	{TLD: "fr", Registry: "AFNIC", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.nic.fr"},
	{TLD: "co.uk", Registry: "Nominet", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.nominet.uk"},
	{TLD: "ai", Registry: "Identity Digital", Expected: CoverageExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "expiration event served by rdap.identitydigital.services"},
	{TLD: "nl", Registry: "SIDN", Expected: CoverageNoExpiry, Verified: true, VerifiedOn: probeDate,
		Note: "rdap.sidn.nl answers but publishes no expiration event; renewal must be read from the registrar"},
	{TLD: "de", Registry: "DENIC", Expected: CoverageNoRDAP, Verified: true, VerifiedOn: probeDate,
		Note: "not served through the rdap.org bootstrap; renewal dates are not automatable today"},
	{TLD: "eu", Registry: "EURid", Expected: CoverageNoRDAP, Verified: true, VerifiedOn: probeDate,
		Note: "not served through the rdap.org bootstrap; renewal dates are not automatable today"},
	{TLD: "io", Registry: "Identity Digital", Expected: CoverageNoRDAP, Verified: true, VerifiedOn: probeDate,
		Note: "not served through the rdap.org bootstrap despite .ai on the same operator being served"},
	{TLD: "uk", Registry: "Nominet", Expected: CoverageExpiry,
		Note: "inferred from co.uk on the same registry; not probed directly"},
}

// Matrix returns a copy of the coverage matrix.
func Matrix() []TLDCoverage {
	out := make([]TLDCoverage, len(matrix))
	copy(out, matrix)
	return out
}

// Lookup returns the coverage row for a domain name, matching the longest
// suffix first so co.uk wins over uk. The second return value is false when
// the TLD is not in the matrix, which callers must treat as unknown.
func Lookup(domain string) (TLDCoverage, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	var best TLDCoverage
	found := false
	for _, row := range matrix {
		suffix := "." + row.TLD
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		if !found || len(row.TLD) > len(best.TLD) {
			best, found = row, true
		}
	}
	return best, found
}
