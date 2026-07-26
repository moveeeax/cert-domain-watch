// Package finding defines the vocabulary every check speaks: a stable code, a
// severity and a human sentence. Reports, JSON output and the alert dedup key
// all derive from these, so codes are part of the public contract.
package finding

import "sort"

// Severity ranks a finding. Higher values are worse and sort first in reports.
type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

// String renders the severity as the lowercase token used in JSON and reports.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Warning:
		return "warning"
	case Info:
		return "info"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the severity as its string form.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Code identifies a rule. Codes are stable: reports and the alert dedup key
// both depend on them, so they must not be renamed casually.
type Code string

const (
	CertExpired          Code = "cert_expired"
	CertExpiring         Code = "cert_expiring"
	CertNotYetValid      Code = "cert_not_yet_valid"
	CertHostnameMismatch Code = "cert_hostname_mismatch"
	CertSelfSigned       Code = "cert_self_signed"
	CertIncompleteChain  Code = "cert_incomplete_chain"
	CertBrokenChain      Code = "cert_chain_broken"
	CertWeakSignature    Code = "cert_weak_signature"
	CertWeakKey          Code = "cert_weak_key"
	TLSUnreachable       Code = "tls_unreachable"

	DomainExpired       Code = "domain_expired"
	DomainExpiring      Code = "domain_expiring"
	DomainExpiryUnknown Code = "domain_expiry_unknown"
	TransferLockOff     Code = "domain_transfer_lock_off"
	TransferLockUnknown Code = "domain_transfer_lock_unknown"
	NameserverDrift     Code = "nameserver_drift"
	RDAPUnavailable     Code = "rdap_unavailable"
)

// Finding is one problem detected on one target.
type Finding struct {
	Code     Code     `json:"code"`
	Severity Severity `json:"severity"`
	// Scope names what the finding is about: the domain itself, or the
	// specific hostname whose certificate was inspected.
	Scope   string `json:"scope,omitempty"`
	Message string `json:"message"`
}

// Worst returns the highest severity present, or Info for an empty slice.
func Worst(fs []Finding) Severity {
	worst := Info
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

// Count returns how many findings carry each severity.
func Count(fs []Finding) map[Severity]int {
	out := map[Severity]int{}
	for _, f := range fs {
		out[f.Severity]++
	}
	return out
}

// SortBySeverity orders findings worst-first, then by scope, then by code, so
// report output is deterministic.
func SortBySeverity(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Scope != fs[j].Scope {
			return fs[i].Scope < fs[j].Scope
		}
		return fs[i].Code < fs[j].Code
	})
}
