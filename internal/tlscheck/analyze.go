// Package tlscheck inspects the TLS certificate chain a host presents and
// turns it into structured findings.
//
// Analysis is deliberately split from transport: [Analyze] is a pure function
// over an already-collected chain, so every rule is testable against generated
// certificates without a network or a live server.
package tlscheck

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
)

// Thresholds control when an approaching certificate expiry becomes a finding.
// They mirror the renewal ladder used by the alert state machine.
const (
	CertCriticalDays = 14
	CertWarningDays  = 30
)

// MinRSABits is the smallest RSA modulus considered acceptable today.
const MinRSABits = 2048

// Certificate is the report-facing view of one certificate in the chain.
type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits,omitempty"`
	IsCA               bool      `json:"is_ca"`
	DNSNames           []string  `json:"dns_names,omitempty"`
}

// Result is the structured outcome of inspecting one host's chain.
type Result struct {
	Host         string            `json:"host"`
	Checked      bool              `json:"checked"`
	Leaf         *Certificate      `json:"leaf,omitempty"`
	Chain        []Certificate     `json:"chain,omitempty"`
	DaysToExpiry *int              `json:"days_to_expiry,omitempty"`
	Findings     []finding.Finding `json:"findings,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// weakSignatures are algorithms no longer accepted by mainstream trust stores.
var weakSignatures = map[x509.SignatureAlgorithm]bool{
	x509.MD2WithRSA:    true,
	x509.MD5WithRSA:    true,
	x509.SHA1WithRSA:   true,
	x509.DSAWithSHA1:   true,
	x509.ECDSAWithSHA1: true,
}

// Analyze applies every certificate rule to a chain as the server presented it:
// leaf first, issuers after. It never consults the system trust store, because
// the interesting failures (missing intermediate, self-signed, wrong hostname)
// are exactly the ones a verifying dialer collapses into one opaque error.
func Analyze(host string, chain []*x509.Certificate, now time.Time) Result {
	res := Result{Host: host, Checked: true}
	if len(chain) == 0 {
		res.Checked = false
		res.Error = "server presented no certificates"
		res.Findings = append(res.Findings, finding.Finding{
			Code:     finding.TLSUnreachable,
			Severity: finding.Critical,
			Message:  "server presented no certificates",
		})
		return res
	}

	for _, c := range chain {
		res.Chain = append(res.Chain, describe(c))
	}
	leaf := chain[0]
	res.Leaf = &res.Chain[0]

	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	res.DaysToExpiry = &days

	res.Findings = append(res.Findings, validityFindings(leaf, days, now)...)
	res.Findings = append(res.Findings, hostnameFindings(host, leaf)...)
	res.Findings = append(res.Findings, chainFindings(chain)...)
	for i, c := range chain {
		res.Findings = append(res.Findings, cryptoFindings(c, i)...)
	}
	return res
}

func validityFindings(leaf *x509.Certificate, days int, now time.Time) []finding.Finding {
	var out []finding.Finding
	switch {
	case now.After(leaf.NotAfter):
		out = append(out, finding.Finding{
			Code:     finding.CertExpired,
			Severity: finding.Critical,
			Message: fmt.Sprintf("certificate expired %d day(s) ago, on %s",
				-days, leaf.NotAfter.UTC().Format(time.DateOnly)),
		})
	case days <= CertCriticalDays:
		out = append(out, finding.Finding{
			Code:     finding.CertExpiring,
			Severity: finding.Critical,
			Message: fmt.Sprintf("certificate expires in %d day(s), on %s",
				days, leaf.NotAfter.UTC().Format(time.DateOnly)),
		})
	case days <= CertWarningDays:
		out = append(out, finding.Finding{
			Code:     finding.CertExpiring,
			Severity: finding.Warning,
			Message: fmt.Sprintf("certificate expires in %d day(s), on %s",
				days, leaf.NotAfter.UTC().Format(time.DateOnly)),
		})
	}
	if now.Before(leaf.NotBefore) {
		out = append(out, finding.Finding{
			Code:     finding.CertNotYetValid,
			Severity: finding.Critical,
			Message: fmt.Sprintf("certificate is not valid before %s",
				leaf.NotBefore.UTC().Format(time.DateOnly)),
		})
	}
	return out
}

func hostnameFindings(host string, leaf *x509.Certificate) []finding.Finding {
	if host == "" {
		return nil
	}
	if err := leaf.VerifyHostname(host); err != nil {
		names := append([]string{}, leaf.DNSNames...)
		if len(names) == 0 && leaf.Subject.CommonName != "" {
			names = []string{leaf.Subject.CommonName}
		}
		return []finding.Finding{{
			Code:     finding.CertHostnameMismatch,
			Severity: finding.Critical,
			Message: fmt.Sprintf("certificate is not valid for %s (presented: %s)",
				host, strings.Join(names, ", ")),
		}}
	}
	return nil
}

func chainFindings(chain []*x509.Certificate) []finding.Finding {
	var out []finding.Finding
	leaf := chain[0]
	selfSigned := isSelfSigned(leaf)

	if selfSigned {
		out = append(out, finding.Finding{
			Code:     finding.CertSelfSigned,
			Severity: finding.Critical,
			Message:  "leaf certificate is self-signed and will not be trusted by browsers",
		})
		return out
	}
	if len(chain) == 1 {
		out = append(out, finding.Finding{
			Code:     finding.CertIncompleteChain,
			Severity: finding.Warning,
			Message: fmt.Sprintf("server sent the leaf only; the intermediate issued by %q is missing "+
				"and some clients will fail to build a path", leaf.Issuer.CommonName),
		})
		return out
	}
	// Every certificate must be issued by the next one in the presented order.
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			out = append(out, finding.Finding{
				Code:     finding.CertBrokenChain,
				Severity: finding.Critical,
				Message: fmt.Sprintf("chain is not contiguous: %q is not issued by the next certificate %q",
					chain[i].Subject.CommonName, chain[i+1].Subject.CommonName),
			})
			return out
		}
	}
	last := chain[len(chain)-1]
	if !isSelfSigned(last) && !last.IsCA {
		out = append(out, finding.Finding{
			Code:     finding.CertIncompleteChain,
			Severity: finding.Warning,
			Message:  "presented chain does not end in a CA certificate",
		})
	}
	return out
}

func cryptoFindings(c *x509.Certificate, index int) []finding.Finding {
	var out []finding.Finding
	// A self-signed root may legitimately still carry SHA-1: trust stores pin
	// roots by key, not by signature. Only leaf and intermediates matter.
	if weakSignatures[c.SignatureAlgorithm] && !isSelfSigned(c) {
		out = append(out, finding.Finding{
			Code:     finding.CertWeakSignature,
			Severity: finding.Critical,
			Message: fmt.Sprintf("%s is signed with %s, which trust stores reject",
				position(index), c.SignatureAlgorithm),
		})
	}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < MinRSABits {
		out = append(out, finding.Finding{
			Code:     finding.CertWeakKey,
			Severity: finding.Critical,
			Message: fmt.Sprintf("%s uses a %d-bit RSA key, below the %d-bit minimum",
				position(index), k.N.BitLen(), MinRSABits),
		})
	}
	return out
}

func position(index int) string {
	if index == 0 {
		return "leaf certificate"
	}
	return fmt.Sprintf("chain certificate #%d", index)
}

// isSelfSigned reports whether a certificate signed itself. Comparing subject
// and issuer alone is not enough — a cross-signed intermediate can share both —
// so the signature is verified against the certificate's own key.
//
// CheckSignature is used rather than CheckSignatureFrom because the latter also
// enforces CA constraints, and a self-signed *leaf* (the classic "we generated
// it with openssl and forgot") is exactly the case this must still detect.
func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	if err == nil {
		return true
	}
	// Go refuses to verify SHA-1 outright. That is a judgement about signature
	// strength, not about who signed the certificate, and weak algorithms are
	// reported separately by cryptoFindings.
	var insecure x509.InsecureAlgorithmError
	return errors.As(err, &insecure)
}

func describe(c *x509.Certificate) Certificate {
	return Certificate{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		PublicKeyBits:      keyBits(c),
		IsCA:               c.IsCA,
		DNSNames:           c.DNSNames,
	}
}

func keyBits(c *x509.Certificate) int {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
