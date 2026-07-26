package tlscheck

import (
	"crypto/x509"
	"testing"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
)

func TestAnalyzeHealthyChain(t *testing.T) {
	chain := testChain(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com", "www.example.com"},
		notBefore: days(-10),
		notAfter:  days(80),
	})

	res := Analyze("www.example.com", chain, refTime)

	if !res.Checked {
		t.Fatalf("expected checked result, got error %q", res.Error)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings on a healthy chain, got %v", codes(res))
	}
	if res.DaysToExpiry == nil || *res.DaysToExpiry != 80 {
		t.Fatalf("days to expiry = %v, want 80", res.DaysToExpiry)
	}
	if got := len(res.Chain); got != 3 {
		t.Fatalf("chain length = %d, want 3", got)
	}
	if res.Leaf == nil || res.Leaf.PublicKeyBits != 2048 {
		t.Fatalf("leaf key bits = %+v, want 2048", res.Leaf)
	}
}

func TestAnalyzeExpiryLadder(t *testing.T) {
	tests := []struct {
		name         string
		notAfter     int
		wantCode     finding.Code
		wantSeverity finding.Severity
		wantNone     bool
	}{
		{name: "comfortable", notAfter: 90, wantNone: true},
		{name: "just outside warning", notAfter: 31, wantNone: true},
		{name: "warning boundary", notAfter: 30, wantCode: finding.CertExpiring, wantSeverity: finding.Warning},
		{name: "critical boundary", notAfter: 14, wantCode: finding.CertExpiring, wantSeverity: finding.Critical},
		{name: "tomorrow", notAfter: 1, wantCode: finding.CertExpiring, wantSeverity: finding.Critical},
		{name: "expired", notAfter: -3, wantCode: finding.CertExpired, wantSeverity: finding.Critical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := testChain(t, certOpts{
				cn:        "example.com",
				dnsNames:  []string{"example.com"},
				notBefore: days(-400),
				notAfter:  days(tc.notAfter),
			})
			res := Analyze("example.com", chain, refTime)

			if tc.wantNone {
				if len(res.Findings) != 0 {
					t.Fatalf("expected no findings, got %v", codes(res))
				}
				return
			}
			if len(res.Findings) != 1 {
				t.Fatalf("expected exactly one finding, got %v", codes(res))
			}
			f := res.Findings[0]
			if f.Code != tc.wantCode {
				t.Errorf("code = %s, want %s", f.Code, tc.wantCode)
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestAnalyzeHostnameMismatch(t *testing.T) {
	chain := testChain(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com", "www.example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
	})

	res := Analyze("shop.example.com", chain, refTime)

	if !hasCode(res, string(finding.CertHostnameMismatch)) {
		t.Fatalf("expected hostname mismatch, got %v", codes(res))
	}
	if got := res.Findings[0].Message; got == "" {
		t.Fatal("expected a message naming the presented names")
	}
	// A wildcard covering the host must not trip the rule.
	wildcard := testChain(t, certOpts{
		cn:        "*.example.com",
		dnsNames:  []string{"*.example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
	})
	if res := Analyze("shop.example.com", wildcard, refTime); len(res.Findings) != 0 {
		t.Fatalf("wildcard should cover the host, got %v", codes(res))
	}
}

func TestAnalyzeSelfSigned(t *testing.T) {
	self := mint(t, certOpts{
		cn:        "internal.example.com",
		dnsNames:  []string{"internal.example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
		isCA:      true,
	}, nil)

	res := Analyze("internal.example.com", []*x509.Certificate{self.cert}, refTime)

	if !hasCode(res, string(finding.CertSelfSigned)) {
		t.Fatalf("expected self-signed finding, got %v", codes(res))
	}
	// Self-signed must not also be reported as an incomplete chain: one problem,
	// one alert, or the agency report reads like noise.
	if hasCode(res, string(finding.CertIncompleteChain)) {
		t.Fatalf("self-signed leaf should not also report an incomplete chain: %v", codes(res))
	}
}

func TestAnalyzeMissingIntermediate(t *testing.T) {
	chain := testChain(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
	})

	res := Analyze("example.com", chain[:1], refTime)

	if !hasCode(res, string(finding.CertIncompleteChain)) {
		t.Fatalf("expected incomplete chain, got %v", codes(res))
	}
	if res.Findings[0].Severity != finding.Warning {
		t.Errorf("severity = %s, want warning", res.Findings[0].Severity)
	}
}

func TestAnalyzeBrokenChainOrder(t *testing.T) {
	chain := testChain(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
	})
	// An unrelated intermediate spliced in where the real issuer should be.
	other := mint(t, certOpts{
		cn:        "Unrelated CA",
		notBefore: days(-100),
		notAfter:  days(1000),
		isCA:      true,
	}, nil)
	spliced := []*x509.Certificate{chain[0], other.cert, chain[2]}

	res := Analyze("example.com", spliced, refTime)

	if !hasCode(res, string(finding.CertBrokenChain)) {
		t.Fatalf("expected broken chain, got %v", codes(res))
	}
}

func TestAnalyzeWeakSignatureAndKey(t *testing.T) {
	root := mint(t, certOpts{
		cn:        "Weak Test Root",
		notBefore: days(-3650),
		notAfter:  days(3650),
		isCA:      true,
	}, nil)
	leaf := mint(t, certOpts{
		cn:        "weak.example.com",
		dnsNames:  []string{"weak.example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
		bits:      1024,
		sigAlg:    x509.SHA1WithRSA,
	}, root)

	res := Analyze("weak.example.com", []*x509.Certificate{leaf.cert, root.cert}, refTime)

	if !hasCode(res, string(finding.CertWeakSignature)) {
		t.Errorf("expected weak signature finding, got %v", codes(res))
	}
	if !hasCode(res, string(finding.CertWeakKey)) {
		t.Errorf("expected weak key finding, got %v", codes(res))
	}
}

// A self-signed root may legitimately carry SHA-1: trust stores pin roots by
// key, not signature. Flagging it would put a false critical in every report.
func TestAnalyzeSHA1RootIsNotFlagged(t *testing.T) {
	root := mint(t, certOpts{
		cn:        "Legacy Root",
		notBefore: days(-3650),
		notAfter:  days(3650),
		isCA:      true,
		sigAlg:    x509.SHA1WithRSA,
	}, nil)
	leaf := mint(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com"},
		notBefore: days(-10),
		notAfter:  days(200),
	}, root)

	res := Analyze("example.com", []*x509.Certificate{leaf.cert, root.cert}, refTime)

	if hasCode(res, string(finding.CertWeakSignature)) {
		t.Fatalf("SHA-1 self-signed root must not be flagged, got %v", codes(res))
	}
}

func TestAnalyzeNotYetValid(t *testing.T) {
	chain := testChain(t, certOpts{
		cn:        "example.com",
		dnsNames:  []string{"example.com"},
		notBefore: days(5),
		notAfter:  days(200),
	})

	res := Analyze("example.com", chain, refTime)

	if !hasCode(res, string(finding.CertNotYetValid)) {
		t.Fatalf("expected not-yet-valid finding, got %v", codes(res))
	}
}

func TestAnalyzeEmptyChain(t *testing.T) {
	res := Analyze("example.com", nil, refTime)

	if res.Checked {
		t.Error("empty chain must not be reported as checked")
	}
	if !hasCode(res, string(finding.TLSUnreachable)) {
		t.Fatalf("expected unreachable finding, got %v", codes(res))
	}
}
