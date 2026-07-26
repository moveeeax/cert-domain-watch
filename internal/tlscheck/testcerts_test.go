package tlscheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// certOpts describes a certificate to mint for a test.
type certOpts struct {
	cn        string
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
	bits      int
	sigAlg    x509.SignatureAlgorithm
}

type issued struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// mint creates a certificate signed by parent, or self-signed when parent is nil.
// Real key material is generated so every signature check in Analyze runs for
// real; nothing here is a stub.
func mint(t *testing.T, o certOpts, parent *issued) *issued {
	t.Helper()

	bits := o.bits
	if bits == 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.cn, Organization: []string{"cert-domain-watch test"}},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
		SignatureAlgorithm:    o.sigAlg,
	}

	signer := tmpl
	signerKey := key
	if parent != nil {
		signer = parent.cert
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate %q: %v", o.cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", o.cn, err)
	}
	return &issued{cert: cert, key: key}
}

// refTime is the fixed "now" every tlscheck test reasons against.
var refTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return refTime.AddDate(0, 0, n) }

// testChain mints a root, an intermediate and a leaf with the given options.
func testChain(t *testing.T, leaf certOpts) []*x509.Certificate {
	t.Helper()
	root := mint(t, certOpts{
		cn:        "cert-domain-watch Test Root",
		notBefore: days(-3650),
		notAfter:  days(3650),
		isCA:      true,
	}, nil)
	inter := mint(t, certOpts{
		cn:        "cert-domain-watch Test Intermediate",
		notBefore: days(-1825),
		notAfter:  days(1825),
		isCA:      true,
	}, root)
	l := mint(t, leaf, inter)
	return []*x509.Certificate{l.cert, inter.cert, root.cert}
}

// codes extracts the finding codes from a result, for compact assertions.
func codes(r Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, string(f.Code))
	}
	return out
}

func hasCode(r Result, want string) bool {
	for _, c := range codes(r) {
		if c == want {
			return true
		}
	}
	return false
}
