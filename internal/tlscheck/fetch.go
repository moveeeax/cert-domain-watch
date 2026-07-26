package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
)

// DefaultPort is the port used when a host is given without one.
const DefaultPort = "443"

// Fetcher collects the certificate chain a host presents.
type Fetcher struct {
	Timeout time.Duration
	Port    string
}

// NewFetcher returns a Fetcher with sane defaults.
func NewFetcher() *Fetcher {
	return &Fetcher{Timeout: 10 * time.Second, Port: DefaultPort}
}

// Fetch dials host over TLS and returns the chain exactly as sent, leaf first.
//
// Verification is disabled on purpose. The whole point of this tool is to
// report *why* a chain is bad — missing intermediate, wrong hostname, expired,
// self-signed — and a verifying handshake collapses all of those into one
// aborted connection with nothing left to inspect. Every trust decision is made
// afterwards by [Analyze], which is stricter than the dialer, not laxer.
func (f *Fetcher) Fetch(ctx context.Context, host string) ([]*x509.Certificate, error) {
	port := f.Port
	if port == "" {
		port = DefaultPort
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}

	d := &net.Dialer{Timeout: f.Timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
		//nolint:gosec // G402: chain is analysed by Analyze, see doc comment above.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn.ConnectionState().PeerCertificates, nil
}

// Check fetches and analyses a host in one call. A transport failure is
// reported as a result carrying a critical finding rather than as an error,
// so a portfolio run never loses a row to one unreachable host.
func (f *Fetcher) Check(ctx context.Context, host string, now time.Time) Result {
	chain, err := f.Fetch(ctx, host)
	if err != nil {
		return Result{
			Host:    host,
			Checked: false,
			Error:   err.Error(),
			Findings: []finding.Finding{{
				Code:     finding.TLSUnreachable,
				Severity: finding.Critical,
				Message:  "TLS connection failed: " + err.Error(),
			}},
		}
	}
	return Analyze(host, chain, now)
}
