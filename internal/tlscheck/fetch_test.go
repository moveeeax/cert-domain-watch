package tlscheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fetch must return the chain from a server whose certificate no trust store
// accepts; httptest's self-signed certificate is exactly that.
func TestFetchReturnsUnverifiedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	f := NewFetcher()
	chain, err := f.Fetch(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("expected the presented chain, got none")
	}
}

// A run that hits its overall timeout must not keep waiting on a host that
// accepted the TCP connection but never answers the handshake.
func TestFetchStopsWhenContextEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold the connection open, say nothing
		}
	}()

	f := NewFetcher() // 10 s dial timeout; the context must win
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := f.Fetch(ctx, ln.Addr().String()); err == nil {
		t.Fatal("expected an error from a silent server")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("fetch took %v after the context expired", elapsed)
	}
}
