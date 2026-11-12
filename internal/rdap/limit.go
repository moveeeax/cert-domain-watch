package rdap

import (
	"io"
	"net/http"
	"sync"
)

// hostLimiter caps the number of requests in flight to any one host. A
// concurrent portfolio run sends most lookups through the same few registries
// (Verisign alone serves .com and .net), and a registry that sees eight
// parallel queries from one address is likely to start answering 429.
//
// The limit is applied per hop, so the bootstrap redirector and the registry it
// redirects to are counted separately. A slot is held until the response body
// is closed, not just until the headers arrive.
type hostLimiter struct {
	next http.RoundTripper
	max  int

	mu    sync.Mutex
	slots map[string]chan struct{}
}

func (l *hostLimiter) sem(host string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.slots == nil {
		l.slots = map[string]chan struct{}{}
	}
	s, ok := l.slots[host]
	if !ok {
		s = make(chan struct{}, l.max)
		l.slots[host] = s
	}
	return s
}

func (l *hostLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	s := l.sem(req.URL.Host)
	select {
	case s <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	release := func() { <-s }

	next := l.next
	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(req)
	if err != nil {
		release()
		return nil, err
	}
	resp.Body = &releaseOnClose{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// releaseOnClose frees a limiter slot exactly once, when the body is closed.
type releaseOnClose struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (r *releaseOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(r.release)
	return err
}
