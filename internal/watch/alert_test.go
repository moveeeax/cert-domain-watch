package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
	"github.com/moveeeax/cert-domain-watch/internal/rdap"
)

func TestRung(t *testing.T) {
	tests := []struct {
		days int
		want int
	}{
		{days: 365, want: NoRung},
		{days: 61, want: NoRung},
		{days: 60, want: 60},
		{days: 45, want: 60},
		{days: 31, want: 60},
		{days: 30, want: 30},
		{days: 15, want: 30},
		{days: 14, want: 14},
		{days: 8, want: 14},
		{days: 7, want: 7},
		{days: 2, want: 7},
		{days: 1, want: 1},
		{days: 0, want: ExpiredRung},
		{days: -5, want: ExpiredRung},
	}
	for _, tc := range tests {
		if got := Rung(tc.days); got != tc.want {
			t.Errorf("Rung(%d) = %d, want %d", tc.days, got, tc.want)
		}
	}
}

// resultFor builds a result the way Checker would, for state tests.
func resultFor(t *testing.T, days int, ns ...string) Result {
	t.Helper()
	c := &Checker{RDAP: fakeRDAP{domain: registration(days, rdap.Yes, ns...)}, SkipTLS: true}
	return c.Check(context.Background(), Target{Client: "Acme", Domain: "example.com"}, refTime)
}

// The whole point of the state machine: an agency on a daily cron must be told
// once per rung, not once per day.
func TestReconcileFiresOncePerRung(t *testing.T) {
	st := &State{Domains: map[string]DomainState{}}

	first := st.Reconcile(resultFor(t, 45))
	if len(first) != 1 || first[0].Code != finding.DomainExpiring {
		t.Fatalf("first run should fire the 60-day rung, got %v", codes(first))
	}

	// Same rung the next day: silence.
	if again := st.Reconcile(resultFor(t, 44)); len(again) != 0 {
		t.Fatalf("same rung must not fire again, got %v", codes(again))
	}
	if again := st.Reconcile(resultFor(t, 31)); len(again) != 0 {
		t.Fatalf("still the 60-day rung, got %v", codes(again))
	}

	// Crossing into the 30-day rung fires once more.
	next := st.Reconcile(resultFor(t, 30))
	if len(next) != 1 || next[0].Code != finding.DomainExpiring {
		t.Fatalf("crossing to the 30-day rung should fire, got %v", codes(next))
	}
	if again := st.Reconcile(resultFor(t, 20)); len(again) != 0 {
		t.Fatalf("same rung must not fire again, got %v", codes(again))
	}
}

func TestReconcileResetsAfterRenewal(t *testing.T) {
	st := &State{Domains: map[string]DomainState{}}
	if fired := st.Reconcile(resultFor(t, 10)); len(fired) != 1 {
		t.Fatalf("expected an alert at 10 days, got %v", codes(fired))
	}
	// Renewed: no finding at all, and the remembered rung must clear so the
	// next renewal cycle alerts again.
	if fired := st.Reconcile(resultFor(t, 400)); len(fired) != 0 {
		t.Fatalf("a renewed domain must be silent, got %v", codes(fired))
	}
	if fired := st.Reconcile(resultFor(t, 10)); len(fired) != 1 {
		t.Fatalf("expected the alert to fire again next cycle, got %v", codes(fired))
	}
}

func TestReconcileNameserverDrift(t *testing.T) {
	st := &State{Domains: map[string]DomainState{}}

	// First sighting establishes a baseline and must not claim drift.
	if fired := st.Reconcile(resultFor(t, 300, "ns1.example-dns.net", "ns2.example-dns.net")); len(fired) != 0 {
		t.Fatalf("first sighting must not report drift, got %v", codes(fired))
	}
	// Same set, different order: still no drift.
	if fired := st.Reconcile(resultFor(t, 300, "ns2.example-dns.net", "ns1.example-dns.net")); len(fired) != 0 {
		t.Fatalf("reordering is not drift, got %v", codes(fired))
	}

	fired := st.Reconcile(resultFor(t, 300, "ns1.other-dns.net", "ns2.other-dns.net"))
	if len(fired) != 1 || fired[0].Code != finding.NameserverDrift {
		t.Fatalf("expected nameserver drift, got %v", codes(fired))
	}
	if fired[0].Severity != finding.Critical {
		t.Errorf("drift severity = %s, want critical", fired[0].Severity)
	}
}

// A failed RDAP lookup must not erase the baseline, or the next successful run
// would report drift that never happened.
func TestReconcileKeepsNameserversWhenLookupFails(t *testing.T) {
	st := &State{Domains: map[string]DomainState{}}
	st.Reconcile(resultFor(t, 300, "ns1.example-dns.net"))

	failed := (&Checker{RDAP: fakeRDAP{err: rdap.ErrNotFound}, SkipTLS: true}).
		Check(context.Background(), Target{Domain: "example.com"}, refTime)
	st.Reconcile(failed)

	if fired := st.Reconcile(resultFor(t, 300, "ns1.example-dns.net")); len(fired) != 0 {
		t.Fatalf("baseline was lost, spurious drift reported: %v", codes(fired))
	}
}

func TestReconcileSteadyFindingFiresOnce(t *testing.T) {
	unknown := &Checker{
		RDAP: fakeRDAP{domain: &rdap.Domain{
			Name:         "example.de",
			ExpiryState:  rdap.ExpiryNotPublished,
			TransferLock: rdap.No,
		}},
		SkipTLS: true,
	}
	res := unknown.Check(context.Background(), Target{Domain: "example.de"}, refTime)

	st := &State{Domains: map[string]DomainState{}}
	if fired := st.Reconcile(res); len(fired) != 2 {
		t.Fatalf("expected both findings on first sight, got %v", codes(fired))
	}
	if fired := st.Reconcile(res); len(fired) != 0 {
		t.Fatalf("steady findings must not repeat, got %v", codes(fired))
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")

	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("load missing state: %v", err)
	}
	if len(st.Domains) != 0 {
		t.Fatal("a missing state file must load as empty, not fail")
	}

	st.Reconcile(resultFor(t, 10, "ns1.example-dns.net"))
	if err := st.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fired := reloaded.Reconcile(resultFor(t, 9, "ns1.example-dns.net")); len(fired) != 0 {
		t.Fatalf("persisted rung was lost across a restart: %v", codes(fired))
	}
}

func TestLoadStateRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("expected an error for a corrupt state file")
	}
}
