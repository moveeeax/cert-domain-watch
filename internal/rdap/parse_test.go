package rdap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// refTime is the fixed "now" every RDAP test reasons against.
var refTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestParseThickRegistry(t *testing.T) {
	d, err := Parse(fixture(t, "com-full.json"), refTime)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if d.Name != "example.com" {
		t.Errorf("name = %q, want example.com", d.Name)
	}
	if d.ExpiryState != ExpiryKnown {
		t.Fatalf("expiry state = %q, want known", d.ExpiryState)
	}
	want := time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC)
	if !d.Expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v", d.Expiry, want)
	}
	if d.DaysToExpiry == nil || *d.DaysToExpiry != 164 {
		t.Errorf("days to expiry = %v, want 164", d.DaysToExpiry)
	}
	if d.Registered == nil || d.Registered.Year() != 1995 {
		t.Errorf("registration date = %v, want 1995", d.Registered)
	}
	if d.TransferLock != Yes {
		t.Errorf("transfer lock = %s, want yes", d.TransferLock)
	}
	if d.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", d.Registrar)
	}
	if d.RegistrarID != "9999" {
		t.Errorf("registrar id = %q, want 9999", d.RegistrarID)
	}
	// Nameservers are lowercased and sorted so drift detection compares sets,
	// not the order the registry happened to serialise them in.
	wantNS := []string{"ns1.example-dns.net", "ns2.example-dns.net"}
	if !reflect.DeepEqual(d.Nameservers, wantNS) {
		t.Errorf("nameservers = %v, want %v", d.Nameservers, wantNS)
	}
	// RDAP has no auto-renew field. Claiming to know is the one thing this
	// product must never do.
	if d.AutoRenew != Unknown {
		t.Errorf("auto renew = %s, want unknown", d.AutoRenew)
	}
}

func TestParseRegistryWithoutExpiry(t *testing.T) {
	d, err := Parse(fixture(t, "de-minimal.json"), refTime)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if d.ExpiryState != ExpiryNotPublished {
		t.Errorf("expiry state = %q, want not_published", d.ExpiryState)
	}
	if d.Expiry != nil || d.DaysToExpiry != nil {
		t.Errorf("expiry must stay nil, got %v / %v", d.Expiry, d.DaysToExpiry)
	}
	// No status array at all means unknown, never "unlocked".
	if d.TransferLock != Unknown {
		t.Errorf("transfer lock = %s, want unknown", d.TransferLock)
	}
	if len(d.Nameservers) != 2 {
		t.Errorf("nameservers = %v, want 2", d.Nameservers)
	}
}

func TestParseTransferLockOff(t *testing.T) {
	d, err := Parse(fixture(t, "no-lock.json"), refTime)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.TransferLock != No {
		t.Errorf("transfer lock = %s, want no", d.TransferLock)
	}
	// Registrar handle stands in when no IANA public ID is published.
	if d.RegistrarID != "1234" {
		t.Errorf("registrar id = %q, want fallback to handle 1234", d.RegistrarID)
	}
}

func TestParseExpiredDomain(t *testing.T) {
	d, err := Parse(fixture(t, "expired.json"), refTime)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.DaysToExpiry == nil || *d.DaysToExpiry >= 0 {
		t.Fatalf("days to expiry = %v, want negative", d.DaysToExpiry)
	}
	if *d.DaysToExpiry != -28 {
		t.Errorf("days to expiry = %d, want -28", *d.DaysToExpiry)
	}
}

func TestParseErrorObject(t *testing.T) {
	if _, err := Parse(fixture(t, "error-404.json"), refTime); err == nil {
		t.Fatal("expected an error for an RDAP error object")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("<html>rate limited</html>"), refTime); err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
	if _, err := Parse([]byte(`{"objectClassName":"nameserver"}`), refTime); err == nil {
		t.Fatal("expected an error for a non-domain object")
	}
}

func TestParseIgnoresUnparseableEventDate(t *testing.T) {
	body := []byte(`{"objectClassName":"domain","ldhName":"weird.example",
		"events":[{"eventAction":"expiration","eventDate":"soon"}]}`)
	d, err := Parse(body, refTime)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.ExpiryState != ExpiryNotPublished {
		t.Errorf("expiry state = %q, want not_published for an unparseable date", d.ExpiryState)
	}
}
