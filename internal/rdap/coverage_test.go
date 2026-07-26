package rdap

import "testing"

func TestLookupPrefersLongestSuffix(t *testing.T) {
	got, ok := Lookup("agency-client.co.uk")
	if !ok {
		t.Fatal("expected a matrix row for co.uk")
	}
	if got.TLD != "co.uk" {
		t.Errorf("tld = %q, want co.uk (longest suffix must win over uk)", got.TLD)
	}
}

func TestLookupUnknownTLD(t *testing.T) {
	got, ok := Lookup("example.zzz-not-a-tld")
	if ok {
		t.Fatalf("expected no match, got %+v", got)
	}
	if got.Expected != CoverageUnknown {
		t.Errorf("zero value coverage = %s, want unknown", got.Expected)
	}
}

func TestLookupIsCaseAndDotInsensitive(t *testing.T) {
	got, ok := Lookup("  EXAMPLE.COM.  ")
	if !ok || got.TLD != "com" {
		t.Fatalf("lookup = %+v, ok = %v; want com", got, ok)
	}
}

// A row may only claim to be verified if it carries the date of the probe that
// verified it. Otherwise "verified" is just a stronger-sounding guess.
func TestMatrixVerifiedRowsCarryAProbeDate(t *testing.T) {
	for _, row := range Matrix() {
		if row.Registry == "" {
			t.Errorf("tld %q has no registry named", row.TLD)
		}
		if row.Verified && row.VerifiedOn == "" {
			t.Errorf("tld %q claims verified with no probe date", row.TLD)
		}
		if !row.Verified && row.VerifiedOn != "" {
			t.Errorf("tld %q has a probe date but is not marked verified", row.TLD)
		}
		if row.Verified && row.Note == "" {
			t.Errorf("tld %q is verified but records no evidence", row.TLD)
		}
	}
}

// The eight TLDs the target agencies actually hold must all be answered for,
// including with a definite "this cannot be automated".
func TestMatrixCoversTheTargetTLDs(t *testing.T) {
	want := []string{"com", "co.uk", "de", "fr", "io", "nl", "eu", "ai"}
	byTLD := map[string]TLDCoverage{}
	for _, row := range Matrix() {
		byTLD[row.TLD] = row
	}
	for _, tld := range want {
		row, ok := byTLD[tld]
		if !ok {
			t.Errorf("tld %q missing from the matrix", tld)
			continue
		}
		if !row.Verified {
			t.Errorf("tld %q is a target TLD but was never probed", tld)
		}
		if row.Expected == CoverageUnknown {
			t.Errorf("tld %q is still unknown after probing", tld)
		}
	}
}

func TestMatrixIsACopy(t *testing.T) {
	m := Matrix()
	m[0].Registry = "mutated"
	if Matrix()[0].Registry == "mutated" {
		t.Fatal("Matrix must return a copy, not the package-level slice")
	}
}
