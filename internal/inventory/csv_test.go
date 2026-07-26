package inventory

import (
	"reflect"
	"strings"
	"testing"
)

func TestLoadCSV(t *testing.T) {
	in := `client,domain,hosts,notes
Acme Ltd,example.com,example.com www.example.com,main site
Acme Ltd,shop.example.net,,checkout
Beta GmbH,beispiel.de,,
`
	got, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d targets, want 3", len(got))
	}
	if got[0].Client != "Acme Ltd" || got[0].Domain != "example.com" {
		t.Errorf("row 0 = %+v", got[0])
	}
	wantHosts := []string{"example.com", "www.example.com"}
	if !reflect.DeepEqual(got[0].Hosts, wantHosts) {
		t.Errorf("hosts = %v, want %v", got[0].Hosts, wantHosts)
	}
	if got[1].Notes != "checkout" {
		t.Errorf("notes = %q", got[1].Notes)
	}
}

func TestLoadCSVHeaderAliasesAndOrder(t *testing.T) {
	in := "Notes,Zone,Customer\nprimary,EXAMPLE.COM,Acme Ltd\n"
	got, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "example.com" || got[0].Client != "Acme Ltd" {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadCSVWithoutDomainColumn(t *testing.T) {
	_, err := Load(strings.NewReader("client,url\nAcme,https://example.com\n"))
	if err == nil {
		t.Fatal("expected an error when no domain column is present")
	}
}

// Every domain belongs to exactly one client. A duplicate is an import bug the
// agency must fix, not something to silently pick a winner for.
func TestLoadCSVRejectsDuplicateDomain(t *testing.T) {
	in := "client,domain\nAcme,example.com\nBeta,www.example.com\n"
	_, err := Load(strings.NewReader(in))
	if err == nil {
		t.Fatal("expected an error for a duplicate domain")
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("error should name the duplicate: %v", err)
	}
}

func TestLoadPlainList(t *testing.T) {
	in := `# client portfolio, pasted from an email
https://example.com/pricing
WWW.Example.NET
example.com

notadomain
`
	got, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v, want example.com and example.net", got)
	}
	if got[0].Domain != "example.com" || got[1].Domain != "example.net" {
		t.Errorf("domains = %q, %q", got[0].Domain, got[1].Domain)
	}
	if got[0].Client != "unassigned" {
		t.Errorf("client = %q, want unassigned", got[0].Client)
	}
}

func TestLoadEmpty(t *testing.T) {
	got, err := Load(strings.NewReader("   \n\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want nothing", got)
	}
}

func TestNormaliseDomain(t *testing.T) {
	tests := map[string]string{
		"Example.COM":                     "example.com",
		"https://www.example.com/a/b?c=1": "example.com",
		"http://example.co.uk":            "example.co.uk",
		"example.com.":                    "example.com",
		"  example.net  ":                 "example.net",
		"localhost":                       "",
		"":                                "",
	}
	for in, want := range tests {
		if got := normaliseDomain(in); got != want {
			t.Errorf("normaliseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitHosts(t *testing.T) {
	got := splitHosts(" a.example.com;b.example.com |c.example.com ")
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitHosts = %v, want %v", got, want)
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile("testdata/does-not-exist.csv"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
