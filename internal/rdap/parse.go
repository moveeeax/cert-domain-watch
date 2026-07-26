package rdap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Tristate models a fact that may be true, false, or genuinely not published.
// It exists so a report can say "unknown" out loud instead of defaulting to
// false and quietly telling an agency their domains are unlocked.
type Tristate int

const (
	Unknown Tristate = iota
	Yes
	No
)

// String renders the tristate as the token used in JSON and reports.
func (t Tristate) String() string {
	switch t {
	case Yes:
		return "yes"
	case No:
		return "no"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the tristate as its string form.
func (t Tristate) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

// ExpiryState says what happened when we looked for a registration expiry.
type ExpiryState string

const (
	// ExpiryKnown means the registry published an expiration event.
	ExpiryKnown ExpiryState = "known"
	// ExpiryNotPublished means RDAP answered but carried no expiration event.
	ExpiryNotPublished ExpiryState = "not_published"
	// ExpiryUnavailable means the lookup itself did not succeed.
	ExpiryUnavailable ExpiryState = "unavailable"
)

// Domain is the parsed, report-facing view of an RDAP domain response.
type Domain struct {
	Name         string      `json:"name"`
	Handle       string      `json:"handle,omitempty"`
	Registrar    string      `json:"registrar,omitempty"`
	RegistrarID  string      `json:"registrar_id,omitempty"`
	Registered   *time.Time  `json:"registered,omitempty"`
	Expiry       *time.Time  `json:"expiry,omitempty"`
	ExpiryState  ExpiryState `json:"expiry_state"`
	DaysToExpiry *int        `json:"days_to_expiry,omitempty"`
	TransferLock Tristate    `json:"transfer_lock"`
	AutoRenew    Tristate    `json:"auto_renew"`
	Statuses     []string    `json:"statuses,omitempty"`
	Nameservers  []string    `json:"nameservers,omitempty"`
	Source       string      `json:"source,omitempty"`
	Error        string      `json:"error,omitempty"`
}

// rawDomain mirrors the subset of RFC 9083 we depend on.
type rawDomain struct {
	ObjectClassName string   `json:"objectClassName"`
	Handle          string   `json:"handle"`
	LDHName         string   `json:"ldhName"`
	UnicodeName     string   `json:"unicodeName"`
	Status          []string `json:"status"`
	Events          []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities  []rawEntity `json:"entities"`
	ErrorCode int         `json:"errorCode"`
	Title     string      `json:"title"`
}

type rawEntity struct {
	Roles      []string        `json:"roles"`
	Handle     string          `json:"handle"`
	VCardArray json.RawMessage `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
}

// Parse decodes an RDAP domain response. now is used to derive days to expiry
// so results are reproducible in tests.
func Parse(body []byte, now time.Time) (*Domain, error) {
	var raw rawDomain
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode rdap response: %w", err)
	}
	if raw.ErrorCode != 0 {
		return nil, fmt.Errorf("rdap error %d: %s", raw.ErrorCode, raw.Title)
	}
	if raw.ObjectClassName != "" && raw.ObjectClassName != "domain" {
		return nil, fmt.Errorf("unexpected objectClassName %q", raw.ObjectClassName)
	}

	name := raw.LDHName
	if name == "" {
		name = raw.UnicodeName
	}
	d := &Domain{
		Name:        strings.ToLower(strings.TrimSuffix(name, ".")),
		Handle:      raw.Handle,
		ExpiryState: ExpiryNotPublished,
		AutoRenew:   Unknown, // RDAP has no auto-renew field; see docs/rdap.md.
	}

	for _, ev := range raw.Events {
		ts, err := time.Parse(time.RFC3339, ev.Date)
		if err != nil {
			continue
		}
		ts = ts.UTC()
		switch strings.ToLower(ev.Action) {
		case "expiration":
			d.Expiry = &ts
			d.ExpiryState = ExpiryKnown
			days := int(ts.Sub(now).Hours() / 24)
			d.DaysToExpiry = &days
		case "registration":
			d.Registered = &ts
		}
	}

	d.Statuses = normaliseStatuses(raw.Status)
	d.TransferLock = transferLock(d.Statuses)

	for _, ns := range raw.Nameservers {
		if ns.LDHName == "" {
			continue
		}
		d.Nameservers = append(d.Nameservers, strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")))
	}
	sort.Strings(d.Nameservers)

	d.Registrar, d.RegistrarID = registrar(raw.Entities)
	return d, nil
}

func normaliseStatuses(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// transferLock reads RFC 8056 status values. An empty status array means the
// registry published nothing, which is unknown — not unlocked.
func transferLock(statuses []string) Tristate {
	if len(statuses) == 0 {
		return Unknown
	}
	for _, s := range statuses {
		if s == "client transfer prohibited" || s == "server transfer prohibited" {
			return Yes
		}
	}
	return No
}

// registrar pulls the registrar name out of the entity list. jCard is a nested
// array-of-arrays, so it is walked positionally: each property is
// [name, params, type, value].
func registrar(entities []rawEntity) (name, id string) {
	for _, e := range entities {
		if !hasRole(e.Roles, "registrar") {
			continue
		}
		for _, p := range e.PublicIDs {
			if strings.Contains(strings.ToLower(p.Type), "registrar id") {
				id = p.Identifier
			}
		}
		if id == "" {
			id = e.Handle
		}
		name = vcardField(e.VCardArray, "fn")
		return name, id
	}
	return "", ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

func vcardField(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var card []json.RawMessage
	if err := json.Unmarshal(raw, &card); err != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(card[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key string
		if err := json.Unmarshal(p[0], &key); err != nil || !strings.EqualFold(key, field) {
			continue
		}
		var val string
		if err := json.Unmarshal(p[3], &val); err != nil {
			continue
		}
		return val
	}
	return ""
}
