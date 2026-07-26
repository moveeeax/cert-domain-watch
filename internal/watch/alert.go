package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/moveeeax/cert-domain-watch/internal/finding"
)

// Ladder is the renewal alert schedule, in days remaining. An alert fires once
// per rung, never once per run — an agency that gets a daily "expires in 43
// days" email stops reading the emails.
var Ladder = []int{60, 30, 14, 7, 1}

// Domain expiry thresholds, aligned with the ladder.
const (
	DomainCriticalDays = 14
	DomainWarningDays  = 60
)

// NoRung means the countdown has not reached the first ladder rung yet.
const NoRung = -1

// ExpiredRung is the terminal rung: the deadline has passed.
const ExpiredRung = 0

// Rung maps days-remaining onto the ladder: the tightest rung that has been
// crossed. 45 days sits on the 60 rung, 8 days on 14, and anything at or past
// the deadline collapses onto ExpiredRung.
func Rung(days int) int {
	if days <= 0 {
		return ExpiredRung
	}
	rung := NoRung
	for _, l := range Ladder {
		if days <= l && (rung == NoRung || l < rung) {
			rung = l
		}
	}
	return rung
}

// State is the persisted memory between runs. Without a database this is a
// JSON file; the shape is deliberately the same one the Postgres tables will
// hold, so Phase 2 is a storage swap and not a redesign.
type State struct {
	Version int                    `json:"version"`
	Domains map[string]DomainState `json:"domains"`
}

// DomainState is what we remember about one domain.
type DomainState struct {
	// Nameservers is the last observed set, sorted, used for drift detection.
	Nameservers []string `json:"nameservers,omitempty"`
	// Rungs records the ladder rung each alert code last fired at, keyed by
	// "code" or "code@scope". A rung only fires when it differs from this.
	Rungs map[string]int `json:"rungs,omitempty"`
}

const stateVersion = 1

// LoadState reads a state file. A missing file is not an error: the first run
// of a new portfolio legitimately has no history.
func LoadState(path string) (*State, error) {
	s := &State{Version: stateVersion, Domains: map[string]DomainState{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parse state file %s: %w", path, err)
	}
	if s.Domains == nil {
		s.Domains = map[string]DomainState{}
	}
	s.Version = stateVersion
	return s, nil
}

// Save writes the state file atomically, so an interrupted run cannot leave a
// truncated file that loses every dedup rung at once.
func (s *State) Save(path string) error {
	if s.Domains == nil {
		s.Domains = map[string]DomainState{}
	}
	s.Version = stateVersion
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cdw-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Reconcile compares a fresh result against remembered state and returns the
// findings that are genuinely new. It also detects nameserver drift, which has
// no countdown and fires on every change.
//
// The state is mutated in place; the caller decides whether to persist it, so a
// dry run can preview alerts without burning them.
func (s *State) Reconcile(res Result) []finding.Finding {
	if s.Domains == nil {
		s.Domains = map[string]DomainState{}
	}
	prev := s.Domains[res.Domain]
	next := DomainState{Rungs: map[string]int{}}

	var fired []finding.Finding

	// Nameserver drift: only meaningful once we have a previous snapshot.
	current := currentNameservers(res)
	next.Nameservers = current
	if len(current) > 0 && len(prev.Nameservers) > 0 && !reflect.DeepEqual(prev.Nameservers, current) {
		fired = append(fired, finding.Finding{
			Code:     finding.NameserverDrift,
			Severity: finding.Critical,
			Scope:    res.Domain,
			Message: fmt.Sprintf("nameservers changed from [%s] to [%s]",
				strings.Join(prev.Nameservers, ", "), strings.Join(current, ", ")),
		})
	}
	if len(current) == 0 {
		// Keep the last known set rather than forgetting it because one RDAP
		// lookup failed; otherwise the next successful run reports false drift.
		next.Nameservers = prev.Nameservers
	}

	for _, f := range res.Findings {
		rung, ok := rungFor(f, res)
		if !ok {
			continue
		}
		key := dedupKey(f)
		if prev.Rungs[key] == rung {
			next.Rungs[key] = rung
			continue
		}
		next.Rungs[key] = rung
		fired = append(fired, f)
	}

	s.Domains[res.Domain] = next
	finding.SortBySeverity(fired)
	return fired
}

// rungFor returns the ladder rung a countdown finding sits on. Findings with no
// countdown (self-signed, weak key, hostname mismatch) return ok=false and are
// deduplicated by the fact that their rung never changes — they fire once when
// they appear and again only after they clear and come back.
func rungFor(f finding.Finding, res Result) (int, bool) {
	switch f.Code {
	case finding.DomainExpiring, finding.DomainExpired:
		if res.Registration != nil && res.Registration.DaysToExpiry != nil {
			return Rung(*res.Registration.DaysToExpiry), true
		}
		return ExpiredRung, true
	case finding.CertExpiring, finding.CertExpired:
		for _, t := range res.TLS {
			if t.Host == f.Scope && t.DaysToExpiry != nil {
				return Rung(*t.DaysToExpiry), true
			}
		}
		return ExpiredRung, true
	case finding.NameserverDrift:
		// Handled separately: drift has no countdown.
		return 0, false
	default:
		// Steady-state problems: one rung, so one alert until they clear.
		return 1, true
	}
}

func dedupKey(f finding.Finding) string {
	if f.Scope == "" {
		return string(f.Code)
	}
	return string(f.Code) + "@" + f.Scope
}

func currentNameservers(res Result) []string {
	if res.Registration == nil || len(res.Registration.Nameservers) == 0 {
		return nil
	}
	out := append([]string(nil), res.Registration.Nameservers...)
	sort.Strings(out)
	return out
}
