// Package sigselect picks exactly one of the signatures the server returns for
// an e-mail address. The choice is deterministic: the same input always gives
// the same signature (independent of the order of the server's answer, which
// is not defined), so that the agent does not flip back and forth every
// 2 hours.
//
// Guiding rule: rather no change than the signature of the wrong person.
package sigselect

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"subsignature-agent/internal/api"
)

const (
	PolicyNewest = "newest" // for duplicates: the most recently changed one
	PolicySkip   = "skip"   // for duplicates: change nothing, warn
)

var (
	// ErrNone: the server knows no (usable) signature for this address.
	ErrNone = errors.New("no signature for this address")
	// ErrNoMatch: there are signatures, but none with the requested account/template.
	ErrNoMatch = errors.New("no signature with the requested account or template")
	// ErrAmbiguous: ambiguous, and the rule forbids guessing.
	ErrAmbiguous = errors.New("signature is ambiguous")
)

// Criteria controls the selection.
type Criteria struct {
	Template      string   // requested template (e.g. signature_pro or signature_pro.html), empty = any
	Username      string   // requested SubSignature account, empty = any
	Policy        string   // newest (default) or skip
	PreferSources []string // ranking of the sources (manual, csv, ldap), empty = no ranking
}

// Choice is the result of the selection.
type Choice struct {
	Sig   api.Signature
	Notes []string // notes for the log (duplicates, ignored entries ...)
}

type cand struct {
	s    api.Signature
	idx  int // position in the server's answer (last tie-break only, keeps things stable)
	rank int // rank of the source, lower = preferred
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// NormTemplate normalizes template names: case and the extension .html/.htm
// do not matter.
func NormTemplate(s string) string {
	s = lower(s)
	s = strings.TrimSuffix(s, ".html")
	return strings.TrimSuffix(s, ".htm")
}

// better: true if a should be chosen over b.
// Order: rank of the source, most recently changed, higher ID (created later), position.
func better(a, b cand) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if !a.s.UpdatedAt.Equal(b.s.UpdatedAt.Time) {
		return a.s.UpdatedAt.After(b.s.UpdatedAt.Time)
	}
	if a.s.ID != b.s.ID {
		return a.s.ID > b.s.ID
	}
	return a.idx < b.idx
}

func contentKey(s api.Signature) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s.HTML)))
	return fmt.Sprintf("%x", sum)
}

// dedupe merges candidates with the same key and keeps the best one.
func dedupe(in []cand, keyOf func(cand) string) (out []cand, dropped int) {
	best := map[string]cand{}
	var order []string
	for _, c := range in {
		k := keyOf(c)
		cur, ok := best[k]
		if !ok {
			best[k] = c
			order = append(order, k)
		} else if better(c, cur) {
			best[k] = c
		}
	}
	for _, k := range order {
		out = append(out, best[k])
	}
	return out, len(in) - len(out)
}

func distinct(in []cand, f func(api.Signature) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		v := f(c.s)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func quoted(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}

func ids(in []cand) string {
	p := make([]string, len(in))
	for i, c := range in {
		p[i] = fmt.Sprintf("#%d", c.s.ID)
	}
	return strings.Join(p, ", ")
}

// Select picks a signature for the address email.
func Select(email string, sigs []api.Signature, c Criteria) (*Choice, error) {
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }

	rankOf := func(src string) int {
		for i, p := range c.PreferSources {
			if lower(p) == lower(src) {
				return i
			}
		}
		return len(c.PreferSources)
	}

	// 1. Protection: only entries with exactly this address and with content.
	var items []cand
	other, empty := 0, 0
	for i, s := range sigs {
		switch {
		case lower(s.Email) != lower(email):
			other++
		case strings.TrimSpace(s.HTML) == "":
			empty++
		default:
			items = append(items, cand{s: s, idx: i, rank: rankOf(s.Source)})
		}
	}
	if other > 0 {
		note("ignored %d entry/entries with a different address (the server should not have returned them)", other)
	}
	if empty > 0 {
		note("ignored %d entry/entries without HTML", empty)
	}
	if len(items) == 0 {
		if empty > 0 {
			return nil, fmt.Errorf("%w: the server's signature(s) have no content", ErrNone)
		}
		return nil, ErrNone
	}

	// 2. Merge IDs delivered more than once and entries with identical content.
	var n int
	items, n = dedupe(items, func(c cand) string {
		if c.s.ID == 0 { // ID missing: never merge
			return fmt.Sprintf("no-id-%d", c.idx)
		}
		return fmt.Sprintf("id-%d", c.s.ID)
	})
	if n > 0 {
		note("merged %d ID(s) that were delivered more than once", n)
	}
	items, n = dedupe(items, func(c cand) string { return contentKey(c.s) })
	if n > 0 {
		note("merged %d signature(s) with identical content", n)
	}

	// 3. Account and template, if requested.
	if want := lower(c.Username); want != "" {
		var m []cand
		for _, it := range items {
			if lower(it.s.Username) == want {
				m = append(m, it)
			}
		}
		if len(m) == 0 {
			return nil, fmt.Errorf("%w: account %q (available: %s)", ErrNoMatch, c.Username,
				quoted(distinct(items, func(s api.Signature) string { return s.Username })))
		}
		items = m
	}
	if want := NormTemplate(c.Template); want != "" {
		var m []cand
		for _, it := range items {
			if NormTemplate(it.s.Template) == want {
				m = append(m, it)
			}
		}
		if len(m) == 0 {
			return nil, fmt.Errorf("%w: template %q (available: %s)", ErrNoMatch, c.Template,
				quoted(distinct(items, func(s api.Signature) string { return s.Template })))
		}
		items = m
	}

	// 4. If the address belongs to several accounts we must not guess: the result
	// would be the name, role and phone number of another person.
	if users := distinct(items, func(s api.Signature) string { return lower(s.Username) }); len(users) > 1 {
		return nil, fmt.Errorf("%w: the address belongs to %d accounts (%s) - set <username> in the configuration",
			ErrAmbiguous, len(users), quoted(users))
	}

	if len(items) == 1 {
		return &Choice{Sig: items[0].s, Notes: notes}, nil
	}

	// 5. Several candidates of the same account: apply the rule.
	if c.Policy == PolicySkip {
		return nil, fmt.Errorf("%w: %d signatures (%s) and duplicate-policy=skip", ErrAmbiguous, len(items), ids(items))
	}
	sort.SliceStable(items, func(i, j int) bool { return better(items[i], items[j]) })
	if tpls := distinct(items, func(s api.Signature) string { return NormTemplate(s.Template) }); len(tpls) > 1 {
		note("several templates available (%s) - <template> in the configuration selects the one you want", quoted(tpls))
	}
	note("%d candidates (%s), chosen #%d by rule %q", len(items), ids(items), items[0].s.ID, PolicyNewest)
	return &Choice{Sig: items[0].s, Notes: notes}, nil
}
