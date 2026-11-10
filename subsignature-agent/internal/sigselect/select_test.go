package sigselect

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"subsignature-agent/internal/api"
)

const mail = "anna@example.com"

func ts(s string) api.Time {
	tm, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
	if err != nil {
		panic(err)
	}
	return api.Time{Time: tm}
}

// sig builds an entry; fields can be adjusted through mod.
func sig(id int64, mod func(*api.Signature)) api.Signature {
	s := api.Signature{
		ID: id, Username: "anna", Name: "Anna Example", Email: mail,
		Template: "signature_pro.html", Source: "manual",
		UpdatedAt: ts("2026-11-01 08:00:00"),
		HTML:      fmt.Sprintf("<p>Signature %d</p>", id),
	}
	if mod != nil {
		mod(&s)
	}
	return s
}

func pick(t *testing.T, sigs []api.Signature, c Criteria) *Choice {
	t.Helper()
	ch, err := Select(mail, sigs, c)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	return ch
}

func TestSingleSignature(t *testing.T) {
	ch := pick(t, []api.Signature{sig(7, nil)}, Criteria{})
	if ch.Sig.ID != 7 {
		t.Fatalf("ID = %d", ch.Sig.ID)
	}
}

func TestNothingToChoose(t *testing.T) {
	if _, err := Select(mail, nil, Criteria{}); !errors.Is(err, ErrNone) {
		t.Fatalf("err = %v, expected ErrNone", err)
	}
}

func TestOtherAddressesAreNeverUsed(t *testing.T) {
	other := sig(1, func(s *api.Signature) { s.Email = "bob@example.com"; s.UpdatedAt = ts("2030-01-01 00:00:00") })
	ch := pick(t, []api.Signature{other, sig(2, nil)}, Criteria{})
	if ch.Sig.ID != 2 {
		t.Fatalf("chosen #%d - the signature of another address must never win, even if it is newer", ch.Sig.ID)
	}
	if !strings.Contains(strings.Join(ch.Notes, "|"), "a different address") {
		t.Errorf("no note in the log: %v", ch.Notes)
	}
	if _, err := Select(mail, []api.Signature{other}, Criteria{}); !errors.Is(err, ErrNone) {
		t.Fatalf("foreign address only: err = %v, expected ErrNone", err)
	}
}

func TestEmailComparisonIgnoresCase(t *testing.T) {
	s := sig(1, func(s *api.Signature) { s.Email = "Anna@Example.COM" })
	if ch := pick(t, []api.Signature{s}, Criteria{}); ch.Sig.ID != 1 {
		t.Fatal("the case of the address must not matter (the server compares case-insensitively)")
	}
}

func TestEmptyHTMLIsIgnoredNeverInstalled(t *testing.T) {
	empty := sig(9, func(s *api.Signature) { s.HTML = " \n\t"; s.UpdatedAt = ts("2030-01-01 00:00:00") })
	if ch := pick(t, []api.Signature{empty, sig(1, nil)}, Criteria{}); ch.Sig.ID != 1 {
		t.Fatalf("chosen #%d - an empty signature would delete the signature in Thunderbird", ch.Sig.ID)
	}
	_, err := Select(mail, []api.Signature{empty}, Criteria{})
	if !errors.Is(err, ErrNone) || !strings.Contains(err.Error(), "no content") {
		t.Fatalf("err = %v", err)
	}
}

func TestSameTemplateDuplicatesNewestWins(t *testing.T) {
	old := sig(1, nil)
	newer := sig(2, func(s *api.Signature) { s.UpdatedAt = ts("2026-11-09 08:00:00") })
	ch := pick(t, []api.Signature{old, newer}, Criteria{Policy: PolicyNewest})
	if ch.Sig.ID != 2 {
		t.Fatalf("chosen #%d, expected the most recently changed #2", ch.Sig.ID)
	}
}

func TestTieBreakIsHigherID(t *testing.T) {
	a, b := sig(5, nil), sig(6, nil) // same timestamp
	if ch := pick(t, []api.Signature{a, b}, Criteria{}); ch.Sig.ID != 6 {
		t.Fatalf("chosen #%d, expected #6 (created later)", ch.Sig.ID)
	}
}

func TestZeroTimestampLosesAgainstReal(t *testing.T) {
	noTime := sig(9, func(s *api.Signature) { s.UpdatedAt = api.Time{} })
	if ch := pick(t, []api.Signature{noTime, sig(1, nil)}, Criteria{}); ch.Sig.ID != 1 {
		t.Fatalf("chosen #%d", ch.Sig.ID)
	}
}

// The API does not define the order of the entries. The selection must not depend on it.
func TestResultIndependentOfServerOrder(t *testing.T) {
	base := []api.Signature{
		sig(1, nil),
		sig(2, func(s *api.Signature) { s.UpdatedAt = ts("2026-11-09 08:00:00"); s.Source = "csv" }),
		sig(3, func(s *api.Signature) { s.UpdatedAt = ts("2026-11-09 08:00:00"); s.Source = "ldap" }),
		sig(4, func(s *api.Signature) { s.Template = "signature_short.html"; s.UpdatedAt = ts("2026-10-01 08:00:00") }),
	}
	crit := []Criteria{{}, {Policy: PolicyNewest}, {Template: "signature_pro"}, {PreferSources: []string{"manual", "csv"}}}
	for ci, c := range crit {
		want := pick(t, base, c).Sig.ID
		rng := rand.New(rand.NewSource(int64(ci)))
		for i := 0; i < 200; i++ {
			p := append([]api.Signature(nil), base...)
			rng.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
			if got := pick(t, p, c).Sig.ID; got != want {
				t.Fatalf("Kriterien %+v: Reihenfolge %v ergibt #%d statt #%d", c, idList(p), got, want)
			}
		}
	}
}

func idList(in []api.Signature) []int64 {
	out := make([]int64, len(in))
	for i, s := range in {
		out[i] = s.ID
	}
	return out
}

func TestIdenticalContentIsCollapsed(t *testing.T) {
	a := sig(1, func(s *api.Signature) { s.HTML = "<p>same</p>" })
	b := sig(2, func(s *api.Signature) { s.HTML = "\n<p>same</p>  " }) // only whitespace differs
	ch, err := Select(mail, []api.Signature{a, b}, Criteria{Policy: PolicySkip})
	if err != nil {
		t.Fatalf("entries with identical content are not a duplicate conflict, not even with skip: %v", err)
	}
	if !strings.Contains(strings.Join(ch.Notes, "|"), "identical content") {
		t.Errorf("Notes = %v", ch.Notes)
	}
}

func TestSameIDDeliveredTwiceIsCollapsed(t *testing.T) {
	a := sig(1, nil)
	b := sig(1, func(s *api.Signature) { s.HTML = "<p>other text</p>" }) // contradictory, but same ID
	if _, err := Select(mail, []api.Signature{a, b}, Criteria{Policy: PolicySkip}); err != nil {
		t.Fatalf("the same ID is the same entry: %v", err)
	}
}

func TestMissingIDsAreNotCollapsed(t *testing.T) {
	a := sig(0, func(s *api.Signature) { s.HTML = "<p>A</p>" })
	b := sig(0, func(s *api.Signature) { s.HTML = "<p>B</p>" })
	if _, err := Select(mail, []api.Signature{a, b}, Criteria{Policy: PolicySkip}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two different entries without ID must not be merged: %v", err)
	}
}

func TestSkipPolicy(t *testing.T) {
	two := []api.Signature{sig(1, nil), sig(2, nil)}
	_, err := Select(mail, two, Criteria{Policy: PolicySkip})
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "#1") || !strings.Contains(err.Error(), "#2") {
		t.Fatalf("err = %v, expected ErrAmbiguous with both IDs", err)
	}
	if ch := pick(t, []api.Signature{sig(1, nil)}, Criteria{Policy: PolicySkip}); ch.Sig.ID != 1 {
		t.Fatal("skip must not block an unambiguous signature")
	}
}

func TestTemplateFilter(t *testing.T) {
	pro := sig(1, nil)
	short := sig(2, func(s *api.Signature) { s.Template = "Signature_Short.HTML"; s.UpdatedAt = ts("2026-11-09 08:00:00") })
	all := []api.Signature{pro, short}

	for _, want := range []string{"signature_short.html", "SIGNATURE_SHORT", " signature_short ", "signature_short.htm"} {
		if ch := pick(t, all, Criteria{Template: want}); ch.Sig.ID != 2 {
			t.Errorf("template %q: chosen #%d", want, ch.Sig.ID)
		}
	}
	// Without a filter the newer one (#2) wins; with a filter on the older template the filter counts, not the age.
	if ch := pick(t, all, Criteria{Template: "signature_pro"}); ch.Sig.ID != 1 {
		t.Fatalf("chosen #%d", ch.Sig.ID)
	}
	_, err := Select(mail, all, Criteria{Template: "does-not-exist"})
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, expected ErrNoMatch", err)
	}
	if !strings.Contains(err.Error(), "signature_pro.html") || !strings.Contains(err.Error(), "Signature_Short.HTML") {
		t.Errorf("the error text does not name the available templates: %v", err)
	}
}

func TestTemplateFilterIgnoresPersonName(t *testing.T) {
	// "name" is the name of the PERSON. It must never count as a template name.
	s := sig(1, func(s *api.Signature) { s.Name = "signature_pro"; s.Template = "signature_other.html" })
	if _, err := Select(mail, []api.Signature{s}, Criteria{Template: "signature_pro"}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, expected ErrNoMatch", err)
	}
}

func TestTemplateFilterAppliesToSingleCandidateToo(t *testing.T) {
	// Only one signature, but not the requested template: change nothing instead of taking the wrong one.
	if _, err := Select(mail, []api.Signature{sig(1, nil)}, Criteria{Template: "signature_sales"}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, expected ErrNoMatch", err)
	}
}

func TestMultipleTemplatesWithoutFilterHintsAtConfig(t *testing.T) {
	short := sig(2, func(s *api.Signature) { s.Template = "signature_short.html" })
	ch := pick(t, []api.Signature{sig(1, nil), short}, Criteria{})
	if !strings.Contains(strings.Join(ch.Notes, "|"), "<template>") {
		t.Errorf("Notes = %v - no hint at <template>", ch.Notes)
	}
}

func TestUsernameFilter(t *testing.T) {
	anna := sig(1, nil)
	bob := sig(2, func(s *api.Signature) { s.Username = "bob"; s.Name = "Bob"; s.UpdatedAt = ts("2026-11-09 08:00:00") })
	for _, u := range []string{"anna", "ANNA", " anna "} {
		if ch := pick(t, []api.Signature{anna, bob}, Criteria{Username: u}); ch.Sig.ID != 1 {
			t.Errorf("account %q: chosen #%d", u, ch.Sig.ID)
		}
	}
	_, err := Select(mail, []api.Signature{anna, bob}, Criteria{Username: "carl"})
	if !errors.Is(err, ErrNoMatch) || !strings.Contains(err.Error(), "anna") || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("err = %v", err)
	}
}

// Shared mailbox: the same address on two accounts. Guessing would mean using the name, role
// and phone number of another person - this holds regardless of the rule.
func TestSeveralAccountsNeverGuessed(t *testing.T) {
	anna := sig(1, nil)
	bob := sig(2, func(s *api.Signature) {
		s.Username = "bob"
		s.HTML = "<p>Bob</p>"
		s.UpdatedAt = ts("2026-11-09 08:00:00")
	})
	for _, pol := range []string{"", PolicyNewest, PolicySkip} {
		_, err := Select(mail, []api.Signature{anna, bob}, Criteria{Policy: pol})
		if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "<username>") {
			t.Fatalf("rule %q: err = %v, expected ErrAmbiguous with a hint at <username>", pol, err)
		}
	}
	if ch := pick(t, []api.Signature{anna, bob}, Criteria{Username: "bob"}); ch.Sig.ID != 2 {
		t.Fatalf("with username=bob: #%d", ch.Sig.ID)
	}
}

func TestTemplateCanResolveAccountConflict(t *testing.T) {
	anna := sig(1, nil)
	bob := sig(2, func(s *api.Signature) { s.Username = "bob"; s.Template = "signature_bob.html" })
	if ch := pick(t, []api.Signature{anna, bob}, Criteria{Template: "signature_bob"}); ch.Sig.ID != 2 {
		t.Fatalf("chosen #%d", ch.Sig.ID)
	}
}

func TestAccountNamesCompareIgnoringCase(t *testing.T) {
	a := sig(1, func(s *api.Signature) { s.Username = "Anna" })
	b := sig(2, func(s *api.Signature) { s.Username = "anna"; s.UpdatedAt = ts("2026-11-09 08:00:00") })
	if ch := pick(t, []api.Signature{a, b}, Criteria{}); ch.Sig.ID != 2 {
		t.Fatalf("Anna/anna is the same account: chosen #%d", ch.Sig.ID)
	}
}

func TestPreferSource(t *testing.T) {
	manual := sig(1, func(s *api.Signature) { s.Source = "manual"; s.UpdatedAt = ts("2026-10-01 08:00:00") })
	ldap := sig(2, func(s *api.Signature) { s.Source = "ldap"; s.UpdatedAt = ts("2026-11-09 08:00:00") })
	csv := sig(3, func(s *api.Signature) { s.Source = "csv"; s.UpdatedAt = ts("2026-11-05 08:00:00") })
	all := []api.Signature{manual, ldap, csv}

	if ch := pick(t, all, Criteria{}); ch.Sig.ID != 2 {
		t.Fatalf("without a ranking only the age counts: #%d", ch.Sig.ID)
	}
	if ch := pick(t, all, Criteria{PreferSources: []string{"manual", "csv", "ldap"}}); ch.Sig.ID != 1 {
		t.Fatalf("manual first: #%d", ch.Sig.ID)
	}
	if ch := pick(t, all, Criteria{PreferSources: []string{"ldap"}}); ch.Sig.ID != 2 {
		t.Fatalf("ldap first: #%d", ch.Sig.ID)
	}
	// Sources not listed come after the listed ones, ordered by age among themselves.
	if ch := pick(t, all, Criteria{PreferSources: []string{"csv"}}); ch.Sig.ID != 3 {
		t.Fatalf("csv first: #%d", ch.Sig.ID)
	}
	if ch := pick(t, all, Criteria{PreferSources: []string{" CSV "}}); ch.Sig.ID != 3 {
		t.Fatalf("spelling does not matter: #%d", ch.Sig.ID)
	}
}

func TestNotesDescribeTheDecision(t *testing.T) {
	ch := pick(t, []api.Signature{sig(1, nil), sig(2, func(s *api.Signature) { s.UpdatedAt = ts("2026-11-09 08:00:00") })}, Criteria{})
	joined := strings.Join(ch.Notes, "|")
	if !strings.Contains(joined, "#1") || !strings.Contains(joined, "#2") || !strings.Contains(joined, "chosen #2") {
		t.Errorf("Notes = %v", ch.Notes)
	}
}

func TestNormTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"signature_pro.html": "signature_pro", "Signature_Pro.HTM": "signature_pro", "  x  ": "x", "": "", "a.html.html": "a.html",
	} {
		if got := NormTemplate(in); got != want {
			t.Errorf("NormTemplate(%q) = %q, expected %q", in, got, want)
		}
	}
}
