package thunderbird

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Prefs are the settings from prefs.js/user.js (value: string, bool or float64).
type Prefs map[string]any

func (p Prefs) String(key string) string {
	s, _ := p[key].(string)
	return s
}

var prefLine = regexp.MustCompile(`^\s*user_pref\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(.*?)\s*\)\s*;\s*$`)

// ParsePrefs reads user_pref("name", value); lines. Unreadable lines are
// skipped; commented-out lines do not count.
func ParsePrefs(content string) Prefs {
	p := Prefs{}
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		m := prefLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var key string
		if err := json.Unmarshal([]byte(`"`+m[1]+`"`), &key); err != nil {
			continue
		}
		var val any
		if err := json.Unmarshal([]byte(m[2]), &val); err != nil {
			continue
		}
		p[key] = val
	}
	return p
}

func readOptional(path string) (string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}

// LoadEffective returns prefs.js overlaid with user.js. Our own block in
// user.js is not included, so that we never read our own values as a
// "user setting".
func LoadEffective(profileDir string) (Prefs, error) {
	pj, err := readOptional(filepath.Join(profileDir, "prefs.js"))
	if err != nil {
		return nil, err
	}
	uj, err := readOptional(filepath.Join(profileDir, "user.js"))
	if err != nil {
		return nil, err
	}
	if stripped, err := StripBlock(uj); err == nil {
		uj = stripped
	}
	p := ParsePrefs(pj)
	for k, v := range ParsePrefs(uj) {
		p[k] = v
	}
	return p, nil
}

// Identity is a sender identity of an account.
type Identity struct {
	ID       string // e.g. "id1"
	Email    string // lower case, without whitespace
	FullName string
}

var (
	identKey   = regexp.MustCompile(`^mail\.identity\.(id\d+)\.useremail$`)
	acctIdents = regexp.MustCompile(`^mail\.account\.account\d+\.identities$`)
)

// NormalizeEmail normalizes addresses for comparison.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Identities returns the identities that have an e-mail address. Identities
// that no longer belong to any account (leftovers of deleted accounts) are
// omitted. Several identities with the same address are kept separately.
func Identities(p Prefs) []Identity {
	linked := map[string]bool{}
	for k, v := range p {
		if acctIdents.MatchString(k) {
			if s, ok := v.(string); ok {
				for _, id := range strings.Split(s, ",") {
					linked[strings.TrimSpace(id)] = true
				}
			}
		}
	}
	var out []Identity
	for k, v := range p {
		m := identKey.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		email := NormalizeEmail(fmt.Sprint(v))
		if !strings.Contains(email, "@") {
			continue
		}
		if len(linked) > 0 && !linked[m[1]] {
			continue
		}
		out = append(out, Identity{ID: m[1], Email: email, FullName: p.String("mail.identity." + m[1] + ".fullName")})
	}
	sort.Slice(out, func(i, j int) bool { return idNum(out[i].ID) < idNum(out[j].ID) })
	return out
}

func idNum(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "id"))
	return n
}
