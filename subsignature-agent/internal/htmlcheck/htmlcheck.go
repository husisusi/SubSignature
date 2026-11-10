// Package htmlcheck checks and normalizes signature HTML before it is written
// to a file that the mail client later inserts into every message.
//
// The check is an additional safeguard (a "tripwire"), not a full HTML
// sanitizer: the server is considered trustworthy.
package htmlcheck

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxSize = 1 << 20 // 1 MiB

var (
	tagRe     = regexp.MustCompile(`(?s)<\s*/?\s*([a-zA-Z][a-zA-Z0-9:-]*)([^>]*)>`)
	onAttrRe  = regexp.MustCompile(`(?i)[\s"'/]on[a-z]+\s*=`)
	scriptURL = regexp.MustCompile(`(?i)(javascript|vbscript)\s*:|data\s*:\s*text/html`)
	refreshRe = regexp.MustCompile(`(?i)http-equiv\s*=\s*["']?\s*refresh`)
	titleRe   = regexp.MustCompile(`(?is)<title\b[^>]*>.*?</title\s*>`)
	htmlTagRe = regexp.MustCompile(`(?i)<html[\s>]`)
	headRe    = regexp.MustCompile(`(?i)<head[^>]*>`)
	htmlOpen  = regexp.MustCompile(`(?i)<html[^>]*>`)
	charsetRe = regexp.MustCompile(`(?i)<meta[^>]+charset`)
)

var forbiddenTags = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true,
	"object": true, "embed": true, "applet": true, "base": true, "form": true,
}

// Check returns all violations found.
func Check(html string) []string {
	var found []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			found = append(found, s)
		}
	}
	for _, m := range tagRe.FindAllStringSubmatch(html, -1) {
		name := strings.ToLower(m[1])
		attrs := m[2]
		if forbiddenTags[name] {
			add("tag <" + name + "> is not allowed")
		}
		if onAttrRe.MatchString(" " + attrs) {
			add("event attribute (on...=) in <" + name + ">")
		}
		if scriptURL.MatchString(attrs) {
			add("javascript:/vbscript:/data:text/html in <" + name + ">")
		}
		if name == "meta" && refreshRe.MatchString(attrs) {
			add("<meta http-equiv=refresh> is not allowed")
		}
	}
	return found
}

// Prepare checks (policy "reject") and normalizes the HTML for Thunderbird:
// valid UTF-8, a complete document with <meta charset>, no <title>
// (some Thunderbird versions otherwise show the title in the message).
func Prepare(raw, policy string) (string, error) {
	s := strings.TrimPrefix(raw, "\xef\xbb\xbf") // UTF-8 BOM
	if strings.TrimSpace(s) == "" {
		return "", errors.New("signature is empty")
	}
	if len(s) > MaxSize {
		return "", fmt.Errorf("signature is larger than %d KiB", MaxSize>>10)
	}
	if !utf8.ValidString(s) {
		return "", errors.New("signature is not valid UTF-8")
	}
	if strings.ContainsRune(s, 0) {
		return "", errors.New("signature contains NUL characters")
	}
	if policy != "off" {
		if v := Check(s); len(v) > 0 {
			return "", fmt.Errorf("signature rejected: %s", strings.Join(v, "; "))
		}
	}

	s = titleRe.ReplaceAllString(s, "")
	if !htmlTagRe.MatchString(s) {
		s = "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"></head><body>\n" + strings.TrimSpace(s) + "\n</body></html>"
	} else if !charsetRe.MatchString(s) {
		const meta = `<meta charset="utf-8">`
		if loc := headRe.FindStringIndex(s); loc != nil {
			s = s[:loc[1]] + meta + s[loc[1]:]
		} else if loc := htmlOpen.FindStringIndex(s); loc != nil {
			s = s[:loc[1]] + "<head>" + meta + "</head>" + s[loc[1]:]
		}
	}
	return strings.TrimRight(s, "\n") + "\n", nil
}
