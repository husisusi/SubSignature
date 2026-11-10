package outlook

import (
	"encoding/binary"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode/utf16"
)

// SignatureName is the name of the signature in Outlook (and the file name
// without extension). It depends only on the prefix and the address, so it is
// stable: if the content changes, only the file is replaced and the registry
// stays the same. Deliberately without parentheses: "Name (address)" is how
// Outlook itself stores roaming signatures - nothing should be confused with that.
func SignatureName(prefix, email string) string {
	var b strings.Builder
	for _, r := range normEmail(email) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '@', r == '+':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	e := strings.TrimRight(b.String(), ".") // Windows file names must not end with "."
	if len(e) > 78 {
		e = strings.TrimRight(e[:78], ".")
	}
	return prefix + " " + e
}

// Extensions are the files an Outlook signature consists of.
var Extensions = []string{".htm", ".txt", ".rtf"}

var styleBlock = regexp.MustCompile(`(?is)<style\b.*?</style\s*>`)

// HTM turns the checked HTML into the file <name>.htm. The result is pure
// ASCII: characters outside ASCII are written as character references
// (&#252;), inside <style> blocks as CSS escapes. Outlook renders signatures
// with the Word engine, which does not reliably guess the encoding - this way
// the encoding of the file no longer matters at all.
func HTM(prepared string) []byte {
	var out strings.Builder
	last := 0
	for _, loc := range styleBlock.FindAllStringIndex(prepared, -1) {
		writeEscaped(&out, prepared[last:loc[0]], false)
		writeEscaped(&out, prepared[loc[0]:loc[1]], true)
		last = loc[1]
	}
	writeEscaped(&out, prepared[last:], false)
	return []byte(out.String())
}

func writeEscaped(b *strings.Builder, s string, css bool) {
	for _, r := range s {
		switch {
		case r < 0x7f:
			b.WriteRune(r)
		case css:
			fmt.Fprintf(b, `\%06X `, r)
		default:
			fmt.Fprintf(b, "&#%d;", r)
		}
	}
}

var (
	dropBlocks = regexp.MustCompile(`(?is)<(head|style|script|title)\b.*?</(head|style|script|title)\s*>`)
	lineBreaks = regexp.MustCompile(`(?i)<br\s*/?>|</(p|div|tr|li|h[1-6]|table)\s*>`)
	cellEnds   = regexp.MustCompile(`(?i)</t[dh]\s*>`)
	anyTag     = regexp.MustCompile(`(?s)<[^>]*>`)
	spaces     = regexp.MustCompile(`[ \t\x{00a0}]+`)
)

// PlainText returns the text for the plain-text version: the server's text
// or - if the server provides none - a simple derivation from the HTML.
func PlainText(serverText, preparedHTML string) string {
	t := serverText
	if strings.TrimSpace(t) == "" {
		t = dropBlocks.ReplaceAllString(preparedHTML, "")
		t = strings.NewReplacer("\r", "", "\n", " ").Replace(t)
		t = lineBreaks.ReplaceAllString(t, "\n")
		t = cellEnds.ReplaceAllString(t, " ")
		t = html.UnescapeString(anyTag.ReplaceAllString(t, ""))
	}
	t = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(t)
	var lines []string
	blank := 0
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(spaces.ReplaceAllString(strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\t' || r == 0x7f || r == 0xfeff {
				return -1
			}
			return r
		}, l), " "))
		if l == "" {
			if blank++; blank > 1 || len(lines) == 0 {
				continue
			}
		} else {
			blank = 0
		}
		lines = append(lines, l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// TXT is <name>.txt: UTF-16LE with BOM and CRLF - the way Outlook creates the file itself.
func TXT(text string) []byte {
	u := utf16.Encode([]rune(strings.ReplaceAll(text, "\n", "\r\n") + "\r\n"))
	b := make([]byte, 0, 2*len(u)+2)
	b = append(b, 0xFF, 0xFE)
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// RTF is <name>.rtf (for messages in Rich Text format): a plain version made
// from the text. The file is pure ASCII; other characters are written as
// \uN?, characters beyond the BMP as a surrogate pair.
func RTF(text string) []byte {
	var b strings.Builder
	b.WriteString(`{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fswiss\fcharset0 Calibri;}}` + "\r\n" + `\pard\f0\fs22 `)
	for _, r := range text {
		switch {
		case r == '\n':
			b.WriteString(`\par` + "\r\n")
		case r == '\\' || r == '{' || r == '}':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\tab `)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r < 0x20:
		default:
			for _, c := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&b, `\u%d?`, int16(c))
			}
		}
	}
	b.WriteString(`\par}` + "\r\n")
	return []byte(b.String())
}
