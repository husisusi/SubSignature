package htmlcheck

import (
	"strings"
	"testing"
)

func TestFragmentIsWrapped(t *testing.T) {
	out, err := Prepare("<p>Hello</p>", "reject")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<!DOCTYPE html>", `<meta charset="utf-8">`, "<body>", "<p>Hello</p>", "</html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing in %q", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("trailing newline is missing")
	}
}

func TestFullDocumentGetsCharsetAndLosesTitle(t *testing.T) {
	in := "<html><head><title>My title</title></head><body>Hello Müller</body></html>"
	out, err := Prepare(in, "reject")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "My title") || strings.Contains(out, "<title") {
		t.Errorf("the title must be removed: %q", out)
	}
	if !strings.Contains(out, `<head><meta charset="utf-8">`) {
		t.Errorf("charset is missing: %q", out)
	}
	if !strings.Contains(out, "Müller") {
		t.Error("umlaut lost")
	}
}

func TestDocumentWithoutHeadGetsOne(t *testing.T) {
	out, err := Prepare(`<html lang="de"><body>x</body></html>`, "reject")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<html lang="de"><head><meta charset="utf-8"></head><body>`) {
		t.Errorf("%q", out)
	}
}

func TestExistingCharsetIsKept(t *testing.T) {
	in := `<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body>x</body></html>`
	out, _ := Prepare(in, "reject")
	if strings.Count(strings.ToLower(out), "charset") != 1 {
		t.Errorf("charset twice: %q", out)
	}
}

func TestIdempotent(t *testing.T) {
	for _, in := range []string{"<p>x</p>", "<html><head><title>t</title></head><body>y</body></html>"} {
		once, err := Prepare(in, "reject")
		if err != nil {
			t.Fatal(err)
		}
		twice, err := Prepare(once, "reject")
		if err != nil {
			t.Fatal(err)
		}
		if once != twice {
			t.Errorf("not idempotent:\n%q\n%q", once, twice)
		}
	}
}

func TestBOMIsStripped(t *testing.T) {
	out, err := Prepare("\xef\xbb\xbf<p>x</p>", "reject")
	if err != nil || strings.Contains(out, "\xef\xbb\xbf") {
		t.Fatalf("BOM: %q %v", out, err)
	}
}

func TestRejects(t *testing.T) {
	bad := map[string]string{
		"script":         `<p>x</p><script>alert(1)</script>`,
		"SCRIPT upper":   `<SCRIPT SRC=x></SCRIPT>`,
		"iframe":         `<iframe src="https://x"></iframe>`,
		"object":         `<object data="x"></object>`,
		"embed":          `<embed src="x">`,
		"form":           `<form action="https://x"><input></form>`,
		"base":           `<base href="https://evil.example/">`,
		"onclick":        `<a href="https://x" onclick="evil()">x</a>`,
		"onerror":        `<img src="x" onerror=alert(1)>`,
		"onload quote":   `<body onload="x()">y</body>`,
		"javascript:":    `<a href="javascript:evil()">x</a>`,
		"JavaScript:":    `<a href=" JaVaScRiPt :evil()">x</a>`,
		"data html":      `<a href="data:text/html;base64,AAAA">x</a>`,
		"meta refresh":   `<meta http-equiv="refresh" content="0;url=https://evil">`,
		"script with ws": "<script\n>x</script>",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Prepare(in, "reject"); err == nil {
				t.Fatalf("%q should have been rejected", in)
			}
		})
	}
}

func TestAcceptsNormalSignatureHTML(t *testing.T) {
	ok := `<table style="font-family:Arial;font-size:12px" cellpadding="0"><tr><td>
	<b>Max Mustermann</b><br>Managing Director<br>
	<a href="https://example.com/contact?a=1&b=2">Contact</a> | Tel. +49 (0)30 123 456<br>
	<img src="https://example.com/logo.png" width="120" alt="Logo on top"> We are online: Monday = Friday
	</td></tr></table>`
	if _, err := Prepare(ok, "reject"); err != nil {
		t.Fatalf("ordinary signature rejected: %v", err)
	}
}

func TestOffPolicySkipsCheck(t *testing.T) {
	if _, err := Prepare(`<script>x</script>`, "off"); err != nil {
		t.Fatalf("policy=off must not check: %v", err)
	}
}

func TestInvalidInput(t *testing.T) {
	if _, err := Prepare("  \n ", "reject"); err == nil {
		t.Error("empty must fail")
	}
	if _, err := Prepare("<p>\xff\xfe</p>", "reject"); err == nil {
		t.Error("invalid UTF-8 must fail")
	}
	if _, err := Prepare("<p>a\x00b</p>", "reject"); err == nil {
		t.Error("NUL must fail")
	}
	if _, err := Prepare(strings.Repeat("a", MaxSize+1), "reject"); err == nil {
		t.Error("too large must fail")
	}
}
