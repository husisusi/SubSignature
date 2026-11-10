package outlook

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"subsignature-agent/internal/platform"
)

const base16 = `Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\` + accountsGUID

func sz(s string) Value { return StringValue(RegSZ, s) }

func winEnv(t *testing.T) platform.Env {
	home := t.TempDir()
	vars := map[string]string{"APPDATA": filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(home, "AppData", "Local")}
	return platform.Env{GOOS: "windows", Home: home, Getenv: func(k string) string { return vars[k] }}
}

func TestStringValueRoundTrip(t *testing.T) {
	for _, s := range []string{"", "Standard", "Müller & Söhne", "名前", "😀 x"} {
		for _, typ := range []uint32{RegSZ, RegBinary, RegExpandSZ} {
			v := StringValue(typ, s)
			if len(v.Data)%2 != 0 || !bytes.HasSuffix(v.Data, []byte{0, 0}) {
				t.Errorf("%q: expected UTF-16 with a terminating NUL, got % x", s, v.Data)
			}
			if got, ok := v.String(); !ok || got != s {
				t.Errorf("%q (Typ %d) -> %q/%v", s, typ, got, ok)
			}
		}
	}
	// Known example from an old Outlook registry: "Default" as REG_BINARY.
	raw := []byte{0x44, 0, 0x65, 0, 0x66, 0, 0x61, 0, 0x75, 0, 0x6c, 0, 0x74, 0, 0, 0}
	if s, ok := (Value{Type: RegBinary, Data: raw}).String(); !ok || s != "Default" {
		t.Errorf("got %q", s)
	}
	if !bytes.Equal(StringValue(RegBinary, "Default").Data, raw) {
		t.Error("encoding differs from the Outlook example")
	}
	// Robust against malformed data.
	if s, _ := (Value{Type: RegSZ, Data: []byte{0x41, 0, 0x42}}).String(); s != "A" {
		t.Errorf("odd length: %q", s)
	}
	if s, _ := (Value{Type: RegSZ, Data: []byte{0x41, 0, 0, 0, 0x42, 0}}).String(); s != "A" {
		t.Errorf("text ends at the first NUL: %q", s)
	}
	if _, ok := DWORDValue(1).String(); ok {
		t.Error("a DWORD is not text")
	}
	if n, ok := DWORDValue(7).DWORD(); !ok || n != 7 {
		t.Error("DWORD")
	}
	if _, ok := sz("1").DWORD(); ok {
		t.Error("text is not a DWORD")
	}
}

func TestAccounts(t *testing.T) {
	reg := NewMemRegistry()
	reg.Put(`Software\Microsoft\Office\16.0\Outlook`, "DefaultProfile", sz("Outlook"))
	reg.Put(base16+`\00000001`, "Account Name", sz("Outlook Address Book"))
	reg.Put(base16+`\00000002`, "Account Name", sz("Work"))
	reg.Put(base16+`\00000002`, "Email", sz(" Max.Mustermann@Example.com "))
	reg.Put(base16+`\00000002`, ValueNew, sz("Old"))
	reg.Put(base16+`\00000003`, "Account Name", sz("erika@example.com")) // Exchange: named after the address
	reg.Put(base16+`\00000004`, "Account Name", sz("Renamed Exchange account"))
	reg.Put(base16+`\00000004`, "Service UID", Value{Type: RegBinary, Data: []byte{1, 2, 3}})
	reg.Put(base16+`\zzz`, "Email", sz("x@example.com")) // not an account subkey
	// second profile and second Office version
	other := `Software\Microsoft\Office\16.0\Outlook\Profiles\Privat\` + accountsGUID + `\00000002`
	reg.Put(other, "Email", sz("private@example.org"))
	old := `Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\` + accountsGUID + `\00000002`
	reg.Put(old, "Email", StringValue(RegBinary, "old@example.com"))
	reg.Put(`Software\Microsoft\Office\14.0\Outlook\Profiles\Outlook\`+accountsGUID+`\00000002`, "Email", sz("ancient@example.com"))
	reg.Put(`Software\Microsoft\Office\ClickToRun`, "x", sz("y"))

	got, err := Accounts(reg, false)
	if err != nil {
		t.Fatal(err)
	}
	var emails []string
	for _, a := range got {
		emails = append(emails, a.Email)
	}
	if strings.Join(emails, ",") != "old@example.com,max.mustermann@example.com,erika@example.com" {
		t.Fatalf("Konten = %v", emails)
	}
	if a := got[0]; a.Version != "15.0" || a.TextType != RegBinary {
		t.Errorf("Outlook 2013: %+v", a)
	}
	if a := got[1]; a.Version != "16.0" || a.Profile != "Outlook" || a.ID != "00000002" || a.Name != "Work" || a.New != "Old" || !a.HasNew || a.HasReply || a.TextType != RegSZ {
		t.Errorf("account = %+v", a)
	}
	if !strings.EqualFold(got[1].Key, base16+`\00000002`) {
		t.Errorf("Key = %q", got[1].Key)
	}

	all, _ := Accounts(reg, true)
	if len(all) != 4 || all[3].Email != "private@example.org" {
		t.Errorf("all profiles: %d accounts", len(all))
	}

	// No default profile named: all profiles count.
	reg2 := NewMemRegistry()
	reg2.Put(other, "Email", sz("private@example.org"))
	if a, _ := Accounts(reg2, false); len(a) != 1 {
		t.Errorf("without DefaultProfile: %d accounts", len(a))
	}
	// No Outlook installed.
	if a, err := Accounts(NewMemRegistry(), true); err != nil || len(a) != 0 {
		t.Errorf("empty registry: %v %v", a, err)
	}
}

func TestSignatureDir(t *testing.T) {
	env := winEnv(t)
	reg := NewMemRegistry()
	want := filepath.Join(env.AppData(), "Microsoft", "Signatures")
	if d, err := SignatureDir(reg, env, "16.0"); err != nil || d != want {
		t.Fatalf("Vorgabe: %q %v", d, err)
	}
	general := `Software\Microsoft\Office\16.0\Common\General`
	reg.Put(general, "Signatures", sz("Signaturen"))
	if d, _ := SignatureDir(reg, env, "16.0"); d != filepath.Join(env.AppData(), "Microsoft", "Signaturen") {
		t.Errorf("lokalisiert: %q", d)
	}
	for _, evil := range []string{`..\..\..\Desktop`, `../x`, `C:\Temp`, `\\server\share`, `a\b`, `..`, `.`, `x:y`} {
		reg.Put(general, "Signatures", sz(evil))
		if d, err := SignatureDir(reg, env, "16.0"); !errors.Is(err, ErrUnusualDir) || d != "" {
			t.Errorf("%q: %q %v - must be rejected", evil, d, err)
		}
	}
}

func TestSetDefaultOnlyWritesWhereAllowed(t *testing.T) {
	reg := NewMemRegistry()
	key := base16 + `\00000002`
	reg.Put(key, "Email", sz("a@b.de"))
	acct := Account{Key: key, TextType: RegSZ}
	if err := SetDefault(reg, acct, ValueNew, "SubSignature a@b.de"); err != nil {
		t.Fatal(err)
	}
	if v, _ := reg.Get(key, ValueNew); v.Type != RegSZ {
		t.Errorf("Typ %d", v.Type)
	}
	reg.Writes = nil

	// other keys, other values, malformed names: all rejected, nothing written
	evilKeys := []string{
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		`Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\` + accountsGUID,
		`Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\` + accountsGUID + `\00000002\Sub`,
		`Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\..\..\..\..\..\Windows\` + accountsGUID + `\00000002`,
		`Software\Microsoft\Office\14.0\Outlook\Profiles\Outlook\` + accountsGUID + `\00000002`,
		`Software\Policies\Microsoft\Office\16.0\Outlook\Profiles\Outlook\` + accountsGUID + `\00000002`,
		``,
	}
	for _, k := range evilKeys {
		reg.AddKey(k)
		if err := SetDefault(reg, Account{Key: k}, ValueNew, "SubSignature a@b.de"); err == nil {
			t.Errorf("key %q was accepted", k)
		}
		if err := Restore(reg, k, ValueNew, nil); err == nil {
			t.Errorf("Restore on %q was accepted", k)
		}
	}
	for _, name := range []string{"Email", "Account Name", "Service UID", "new signature ", ""} {
		if err := SetDefault(reg, acct, name, "SubSignature a@b.de"); err == nil {
			t.Errorf("value name %q was accepted", name)
		}
	}
	for _, sig := range []string{"", `..\..\evil`, "a/b", "x\x00y", `a"b`, strings.Repeat("a", 200), " leading"} {
		if err := SetDefault(reg, acct, ValueNew, sig); err == nil {
			t.Errorf("signature name %q was accepted", sig)
		}
	}
	if len(reg.Writes) != 0 {
		t.Fatalf("written despite rejection: %v", reg.Writes)
	}

	// Restore: an implausible previous value (from a manipulated state file) is not written back.
	if err := Restore(reg, key, ValueNew, &Value{Type: RegDWORD, Data: []byte{1, 0, 0, 0}}); err == nil {
		t.Error("a DWORD was written back as signature name")
	}
	if err := Restore(reg, key, ValueNew, &Value{Type: RegSZ, Data: make([]byte, 10000)}); err == nil {
		t.Error("a huge previous value was written back")
	}
	prev := sz("Old")
	if err := Restore(reg, key, ValueReply, &prev); err != nil {
		t.Fatal(err)
	}
	if err := Restore(reg, key, ValueNew, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Get(key, ValueNew); !errors.Is(err, ErrNotExist) {
		t.Error("the value should have been removed")
	}
}

func TestSetNeverCreatesKeys(t *testing.T) {
	reg := NewMemRegistry()
	key := base16 + `\00000002` // does not exist
	if err := SetDefault(reg, Account{Key: key, TextType: RegSZ}, ValueNew, "SubSignature a@b.de"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("err = %v - nothing may be written into a missing key", err)
	}
	one := DWORDValue(1)
	if err := SetRoamingSwitch(reg, "16.0", ValueNoRoaming, &one); !errors.Is(err, ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
	if subs, err := reg.SubKeys(`Software`); err == nil && len(subs) > 0 {
		t.Errorf("keys were created: %v", subs)
	}
}

func TestRoamingSwitch(t *testing.T) {
	reg := NewMemRegistry()
	if s := RoamingState(reg, "16.0"); s.Disabled || s.HasSetup {
		t.Errorf("leer: %+v", s)
	}
	reg.AddKey(setupKey("16.0"))
	one, zero := DWORDValue(1), DWORDValue(0)
	for _, bad := range []string{"First-Run", "DisableRoamingSignaturesX", ""} {
		if err := SetRoamingSwitch(reg, "16.0", bad, &one); err == nil {
			t.Errorf("value %q accepted", bad)
		}
	}
	for _, ver := range []string{"14.0", `16.0\..\..`, "", "x"} {
		reg.AddKey(setupKey(ver))
		if err := SetRoamingSwitch(reg, ver, ValueNoRoaming, &one); err == nil {
			t.Errorf("Version %q akzeptiert", ver)
		}
	}
	notDword := sz("1")
	if err := SetRoamingSwitch(reg, "16.0", ValueNoRoaming, &notDword); err == nil {
		t.Error("text instead of a DWORD was accepted")
	}
	if len(reg.Writes) != 0 {
		t.Fatalf("written: %v", reg.Writes)
	}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(SetRoamingSwitch(reg, "16.0", ValueNoRoaming, &zero))
	if RoamingState(reg, "16.0").Disabled {
		t.Error("0 does not mean disabled")
	}
	must(SetRoamingSwitch(reg, "16.0", ValueNoRoamingOld, &one))
	if s := RoamingState(reg, "16.0"); !s.Disabled || s.ByPolicy || !s.HasSetup {
		t.Errorf("%+v", s)
	}
	must(SetRoamingSwitch(reg, "16.0", ValueNoRoamingOld, nil))
	if RoamingState(reg, "16.0").Disabled || RoamingSwitchValue(reg, "16.0", ValueNoRoamingOld) != nil {
		t.Error("switch not removed")
	}
	reg.Put(policyKey+`\16.0\Outlook\Setup`, ValueNoRoaming, one)
	if s := RoamingState(reg, "16.0"); !s.Disabled || !s.ByPolicy {
		t.Errorf("Richtlinie: %+v", s)
	}
	for _, w := range reg.Writes {
		if strings.Contains(strings.ToLower(w), "policies") {
			t.Errorf("policy branch written: %s", w)
		}
	}
}

func TestDetectNewOutlook(t *testing.T) {
	env := winEnv(t)
	reg := NewMemRegistry()
	if n := DetectNewOutlook(reg, env); n.Installed || n.Active {
		t.Errorf("%+v", n)
	}
	if err := os.MkdirAll(filepath.Join(env.LocalAppData(), "Packages", "Microsoft.OutlookForWindows_8wekyb3d8bbwe"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg.Put(`Software\Microsoft\Office\16.0\Outlook\Preferences`, "UseNewOutlook", DWORDValue(0))
	if n := DetectNewOutlook(reg, env); !n.Installed || n.Active {
		t.Errorf("%+v", n)
	}
	reg.Put(`Software\Microsoft\Office\16.0\Outlook\Preferences`, "UseNewOutlook", DWORDValue(1))
	if n := DetectNewOutlook(reg, env); !n.Active {
		t.Errorf("%+v", n)
	}
	if n := DetectNewOutlook(nil, env); !n.Installed || n.Active {
		t.Errorf("without registry: %+v", n)
	}
}

func TestSignatureName(t *testing.T) {
	cases := map[string]string{
		"Max.Mustermann@Example.com":    "SubSignature max.mustermann@example.com",
		"a+b_c-d@x.de":                  "SubSignature a+b_c-d@x.de",
		`a\..\..\b@x.de`:                "SubSignature a_.._.._b@x.de",
		"a/b:c*d?e\"f<g>h|i@x.de":       "SubSignature a_b_c_d_e_f_g_h_i@x.de",
		"müller@exämple.de":             "SubSignature m_ller@ex_mple.de",
		"a@x.de.":                       "SubSignature a@x.de",
		"a b@x.de\r\n":                  "SubSignature a_b@x.de",
		strings.Repeat("a", 200) + "@x": "SubSignature " + strings.Repeat("a", 78),
	}
	for in, want := range cases {
		got := SignatureName("SubSignature", in)
		if got != want {
			t.Errorf("%q -> %q, expected %q", in, got, want)
		}
		if !ValidName(got) {
			t.Errorf("%q is not a valid name", got)
		}
		if strings.ContainsAny(got, `\/:*?"<>|`) || strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
			t.Errorf("%q is not usable as a Windows file name", got)
		}
	}
	if SignatureName("X", "a@b.de") == SignatureName("X", "a_b.de") {
		t.Log("note: @ is kept, hence no collision with a_b.de")
	}
}

func TestHTMIsPureASCIIAndKeepsMeaning(t *testing.T) {
	in := "<html><head><meta charset=\"utf-8\"><style>p{font-family:'Grüße'}</style></head><body>" +
		"<p title=\"Größe\">Jörg Müßig – 日本 😀 &amp; &uuml;</p><STYLE type=\"text/css\">.ä{}</STYLE></body></html>"
	out := string(HTM(in))
	for i := 0; i < len(out); i++ {
		if out[i] >= 0x7f {
			t.Fatalf("byte 0x%02x at position %d - the file must be pure ASCII", out[i], i)
		}
	}
	for _, want := range []string{
		"J&#246;rg M&#252;&#223;ig &#8211; &#26085;&#26412; &#128512; &amp; &uuml;", // text: character references, existing ones are kept
		`title="Gr&#246;&#223;e"`,           // attributes likewise
		`font-family:'Gr\0000FC \0000DF e'`, // CSS: HTML references do not apply there
		`.\0000E4 {}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "&#") && strings.Contains(out[strings.Index(out, "<style>"):strings.Index(out, "</style>")], "&#") {
		t.Error("HTML character reference inside <style>")
	}
	if plain := "<p>ASCII only</p>"; string(HTM(plain)) != plain {
		t.Error("ASCII must stay unchanged")
	}
}

func TestPlainText(t *testing.T) {
	if got := PlainText("Anna Example\r\nCTO\r\n\r\n\r\n\r\nTel. 1\x00\x07\n", "<p>ignored</p>"); got != "Anna Example\nCTO\n\nTel. 1" {
		t.Errorf("Servertext: %q", got)
	}
	html := "<html><head><title>x</title><style>p{color:red}</style></head><body>\n<table><tr><td><b>Max&nbsp;M&uuml;ller</b><br>Example Ltd</td><td>Tel. +49</td></tr></table><p>Fu&szlig;zeile</p></body></html>"
	got := PlainText("  ", html)
	if got != "Max Müller\nExample Ltd Tel. +49\n\nFußzeile" && got != "Max Müller\nExample Ltd Tel. +49\nFußzeile" {
		t.Errorf("from HTML: %q", got)
	}
	if strings.Contains(got, "color") || strings.Contains(got, "<") {
		t.Errorf("leftover markup: %q", got)
	}
}

func TestTXTIsUTF16WithBOM(t *testing.T) {
	b := TXT("Grüße\nLine 2 😀")
	if len(b) < 2 || b[0] != 0xFF || b[1] != 0xFE || len(b)%2 != 0 {
		t.Fatalf("BOM/length: % x", b[:4])
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 2; i < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	if got := string(utf16.Decode(u)); got != "Grüße\r\nLine 2 😀\r\n" {
		t.Errorf("content: %q", got)
	}
}

func TestRTF(t *testing.T) {
	out := string(RTF("Müller {a} \\ b\nLine 2\t€ 😀\x01"))
	for i := 0; i < len(out); i++ {
		if out[i] >= 0x7f {
			t.Fatal("RTF must be ASCII")
		}
	}
	if !strings.HasPrefix(out, `{\rtf1\ansi`) || !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Errorf("Rahmen: %q", out)
	}
	for _, want := range []string{`M\u252?ller \{a\} \\ b\par`, `Line 2\tab \u8364? \u-10179?\u-8704?`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in %q", want, out)
		}
	}
	// Braces must balance, otherwise Word cannot read the file.
	depth := 0
	for i := 0; i < len(out); i++ {
		switch {
		case out[i] == '\\' && i+1 < len(out):
			i++
		case out[i] == '{':
			depth++
		case out[i] == '}':
			depth--
		}
	}
	if depth != 0 {
		t.Errorf("braces not balanced (%d)", depth)
	}
}

func TestMemRegistryBehavesLikeWindows(t *testing.T) {
	reg := NewMemRegistry()
	reg.Put(`Software\A\B`, "Name", sz("x"))
	if v, err := reg.Get(`software\a\b\`, "NAME"); err != nil || v.Type != RegSZ {
		t.Error("key and value names are not case-sensitive on Windows")
	}
	if subs, _ := reg.SubKeys(`SOFTWARE\a`); len(subs) != 1 || subs[0] != "B" {
		t.Errorf("SubKeys = %v", subs)
	}
	if _, err := reg.SubKeys(`Software\Missing`); !errors.Is(err, ErrNotExist) {
		t.Error("missing key")
	}
	if err := reg.Set(`Software\Missing`, "x", sz("y")); !errors.Is(err, ErrNotExist) {
		t.Error("Set must not create a key")
	}
	if err := reg.Delete(`Software\Missing`, "x"); err != nil {
		t.Error("Delete on something missing is not an error")
	}
}

func TestSetDefaultKeepsTheTypeOutlookUses(t *testing.T) {
	reg := NewMemRegistry()
	key := base16 + `\00000002`
	reg.Put(key, "Email", sz("a@b.de"))
	reg.Put(key, ValueNew, StringValue(RegBinary, "Old")) // this value is binary although "Email" is text
	accts, _ := Accounts(reg, true)
	if len(accts) != 1 {
		t.Fatal("account not found")
	}
	for _, vn := range []string{ValueNew, ValueReply} {
		if err := SetDefault(reg, accts[0], vn, "SubSignature a@b.de"); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := reg.Get(key, ValueNew); v.Type != RegBinary {
		t.Errorf("New: type %d, expected the type of the existing value (REG_BINARY)", v.Type)
	}
	if v, _ := reg.Get(key, ValueReply); v.Type != RegSZ {
		t.Errorf("Reply: type %d, expected REG_SZ like the other texts of the account", v.Type)
	}
	// A previous value of an unexpected type (e.g. DWORD) is never adopted.
	reg.Put(key, ValueNew, DWORDValue(5))
	accts, _ = Accounts(reg, true)
	SetDefault(reg, accts[0], ValueNew, "SubSignature a@b.de")
	if v, _ := reg.Get(key, ValueNew); v.Type != RegSZ {
		t.Errorf("Typ %d", v.Type)
	}
}
