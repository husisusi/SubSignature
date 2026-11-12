package config

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"subsignature-agent/internal/platform"
	"time"
)

func parse(t *testing.T, doc string) *Config {
	t.Helper()
	cfg := Default()
	if err := xml.Unmarshal([]byte(doc), cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestExampleParsesWithoutWarnings(t *testing.T) {
	cfg := parse(t, Example())
	warns, err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if cfg.Server.BaseURL.Scheme != "https" || cfg.Sync.Interval.Duration != 2*time.Hour {
		t.Fatalf("example read incorrectly: %+v", cfg.Server)
	}
}

func TestMinimalConfigKeepsSecureDefaults(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://sig.example</url></server></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.AllowInsecureHTTP || cfg.Server.TLS.InsecureSkipVerify || cfg.Server.UseProxy {
		t.Fatal("insecure default")
	}
	if cfg.Sync.Interval.Duration != 2*time.Hour || cfg.Signature.DuplicatePolicy != "newest" || cfg.Signature.HTMLPolicy != "reject" {
		t.Fatalf("defaults missing: %+v %+v", cfg.Sync, cfg.Signature)
	}
	if cfg.Server.APIPath != "/api/v1" {
		t.Fatalf("api-path = %q", cfg.Server.APIPath)
	}
}

func TestHTTPNeedsExplicitLatch(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>http://10.0.0.5:8080</url></server></subsignature-agent>`)
	_, err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "allow-insecure-http") {
		t.Fatalf("http without the switch must be rejected, err=%v", err)
	}

	cfg = parse(t, `<subsignature-agent><server><url>http://10.0.0.5:8080</url><allow-insecure-http>true</allow-insecure-http></server></subsignature-agent>`)
	warns, err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) == 0 || !strings.Contains(warns[0], "UNENCRYPTED") {
		t.Fatalf("warning missing: %v", warns)
	}
}

func TestInsecureSkipVerifyWarns(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url><tls><insecure-skip-verify>true</insecure-skip-verify></tls></server></subsignature-agent>`)
	warns, err := cfg.Validate()
	if err != nil || len(warns) == 0 {
		t.Fatalf("expected a warning, got %v / %v", warns, err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"no URL":             `<subsignature-agent></subsignature-agent>`,
		"ftp":                `<subsignature-agent><server><url>ftp://x</url></server></subsignature-agent>`,
		"credentials":        `<subsignature-agent><server><url>https://u:p@x</url></server></subsignature-agent>`,
		"interval":           `<subsignature-agent><server><url>https://x</url></server><sync><interval>10s</interval></sync></subsignature-agent>`,
		"jitter":             `<subsignature-agent><server><url>https://x</url></server><sync><jitter>3h</jitter></sync></subsignature-agent>`,
		"policy":             `<subsignature-agent><server><url>https://x</url></server><signature><duplicate-policy>random</duplicate-policy></signature></subsignature-agent>`,
		"api-path":           `<subsignature-agent><server><url>https://x</url><api-path>api?x=1</api-path></server></subsignature-agent>`,
		"policy first":       `<subsignature-agent><server><url>https://x</url></server><signature><duplicate-policy>first</duplicate-policy></signature></subsignature-agent>`,
		"unknown source":     `<subsignature-agent><server><url>https://x</url></server><signature><prefer-source>manual,web</prefer-source></signature></subsignature-agent>`,
		"name contradicts":   `<subsignature-agent><server><url>https://x</url></server><signature><name>a</name><template>b</template></signature></subsignature-agent>`,
		"override twice":     `<subsignature-agent><server><url>https://x</url></server><signature><override email="a@b.de" template="x"/><override email="A@B.de" template="y"/></signature></subsignature-agent>`,
		"profiles":           `<subsignature-agent><server><url>https://x</url></server><thunderbird><profiles>some</profiles></thunderbird></subsignature-agent>`,
		"invalid duration":   "", // checked below while parsing
		"timeout too large":  `<subsignature-agent><server><url>https://x</url><timeout>1h</timeout></server></subsignature-agent>`,
		"log level":          `<subsignature-agent><server><url>https://x</url></server><logging><level>loud</level></logging></subsignature-agent>`,
		"retry larger":       `<subsignature-agent><server><url>https://x</url></server><sync><interval>5m</interval><retry-interval>10m</retry-interval></sync></subsignature-agent>`,
		"override empty":     `<subsignature-agent><server><url>https://x</url></server><signature><override email="a@b.de"/></signature></subsignature-agent>`,
		"override w/o addr.": `<subsignature-agent><server><url>https://x</url></server><signature><override template="x"/></signature></subsignature-agent>`,
	}
	for name, doc := range cases {
		if doc == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if _, err := parse(t, doc).Validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	cfg := Default()
	if err := xml.Unmarshal([]byte(`<subsignature-agent><sync><interval>two hours</interval></sync></subsignature-agent>`), cfg); err == nil {
		t.Fatal("an invalid duration must fail while reading")
	}
}

func TestCriteriaForAndExcluded(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url></server>
	  <signature><template>signature_pro.html</template><username>anna</username>
	    <override email="Sales@Example.com" template="signature_sales.html"/>
	    <override email="info@example.com" username="bob"/></signature>
	  <thunderbird><exclude-email> Private@Example.org </exclude-email></thunderbird></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for email, want := range map[string][2]string{
		"sales@example.com": {"signature_sales.html", "anna"}, // an override replaces only the field it names
		"INFO@example.com":  {"signature_pro.html", "bob"},
		"max@example.com":   {"signature_pro.html", "anna"},
	} {
		if tpl, usr := cfg.CriteriaFor(email); tpl != want[0] || usr != want[1] {
			t.Errorf("%s: %q/%q, expected %q/%q", email, tpl, usr, want[0], want[1])
		}
	}
	if !cfg.Excluded("PRIVATE@example.org") || cfg.Excluded("max@example.com") {
		t.Fatal("exclusion wrong")
	}
}

func TestOldNameElementStillWorksButWarns(t *testing.T) {
	// Silently ignoring <name> would switch off template selection unnoticed.
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url></server>
	  <signature><name>signature_pro.html</name><override email="a@b.de" name="signature_x.html"/></signature></subsignature-agent>`)
	warns, err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if tpl, _ := cfg.CriteriaFor("c@d.de"); tpl != "signature_pro.html" {
		t.Errorf("global: %q", tpl)
	}
	if tpl, _ := cfg.CriteriaFor("a@b.de"); tpl != "signature_x.html" {
		t.Errorf("override: %q", tpl)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "template") {
		t.Errorf("Warnungen = %v", warns)
	}
	// The same value in both elements is not a contradiction.
	cfg = parse(t, `<subsignature-agent><server><url>https://x</url></server><signature><name>A.html</name><template>a.HTML</template></signature></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Errorf("same value: %v", err)
	}
}

func TestOldDefaultPolicyMapsToNewest(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url></server><signature><duplicate-policy>default</duplicate-policy></signature></subsignature-agent>`)
	warns, err := cfg.Validate()
	if err != nil || cfg.Signature.DuplicatePolicy != "newest" || len(warns) != 1 {
		t.Fatalf("%q %v %v", cfg.Signature.DuplicatePolicy, warns, err)
	}
}

func TestPreferSource(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url></server><signature><prefer-source> Manual , csv,, LDAP </prefer-source></signature></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Signature.PreferSources, ","); got != "manual,csv,ldap" {
		t.Fatalf("PreferSources = %q", got)
	}
	cfg = parse(t, `<subsignature-agent><server><url>https://x</url></server></subsignature-agent>`)
	cfg.Validate()
	if len(cfg.Signature.PreferSources) != 0 {
		t.Fatal("without the setting there must be no ranking")
	}
}

func TestAPIPathLegacyAndNormalization(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url><api-path>/api/v1/signatures</api-path></server></subsignature-agent>`)
	warns, err := cfg.Validate()
	if err != nil || cfg.Server.APIPath != "/api/v1" || len(warns) != 1 {
		t.Fatalf("%q %v %v", cfg.Server.APIPath, warns, err)
	}
	cfg = parse(t, `<subsignature-agent><server><url>https://x</url><api-path> /api/v1/ </api-path></server></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil || cfg.Server.APIPath != "/api/v1" {
		t.Fatalf("%q %v", cfg.Server.APIPath, err)
	}
}

func TestTokenOrder(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("ssg_from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Server.Auth.TokenFile = file
	cfg.Server.Auth.Token = "ssg_inline"
	cfg.Server.Auth.TokenEnv = "SUBSIG_TEST_TOKEN"

	t.Setenv("SUBSIG_TEST_TOKEN", "ssg_from-env")
	if tok, _, _ := cfg.Token(); tok != "ssg_from-env" {
		t.Fatalf("env first, got %q", tok)
	}
	t.Setenv("SUBSIG_TEST_TOKEN", "")
	tok, warns, err := cfg.Token()
	if err != nil || tok != "ssg_from-file" || len(warns) != 0 {
		t.Fatalf("file: %q %v %v", tok, warns, err)
	}
	// permissions too open -> warning
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, warns, _ := cfg.Token(); len(warns) == 0 {
		t.Fatal("warning for a readable token file is missing")
	}
	// file missing -> error (no silent fallback to inline)
	cfg.Server.Auth.TokenFile = filepath.Join(dir, "not-there")
	if _, _, err := cfg.Token(); err == nil {
		t.Fatal("a missing token file must be an error")
	}
	cfg.Server.Auth.TokenFile = ""
	if tok, warns, _ := cfg.Token(); tok != "ssg_inline" || len(warns) == 0 {
		t.Fatalf("inline: %q %v", tok, warns)
	}
}

func TestTokenIsRequired(t *testing.T) {
	// The API always requires a token; without one the agent must not even send a request.
	cfg := Default()
	cfg.Server.Auth.TokenEnv = "SUBSIG_TEST_NOT_SET"
	tok, _, err := cfg.Token()
	if err == nil || tok != "" || !strings.Contains(err.Error(), "SUBSIG_TEST_NOT_SET") {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	// empty token file: an error as well
	f := filepath.Join(t.TempDir(), "leer")
	os.WriteFile(f, []byte(" \n"), 0o600)
	cfg.Server.Auth.TokenFile = f
	if _, _, err := cfg.Token(); err == nil {
		t.Fatal("an empty token file must be an error")
	}
}

func TestTokenWithoutPrefixWarns(t *testing.T) {
	cfg := Default()
	cfg.Server.Auth.TokenEnv = "SUBSIG_TEST_TOKEN2"
	t.Setenv("SUBSIG_TEST_TOKEN2", "abc123")
	tok, warns, err := cfg.Token()
	if err != nil || tok != "abc123" || len(warns) != 1 || !strings.Contains(warns[0], "ssg_") {
		t.Fatalf("%q %v %v", tok, warns, err)
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.xml")
	if err := os.WriteFile(p, []byte(Example()), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Find(p); err != nil || got != p {
		t.Fatalf("explizit: %q %v", got, err)
	}
	if _, err := Find(filepath.Join(dir, "missing.xml")); err == nil {
		t.Fatal("a missing explicit file must fail")
	}
	t.Setenv("SUBSIGNATURE_CONFIG", p)
	if got, err := Find(""); err != nil || got != p {
		t.Fatalf("env: %q %v", got, err)
	}
	cfg, _, err := Load(p)
	if err != nil || cfg.Path != p {
		t.Fatalf("Load: %v", err)
	}
}

// ---------- cross-platform ----------

func TestOutlookSectionDefaultsAndValidation(t *testing.T) {
	cfg := parse(t, `<subsignature-agent><server><url>https://x</url></server></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	o := cfg.Outlook
	if !o.On() || !o.New() || !o.Reply() || !o.NoRoam() || o.SignatureName != "SubSignature" || o.Profiles != "default" {
		t.Errorf("Vorgaben: %+v", o)
	}
	if !cfg.Thunderbird.On() {
		t.Error("Thunderbird is on by default")
	}

	cfg = parse(t, `<subsignature-agent><server><url>https://x</url></server>
	  <thunderbird><enabled>false</enabled></thunderbird>
	  <outlook><enabled>true</enabled><profiles> ALL </profiles><signature-name>Company Ltd</signature-name>
	    <set-new>true</set-new><set-reply>false</set-reply><roaming-signatures>Disable</roaming-signatures>
	    <exclude-email> Boss@Example.com </exclude-email></outlook></subsignature-agent>`)
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	o = cfg.Outlook
	if o.Profiles != "all" || o.SignatureName != "Company Ltd" || !o.New() || o.Reply() || !o.NoRoam() || cfg.Thunderbird.On() {
		t.Errorf("gelesen: %+v", o)
	}
	if !cfg.Excluded("boss@example.com") {
		t.Error("exclude-email under <outlook> applies to all mail clients")
	}

	bad := map[string]string{
		"name with path":   `<signature-name>..\..\x</signature-name>`,
		"name with umlaut": `<signature-name>Grüße</signature-name>`,
		"name empty":       `<signature-name> </signature-name>`,
		"name too long":    `<signature-name>` + strings.Repeat("a", 41) + `</signature-name>`,
		"name with dot":    `<signature-name>a.b</signature-name>`,
		"roaming unknown":  `<roaming-signatures>off</roaming-signatures>`,
		"profiles unknown": `<profiles>some</profiles>`,
	}
	for name, frag := range bad {
		c := parse(t, `<subsignature-agent><server><url>https://x</url></server><outlook>`+frag+`</outlook></subsignature-agent>`)
		if _, err := c.Validate(); err == nil {
			t.Errorf("%s: was accepted", name)
		}
	}
}

func TestRelativePathsAreRelativeToConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte(`<subsignature-agent><server><url>https://x</url><tls><ca-file>ca.pem</ca-file></tls>
	  <auth><token-env></token-env><token-file>./token</token-file></auth></server></subsignature-agent>`), 0o600)
	os.WriteFile(filepath.Join(dir, "token"), []byte("ssg_next-to-the-config\n"), 0o600)

	// Started from an entirely different folder: the result must not depend on it.
	t.Chdir(t.TempDir())
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Auth.TokenFile != filepath.Join(dir, "token") || cfg.Server.TLS.CAFile != filepath.Join(dir, "ca.pem") {
		t.Errorf("token-file=%q ca-file=%q", cfg.Server.Auth.TokenFile, cfg.Server.TLS.CAFile)
	}
	if tok, _, err := cfg.Token(); err != nil || tok != "ssg_next-to-the-config" {
		t.Errorf("Token = %q, %v", tok, err)
	}
}

func TestSameConfigFileWorksForBothSystems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	os.WriteFile(path, []byte(Example()), 0o600)
	// The shipped example configuration must load without errors on both systems.
	for _, goos := range []string{"linux", "windows"} {
		env := platform.Env{GOOS: goos, Home: dir, Getenv: func(string) string { return "" }}
		cfg, _, err := LoadEnv(path, env)
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if !cfg.Outlook.On() || !cfg.Thunderbird.On() || cfg.Outlook.SignatureName != "SubSignature" {
			t.Errorf("%s: %+v", goos, cfg.Outlook)
		}
	}
}

func TestFindEnvWindowsAndLinux(t *testing.T) {
	dir := t.TempDir()
	vars := map[string]string{"APPDATA": filepath.Join(dir, "Roaming"), "ProgramData": filepath.Join(dir, "ProgramData")}
	win := platform.Env{GOOS: "windows", Home: dir, Getenv: func(k string) string { return vars[k] }}
	if _, err := FindEnv("", win); err == nil || !strings.Contains(err.Error(), filepath.Join("Roaming", "subsignature-agent", "config.xml")) {
		t.Fatalf("the error message should name the locations searched: %v", err)
	}
	sys := filepath.Join(dir, "ProgramData", "subsignature-agent", "config.xml")
	os.MkdirAll(filepath.Dir(sys), 0o755)
	os.WriteFile(sys, []byte("x"), 0o644)
	if p, err := FindEnv("", win); err != nil || p != sys {
		t.Fatalf("rechnerweit: %q %v", p, err)
	}
	user := filepath.Join(dir, "Roaming", "subsignature-agent", "config.xml")
	os.MkdirAll(filepath.Dir(user), 0o755)
	os.WriteFile(user, []byte("x"), 0o644)
	if p, _ := FindEnv("", win); p != user {
		t.Fatalf("the user configuration takes precedence: %q", p)
	}
	vars["SUBSIGNATURE_CONFIG"] = sys
	if p, _ := FindEnv("", win); p != sys {
		t.Fatalf("the environment variable takes precedence: %q", p)
	}
	if p, _ := FindEnv(user, win); p != user {
		t.Fatalf("-c takes precedence over everything: %q", p)
	}
}

func TestWindowsTokenOutsideProfileWarns(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	win := platform.Env{GOOS: "windows", Home: home, Getenv: func(string) string { return "" }}
	for _, c := range []struct {
		dir  string
		warn bool
	}{{home, false}, {outside, true}} {
		f := filepath.Join(c.dir, "token")
		os.WriteFile(f, []byte("ssg_x"), 0o644) // permission bits mean nothing on Windows
		cfg := Default()
		cfg.Env = win
		cfg.Server.Auth.TokenEnv = ""
		cfg.Server.Auth.TokenFile = f
		tok, warns, err := cfg.Token()
		if err != nil || tok != "ssg_x" {
			t.Fatalf("%v %q", err, tok)
		}
		if got := len(warns) > 0; got != c.warn {
			t.Errorf("token in %s: warnings=%v, expected warning=%v", c.dir, warns, c.warn)
		}
		for _, w := range warns {
			if strings.Contains(w, "chmod") {
				t.Errorf("chmod hint on Windows: %s", w)
			}
		}
	}
}
