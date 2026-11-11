// Package config loads and validates the agent's XML configuration.
package config

import (
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"subsignature-agent/internal/platform"
)

//go:embed config.example.xml
var exampleXML string

// Example returns the commented example configuration.
func Example() string { return exampleXML }

// Duration is a time.Duration read from text such as "2h" or "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("invalid duration %q (examples: 30s, 10m, 2h)", string(b))
	}
	d.Duration = v
	return nil
}

type Config struct {
	XMLName     xml.Name    `xml:"subsignature-agent"`
	Server      Server      `xml:"server"`
	Sync        Sync        `xml:"sync"`
	Signature   Signature   `xml:"signature"`
	Thunderbird Thunderbird `xml:"thunderbird"`
	Outlook     Outlook     `xml:"outlook"`
	Logging     Logging     `xml:"logging"`

	// Path is the file that was loaded (informational only).
	Path string `xml:"-"`
	// Env is the environment paths are resolved against (empty = the running system).
	Env platform.Env `xml:"-"`
}

type Server struct {
	URL               string   `xml:"url"`
	APIPath           string   `xml:"api-path"`
	Timeout           Duration `xml:"timeout"`
	AllowInsecureHTTP bool     `xml:"allow-insecure-http"`
	UseProxy          bool     `xml:"use-proxy"`
	TLS               TLS      `xml:"tls"`
	Auth              Auth     `xml:"auth"`

	// BaseURL is the validated URL (set by Validate).
	BaseURL *url.URL `xml:"-"`
}

type TLS struct {
	CAFile             string `xml:"ca-file"`
	InsecureSkipVerify bool   `xml:"insecure-skip-verify"`
}

// Auth: the API uses "Authorization: Bearer ssg_..." exclusively.
type Auth struct {
	TokenEnv  string `xml:"token-env"`
	TokenFile string `xml:"token-file"`
	Token     string `xml:"token"`
}

type Sync struct {
	Interval      Duration `xml:"interval"`
	Jitter        Duration `xml:"jitter"`
	RetryInterval Duration `xml:"retry-interval"`
	RunOnStart    bool     `xml:"run-on-start"`
	// ReportStatus: after each real sync (not "check"), push a status report
	// (ok/warn/error per address) to the server via POST /api/v1/status, so
	// admins see in "All Signatures" whether and when this device last
	// applied a signature. Requires a token with the status:write scope in
	// addition to signatures:read; a server/token that lacks it only makes
	// this one call fail (logged as a warning), the sync itself still
	// succeeds. Default true.
	ReportStatus *bool `xml:"report-status"`
}

// ReportStatusOn reports whether this device should push its sync status to
// the server after a run.
func (y Sync) ReportStatusOn() bool { return y.ReportStatus == nil || *y.ReportStatus }

// Override applies to exactly one address and replaces the global values for it.
type Override struct {
	Email    string `xml:"email,attr"`
	Template string `xml:"template,attr"`
	Username string `xml:"username,attr"`
	Name     string `xml:"name,attr"` // deprecated: same as template
}

type Signature struct {
	// Template selects the template among several signatures of an address
	// (file name of the template on the server, e.g. signature_pro.html).
	Template string `xml:"template"`
	// Name is the old name for Template and is still accepted.
	Name string `xml:"name"`
	// Username restricts to one SubSignature account (needed if several accounts share the same address).
	Username        string     `xml:"username"`
	DuplicatePolicy string     `xml:"duplicate-policy"`
	PreferSource    string     `xml:"prefer-source"`
	HTMLPolicy      string     `xml:"html-policy"`
	Overrides       []Override `xml:"override"`

	// PreferSources is prefer-source as a list (set by Validate).
	PreferSources []string `xml:"-"`
}

type Thunderbird struct {
	Enabled       *bool    `xml:"enabled"` // default true
	Profiles      string   `xml:"profiles"`
	ProfilePath   string   `xml:"profile-path"`
	ExcludeEmails []string `xml:"exclude-email"`
	SigOnReply    *bool    `xml:"sig-on-reply"`
	SigOnForward  *bool    `xml:"sig-on-forward"`
	SigBottom     *bool    `xml:"sig-bottom"`
}

// On reports whether Thunderbird should be handled.
func (t Thunderbird) On() bool { return t.Enabled == nil || *t.Enabled }

// Outlook only applies on Windows (classic Outlook). On Linux the section is
// read and validated but not used - so one config.xml stays valid for both
// systems.
type Outlook struct {
	Enabled           *bool    `xml:"enabled"`            // default true
	Profiles          string   `xml:"profiles"`           // default | all
	SignatureName     string   `xml:"signature-name"`     // display name in Outlook, default "SubSignature"
	SetNew            *bool    `xml:"set-new"`            // set as default for new messages (default true)
	SetReply          *bool    `xml:"set-reply"`          // set as default for replies/forwards (default true)
	RoamingSignatures string   `xml:"roaming-signatures"` // keep | disable
	ExcludeEmails     []string `xml:"exclude-email"`
}

func (o Outlook) On() bool     { return o.Enabled == nil || *o.Enabled }
func (o Outlook) New() bool    { return o.SetNew == nil || *o.SetNew }
func (o Outlook) Reply() bool  { return o.SetReply == nil || *o.SetReply }
func (o Outlook) NoRoam() bool { return o.RoamingSignatures == "disable" }

var sigNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$`)

type Logging struct {
	Level string `xml:"level"`
	File  string `xml:"file"`
}

// Default returns the defaults. Elements missing from the XML file keep these
// values; the safe defaults (TLS on, verification on) therefore always apply.
func Default() *Config {
	return &Config{
		Server: Server{
			APIPath: "/api/v1",
			Timeout: Duration{20 * time.Second},
			Auth:    Auth{TokenEnv: "SUBSIGNATURE_TOKEN"},
		},
		Sync: Sync{
			Interval:      Duration{2 * time.Hour},
			Jitter:        Duration{5 * time.Minute},
			RetryInterval: Duration{10 * time.Minute},
			RunOnStart:    true,
		},
		Signature:   Signature{DuplicatePolicy: "newest", HTMLPolicy: "reject"},
		Thunderbird: Thunderbird{Profiles: "default"},
		Outlook:     Outlook{Profiles: "default", SignatureName: "SubSignature", RoamingSignatures: "keep"},
		Logging:     Logging{Level: "info"},
	}
}

// Find locates the configuration file (explicit, $SUBSIGNATURE_CONFIG, per user, system-wide).
func Find(explicit string) (string, error) { return FindEnv(explicit, platform.Current()) }

// FindEnv locates the configuration: given explicitly, $SUBSIGNATURE_CONFIG,
// the user's folder (Linux ~/.config, Windows %APPDATA%), then machine-wide
// (Linux /etc, Windows %ProgramData%).
func FindEnv(explicit string, env platform.Env) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("configuration %s: %w", explicit, err)
		}
		return explicit, nil
	}
	var cands []string
	if env.Getenv != nil {
		if v := env.Getenv("SUBSIGNATURE_CONFIG"); v != "" {
			cands = append(cands, v)
		}
	}
	cands = append(cands, filepath.Join(env.ConfigDir(), "config.xml"))
	if d := env.SystemConfigDir(); d != "" {
		cands = append(cands, filepath.Join(d, "config.xml"))
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no configuration found (looked in: %s) - 'subsignature-agent init' creates a template", strings.Join(cands, ", "))
}

func Load(path string) (*Config, []string, error) { return LoadEnv(path, platform.Current()) }

// LoadEnv loads the configuration and resolves paths against env.
func LoadEnv(path string, env platform.Env) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg := Default()
	if err := xml.Unmarshal(data, cfg); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path, cfg.Env = path, env
	warns, err := cfg.Validate()
	if err != nil {
		return nil, warns, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, warns, nil
}

// Validate normalizes and checks the values. Errors prevent the start,
// warnings point out insecure but permitted settings.
func (c *Config) Validate() (warnings []string, err error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	warn := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }

	// --- Server ---
	s := &c.Server
	s.URL = strings.TrimSpace(s.URL)
	switch u, perr := url.Parse(s.URL); {
	case s.URL == "":
		bad("server/url is missing")
	case perr != nil:
		bad("server/url is invalid: %v", perr)
	case u.Scheme != "http" && u.Scheme != "https":
		bad("server/url must start with http:// or https://")
	case u.Host == "":
		bad("server/url contains no host")
	case u.User != nil:
		bad("server/url must not contain credentials (use token-file or token-env)")
	default:
		s.BaseURL = u
		if u.Scheme == "http" {
			if !s.AllowInsecureHTTP {
				bad("http:// is not allowed without <allow-insecure-http>true</allow-insecure-http> (token and signatures would be readable in clear text; for tests only)")
			} else {
				warn("UNENCRYPTED connection (http) is active - use for tests only")
			}
			if s.TLS.CAFile != "" || s.TLS.InsecureSkipVerify {
				warn("TLS settings have no effect with http://")
			}
		} else if s.TLS.InsecureSkipVerify {
			warn("TLS certificate verification is SWITCHED OFF (insecure-skip-verify) - use for tests only")
		}
	}
	s.APIPath = strings.TrimRight(strings.TrimSpace(s.APIPath), "/")
	if strings.HasSuffix(s.APIPath, "/signatures") { // leftover from an earlier example configuration
		s.APIPath = strings.TrimSuffix(s.APIPath, "/signatures")
		warn("server/api-path ends with /signatures - using %q (api-path is the API root)", s.APIPath)
	}
	if !strings.HasPrefix(s.APIPath, "/") || strings.ContainsAny(s.APIPath, "?#") {
		bad("server/api-path must start with / and must not contain ? or # (default: /api/v1)")
	}
	if s.Timeout.Duration < time.Second || s.Timeout.Duration > 5*time.Minute {
		bad("server/timeout must be between 1s and 5m")
	}
	if c.Env.GOOS == "" {
		c.Env = platform.Current()
	}
	// Relative paths are relative to the folder of the configuration file.
	baseDir := ""
	if c.Path != "" {
		if abs, e := filepath.Abs(c.Path); e == nil {
			baseDir = filepath.Dir(abs)
		}
	}
	expandPath := func(p string) string { return c.Env.ExpandPath(p, baseDir) }
	s.TLS.CAFile = expandPath(s.TLS.CAFile)
	s.Auth.TokenFile = expandPath(s.Auth.TokenFile)
	if strings.TrimSpace(s.Auth.Token) != "" && c.Path != "" {
		if w := c.readableByOthers(c.Path); w != "" {
			warn("%s contains a token and %s", c.Path, w)
		}
	}

	// --- Sync ---
	y := &c.Sync
	if y.Interval.Duration < time.Minute {
		bad("sync/interval must be at least 1m")
	}
	if y.Jitter.Duration < 0 || y.Jitter.Duration > y.Interval.Duration {
		bad("sync/jitter must be between 0 and interval")
	}
	if y.RetryInterval.Duration < 30*time.Second || y.RetryInterval.Duration > y.Interval.Duration {
		bad("sync/retry-interval must be between 30s and interval")
	}

	// --- Signature ---
	g := &c.Signature
	g.Template = strings.TrimSpace(g.Template)
	g.Name = strings.TrimSpace(g.Name)
	switch {
	case g.Name != "" && g.Template != "" && !strings.EqualFold(g.Name, g.Template):
		bad("signature/name (old name) and signature/template contradict each other - use template only")
	case g.Name != "" && g.Template == "":
		g.Template = g.Name
		warn("signature/name is now called signature/template (the value is the server's template name)")
	}
	g.Username = strings.TrimSpace(g.Username)
	g.DuplicatePolicy = strings.ToLower(strings.TrimSpace(g.DuplicatePolicy))
	g.HTMLPolicy = strings.ToLower(strings.TrimSpace(g.HTMLPolicy))
	switch g.DuplicatePolicy {
	case "default": // earlier name; the server has no default marker
		g.DuplicatePolicy = "newest"
		warn("signature/duplicate-policy \"default\" no longer exists - using \"newest\"")
	case "newest", "skip":
	default:
		bad("signature/duplicate-policy must be newest or skip")
	}
	g.PreferSources = nil
	for _, p := range strings.Split(g.PreferSource, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p == "" {
			continue
		}
		if !oneOf(p, "manual", "csv", "ldap") {
			bad("signature/prefer-source: unknown source %q (allowed: manual, csv, ldap)", p)
		}
		g.PreferSources = append(g.PreferSources, p)
	}
	if !oneOf(g.HTMLPolicy, "reject", "off") {
		bad("signature/html-policy must be reject or off")
	}
	if g.HTMLPolicy == "off" {
		warn("HTML check is switched off (html-policy=off)")
	}
	seen := map[string]bool{}
	for i := range g.Overrides {
		o := &g.Overrides[i]
		o.Email = normEmail(o.Email)
		o.Template = strings.TrimSpace(o.Template)
		o.Username = strings.TrimSpace(o.Username)
		if n := strings.TrimSpace(o.Name); n != "" && o.Template == "" {
			o.Template = n
		}
		switch {
		case !strings.Contains(o.Email, "@") || (o.Template == "" && o.Username == ""):
			bad("signature/override needs email and template and/or username")
		case seen[o.Email]:
			bad("signature/override for %s is present twice", o.Email)
		}
		seen[o.Email] = true
	}

	// --- Thunderbird ---
	t := &c.Thunderbird
	t.Profiles = strings.ToLower(strings.TrimSpace(t.Profiles))
	if !oneOf(t.Profiles, "default", "all") {
		bad("thunderbird/profiles must be default or all")
	}
	t.ProfilePath = expandPath(t.ProfilePath)
	for i := range t.ExcludeEmails {
		t.ExcludeEmails[i] = normEmail(t.ExcludeEmails[i])
	}

	// --- Outlook (only effective on Windows) ---
	o := &c.Outlook
	o.Profiles = strings.ToLower(strings.TrimSpace(o.Profiles))
	if !oneOf(o.Profiles, "default", "all") {
		bad("outlook/profiles must be default or all")
	}
	o.SignatureName = strings.TrimSpace(o.SignatureName)
	if !sigNameOK.MatchString(o.SignatureName) {
		bad("outlook/signature-name: 1 to 40 characters from letters (a-z), digits, spaces, - and _ (file names are derived from it)")
	}
	o.RoamingSignatures = strings.ToLower(strings.TrimSpace(o.RoamingSignatures))
	if !oneOf(o.RoamingSignatures, "keep", "disable") {
		bad("outlook/roaming-signatures must be keep or disable")
	}
	for i := range o.ExcludeEmails {
		o.ExcludeEmails[i] = normEmail(o.ExcludeEmails[i])
	}

	// --- Logging ---
	l := &c.Logging
	l.Level = strings.ToLower(strings.TrimSpace(l.Level))
	if !oneOf(l.Level, "debug", "info", "warn", "error") {
		bad("logging/level must be debug, info, warn or error")
	}
	l.File = expandPath(l.File)

	return warnings, errors.Join(errs...)
}

// CriteriaFor returns the template and account to look for for an address:
// the global values, each field replaced by a matching override.
func (c *Config) CriteriaFor(email string) (template, username string) {
	template, username = c.Signature.Template, c.Signature.Username
	email = normEmail(email)
	for _, o := range c.Signature.Overrides {
		if o.Email == email {
			if o.Template != "" {
				template = o.Template
			}
			if o.Username != "" {
				username = o.Username
			}
		}
	}
	return template, username
}

// Excluded reports whether the agent should ignore an address. The lists
// under <thunderbird> and <outlook> apply jointly to all mail clients: whoever
// excludes an address does not want it managed anywhere.
func (c *Config) Excluded(email string) bool {
	email = normEmail(email)
	for _, list := range [][]string{c.Thunderbird.ExcludeEmails, c.Outlook.ExcludeEmails} {
		for _, e := range list {
			if e == email {
				return true
			}
		}
	}
	return false
}

// readableByOthers checks whether a file holding a secret might be readable
// by other users and, if so, returns a hint text (otherwise "").
// Linux: file permissions. Windows: the permission bits mean nothing there;
// inside the user profile the default ACL protects (user, SYSTEM, administrators only).
// If the file lies outside, the agent cannot judge the ACL and warns.
func (c *Config) readableByOthers(path string) string {
	if c.Env.Windows() {
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if c.Env.Home != "" && !c.Env.Within(path, c.Env.Home) {
			return "lies outside the user profile - please make sure that only this user may read the file (ACL)"
		}
		return ""
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return "is readable by others - run 'chmod 600'"
	}
	return ""
}

// Token determines the API token: environment variable, token-file, then token.
// The API always requires a token; without one an error is returned.
func (c *Config) Token() (token string, warnings []string, err error) {
	token, warnings, err = c.findToken()
	if err == nil && !strings.HasPrefix(token, "ssg_") {
		warnings = append(warnings, "the token does not start with ssg_ - is it a SubSignature API token?")
	}
	return token, warnings, err
}

func (c *Config) findToken() (token string, warnings []string, err error) {
	a := c.Server.Auth
	if a.TokenEnv != "" {
		if v := strings.TrimSpace(os.Getenv(a.TokenEnv)); v != "" {
			return v, nil, nil
		}
	}
	if a.TokenFile != "" {
		if _, e := os.Stat(a.TokenFile); e != nil {
			return "", nil, fmt.Errorf("token-file: %w", e)
		}
		if w := c.readableByOthers(a.TokenFile); w != "" {
			warnings = append(warnings, a.TokenFile+" "+w)
		}
		b, e := os.ReadFile(a.TokenFile)
		if e != nil {
			return "", warnings, fmt.Errorf("token-file: %w", e)
		}
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, warnings, nil
		}
		return "", warnings, fmt.Errorf("token-file %s is empty", a.TokenFile)
	}
	if tok := strings.TrimSpace(a.Token); tok != "" {
		return tok, append(warnings, "the token is stored in clear text in the configuration - prefer token-file or an environment variable"), nil
	}
	return "", warnings, errors.New("no API token configured (environment variable " + tokenEnvName(a) + ", token-file or token); an admin creates tokens under \"API Tokens\"")
}

func normEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func tokenEnvName(a Auth) string {
	if a.TokenEnv != "" {
		return a.TokenEnv
	}
	return "SUBSIGNATURE_TOKEN"
}
