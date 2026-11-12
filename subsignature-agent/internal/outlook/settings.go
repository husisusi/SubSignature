package outlook

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"subsignature-agent/internal/platform"
)

const (
	officeKey = `Software\Microsoft\Office`
	policyKey = `Software\Policies\Microsoft\Office`
	// Under this fixed key every Outlook profile keeps its accounts.
	accountsGUID = `9375CFF0413111d3B88A00104B2A6676`

	ValueNew   = "New Signature"
	ValueReply = "Reply-Forward Signature"

	// Switches for roaming signatures (signatures stored in the Microsoft 365 mailbox).
	// Microsoft documents "DisableRoamingSignatures" today; older builds and
	// many guides use "DisableRoamingSignaturesTemporaryToggle".
	ValueNoRoaming    = "DisableRoamingSignatures"
	ValueNoRoamingOld = "DisableRoamingSignaturesTemporaryToggle"
)

var (
	versionRe    = regexp.MustCompile(`^(1[5-9]|[2-9][0-9])\.0$`) // from Outlook 2013 (15.0)
	accountKeyRe = regexp.MustCompile(`(?i)^Software\\Microsoft\\Office\\(1[5-9]|[2-9][0-9])\.0\\Outlook\\Profiles\\[^\\]+\\` + accountsGUID + `\\[0-9a-f]{8}$`)
	setupKeyRe   = regexp.MustCompile(`(?i)^Software\\Microsoft\\Office\\(1[5-9]|[2-9][0-9])\.0\\Outlook\\Setup$`)
	sigNameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,119}$`)
	emailRe      = regexp.MustCompile(`^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$`)

	// ErrUnusualDir: the signature folder has been redirected in the registry.
	ErrUnusualDir = errors.New("unusual Outlook signature folder in the registry - not used for security reasons")
)

// Account is an e-mail account in an Outlook profile.
type Account struct {
	Version  string // e.g. "16.0"
	Profile  string
	ID       string // name of the subkey, e.g. "00000002"
	Key      string // full key relative to HKEY_CURRENT_USER
	Email    string // lower case
	Name     string // "Account Name"
	New      string // current default signature for new messages ("" = none)
	Reply    string // ... for replies and forwards
	HasNew   bool   // the value exists
	HasReply bool
	// TextType is the data type of the account's texts ("Email" / "Account
	// Name"); only used for Outlook 2013, see DefaultValueType.
	TextType uint32
	// Raw values, so that "remove" can restore exactly the previous state.
	RawNew, RawReply Value
}

func normEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func getString(reg Registry, key, name string) (string, uint32, bool) {
	v, err := reg.Get(key, name)
	if err != nil {
		return "", 0, false
	}
	s, ok := v.String()
	return strings.TrimSpace(s), v.Type, ok
}

// Versions returns the Office versions that have an Outlook branch, ascending.
func Versions(reg Registry) []string {
	subs, err := reg.SubKeys(officeKey)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range subs {
		if versionRe.MatchString(s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Accounts reads the e-mail accounts of all Outlook versions. allProfiles=false
// restricts to the default profile (if Outlook names one).
//
// The address is in the value "Email" (POP/IMAP) or - for Exchange accounts,
// which Outlook names after the address - in the value "Account Name". Entries
// without a recognizable address (address book, renamed accounts) are omitted.
func Accounts(reg Registry, allProfiles bool) ([]Account, error) {
	var out []Account
	for _, ver := range Versions(reg) {
		outlookKey := officeKey + `\` + ver + `\Outlook`
		profiles, err := reg.SubKeys(outlookKey + `\Profiles`)
		if errors.Is(err, ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		def, _, _ := getString(reg, outlookKey, "DefaultProfile")
		sort.Strings(profiles)
		for _, prof := range profiles {
			if !allProfiles && def != "" && !strings.EqualFold(prof, def) {
				continue
			}
			base := outlookKey + `\Profiles\` + prof + `\` + accountsGUID
			ids, err := reg.SubKeys(base)
			if errors.Is(err, ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			sort.Strings(ids)
			for _, id := range ids {
				key := base + `\` + id
				if !accountKeyRe.MatchString(key) {
					continue // e.g. a profile name containing "\" cannot exist; skip anything unexpected
				}
				name, nameType, _ := getString(reg, key, "Account Name")
				email, emailType, _ := getString(reg, key, "Email")
				textType := emailType
				if !emailRe.MatchString(email) {
					email, textType = name, nameType
				}
				if !emailRe.MatchString(email) {
					continue
				}
				if textType != RegBinary {
					textType = RegSZ
				}
				a := Account{Version: ver, Profile: prof, ID: id, Key: key, Email: normEmail(email), Name: name, TextType: textType}
				if v, err := reg.Get(key, ValueNew); err == nil {
					a.RawNew, a.HasNew = v, true
					a.New, _ = v.String()
				}
				if v, err := reg.Get(key, ValueReply); err == nil {
					a.RawReply, a.HasReply = v, true
					a.Reply, _ = v.String()
				}
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// SignatureDir is the folder in which classic Outlook looks for signatures:
// %APPDATA%\Microsoft\<name>. The name is stored in the registry and differs
// by Office language ("Signatures", formerly e.g. "Signaturen"). Outlook also
// allows paths with "..\" there; the agent deliberately does not use such a
// value, so that it never writes outside %APPDATA%\Microsoft.
func SignatureDir(reg Registry, env platform.Env, version string) (string, error) {
	name := "Signatures"
	if s, _, ok := getString(reg, officeKey+`\`+version+`\Common\General`, "Signatures"); ok && s != "" {
		name = s
	}
	if strings.ContainsAny(name, `\/:*?"<>|`) || strings.Contains(name, "..") || name == "." || len(name) > 100 {
		return "", fmt.Errorf("%w (%q)", ErrUnusualDir, name)
	}
	return filepath.Join(env.AppData(), "Microsoft", name), nil
}

// DefaultValueType is the registry type in which Outlook reads the default
// signature values ("New Signature", "Reply-Forward Signature") of account a.
//
// Outlook 2016 and later (16.0, including Microsoft 365) only accept REG_SZ
// there - even though the account's other texts ("Email", "Account Name")
// are often REG_BINARY. Field report (IMAP account, Microsoft 365): a
// REG_BINARY value with the right name was ignored, the signature was listed
// in Outlook but not selected as the default. Outlook 2013 (15.0) stored
// these values as REG_BINARY; for it the type of an existing value, otherwise
// the type of the account's texts, is kept.
func DefaultValueType(a Account, valueName string) uint32 {
	if major(a.Version) >= 16 {
		return RegSZ
	}
	if valueName == ValueNew && a.HasNew && (a.RawNew.Type == RegSZ || a.RawNew.Type == RegBinary) {
		return a.RawNew.Type
	}
	if valueName == ValueReply && a.HasReply && (a.RawReply.Type == RegSZ || a.RawReply.Type == RegBinary) {
		return a.RawReply.Type
	}
	if a.TextType == RegBinary {
		return RegBinary
	}
	return RegSZ
}

// IsDefault reports whether the value valueName of account a already names
// the signature name in the type Outlook reads (see DefaultValueType).
func IsDefault(a Account, valueName, name string) bool {
	cur, has, raw := a.New, a.HasNew, a.RawNew
	if valueName == ValueReply {
		cur, has, raw = a.Reply, a.HasReply, a.RawReply
	}
	return has && cur == name && raw.Type == DefaultValueType(a, valueName)
}

// major returns the major number of an Office version such as "16.0" (0 if unreadable).
func major(version string) int {
	n := 0
	for _, c := range version {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		if n > 1000 {
			return 0
		}
	}
	return n
}

// SetDefault registers name as the default signature of an account. valueName
// is ValueNew or ValueReply. Anything else is rejected. The value is written
// in the type Outlook reads (DefaultValueType); nothing else is ever written.
func SetDefault(reg Registry, a Account, valueName, name string) error {
	if err := checkAccountWrite(a.Key, valueName); err != nil {
		return err
	}
	if !sigNameRe.MatchString(name) {
		return fmt.Errorf("outlook: invalid signature name %q", name)
	}
	return reg.Set(a.Key, valueName, StringValue(DefaultValueType(a, valueName), name))
}

// Restore restores an earlier value (prev == nil: remove the value).
func Restore(reg Registry, key, valueName string, prev *Value) error {
	if err := checkAccountWrite(key, valueName); err != nil {
		return err
	}
	if prev == nil {
		return reg.Delete(key, valueName)
	}
	if prev.Type != RegSZ && prev.Type != RegBinary && prev.Type != RegExpandSZ || len(prev.Data) > 4096 {
		return fmt.Errorf("outlook: stored previous value for %s is implausible - not written back", valueName)
	}
	return reg.Set(key, valueName, *prev)
}

func checkAccountWrite(key, valueName string) error {
	if !accountKeyRe.MatchString(key) {
		return fmt.Errorf("outlook: %q is not an account key of an Outlook profile - not written", key)
	}
	if valueName != ValueNew && valueName != ValueReply {
		return fmt.Errorf("outlook: value %q is not written", valueName)
	}
	return nil
}

// Roaming describes the roaming-signature switch of one Office version.
type Roaming struct {
	Version  string
	Disabled bool // disabled by user setting or group policy
	ByPolicy bool
	HasSetup bool // the key ...\Outlook\Setup exists (Outlook has been started before)
}

func setupKey(version string) string { return officeKey + `\` + version + `\Outlook\Setup` }

func isOne(reg Registry, key, name string) bool {
	v, err := reg.Get(key, name)
	if err != nil {
		return false
	}
	n, ok := v.DWORD()
	return ok && n == 1
}

// RoamingState reads the switch (user branch and policy branch).
func RoamingState(reg Registry, version string) Roaming {
	r := Roaming{Version: version}
	_, err := reg.SubKeys(setupKey(version))
	r.HasSetup = err == nil
	pol := policyKey + `\` + version + `\Outlook\Setup`
	r.ByPolicy = isOne(reg, pol, ValueNoRoaming) || isOne(reg, pol, ValueNoRoamingOld)
	r.Disabled = r.ByPolicy || isOne(reg, setupKey(version), ValueNoRoaming) || isOne(reg, setupKey(version), ValueNoRoamingOld)
	return r
}

// SetRoamingSwitch sets one of the two switches (v == nil: remove the value).
// The policy branch is never written.
func SetRoamingSwitch(reg Registry, version, valueName string, v *Value) error {
	key := setupKey(version)
	if !setupKeyRe.MatchString(key) || (valueName != ValueNoRoaming && valueName != ValueNoRoamingOld) {
		return fmt.Errorf("outlook: %s\\%s is not written", key, valueName)
	}
	if v == nil {
		return reg.Delete(key, valueName)
	}
	if v.Type != RegDWORD || len(v.Data) != 4 {
		return fmt.Errorf("outlook: switch %s must be a DWORD", valueName)
	}
	return reg.Set(key, valueName, *v)
}

// NewOutlook describes whether the "new Outlook" (olk.exe) is present.
type NewOutlook struct {
	Installed bool // the app package Microsoft.OutlookForWindows is present for the user
	Active    bool // the user has switched from classic Outlook to the new one
}

// DetectNewOutlook detects the new Outlook. It stores signatures in the
// mailbox and reads neither signature files nor the registry; a local agent
// cannot configure anything there - it can only report it.
func DetectNewOutlook(reg Registry, env platform.Env) NewOutlook {
	var n NewOutlook
	if m, _ := filepath.Glob(filepath.Join(env.LocalAppData(), "Packages", "Microsoft.OutlookForWindows_*")); len(m) > 0 {
		n.Installed = true
	}
	if reg != nil {
		for _, ver := range Versions(reg) {
			if isOne(reg, officeKey+`\`+ver+`\Outlook\Preferences`, "UseNewOutlook") {
				n.Active = true
			}
		}
	}
	return n
}

// ValidName reports whether name is a signature name as assigned by the agent.
func ValidName(name string) bool { return sigNameRe.MatchString(name) }

// RoamingSwitchValue reads one of the two switches from the user branch (nil = not set).
func RoamingSwitchValue(reg Registry, version, valueName string) *Value {
	v, err := reg.Get(setupKey(version), valueName)
	if err != nil {
		return nil
	}
	return &v
}

// Forced is a default signature that Outlook takes from Common\MailSettings
// instead of from the account: set by a group policy (Software\Policies\...)
// or left over from Outlook 2007 / older deployment scripts. While such a
// value exists, the per-account default the agent sets may be ignored.
type Forced struct {
	Version  string
	ByPolicy bool
	Value    string // NewSignature or ReplySignature
	Name     string // the signature name (may be empty = "no signature")
}

// ForcedDefaults reads NewSignature/ReplySignature from the user branch and
// the policy branch of Common\MailSettings. Only reads, never writes.
func ForcedDefaults(reg Registry, version string) []Forced {
	var out []Forced
	for _, br := range []struct {
		key    string
		policy bool
	}{
		{policyKey + `\` + version + `\Common\MailSettings`, true},
		{officeKey + `\` + version + `\Common\MailSettings`, false},
	} {
		for _, vn := range []string{"NewSignature", "ReplySignature"} {
			if s, _, ok := getString(reg, br.key, vn); ok {
				out = append(out, Forced{Version: version, ByPolicy: br.policy, Value: vn, Name: s})
			}
		}
	}
	return out
}
